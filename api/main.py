import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from api.routes import accounted, health
from api.routes import provenance as provenance_module
from api.middleware import ProvenanceMiddleware, RateLimitMiddleware
from collectors.api_collector import create_api_collector
from database.graph_db import graph_db
from database.cache import cache_manager
from processing.event_processor import stream_processor
from config import settings


try:
    import aiokafka  # noqa: F401
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def api_maker_lock(path: str = None):
    """The held lock file if this uvicorn worker runs the host's backup statement maker, else None."""
    path = path or os.getenv("ACCT_API_MAKER_LOCK", "/tmp/acct-maker.lock")
    try:
        import fcntl
    except ImportError:                  # no fcntl (Windows): no API maker
        return None
    f = open(path, "a")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


async def _source_partitions(producer, topic: str):
    """The partitions the producer's topic has now, or None."""
    try:
        return {int(p) for p in (await producer.partitions_for(topic) or ())}
    except Exception as e:
        logger.warning(f"acct_mode: partitions of {topic} not readable: {type(e).__name__}: {e}")
    return None


async def acct_source_problems(producer) -> list:
    """Why the API must not acknowledge on this producer's topic (partitions, topic settings or send
    bound against the published contract); empty when they match or no contract is published."""
    from processing import sources
    _, cbody = provenance_module._acct_contract()
    if cbody is None:
        return []
    topic = settings.kafka_provenance_topic
    parts = await _source_partitions(producer, topic)
    config = None
    try:
        config = await sources.kafka_topic_config(producer, settings, topic)
        if config is None:
            logger.warning(f"acct_mode: settings of topic {topic} not readable: retention unchecked")
    except Exception as e:
        logger.warning(f"acct_mode: settings of topic {topic} not readable ({type(e).__name__}: {e}): "
                       f"retention unchecked")
    problems, warnings = sources.check_source_against_contract(
        cbody, topic=topic, open_partitions=parts, topic_config=config)
    problems = list(problems) + provenance_module.acct_timing_problems(cbody)
    for w in warnings:
        logger.warning(f"acct_mode: {w}")
    return problems


async def _acct_source_watch(period_s: float) -> None:
    """Repeat acct_source_problems every period_s; on a problem stop the producer (the route then
    answers 503)."""
    while True:
        await asyncio.sleep(period_s)
        producer = provenance_module.kafka_producer
        if producer is None:
            return
        problems = await acct_source_problems(producer)
        if problems:
            for p in problems:
                logger.error(f"INTEGRITY ALARM [source]: {p}; not acknowledging")
            provenance_module.kafka_producer = None
            try:
                await producer.stop()
            except Exception:
                pass
            return


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting the ingest API")
    # Raises before any connection is opened.
    settings.validate_production_settings()

    try:
        await graph_db.initialize()
        await cache_manager.initialize()

        api_collector = create_api_collector()
        if settings.acct_mode and api_collector.ingest_client is None:
            # Accounted mode admits events only through the ingest API: a collector producing to
            # Kafka directly would put records in the broker that authenticate no tenant.
            logger.error("acct_mode: the request-path collector has no ingest client "
                         "(ACCT_INGEST_URL, ACCT_INGEST_API_KEY); request-path collection is off")
            api_collector = None
        else:
            await api_collector.initialize()
        app.state.api_collector = api_collector

        # Each processor opens its own consumer in the group, in every uvicorn worker.
        n_proc = int(os.getenv("STREAM_PROCESSORS", "3"))
        # START_STREAM_PROCESSOR=false: the consumers run as separate processes (processing/run_consumer.py).
        if os.getenv("START_STREAM_PROCESSOR", "true").strip().lower() in ("1", "true", "yes"):
            await stream_processor.initialize(num_processors=n_proc)
            app.state.processor_task = asyncio.create_task(stream_processor.start())
            logger.info("Stream processor started")
        else:
            logger.warning("START_STREAM_PROCESSOR=false: no consumer in this process; "
                           "run processing.run_consumer separately")

        acct = bool(settings.acct_mode)
        from processing import sources as _sources
        if KAFKA_AVAILABLE and settings.kafka_bootstrap_servers:
            try:
                from aiokafka import AIOKafkaProducer
                # Not idempotent: an idempotent aiokafka batch never expires and could land after delta.
                timing = _sources.kafka_producer_timing()
                provenance_module.kafka_producer = AIOKafkaProducer(
                    bootstrap_servers=settings.kafka_bootstrap_servers,
                    # allow_nan=False: bytes the record validator refuses are never produced.
                    value_serializer=lambda v: json.dumps(v, default=str, allow_nan=False).encode('utf-8'),
                    compression_type='gzip',
                    acks='all',
                    enable_idempotence=False,
                    request_timeout_ms=timing["request_timeout_ms"],
                    retry_backoff_ms=timing["retry_backoff_ms"],
                    linger_ms=timing["linger_ms"],
                    max_batch_size=_sources.kafka_producer_batch_bytes(),
                )
                await provenance_module.kafka_producer.start()
                logger.info("Kafka producer started")
                if acct:
                    # A topic that does not match the contract is not acknowledged on (503).
                    problems = await acct_source_problems(provenance_module.kafka_producer)
                    if problems:
                        for p in problems:
                            logger.error(f"acct_mode: {p}; not acknowledging")
                        await provenance_module.kafka_producer.stop()
                        provenance_module.kafka_producer = None
                    else:
                        app.state.acct_source_watch = asyncio.create_task(_acct_source_watch(
                            float(settings.acct_partition_check_s or 60.0)))
            except Exception as e:
                logger.warning(f"Kafka producer not started: {e}")
                provenance_module.kafka_producer = None
        else:
            logger.info("No Kafka producer: aiokafka or kafka_bootstrap_servers missing")

        # A backup statement maker, one per host; the deployment's maker is processing/run_maker.py.
        if acct and settings.acct_periods and settings.acct_api_maker:
            lock = api_maker_lock()
            if lock is not None:
                from crypto.period_statements import period_statement_loop
                app.state.api_maker_lock = lock
                app.state.api_maker = asyncio.create_task(period_statement_loop(backup=True))
                logger.info("This API process runs a backup statement maker")

        logger.info("All services initialized")
        from processing.runtime import freeze_startup_heap
        freeze_startup_heap(logger)

        yield

    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise
    finally:
        logger.info("Shutting down the ingest API")

        if hasattr(app.state, 'acct_source_watch'):
            app.state.acct_source_watch.cancel()
        if hasattr(app.state, 'api_maker'):
            app.state.api_maker.cancel()
        if hasattr(app.state, 'processor_task'):
            app.state.processor_task.cancel()
            try:
                await app.state.processor_task
            except asyncio.CancelledError:
                pass

        if provenance_module.kafka_producer:
            await provenance_module.kafka_producer.stop()
            logger.info("Kafka producer stopped")

        await stream_processor.stop()
        await cache_manager.close()

        logger.info("Shutdown complete")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Ingest API of the accounted provenance pipeline",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(RateLimitMiddleware,
                   requests_per_minute=settings.rate_limit_requests_per_minute)
if settings.provenance_middleware_enabled:
    app.add_middleware(ProvenanceMiddleware)


app.include_router(
    health.router,
    prefix="/health",
    tags=["health"]
)

app.include_router(
    provenance_module.router,
    prefix=settings.api_prefix + "/provenance",
    tags=["provenance"]
)

app.include_router(accounted.router, prefix=settings.api_prefix + "/accounted", tags=["accounted"])


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Bad Request",
            "message": str(exc)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }
    )


if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info"
    )
