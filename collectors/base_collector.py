import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

try:
    from kafka import KafkaProducer
    from aiokafka import AIOKafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KafkaProducer = None
    AIOKafkaProducer = None
    KAFKA_AVAILABLE = False

from api.ingest_rules import valid_tenant_id
from schemas import (ProvenanceActivity, ProvenanceAgent, ProvenanceEntity, ProvenanceEvent, SourceType,
                     EventType)
from config import settings

logger = logging.getLogger(__name__)


class BaseProvenanceCollector:
    def __init__(self, source_type: SourceType, ingest_client=None):
        self.source_type = source_type
        self.kafka_producer = None
        self.async_producer = None
        self._is_initialized = False
        # With an ingest client every event goes through the ingest API and its acknowledgement
        # contract; without one, events are produced to Kafka directly, with no receipt.
        self.ingest_client = ingest_client

    async def initialize(self):
        try:
            if self.ingest_client is not None:
                self._is_initialized = True
                logger.info(f"{self.__class__.__name__} initialized (delivery through the ingest API)")
                return
            if settings.acct_mode:
                # Only the ingest API tags records; one produced here would be accounted as UNAUTH.
                raise RuntimeError(f"{self.__class__.__name__}: acct_mode requires delivery "
                                   f"through the ingest API (pass an ingest_client)")
            if not KAFKA_AVAILABLE:
                logger.warning("Kafka not available, events are stored locally for retry")
                self._is_initialized = True
                return

            try:
                self.async_producer = AIOKafkaProducer(
                    bootstrap_servers=settings.kafka_bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None,
                    acks='all',
                    compression_type='gzip'
                )
                await self.async_producer.start()
                logger.debug("Kafka async producer initialized")

            except Exception as kafka_error:
                logger.warning(f"Failed to initialize Kafka async producer: {kafka_error}")
                self.async_producer = None

            try:
                if not self.async_producer:
                    self.kafka_producer = KafkaProducer(
                        bootstrap_servers=settings.kafka_bootstrap_servers,
                        value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                        key_serializer=lambda k: k.encode('utf-8') if k else None,
                        acks='all',
                        retries=3,
                        max_in_flight_requests_per_connection=1,
                        compression_type='gzip'
                    )
                    logger.debug("Kafka sync producer initialized as fallback")

            except Exception as kafka_error:
                logger.warning(f"Failed to initialize Kafka sync producer: {kafka_error}")
                self.kafka_producer = None

            if not self.async_producer and not self.kafka_producer:
                logger.warning("Kafka not available, events are stored locally for retry")

            self._is_initialized = True
            logger.info(f"{self.__class__.__name__} initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize {self.__class__.__name__}: {e}")
            raise

    async def send_event(self, event: ProvenanceEvent) -> bool:
        if not self._is_initialized:
            logger.error("Collector not initialized")
            return False

        try:
            if not self._validate_event(event):
                return False

            if self.ingest_client is not None:
                return await self.ingest_client.submit(self.to_ingest_body(event))

            event_dict = event.dict()

            if self.async_producer or self.kafka_producer:
                try:
                    if self.async_producer:
                        # send() only buffers; wait for the broker's acknowledgement.
                        await self.async_producer.send_and_wait(
                            settings.kafka_provenance_topic,
                            key=event.tenant_id,
                            value=event_dict
                        )
                        logger.debug(f"Sent event {event.event_id} to Kafka (async)")
                    else:
                        self.kafka_producer.send(
                            settings.kafka_provenance_topic,
                            key=event.tenant_id,
                            value=event_dict
                        )
                        logger.debug(f"Sent event {event.event_id} to Kafka (sync)")
                    return True

                except Exception as kafka_error:
                    logger.error(f"Failed to send to Kafka: {kafka_error}")
                    await self._store_for_retry(event)
                    return False
            else:
                logger.debug(f"Kafka not available, storing event {event.event_id} locally")
                await self._store_for_retry(event)
                await self._try_direct_processing(event_dict)
                return True

        except Exception as e:
            logger.error(f"Unexpected error sending event: {e}")
            return False

    @staticmethod
    def to_ingest_body(event: ProvenanceEvent) -> Dict[str, Any]:
        """The ingest API's flat form of an event (POST /api/v1/provenance/events)."""
        body = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source.value,
            "event_type": event.event_type.value,
            "operation": event.activity.operation.value,
            "resource": event.activity.resource,
            "user_id": event.agent.id,
            "user_ip": event.agent.ip,
            "details": event.activity.metadata,
        }
        # Metadata may hold datetimes and enums; the body must be plain JSON.
        return json.loads(json.dumps(body, default=str))

    async def _store_for_retry(self, event: ProvenanceEvent):
        try:
            retry_dir = "retry_queue"
            os.makedirs(retry_dir, exist_ok=True)
            retry_file = f"{retry_dir}/event_{event.event_id}.json"
            with open(retry_file, 'w') as f:
                json.dump(event.dict(), f, default=str)
            logger.debug(f"Stored event {event.event_id} for retry")

        except Exception as e:
            logger.error(f"Failed to store event for retry: {e}")

    async def _try_direct_processing(self, event_dict: dict):
        """Process the event in this process when Kafka is not available and a processor runs here."""
        try:
            from processing.event_processor import stream_processor   # here: circular import
            if stream_processor.processors:
                await stream_processor.processors[0]._process_single_event(event_dict)
                logger.debug(f"Processed event {event_dict.get('event_id')} directly")
        except Exception as e:
            logger.debug(f"Direct processing failed: {e}; event stored for later")

    def _validate_event(self, event: ProvenanceEvent) -> bool:
        if not event.event_id:
            logger.error("Event missing required event_id")
            return False

        # The id becomes a Kafka key and a path component in the anchor store.
        if not valid_tenant_id(event.tenant_id):
            logger.error(f"Invalid tenant_id {event.tenant_id!r}")
            return False

        if event.source != self.source_type:
            logger.error(f"Event source {event.source} doesn't match collector type {self.source_type}")
            return False

        return True

    def create_event(self, event_type: EventType, entity_data: Dict[str, Any],
                     agent_data: Dict[str, Any], activity_data: Dict[str, Any],
                     tenant_id: str, timestamp: Optional[datetime] = None,
                     event_id: Optional[str] = None) -> ProvenanceEvent:
        # A collector passes an event_id derived from its source, so a resent event is the same event.
        return ProvenanceEvent(
            event_id=event_id or str(uuid.uuid4()),
            timestamp=timestamp or datetime.utcnow(),
            tenant_id=tenant_id,
            source=self.source_type,
            event_type=event_type,
            entity=ProvenanceEntity(**entity_data),
            agent=ProvenanceAgent(**agent_data),
            activity=ProvenanceActivity(**activity_data),
        )

    async def batch_send_events(self, events: List[ProvenanceEvent]) -> Dict[str, int]:
        results = {"success": 0, "failed": 0}
        for event in events:
            if await self.send_event(event):
                results["success"] += 1
            else:
                results["failed"] += 1
        logger.info(f"Batch send completed: {results['success']} success, {results['failed']} failed")
        return results


class ProvenanceEventBuffer:
    """A bounded queue between the request path and a background sender, which sends batches of up
    to max_size events or what arrived within max_age_seconds of the first. add_event() never waits;
    on a full queue the event is dropped and counted, so a pipeline outage does not block requests."""

    def __init__(self, max_size: int = 100, max_age_seconds: float = 30, queue_max: int = 10_000):
        self.max_size = max(1, int(max_size))
        self.max_age_seconds = float(max_age_seconds)
        self.queue_max = max(1, int(queue_max))
        self._queue: Optional[asyncio.Queue] = None
        self._task: Optional[asyncio.Task] = None
        self._collector: Optional[BaseProvenanceCollector] = None
        self.stats = {"queued": 0, "dropped": 0, "sent": 0, "failed": 0, "batches": 0, "queue_peak": 0}

    def _ensure(self, collector: BaseProvenanceCollector) -> None:
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=self.queue_max)
        self._collector = collector
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def add_event(self, event: ProvenanceEvent, collector: BaseProvenanceCollector) -> bool:
        """False if the queue was full and the event was dropped."""
        self._ensure(collector)
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.stats["dropped"] += 1
            logger.error(f"Provenance event queue full: event {event.event_id} dropped")
            return False
        self.stats["queued"] += 1
        self.stats["queue_peak"] = max(self.stats["queue_peak"], self._queue.qsize())
        return True

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            batch = [await self._queue.get()]
            end = loop.time() + self.max_age_seconds
            while len(batch) < self.max_size:
                try:
                    batch.append(self._queue.get_nowait())
                    continue
                except asyncio.QueueEmpty:
                    pass
                left = end - loop.time()
                if left <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self._queue.get(), timeout=left))
                except asyncio.TimeoutError:
                    break
            try:
                results = await self._collector.batch_send_events(batch)
                self.stats["sent"] += results.get("success", 0)
                self.stats["failed"] += results.get("failed", 0)
            except Exception as e:
                logger.error(f"Failed to send a batch of provenance events: {e}")
                self.stats["failed"] += len(batch)
            finally:
                self.stats["batches"] += 1
                for _ in batch:
                    self._queue.task_done()
