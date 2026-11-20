import asyncio
import logging
import os
import signal

from config import settings
from crypto.merkle_tree_storage import merkle_tree_storage
from database.graph_db import graph_db
from processing.event_processor import stream_processor
from processing.runtime import freeze_startup_heap

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("run_consumer")


def _publisher_loop():
    """In accounted mode, a backup period-statement maker (the main one is processing/run_maker.py)."""
    if settings.acct_mode and settings.acct_periods:
        from crypto.period_statements import period_statement_loop
        return period_statement_loop(backup=True)
    return asyncio.sleep(0)


async def main() -> None:
    await graph_db.initialize()

    n_proc = int(os.getenv("STREAM_PROCESSORS", "1"))
    await stream_processor.initialize(num_processors=n_proc)
    logger.info(f"consumer process up: {n_proc} stream processor(s), group {settings.kafka_consumer_group}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:      # not on this platform
            pass

    # The heartbeat anchors this process's own tail when traffic stops; only the process that
    # appended a record may anchor it.
    heartbeat = asyncio.create_task(merkle_tree_storage.anchor_heartbeat_loop())
    publisher = asyncio.create_task(_publisher_loop())

    freeze_startup_heap(logger)
    task = asyncio.create_task(stream_processor.start())
    done, _ = await asyncio.wait({task, asyncio.create_task(stop.wait())},
                                 return_when=asyncio.FIRST_COMPLETED)
    if task in done and task.exception() is not None:
        logger.error(f"stream processor exited: {task.exception()}")
    else:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    heartbeat.cancel()
    publisher.cancel()
    await asyncio.gather(heartbeat, publisher, return_exceptions=True)
    await stream_processor.stop()
    logger.info("consumer process stopped")


if __name__ == "__main__":
    asyncio.run(main())
