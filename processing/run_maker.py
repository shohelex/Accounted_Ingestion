import asyncio
import logging
import signal

from config import settings
from processing.runtime import freeze_startup_heap

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("run_maker")


def why_idle():
    """None when this process should run the maker, else the reason it does not."""
    if not settings.acct_mode:
        return "not in accounted mode"
    if not settings.acct_periods:
        return "period statements are off (acct_periods)"
    return None


async def main(stop: asyncio.Event = None) -> None:
    stop = stop or asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):   # not on this platform or thread
            pass
    reason = why_idle()
    if reason is not None:
        logger.info(f"statement maker idle: {reason}")
        await stop.wait()
        return
    logger.info(f"statement maker process up (deployment {settings.acct_deployment_id})")
    from crypto.period_statements import period_statement_loop
    freeze_startup_heap(logger)
    task = asyncio.create_task(period_statement_loop(backup=False))
    waiter = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    if task in done:
        # period_statement_loop runs until cancelled; the container restarts a maker that exits.
        logger.error(f"statement maker exited: {task.exception()}")
        waiter.cancel()
        raise SystemExit(1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    logger.info("statement maker process stopped")


if __name__ == "__main__":
    asyncio.run(main())
