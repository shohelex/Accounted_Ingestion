from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))          # the project root: crypto/, schemas.py

import sqlledger_common as sc                     # noqa: E402
from immudb_sink import bootstrap_servers, key_of, leaf_bytes   # noqa: E402

log = logging.getLogger("sqlledger_sink")


class Sink:
    def __init__(self, connect=None):
        self.settings = sc.settings()
        self.batch = min(sc.MAX_ROWS_PER_INSERT, max(1, int(os.environ.get("SINK_BATCH", "32"))))
        self.topic = os.environ.get("KAFKA_TOPIC", "provenance-events")
        self.group = os.environ.get("SINK_GROUP", "sqlledger-sink")
        self._connect_fn = connect or (lambda: sc.connect(self.settings))
        self.conn = None
        self.stop = asyncio.Event()
        self.written = self.transactions = self.retries = 0
        self.watchdog_s = float(os.environ.get("SQLLEDGER_WATCHDOG_S", "60"))

    # pymssql is synchronous; calls run in a thread.
    def _write(self, kv: dict) -> None:
        # The connection is held locally: a call abandoned by the watchdog below may return long
        # after, and must not then drop the connection a later attempt opened.
        conn = self.conn
        if conn is None:
            conn = self.conn = self._connect_fn()
        try:
            cur = conn.cursor()
            cur.execute(sc.insert_statement(len(kv)), sc.insert_params(kv))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass
            if self.conn is conn:
                self.conn = None        # reconnect on the next attempt; the caller retries
            raise

    async def write(self, kv: dict) -> None:
        delay = 0.5
        while not self.stop.is_set():
            try:
                # A wall-clock limit on the whole call; a stuck connection is abandoned.
                try:
                    await asyncio.wait_for(asyncio.to_thread(self._write, kv), self.watchdog_s)
                except asyncio.TimeoutError:
                    self.conn = None
                    raise TimeoutError(f"no answer in {self.watchdog_s:.0f} s; reconnecting")
                self.transactions += 1
                self.written += len(kv)
                return
            except Exception as e:
                self.retries += 1
                log.warning(f"SQL ledger write failed ({str(e)[:160]}); retrying in {delay:.1f} s")
                await asyncio.sleep(delay)
                delay = min(8.0, delay * 2)
        raise RuntimeError("stopping")

    async def run(self) -> None:
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            self.topic, bootstrap_servers=bootstrap_servers(), group_id=self.group, enable_auto_commit=False,
            auto_offset_reset="earliest", max_poll_records=self.batch * 8,
            session_timeout_ms=int(os.environ.get("KAFKA_SESSION_TIMEOUT_MS", "45000")),
            max_poll_interval_ms=int(os.environ.get("KAFKA_MAX_POLL_INTERVAL_MS", "600000")))
        await consumer.start()
        s = self.settings
        log.info(f"Sink up: {self.topic} -> SQL ledger {s['host']}:{s['port']}/{s['database']}, "
                 f"batch {self.batch}")
        ticker = asyncio.create_task(self.tick())
        try:
            while not self.stop.is_set():
                polled = await consumer.getmany(timeout_ms=200, max_records=self.batch * 8)
                for tp, records in polled.items():
                    for i in range(0, len(records), self.batch):
                        chunk = records[i:i + self.batch]
                        kv = self.chunk_to_kv(chunk, tp)
                        if kv:
                            await self.write(kv)
                        await consumer.commit({tp: chunk[-1].offset + 1})
        finally:
            ticker.cancel()
            await consumer.stop()

    @staticmethod
    def chunk_to_kv(chunk, tp=None) -> dict:
        kv = {}
        for r in chunk:
            try:
                ev = json.loads(r.value)
                kv[key_of(ev)] = leaf_bytes(ev)
            except Exception as e:      # unparsable: nothing to store, do not block the partition
                log.error(f"Skipping an unparsable record at {tp}:{r.offset}: {e}")
        return kv

    def tick_line(self) -> str:
        # The format sink_rate.py parses.
        return (f"SINK_TICK t={time.time():.3f} written={self.written} "
                f"transactions={self.transactions} retries={self.retries}")

    async def tick(self) -> None:
        while not self.stop.is_set():
            log.info(self.tick_line())
            await asyncio.sleep(1.0)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sink = Sink()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, sink.stop.set)
        except NotImplementedError:
            pass
    await sink.run()


if __name__ == "__main__":
    import argparse
    argparse.ArgumentParser().parse_args()      # settings come from the environment
    asyncio.run(main())
