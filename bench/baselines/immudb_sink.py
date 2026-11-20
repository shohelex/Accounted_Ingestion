from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))     # the project root: crypto/, schemas.py

log = logging.getLogger("immudb_sink")


def bootstrap_servers() -> list:
    raw = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").strip()
    if raw.startswith("["):
        return json.loads(raw)
    return [x.strip() for x in raw.split(",") if x.strip()]


def leaf_bytes(event: dict) -> bytes:
    """The leaf bytes the pipeline's log would hash; canonical JSON for a record the schema rejects."""
    try:
        from crypto.incremental_merkle import canonicalize
        from crypto.leaf_format import leaf_event_data
        from schemas import ProvenanceEvent
        return canonicalize(leaf_event_data(ProvenanceEvent(**event)))
    except Exception:
        return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode()


def key_of(event: dict) -> bytes:
    # The event id is unique across tenants and is what the API returns in the acknowledgement.
    return str(event.get("event_id")).encode()


class Sink:
    def __init__(self):
        self.addr = os.environ.get("IMMUDB_ADDR", "localhost:3322")
        self.user = os.environ.get("IMMUDB_USER", "immudb")
        self.password = os.environ.get("IMMUDB_PASSWORD", "immudb")
        self.database = os.environ.get("IMMUDB_DATABASE", "defaultdb")
        self.batch = max(1, int(os.environ.get("SINK_BATCH", "32")))
        self.topic = os.environ.get("KAFKA_TOPIC", "provenance-events")
        self.group = os.environ.get("SINK_GROUP", "immudb-sink")
        self.client = None
        self.stop = asyncio.Event()
        self.written = self.transactions = self.retries = 0

    # The immudb client is synchronous; calls run in a thread.
    def _connect(self):
        from immudb import ImmudbClient
        c = ImmudbClient(self.addr)
        c.login(self.user, self.password)
        c.useDatabase(self.database.encode())
        self.client = c

    def _write(self, kv: dict) -> None:
        if self.client is None:
            self._connect()
        try:
            self.client.setAll(kv)
        except Exception:
            self.client = None          # reconnect on the next attempt; the caller retries
            raise

    async def write(self, kv: dict) -> None:
        delay = 0.5
        while not self.stop.is_set():
            try:
                await asyncio.to_thread(self._write, kv)
                self.transactions += 1
                self.written += len(kv)
                return
            except Exception as e:
                self.retries += 1
                log.warning(f"immudb write failed ({str(e)[:120]}); retrying in {delay:.1f} s")
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
        log.info(f"Sink up: {self.topic} -> immudb {self.addr}, batch {self.batch}")
        ticker = asyncio.create_task(self.tick())
        try:
            while not self.stop.is_set():
                polled = await consumer.getmany(timeout_ms=200, max_records=self.batch * 8)
                for tp, records in polled.items():
                    for i in range(0, len(records), self.batch):
                        chunk = records[i:i + self.batch]
                        kv = {}
                        for r in chunk:
                            try:
                                ev = json.loads(r.value)
                                kv[key_of(ev)] = leaf_bytes(ev)
                            except Exception as e:      # unparsable: nothing to store, do not block the partition
                                log.error(f"Skipping an unparsable record at {tp}:{r.offset}: {e}")
                        if kv:
                            await self.write(kv)
                        await consumer.commit({tp: chunk[-1].offset + 1})
        finally:
            ticker.cancel()
            await consumer.stop()

    def tick_line(self) -> str:
        return (f"SINK_TICK t={time.time():.3f} written={self.written} "
                f"transactions={self.transactions} retries={self.retries}")

    async def tick(self) -> None:
        # Its own task, so a write that is retrying does not stop the clock.
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
