from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

PREFIX = "stops"


def stop_prefix(topic: str) -> str:
    return f"{PREFIX}/{topic}/"


def stop_key(topic: str, p: int, o: int) -> str:
    return f"{PREFIX}/{topic}/{int(p):05d}/{int(o):020d}.json"


def parse_stop_key(key: str) -> Optional[tuple]:
    """(topic, p, o) of a marker key, or None."""
    parts = str(key).split("/")
    if len(parts) != 4 or parts[0] != PREFIX or not parts[3].endswith(".json"):
        return None
    try:
        return parts[1], int(parts[2]), int(parts[3][:-len(".json")])
    except ValueError:
        return None


# Names this process in the markers it writes, without naming its host.
WRITER_ID = secrets.token_hex(8)


def stop_body(topic: str, p: int, o: int, tenant: str, reason: str, epoch: Optional[int]) -> bytes:
    return json.dumps({"v": 1, "kind": "stop", "topic": topic, "p": int(p), "o": int(o),
                       "tenant": tenant, "reason": reason, "epoch": epoch, "writer": WRITER_ID,
                       "at_ms": int(time.time() * 1000)},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


async def write_stop(store, topic: str, p: int, o: int, tenant: str, reason: str,
                     epoch: Optional[int], attempts: int = 3, backoff_s: float = 0.5) -> bool:
    """Write the marker, retrying a failing store a bounded number of times. True once a marker for
    (topic, p, o) is in the store, written now or already there (WriteConflict). Never raises."""
    from crypto.anchor_store import WriteConflict
    key = stop_key(topic, p, o)
    body = stop_body(topic, p, o, tenant, reason, epoch)
    for i in range(max(1, int(attempts))):
        try:
            await asyncio.to_thread(store.put_once, key, body)
            return True
        except WriteConflict:
            return True
        except Exception as e:                      # the store is down or slow
            logger.warning(f"stop marker {key} not written (attempt {i + 1}/{attempts}): {e}")
            if i + 1 < attempts:
                await asyncio.sleep(backoff_s * (2 ** i))
    return False


def stopped_partitions(store, topic: str) -> Dict[int, int]:
    """{partition: lowest stopped offset} from the markers of topic. Raises if the store cannot
    be listed (the caller keeps its last answer)."""
    out: Dict[int, int] = {}
    for k in store.list_keys(stop_prefix(topic)):
        parsed = parse_stop_key(k)
        if parsed is None or parsed[0] != topic:
            continue
        _, p, o = parsed
        out[p] = min(o, out.get(p, o))
    return out


class StopWatch:
    """One API process's view of the stopped partitions, refreshed at most every interval_s; the
    last good answer is kept when a listing fails."""

    def __init__(self, wait_s: float = 0.5):
        self.stopped: Dict[int, int] = {}
        self.checked_at = 0.0
        self.topic: Optional[str] = None
        self.store = None
        self.alarmed: set = set()
        self.wait_s = float(wait_s)
        self._task = None

    async def _list(self, store, topic: str) -> None:
        try:
            got = await asyncio.to_thread(stopped_partitions, store, topic)
        except Exception as e:
            logger.warning(f"stop markers of {topic} not listed, keeping the last answer: {e}")
            return
        if self.store is store and self.topic == topic:
            self.stopped = got

    async def refresh(self, store, topic: str, interval_s: float, now: float) -> Dict[int, int]:
        """Start a listing when the last one is interval_s old and wait for it at most wait_s, so a
        slow store does not hold ingest requests; the last answer stands meanwhile."""
        if self.topic != topic or self.store is not store:
            # Another topic (the deployment re-pointed) or another store: start afresh.
            self.topic, self.store, self.stopped, self.checked_at, self.alarmed = \
                topic, store, {}, 0.0, set()
            self._task = None
        if self._task is not None and self._task.get_loop() is not asyncio.get_running_loop():
            self._task = None                              # left by a loop that has since closed
        if (not self.checked_at or now - self.checked_at >= interval_s) and \
                (self._task is None or self._task.done()):
            self.checked_at = now
            self._task = asyncio.get_running_loop().create_task(self._list(store, topic))
        if self._task is not None and not self._task.done():
            await asyncio.wait({self._task}, timeout=self.wait_s)
        return self.stopped

    def refuse(self, topic: str, p: int) -> Optional[str]:
        """The reason to refuse partition p, logged once per partition, or None."""
        o = self.stopped.get(int(p))
        if o is None:
            return None
        why = (f"{topic}/{p} was stopped by the consumers at offset {o} (anchored data contradicts "
               f"the broker there: its log went backwards)")
        if int(p) not in self.alarmed:
            self.alarmed.add(int(p))
            logger.error(f"INTEGRITY ALARM [partition-stopped]: {why}; refusing its tenants until "
                         f"the deployment is re-pointed to a fresh topic")
        return why
