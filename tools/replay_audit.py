#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# broker readers

def _dump_records(path: str):
    # One {"topic", "p", "o", "bt_ms", "key", "value"} per line (key and value as UTF-8, or base64
    # under key_b64 / value_b64), and optional {"topic", "p", "log_start", "hw"} partition lines.
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if "key_b64" in d:
                d["key"] = base64.b64decode(d.pop("key_b64"))
            elif isinstance(d.get("key"), str):
                d["key"] = d["key"].encode()
            if "value_b64" in d:
                d["value"] = base64.b64decode(d.pop("value_b64"))
            elif isinstance(d.get("value"), str):
                d["value"] = d["value"].encode()
            out.append(d)
    return out


_END = object()


class KafkaPartitionReader:
    """Every retained record of one partition from `start`, read by a thread outside any consumer
    group. marker["complete"] is True only if every offset up to hw was read before idle_s passed
    without progress."""

    def __init__(self, bootstrap: str, topic: str, p: int, start: Optional[int] = None,
                 idle_s: float = 60.0, depth: int = 10_000):
        self.bootstrap, self.topic, self.p = bootstrap, topic, int(p)
        self.start, self.idle_s = start, float(idle_s)
        self.q: "queue.Queue" = queue.Queue(maxsize=depth)
        self.marker: Dict = {"topic": topic, "p": int(p)}
        self._ready = threading.Event()
        self._error: Optional[BaseException] = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._error is not None:
            raise self._error

    def _run(self):
        try:
            asyncio.run(self._go())
        except BaseException as e:            # raised in the caller's thread
            self._error = e
            self._ready.set()
            self.q.put(_END)

    async def _go(self):
        from aiokafka import AIOKafkaConsumer
        from aiokafka.structs import TopicPartition
        consumer = AIOKafkaConsumer(bootstrap_servers=self.bootstrap, enable_auto_commit=False,
                                    auto_offset_reset="earliest")
        await consumer.start()
        try:
            tp = TopicPartition(self.topic, self.p)
            consumer.assign([tp])
            log_start = (await consumer.beginning_offsets([tp]))[tp]
            hw = (await consumer.end_offsets([tp]))[tp]
            self.marker.update(log_start=int(log_start), hw=int(hw))
            pos = max(int(log_start), int(self.start) if self.start is not None else 0)
            self._ready.set()
            if pos < hw:
                consumer.seek(tp, pos)
            last_progress = time.monotonic()
            while pos < hw:
                batch = await consumer.getmany(tp, timeout_ms=1000, max_records=5000)
                recs = batch.get(tp) or []
                if not recs:
                    if time.monotonic() - last_progress > self.idle_s:
                        break
                    continue
                for r in recs:
                    self.q.put({"topic": r.topic, "p": r.partition, "o": r.offset, "bt_ms": r.timestamp,
                                "key": r.key, "value": r.value})
                    pos = r.offset + 1
                last_progress = time.monotonic()
            self.marker["complete"] = pos >= hw
        finally:
            await consumer.stop()
            self.q.put(_END)

    def __iter__(self) -> Iterator[dict]:
        while True:
            item = self.q.get()
            if item is _END:
                if self._error is not None:
                    raise self._error
                return
            yield item


async def _kafka_partitions(bootstrap: str, topic: str) -> List[int]:
    from aiokafka import AIOKafkaConsumer
    consumer = AIOKafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    await consumer.start()
    try:
        parts = consumer.partitions_for_topic(topic)
        if not parts:
            # An unassigned consumer keeps no metadata for the topic (aiokafka): read it directly.
            md = await consumer._client.fetch_all_metadata()
            parts = md.partitions_for_topic(topic) or set()
        if not parts:
            raise RuntimeError(f"topic {topic} has no partitions at {bootstrap}: nothing to replay")
        return sorted(int(p) for p in parts)
    finally:
        await consumer.stop()


# stores

def make_store(spec: Tuple, key: bytes):
    from crypto.anchor_store import LocalWORMAnchorStore, S3ObjectLockAnchorStore
    if spec[0] == "local":
        store = LocalWORMAnchorStore(spec[1], fsync=False)
    else:
        store = S3ObjectLockAnchorStore(spec[1], prefix=spec[2], endpoint_url=spec[3])
    store.verify_key = key
    return store


def stored_periods(store, dep: str) -> Dict[int, set]:
    """{j: suffixes} of the period objects in the store, e.g. {".json", ".receipt.json"} for
    periods/<dep>/<j>.json and periods/<dep>/<j>.receipt.json."""
    pre = f"periods/{dep}/"
    out: Dict[int, set] = {}
    for k in store.list_keys(pre):
        name = k[len(pre):]
        j, dot, rest = name.partition(".")
        if dot and "/" not in name and j.isdigit():
            out.setdefault(int(j), set()).add("." + rest)
    return out


def load_statements(store, dep: str) -> Dict[int, dict]:
    from crypto.period_statements import period_key
    return {j: json.loads(store.get_object(period_key(dep, j)))
            for j, kinds in sorted(stored_periods(store, dep).items()) if ".json" in kinds}


# one partition, in a worker

def _replay_one(job: dict) -> dict:
    """Replay one partition with its own broker reader and store client, so it can run in a
    process of its own."""
    from crypto.audit_custody import replay_partition
    key = bytes.fromhex(job["key"])
    store = make_store(tuple(job["store"]), key)
    src = job["source"]
    if src[0] == "kafka":
        reader = KafkaPartitionReader(src[1], src[2], src[3], start=job["audit_from"], idle_s=src[4])
        records, marker = reader, reader.marker
    else:
        records, marker = src[1], src[2]
    return replay_partition(job["tk"], records, marker, store, job["plans"], job["contract"], key,
                            job["now_ms"], job["audit_from"], job["density"], job["W"], job["head_j"])


def run_audit(jobs: List[dict], workers: int) -> List[dict]:
    if workers <= 1 or len(jobs) <= 1:
        return [_replay_one(j) for j in jobs]
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        return list(pool.map(_replay_one, jobs))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", required=True, help="signed contract statement (JSON)")
    ap.add_argument("--key", required=True, help="deployment public key (hex)")
    ap.add_argument("--state", required=True, help="the auditor's state file (created if absent)")
    ap.add_argument("--out", required=True, help="directory for report.json and complaint files")
    ap.add_argument("--broker-dump", help="JSONL dump of the broker records, instead of --bootstrap")
    ap.add_argument("--bootstrap", help="Kafka bootstrap servers")
    ap.add_argument("--topic", default="provenance-events", help="Kafka topic")
    ap.add_argument("--store-dir", help="local anchor store, instead of --s3-bucket")
    ap.add_argument("--s3-bucket", help="S3 bucket of the anchor store")
    ap.add_argument("--s3-prefix", default="anchors", help="key prefix of the anchors in the bucket")
    ap.add_argument("--s3-endpoint", help="S3 endpoint URL (default: AWS)")
    ap.add_argument("--now-ms", type=int, default=None, help="evaluation time (default: now)")
    ap.add_argument("--workers", type=int, default=1, help="partitions replayed at once, one process each")
    ap.add_argument("--read-idle-s", type=float, default=60.0,
                    help="a Kafka read with no progress for this long ends (incomplete)")
    ap.add_argument("--partitions", default=None,
                    help="comma list: replay only these partitions (default: every partition)")
    a = ap.parse_args(argv)

    from crypto import records as R
    from crypto.audit_custody import (_latest_head_W, merge_reports, plan_replay,
                                      split_by_partition)
    from crypto.signing import verify
    pk = bytes.fromhex(a.key)
    with open(a.contract, encoding="utf-8") as f:
        contract = json.load(f)
    body = contract.get("body") if isinstance(contract, dict) else None
    if not isinstance(body, dict) or not verify(pk, contract.get("sig"), R.NS_STMT + R.canon(body)):
        print("error: the contract is not a statement signed under --key", file=sys.stderr)
        return 2
    dep = body["dep"]
    if a.store_dir:
        store_spec = ("local", a.store_dir)
    elif a.s3_bucket:
        store_spec = ("s3", a.s3_bucket, a.s3_prefix, a.s3_endpoint)
    else:
        ap.error("one of --store-dir or --s3-bucket is required")
    store = make_store(store_spec, pk)
    state = {}
    if os.path.isfile(a.state):
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)
    checkpoint = state.get("checkpoint")
    audit_from = dict(state.get("audit_from") or (checkpoint or {}).get("audit_from") or {})
    now = a.now_ms if a.now_ms is not None else int(time.time() * 1000)
    t0 = time.perf_counter()

    plan = plan_replay(store, pk, checkpoint)
    head_j, head_W = _latest_head_W(load_statements(store, dep), pk)
    density = (checkpoint or {}).get("density") or {}
    sources: Dict[str, tuple] = {}
    if a.broker_dump:
        flat = _dump_records(a.broker_dump)
        recs, markers = split_by_partition(flat)
        for tk in set(recs) | set(markers):
            sources[tk] = ("records", recs.get(tk, []), markers.get(tk))
    elif a.bootstrap:
        for p in asyncio.run(_kafka_partitions(a.bootstrap, a.topic)):
            sources[f"{a.topic}/{p}"] = ("kafka", a.bootstrap, a.topic, p, a.read_idle_s)
    else:
        ap.error("one of --broker-dump or --bootstrap is required")
    jobs = []
    only = {int(p) for p in a.partitions.split(",") if p.strip()} if a.partitions else None
    for tk in sorted(set(sources) | set(plan["parts"])):
        if only is not None and int(tk.rsplit("/", 1)[1]) not in only:
            continue
        src = sources.get(tk, ("records", [], None))
        jobs.append({"tk": tk, "source": src, "store": store_spec, "plans": plan["parts"].get(tk, {}),
                     "contract": contract, "key": a.key, "now_ms": now,
                     "audit_from": audit_from.get(tk), "density": density.get(tk),
                     "W": head_W.get(tk), "head_j": head_j})
    reports = run_audit(jobs, max(1, int(a.workers)))
    for job, rep in zip(jobs, reports):
        if job["tk"] not in sources:
            rep["audit_from"] = {}
    rep = merge_reports(reports, plan, checkpoint, audit_from, t0)

    os.makedirs(a.out, exist_ok=True)
    for c in rep["complaints"]:
        pos = c["complaint"]["sub_record"]["pos"]
        name = f"complaint-{pos['topic']}-{pos['p']}-{pos['o']}.json"
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as f:
            json.dump(dict(c, contract=contract), f, indent=1, sort_keys=True)
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in rep.items() if k not in ("complaints", "checkpoint")}
                  | {"complaints": len(rep["complaints"])}, f, indent=1, sort_keys=True, default=str)
    tmp = a.state + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"audit_from": rep["audit_from"], "checkpoint": rep["checkpoint"], "at_ms": now},
                  f, sort_keys=True)
    os.replace(tmp, a.state)
    print(json.dumps({"counts": rep["counts"], "findings": len(rep["findings"]),
                      "complaints": len(rep["complaints"]), "incomplete": rep["incomplete"],
                      "records_per_s": rep["records_per_s"]}, sort_keys=True))
    bad = rep["complaints"] or rep["incomplete"] or \
        any(f["type"] != "ROOT_UNCHECKED" for f in rep["findings"])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
