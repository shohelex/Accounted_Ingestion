#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
from datetime import datetime
import gzip
import json
import random
import statistics as st
import string
import sys
import time
from pathlib import Path

import httpx

try:
    from kafka import KafkaAdminClient, KafkaConsumer, TopicPartition
except Exception:  # pragma: no cover
    KafkaAdminClient = None

try:
    from neo4j import GraphDatabase
except Exception:  # pragma: no cover
    GraphDatabase = None

MAX_INFLIGHT = 512             # requests in flight, split across the emitter processes
REQUEST_TIMEOUT_S = 30.0
TOPIC = "provenance-events"
LAG_INTERVAL_S = 2.0
LAG_TIMEOUT_S = 5.0            # a slower lag sample is recorded as missing
DRAIN_TARGET = 100             # lag at which the drain counts as done
SLO_LAG_FRAC = 0.01
SLO_LOSS_FRAC = 0.01
MIN_ACK_FRAC = 0.5             # a run acknowledging less of the offered events is invalid
RETRY_BACKOFF_S = 0.5
RETRY_BACKOFF_MAX_S = 8.0


class LagProbe:
    """Kafka consumer lag = sum over partitions of (end offset - committed)."""

    def __init__(self, bootstrap: str, group: str, topic: str):
        self.bootstrap, self.group, self.topic = bootstrap, group, topic
        self._c = None

    def _consumer(self):
        if self._c is None:
            self._c = KafkaConsumer(
                bootstrap_servers=self.bootstrap,
                group_id=None,
                enable_auto_commit=False,
                consumer_timeout_ms=3000,
            )
        return self._c

    def lag(self):
        try:
            c = self._consumer()
            parts = c.partitions_for_topic(self.topic)
            if not parts:
                return None
            tps = [TopicPartition(self.topic, p) for p in parts]
            ends = c.end_offsets(tps)
            admin = KafkaAdminClient(bootstrap_servers=self.bootstrap)
            try:
                committed = admin.list_consumer_group_offsets(self.group)
            finally:
                admin.close()
            total = 0
            for tp in tps:
                end = ends.get(tp, 0)
                md = committed.get(tp)
                cur = md.offset if md and md.offset >= 0 else 0
                total += max(0, end - cur)
            return total
        except Exception:
            return None


class LagSampler:
    """LagProbe.lag in a background thread with a deadline: a hung broker costs samples, not the
    emitter's cadence. A sample that misses the deadline is recorded as missing."""

    def __init__(self, probe):
        self.probe = probe
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._fut = None
        self.timed_out = self.skipped = 0

    async def sample(self):
        if self._fut is not None and not self._fut.done():
            self.skipped += 1
            return None
        self._fut = self._pool.submit(self.probe.lag)
        try:
            return await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(self._fut)), LAG_TIMEOUT_S)
        except (asyncio.TimeoutError, TimeoutError):
            self.timed_out += 1
            return None
        except Exception:
            return None

    def close(self):
        self._pool.shutdown(wait=False)


def slope(xs, ys):
    """Least-squares slope (events per second of lag growth)."""
    n = len(xs)
    if n < 3:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / den


def pct(v, q):
    if not v:
        return None
    s = sorted(v)
    k = (len(s) - 1) * q / 100.0
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return round(s[f] + (s[c] - s[f]) * (k - f), 3)


def rid(n=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


async def _emit_shard(args, results, shard=0, nshards=1, t0=None):
    """Open-loop emitter for one shard: tick i (intended time t0 + i * gap) belongs to shard
    i mod nshards. t0 is a perf_counter() value shared by all shards (system-wide on Linux).
    Each attempt is recorded as (send_s, done_s, outcome, attempt_no, http_code)."""
    url = f"{args.base_url.rstrip('/')}/api/v1/provenance/events"
    headers = {"x-api-key": args.api_key}
    # With --batch N each tick is one POST /events/batch of N events; counts stay in events.
    batch = max(1, getattr(args, "batch", 1))
    if batch > 1:
        url += "/batch"
    gap = batch / args.rate
    if t0 is None:
        t0 = time.perf_counter()
    inflight = set()
    per_shard_inflight = max(8, MAX_INFLIGHT // nshards)
    # Each connection is a file descriptor: the cap stays below the process's descriptor limit.
    try:
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft != resource.RLIM_INFINITY:
            per_shard_inflight = min(per_shard_inflight, max(8, soft - 64))
    except Exception:
        pass
    results["inflight_per_shard"] = per_shard_inflight
    sem = asyncio.Semaphore(per_shard_inflight)
    attempts = results["attempts"]
    per_tenant = results["per_tenant"]
    fixed_tenant = getattr(args, "tenant_id", None)
    sample_n = getattr(args, "receipts_sample", 0)
    keep_receipts = bool(getattr(args, "receipts_out", None) or sample_n)
    receipts = results["receipts"]
    sample = results["receipts_sample"]
    seen = 0

    def keep_receipt(done, tenant, act_id, reply):
        nonlocal seen
        # Receipt v2 (accounted mode) adds the broker position and the submission time.
        rc = reply.get("receipt_v2")
        if not isinstance(rc, dict):
            rc = None
        pos = (rc or {}).get("pos") or {}
        receipts.append((round(done - t0, 4), tenant, act_id, pos.get("p"), pos.get("o"),
                         (rc or {}).get("at_ms")))
        if rc is not None and sample_n:
            # Reservoir sample over this process's receipts.
            seen += 1
            if len(sample) < sample_n:
                sample.append(rc)
            else:
                j = random.randrange(seen)
                if j < sample_n:
                    sample[j] = rc

    def tenant_headers(tenant):
        # The API takes the tenant from the x-tenant-id header, not from the body.
        if args.tenants <= 1 and not fixed_tenant:
            return headers
        return {**headers, "x-tenant-id": tenant}

    limits = httpx.Limits(max_connections=per_shard_inflight,
                          max_keepalive_connections=per_shard_inflight)
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_S, limits=limits) as client:

        spooled = 0
        max_retries = args.retry_refused

        async def one(intended_at, tenant):
            nonlocal spooled
            if batch > 1:
                return await attempt_batch(intended_at, tenant)
            body_retry = None
            if max_retries:
                # A fixed id and timestamp make a resend the same event to the pipeline.
                body_retry = {"event_id": "lg_" + rid(20), "timestamp": datetime.utcnow().isoformat()}
            code, act_id = await attempt(intended_at, tenant, body_retry, n=0)
            if 200 <= code < 400 or not max_retries:
                return finish(intended_at, act_id, code)
            rt = results["retry"]
            if spooled >= args.retry_spool:
                rt["spool_dropped"] += 1
                return finish(intended_at, act_id, code)
            spooled += 1
            rt["spool_peak"] = max(rt["spool_peak"], spooled)
            rt["retried_events"] += 1
            try:
                for n in range(1, max_retries + 1):
                    await asyncio.sleep(min(RETRY_BACKOFF_MAX_S, RETRY_BACKOFF_S * (2 ** (n - 1)))
                                        * random.uniform(0.8, 1.2))
                    rt["resends"] += 1
                    code, act_id = await attempt(intended_at, tenant, body_retry, n=n)
                    if 200 <= code < 400:
                        rt["acked_after_retry"] += 1
                        rt["ack_delay_ms"].append((time.perf_counter() - intended_at) * 1000.0)
                        break
                else:
                    rt["gave_up"] += 1
            finally:
                spooled -= 1
            return finish(intended_at, act_id, code)

        def finish(intended_at, act_id, code):
            if 200 <= code < 400:
                results["accepted"] += 1
            else:
                results["rejected"] += 1
            results["ids"].append((intended_at - t0, act_id, code))

        def record(send, done, outcome, n, code):
            attempts.append((round(send - t0, 4), round(done - t0, 4), outcome, n, code))
            results["codes"][code] = results["codes"].get(code, 0) + 1

        def record_first(intended_at, send, done, tenant, outcome):
            # Latency from the intended time (no coordinated omission), first attempts only.
            results["lat_intended"].append((done - intended_at) * 1000.0)
            results["lat_service"].append((done - send) * 1000.0)
            results["t_of_req"].append(intended_at - t0)   # same index as the two above
            pt = per_tenant.setdefault(tenant, {"outcomes": {}, "lat_service": []})
            pt["outcomes"][outcome] = pt["outcomes"].get(outcome, 0) + 1
            pt["lat_service"].append(round((done - send) * 1000.0, 3))

        async def attempt(intended_at, tenant, extra, n):
            async with sem:
                body = event_body(tenant)
                if extra is not None:
                    extra.setdefault("user_id", body["user_id"])
                    extra.setdefault("resource", body["resource"])
                    body.update(extra)                     # a resend carries the first attempt's fields
                send = time.perf_counter()
                act_id = None
                try:
                    r = await client.post(url, json=body, headers=tenant_headers(tenant))
                    code = r.status_code
                    outcome = "admitted" if 200 <= code < 400 else "refused"
                    if 200 <= code < 400:
                        # activity_id is also the graph's Activity.id: delivery is reconciled per event.
                        try:
                            reply = r.json()
                            act_id = reply.get("activity_id")
                        except Exception:
                            reply, act_id = None, None
                        if keep_receipts and isinstance(reply, dict):
                            keep_receipt(time.perf_counter(), tenant, act_id, reply)
                except httpx.TimeoutException:
                    code, outcome = 0, "timeout"
                except Exception:
                    code, outcome = 0, "error"
                done = time.perf_counter()
                record(send, done, outcome, n, code)
                if n == 0:
                    record_first(intended_at, send, done, tenant, outcome)
                return code, act_id

        def event_body(tenant):
            # The flat shape the route accepts.
            return {"event_type": "access", "user_id": f"u{random.randint(0, 4999):05d}",
                    "resource": f"/book/book_{random.randint(0, 399):03d}", "operation": "GET",
                    "source": "api", "tenant_id": tenant, "status_code": 200, "duration_ms": 12}

        async def attempt_batch(intended_at, tenant):
            # Each event's result is counted as a single request's would be; no resends.
            async with sem:
                body = {"events": [event_body(tenant) for _ in range(batch)]}
                send = time.perf_counter()
                rows = None
                try:
                    r = await client.post(url, json=body, headers=tenant_headers(tenant))
                    code = r.status_code
                    if code == 200:
                        try:
                            rows = r.json().get("results")
                        except Exception:
                            rows = None
                    outcome = "admitted" if code == 200 else "refused"
                except httpx.TimeoutException:
                    code, outcome = 0, "timeout"
                except Exception:
                    code, outcome = 0, "error"
                done = time.perf_counter()
                ok = 0
                for j in range(batch):
                    res = rows[j] if isinstance(rows, list) and j < len(rows) else None
                    c = int(res.get("status_code", 0)) if isinstance(res, dict) else (0 if code == 200 else code)
                    aid = res.get("activity_id") if isinstance(res, dict) and c == 200 else None
                    if c == 200:
                        ok += 1
                        if keep_receipts:
                            keep_receipt(done, tenant, aid, res)
                    finish(intended_at, aid, c)
                if code == 200 and ok < batch:
                    outcome = "partial" if ok else "refused"
                record(send, done, outcome, 0, code)
                record_first(intended_at, send, done, tenant, outcome)

        i = shard
        n_sent = 0
        while True:
            now = time.perf_counter()
            if now - t0 >= args.duration_s:
                break
            intended = t0 + i * gap
            if intended > now:
                await asyncio.sleep(intended - now)
            if fixed_tenant:
                tenant = fixed_tenant
            else:
                tenant = f"tenant_{i % args.tenants}" if args.tenants > 1 else "default"
            task = asyncio.create_task(one(intended, tenant))
            inflight.add(task)
            task.add_done_callback(inflight.discard)
            i += nshards
            n_sent += 1
        results["offered"] = n_sent * batch          # events, also in batch mode
        results["schedule_s"] = round(args.duration_s, 3)
        if inflight:
            await asyncio.gather(*list(inflight), return_exceptions=True)


def _new_results():
    retry = {"retried_events": 0, "resends": 0, "acked_after_retry": 0, "gave_up": 0,
             "spool_dropped": 0, "spool_peak": 0, "ack_delay_ms": []}
    return {"lat_intended": [], "lat_service": [], "t_of_req": [], "codes": {},
            "accepted": 0, "rejected": 0, "lag": [], "lag_ts": [], "offered": 0,
            "ids": [], "retry": retry, "attempts": [], "schedule_s": None,
            "inflight_per_shard": None, "per_tenant": {}, "receipts": [], "receipts_sample": []}


OUTCOMES = ("admitted", "refused", "timeout", "error")


def attempt_series(attempts, n_seconds=None):
    """Attempts per second by the second each was sent; admissions also by the second they completed."""
    last = max((a[0] for a in attempts), default=0.0)
    n = max(int(n_seconds or 0), int(last) + 1)
    out = {k: [0] * n for k in ("sent",) + OUTCOMES}
    out["admitted_by_completion"] = [0] * n
    for send, done, outcome, _n, _code in attempts:
        s = min(n - 1, max(0, int(send)))
        out["sent"][s] += 1
        out[outcome if outcome in OUTCOMES else "error"][s] += 1
        if outcome == "admitted":
            out["admitted_by_completion"][min(n - 1, max(0, int(done)))] += 1
    return out


def write_receipts(path, receipts):
    """Gzipped CSV, one row per acknowledgement: done_s,tenant,event_id,p,o,at_ms (p, o, at_ms empty
    without a receipt v2)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        f.write("done_s,tenant,event_id,p,o,at_ms\n")
        for done, tenant, eid, p, o, at in sorted(receipts, key=lambda r: r[0]):
            f.write(f"{done:.4f},{tenant},{eid or ''},{'' if p is None else p},{'' if o is None else o},"
                    f"{'' if at is None else at}\n")


def per_tenant_summary(per_tenant):
    out = {}
    for t, v in sorted(per_tenant.items()):
        lat = v["lat_service"]
        out[t] = dict(v["outcomes"], lat_service_p50_ms=pct(lat, 50), lat_service_p99_ms=pct(lat, 99))
    return out


def retry_summary(r, enabled):
    out = {k: v for k, v in r.items() if k != "ack_delay_ms"}
    out.update(enabled=enabled, ack_delay_ms_p50=pct(r["ack_delay_ms"], 50),
               ack_delay_ms_p99=pct(r["ack_delay_ms"], 99),
               never_acknowledged=r["gave_up"] + r["spool_dropped"])
    return out


def write_attempts(path, attempts):
    """Gzipped CSV, one row per attempt: send_s,done_s,outcome,attempt,code."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        f.write("send_s,done_s,outcome,attempt,code\n")
        for send, done, outcome, n, code in sorted(attempts):
            f.write(f"{send:.4f},{done:.4f},{outcome},{n},{code}\n")


def _die_with_parent() -> None:
    """Linux: SIGTERM this emitter process when the load generator that started it dies."""
    try:
        import ctypes
        import signal
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)   # PR_SET_PDEATHSIG
    except Exception:
        pass


def _emit_proc(args, shard, nshards, t0):
    _die_with_parent()
    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass
    res = _new_results()
    asyncio.run(_emit_shard(args, res, shard, nshards, t0))
    return res


async def emit(args, results, t0):
    """The schedule sharded by tick across --emit-procs processes (one process saturates a core
    near 150 requests/s); their results are merged."""
    n = max(1, args.emit_procs)
    if n == 1:
        await _emit_shard(args, results, 0, 1, t0)
        return
    import multiprocessing as mp
    loop = asyncio.get_running_loop()
    with concurrent.futures.ProcessPoolExecutor(max_workers=n, mp_context=mp.get_context("spawn")) as pool:
        futs = [loop.run_in_executor(pool, _emit_proc, args, k, n, t0) for k in range(n)]
        parts = await asyncio.gather(*futs)
    for p in parts:
        for key in ("lat_intended", "lat_service", "t_of_req", "ids", "attempts", "receipts",
                    "receipts_sample"):
            results[key].extend(p[key])
        for code, c in p["codes"].items():
            results["codes"][code] = results["codes"].get(code, 0) + c
        for key, v in p["retry"].items():
            if isinstance(v, list):
                results["retry"][key].extend(v)
            else:
                results["retry"][key] += v          # spool_peak: the sum of per-process peaks
        results["accepted"] += p["accepted"]
        results["rejected"] += p["rejected"]
        results["offered"] += p["offered"]
        for t, v in p["per_tenant"].items():
            pt = results["per_tenant"].setdefault(t, {"outcomes": {}, "lat_service": []})
            for k, c in v["outcomes"].items():
                pt["outcomes"][k] = pt["outcomes"].get(k, 0) + c
            pt["lat_service"].extend(v["lat_service"])
        results["schedule_s"] = max(results["schedule_s"] or 0.0, p["schedule_s"])
        results["inflight_per_shard"] = p["inflight_per_shard"]


def _per_second(ids, duration_s):
    n = int(duration_s) + 1
    acc, ref = [0] * n, [0] * n
    for t, _aid, code in ids:
        s = min(n - 1, max(0, int(t)))
        if 200 <= code < 400:
            acc[s] += 1
        else:
            ref[s] += 1
    return {"accepted": acc, "refused": ref}


async def sample_lag(sampler, results, stop, t0):
    """Lag every LAG_INTERVAL_S seconds on the emitter's time axis (seconds since t0)."""
    while not stop.is_set():
        lg = await sampler.sample()
        if lg is not None:
            results["lag_ts"].append(round(time.perf_counter() - t0, 2))
            results["lag"].append(lg)
        try:
            await asyncio.wait_for(stop.wait(), LAG_INTERVAL_S)
        except (asyncio.TimeoutError, TimeoutError):
            pass


def graph_activity_ids(uri, pw):
    """Activity.id of every API-created event (an index-backed STARTS WITH scan)."""
    if GraphDatabase is None:
        return None
    try:
        d = GraphDatabase.driver(uri, auth=("neo4j", pw))
        with d.session() as s:
            # 'ext_' ids are minted by the API, 'c_' ids are caller-supplied (--retry-refused).
            ids = {rec["id"] for rec in s.run(
                "MATCH (a:Activity) WHERE a.id STARTS WITH 'ext_' OR a.id STARTS WITH 'c_' "
                "RETURN a.id AS id")}
        d.close()
        return ids
    except Exception:
        return None


def graph_counts(uri, pw):
    """Total nodes and relationships, and Activity nodes (the only per-event node)."""
    if GraphDatabase is None:
        return None
    try:
        d = GraphDatabase.driver(uri, auth=("neo4j", pw))
        with d.session() as s:
            n = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            r = s.run("MATCH ()-[x]->() RETURN count(x) AS c").single()["c"]
            a = s.run("MATCH (n:Activity) RETURN count(n) AS c").single()["c"]
        d.close()
        return {"nodes": n, "rels": r, "activities": a}
    except Exception:
        return None


async def main_async(args):
    results = _new_results()
    # --no-graph (a baseline store behind the API): graph figures are null, not zero.
    no_graph = bool(getattr(args, "no_graph", False))
    counts = (lambda: None) if no_graph else (lambda: graph_counts(args.neo4j_uri, args.neo4j_password))
    act_ids = (lambda: None) if no_graph else (lambda: graph_activity_ids(args.neo4j_uri, args.neo4j_password))
    before = counts() or {"nodes": 0, "rels": 0, "activities": 0}

    # Graph samples at the end of the warm-up and at the end of emission bound the steady window.
    at_warmup = {"activities": None, "ids": None}

    async def sample_at_warmup():
        await asyncio.sleep(args.warmup_s)
        # Off the event loop, so the queries cannot stall the emitter or the lag samples.
        g = await asyncio.to_thread(counts)
        if g:
            at_warmup.update(g)
        at_warmup["ids"] = await asyncio.to_thread(act_ids)

    # Unix time of t = 0 of every series in the output (lag, per-second rates, attempts).
    epoch_start = time.time()
    wall0 = time.perf_counter()
    stop = asyncio.Event()
    sampler = LagSampler(LagProbe(args.kafka, args.group, TOPIC))
    lag_task = asyncio.create_task(sample_lag(sampler, results, stop, wall0))
    warm_task = asyncio.create_task(sample_at_warmup())
    await emit(args, results, wall0)
    wall = time.perf_counter() - wall0
    at_emit_end = counts() or {}
    ids_emit_end = act_ids()
    stop.set()
    await asyncio.gather(lag_task, warm_task, return_exceptions=True)

    # Let the consumer drain, for at most --drain-max-s.
    drained_at = None
    t_drain0 = time.perf_counter()
    drain_t, drain_lag = [], []        # same time axis as the lag series: seconds since emission began
    while time.perf_counter() - t_drain0 < args.drain_max_s:
        lg = await sampler.sample()
        if lg is not None:
            drain_t.append(round(time.perf_counter() - wall0, 2))
            drain_lag.append(lg)
        if lg is not None and lg <= DRAIN_TARGET:
            drained_at = round(time.perf_counter() - t_drain0, 1)
            break
        await asyncio.sleep(LAG_INTERVAL_S)
    sampler.close()
    # Up to DRAIN_TARGET events can still be in flight: within --drain-max-s, also wait until the
    # graph holds as many activities as were acknowledged.
    if not no_graph:
        while time.perf_counter() - t_drain0 < args.drain_max_s:
            g = counts()
            if g is not None and g["activities"] - before["activities"] >= results["accepted"]:
                break
            await asyncio.sleep(LAG_INTERVAL_S)
    after = counts() or {"nodes": 0, "rels": 0, "activities": 0}
    ids_after = act_ids()

    # Statistics exclude the warm-up.
    w = args.warmup_s
    keep = [i for i, t in enumerate(results["t_of_req"]) if t >= w]
    lat_i = [results["lat_intended"][i] for i in keep]
    lat_s = [results["lat_service"][i] for i in keep]
    sched_s = float(results["schedule_s"] or args.duration_s)
    steady_s = max(1e-9, sched_s - w)
    n_steady = len(keep)
    n_steady_accepted = sum(1 for t, _aid, c in results["ids"] if t >= w and 200 <= c < 400)
    attempts = results["attempts"]
    series = attempt_series(attempts, int(sched_s) + 1)
    outcome_totals = {k: sum(series[k]) for k in OUTCOMES}

    lag_keep = [(t, l) for t, l in zip(results["lag_ts"], results["lag"]) if t >= w]
    lag_slope = slope([t for t, _ in lag_keep], [l for _, l in lag_keep]) if lag_keep else 0.0

    nodes_added = after["nodes"] - before["nodes"]
    # Delivery over the whole run, drain included: a loss figure, not a throughput.
    acts_added = after["activities"] - before["activities"]
    per_event = (acts_added / results["accepted"]) if results["accepted"] else 0.0
    loss_frac = max(0.0, 1.0 - per_event)

    # Activities written between the end of the warm-up and the end of emission; includes the
    # warm-up backlog drained in that window.
    steady_delivered_eps = None
    if at_warmup.get("activities") is not None and at_emit_end.get("activities") is not None:
        d = at_emit_end["activities"] - at_warmup["activities"]
        steady_delivered_eps = round(max(0, d) / steady_s, 2)

    # The lag trend is offered - consumed, so consumed = offered - slope.
    implied_capacity_eps = round(args.rate - lag_slope, 2)

    # Reconciliation by activity id: an event is delivered in the window only if it was offered in
    # the window and its id is in the graph.
    rec = None
    if ids_emit_end is not None and ids_after is not None:
        warm_ids = at_warmup.get("ids") or set()
        win = [(t, aid, c) for t, aid, c in results["ids"] if t >= w]
        acc_win = {aid for t, aid, c in win if aid and 200 <= c < 400}
        acc_win_noid = sum(1 for t, aid, c in win if not aid and 200 <= c < 400)
        acc_warm = {aid for t, aid, c in results["ids"] if t < w and aid and 200 <= c < 400}
        cw_emit = len(acc_win & ids_emit_end)
        cw_after = len(acc_win & ids_after)
        rec = {
            "offered_window": len(win),
            "accepted_window": len(acc_win) + acc_win_noid,
            "accepted_window_unreconcilable": acc_win_noid,
            "rejected_window": sum(1 for t, aid, c in win if not (200 <= c < 400)),
            "committed_window_by_emit_end": cw_emit,
            "committed_window_after_drain": cw_after,
            "pending_at_emit_end": cw_after - cw_emit,
            "lost_window": len(acc_win) - cw_after,
            "loss_fraction_reconciled": round((len(acc_win) - cw_after) / len(acc_win), 5) if acc_win else 0.0,
            "delivered_window_eps": round(cw_emit / steady_s, 2),
            "eventually_delivered_window_eps": round(cw_after / steady_s, 2),
            "warmup_accepted": len(acc_warm),
            "warmup_backlog_at_window_start": len(acc_warm) - len(acc_warm & warm_ids),
            "warmup_drained_inside_window": len(acc_warm & ids_emit_end) - len(acc_warm & warm_ids),
            "warmup_lost_after_drain": len(acc_warm) - len(acc_warm & ids_after),
            "note": ("delivered_window_eps: events offered in the steady window and in the graph "
                     "by the end of emission, over the window. lost_window: absent after the drain; "
                     "pending_at_emit_end: arrived after the end of emission."),
        }

    slo_lag_limit = SLO_LAG_FRAC * args.rate
    slo1 = lag_slope <= slo_lag_limit
    # SLO 2 on the reconciled loss when available, else on the count-based loss.
    slo2_loss = rec["loss_fraction_reconciled"] if rec else loss_frac
    slo2_basis = "reconciled_by_activity_id" if rec else "activities_added_over_accepted"
    slo2 = slo2_loss <= SLO_LOSS_FRAC
    if no_graph:
        # Loss is then judged by the store's own verifier (bench/baselines).
        slo2_loss, slo2_basis, slo2 = None, "not measured here: --no-graph", None
    # A run that acknowledged too few of the offered events is invalid.
    scheduled = results["offered"]
    ack_frac = (results["accepted"] / scheduled) if scheduled else 0.0
    valid = bool(results["accepted"] > 0 and ack_frac >= MIN_ACK_FRAC)

    out = {
        "config": {
            "rate_target_eps": args.rate, "duration_s": args.duration_s,
            "warmup_s": args.warmup_s, "tenants": args.tenants,
            "max_inflight": MAX_INFLIGHT,
            "emit_procs": args.emit_procs,
            "inflight_per_process": results["inflight_per_shard"],
            "request_timeout_s": REQUEST_TIMEOUT_S,
            "schedule_s_actual": round(sched_s, 3),
            "graph": not no_graph,
            "epoch_start": round(epoch_start, 3),
        },
        "offered": {
            "requests_scheduled": results["offered"],
            "achieved_offer_rate_eps": round(results["offered"] / wall, 1) if wall else 0,
            "wall_s": round(wall, 2),
        },
        "capacity": {
            "steady_delivered_eps": steady_delivered_eps,
            "implied_capacity_eps": implied_capacity_eps,
            "note": ("steady_delivered_eps includes warm-up backlog drained in the window; "
                     "reconciled.delivered_window_eps does not. implied_capacity_eps = offered - lag slope."),
        },
        "reconciled": rec,
        # Rates per wall-clock second, for when the emitter fell behind its schedule.
        "wallclock": {
            "wall_s": round(wall, 2),
            # duration_s is the whole emission schedule; warmup_s is its first part.
            "schedule_s": round(sched_s, 2),
            "emitter_behind_schedule_x": round(wall / sched_s, 2) if sched_s else None,
            "accepted_eps": round(results["accepted"] / wall, 2) if wall else None,
            "commit_eps": round(
                (at_emit_end.get("activities", 0) - at_warmup.get("activities", 0))
                / (wall - args.warmup_s), 2)
                if (wall - args.warmup_s) > 0 and at_emit_end.get("activities") is not None
                and at_warmup.get("activities") is not None else None,
            "drain_eps": round(rec["pending_at_emit_end"] / drained_at, 2)
                if (rec and drained_at) else None,
            "note": ("accepted_eps = accepted_total / wall. commit_eps = activities added between "
                     "the warm-up sample and the end of emission, over that span. drain_eps = "
                     "pending_at_emit_end over the drain time."),
        },
        "steady_state": {
            # Events scheduled in the steady window, and of those the ones finally accepted.
            "requests": n_steady,
            "scheduled_rate_eps": round(n_steady / steady_s, 1),
            "accepted_rate_eps": round(n_steady_accepted / steady_s, 1),
        },
        "response_codes": results["codes"],
        # Final outcome per event by the second it was scheduled in (warm-up included).
        "per_second": _per_second(results["ids"], sched_s),
        # Every attempt (resends included) by the second it was sent; admitted_by_completion by the
        # second the acknowledgement arrived.
        "attempts_per_second": series,
        "attempt_outcomes": outcome_totals,
        # With --retry-refused, accepted_total and rejected_total are final outcomes per event and
        # response_codes counts every attempt.
        "retry": retry_summary(results["retry"], bool(args.retry_refused)),
        "accepted_total": results["accepted"],
        "rejected_total": results["rejected"],
        # First attempts only, whole run.
        "per_tenant": per_tenant_summary(results["per_tenant"]),
        "latency_from_intended_ms": {
            "p50": pct(lat_i, 50), "p90": pct(lat_i, 90), "p95": pct(lat_i, 95),
            "p99": pct(lat_i, 99), "p999": pct(lat_i, 99.9),
            "max": round(max(lat_i), 3) if lat_i else None,
            "mean": round(st.mean(lat_i), 3) if lat_i else None,
        },
        "latency_service_ms": {
            "p50": pct(lat_s, 50), "p95": pct(lat_s, 95), "p99": pct(lat_s, 99),
            "max": round(max(lat_s), 3) if lat_s else None,
        },
        "lag": {
            "samples": len(lag_keep),
            "series_t": [t for t, _ in lag_keep],
            "series_lag": [l for _, l in lag_keep],
            "drain_t": drain_t, "drain_lag": drain_lag,
            "trend_slope_eps": round(lag_slope, 2),
            "max": max([l for _, l in lag_keep], default=0),
            "final": lag_keep[-1][1] if lag_keep else None,
        },
        "graph": None if no_graph else {
            "before": before, "after": after,
            "nodes_added": nodes_added, "rels_added": after["rels"] - before["rels"],
            "activities_added": acts_added,
            "activities_per_accepted_event": round(per_event, 4),
            "activities_at_warmup_end": at_warmup.get("activities"),
            "activities_at_emit_end": at_emit_end.get("activities"),
            "nodes_per_accepted_event": round(
                (nodes_added / results["accepted"]) if results["accepted"] else 0.0, 4),
            "drained_after_s": drained_at,
        },
        "slo": {
            "lag_trend_limit_eps": round(slo_lag_limit, 2),
            "lag_trend_observed_eps": round(lag_slope, 2),
            "slo1_lag_ok": bool(slo1),
            "loss_fraction": None if slo2_loss is None else round(slo2_loss, 5),
            "loss_basis": slo2_basis,
            "loss_fraction_count_based": None if no_graph else round(loss_frac, 5),
            "loss_limit": SLO_LOSS_FRAC,
            "slo2_data_ok": None if slo2 is None else bool(slo2),
            "acknowledged_fraction": round(ack_frac, 5),
            "min_ack_frac": MIN_ACK_FRAC,
            "valid": valid,
            "PASS": valid and (bool(slo1) if slo2 is None else bool(slo1 and slo2)),
            "note": ("A passing SLO permits up to loss_limit of accepted events to be missing; "
                     "reconciled.lost_window counts acknowledged events that never reached the graph."),
        },
        "method": {
            "load_type": "offered event rate (events/s), open loop",
            "resource_type": "ingestion consumer workers",
            "slo": ("lag trend <= %g x offered rate, fitted by least squares after "
                    "warm-up; and <= %g of accepted events missing from the graph"
                    % (SLO_LAG_FRAC, SLO_LOSS_FRAC)),
            "latency_reference": "intended send time (coordinated-omission safe)",
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    if getattr(args, "attempts_out", None):
        write_attempts(args.attempts_out, attempts)
    if getattr(args, "receipts_out", None):
        write_receipts(args.receipts_out, results["receipts"])
    if getattr(args, "receipts_sample_out", None):
        smp = results["receipts_sample"]
        n = getattr(args, "receipts_sample", 0)
        if n and len(smp) > n:
            smp = random.sample(smp, n)       # one uniform sample from the processes' samples
        args.receipts_sample_out.parent.mkdir(parents=True, exist_ok=True)
        args.receipts_sample_out.write_text(json.dumps(smp), encoding="utf-8")
    if getattr(args, "dump_ids", None):
        # One acknowledged event id per line, for the baseline verifiers.
        args.dump_ids.write_text("\n".join(aid for _t, aid, c in results["ids"] if aid and 200 <= c < 400) + "\n",
                                 encoding="utf-8")

    s = out["slo"]
    dl = f"del={rec['delivered_window_eps']:>8}/s " if rec else "del=     n/a "
    print(f"  rate={args.rate:>7} "
          f"acc={results['accepted']:>7} rej={results['rejected']:>6} "
          f"{dl}"
          f"p99={out['latency_from_intended_ms']['p99']:>9} ms "
          f"lagslope={s['lag_trend_observed_eps']:>9}/s "
          + (f"loss={s['loss_fraction']:.4f} " if s["loss_fraction"] is not None else "loss=n/a ")
          + (f"timeouts={outcome_totals['timeout']} " if outcome_totals["timeout"] else "")
          + ("" if s["valid"] else f"INVALID (acknowledged {s['acknowledged_fraction']:.3f} of the offered "
                                     f"events, floor {s['min_ack_frac']}) ")
          + f"{'PASS' if s['PASS'] else 'FAIL'}")
    return 0 if s["PASS"] else 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--rate", type=int, required=True, help="offered events/s")
    ap.add_argument("--duration-s", type=float, default=300.0, help="emission time, warm-up included")
    ap.add_argument("--warmup-s", type=float, default=120.0)
    ap.add_argument("--tenants", type=int, default=1)
    ap.add_argument("--tenant-id", default=None, help="send every event as this tenant")
    ap.add_argument("--batch", type=int, default=1, help="events per request")
    ap.add_argument("--emit-procs", type=int, default=4, help="emitter processes")
    ap.add_argument("--retry-refused", type=int, default=0, help="resend a refused event up to N times")
    ap.add_argument("--retry-spool", type=int, default=20000, help="events waiting to be resent, per process")
    ap.add_argument("--drain-max-s", type=float, default=600.0, help="longest wait for the backlog after emission")
    ap.add_argument("--kafka", default="localhost:9092")
    ap.add_argument("--group", default="provenance-processor", help="consumer group whose lag is sampled")
    ap.add_argument("--neo4j-uri", default="neo4j://localhost:7687")
    ap.add_argument("--neo4j-password", required=True)
    ap.add_argument("--no-graph", action="store_true", help="the store behind the API is not Neo4j")
    ap.add_argument("--out", type=Path, required=True, help="JSON report")
    ap.add_argument("--attempts-out", type=Path, default=None, help="every attempt, gzipped CSV")
    ap.add_argument("--receipts-out", type=Path, default=None, help="every receipt position, gzipped CSV")
    ap.add_argument("--receipts-sample", type=int, default=0, help="receipts v2 to sample for the judge")
    ap.add_argument("--receipts-sample-out", type=Path, default=None)
    ap.add_argument("--dump-ids", type=Path, default=None, help="acknowledged event ids, one per line")
    args = ap.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
