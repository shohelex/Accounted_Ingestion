#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import random
import sys
import tempfile
import time
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional

if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

WAIT_MAX_S = 420.0         # longest wait for the last sampled receipt's period to be posted
REPLAY_WORKERS = 8
JUDGE_SAMPLE = 64          # receipts judged
MAX_COMPLAINTS = 20        # replay complaints judged
SAMPLE_SEED = "0"
HEAD_SLACK_MS = 30_000     # the test log's witnesses cosign a new head about every 10 s


def emit(obj) -> None:
    print("RESULT_JSON:" + json.dumps(obj, default=str, separators=(",", ":")), flush=True)


def _cpu() -> float:
    import resource
    s, c = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return s.ru_utime + s.ru_stime + c.ru_utime + c.ru_stime


def _rss_mb() -> float:
    import resource
    # ru_maxrss is KiB on Linux; the children's peak counts the replay workers.
    return round(max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                     resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss) / 1024.0, 1)


def section(fn: Callable[[], dict]) -> dict:
    """A section that fails reports why instead of taking the audit down with it."""
    t0, c0 = time.perf_counter(), _cpu()
    try:
        out = fn()
    except Exception as e:                                   # noqa: BLE001
        out = {"error": f"{type(e).__name__}: {str(e)[:300]}"}
    out = out if isinstance(out, dict) else {"result": out}
    out.setdefault("wall_s", round(time.perf_counter() - t0, 3))
    out.setdefault("cpu_s", round(_cpu() - c0, 3))
    return out


def anchors_dump(store) -> dict:
    """{tenant: [[n, ts, p, o_last], ...]} in chain order, and the record versions seen."""
    out, vers = {}, Counter()
    for t in store.tenants():
        rows = []
        for r in sorted(store.all(t), key=lambda r: int(r.n)):
            pl = r.pos_last or {}
            seg = r.seg or {}
            vers[str(r.v or 1)] += 1
            rows.append([int(r.n), float(r.ts), pl.get("p"), seg.get("o_last", pl.get("o"))])
        out[t] = rows
    return {"mode": "v2" if vers.get("2") else "v1", "versions": dict(vers), "anchors": out}


def _family(rel: str) -> str:
    parts = rel.split("/")
    fam = parts[0]
    if fam == "periods" and len(parts) >= 3:
        name = parts[2]
        for kind in ("open", "agg", "receipt", "outage"):
            if f".{kind}" in name:
                return f"periods.{kind}"
        return "periods.statement"
    return fam


def census(store) -> dict:
    """Objects and bytes by family under this run's store root."""
    fams: Dict[str, List[int]] = {}
    s3 = getattr(store, "_s3", None)
    if s3 is not None:
        prefix = store.prefix
        root = prefix.rsplit("/", 1)[0] + "/" if "/" in prefix else ""
        anchors_root = prefix + "/"
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=store.bucket, Prefix=root):
            for o in page.get("Contents", []) or []:
                k = o["Key"]
                if k.startswith(anchors_root):
                    fam = "anchors"
                elif root and not k.startswith(root):
                    continue
                else:
                    fam = _family(k[len(root):])
                    if not root and fam.startswith("anchors-"):
                        continue                              # another run's anchor prefix
                c = fams.setdefault(fam, [0, 0])
                c[0] += 1
                c[1] += int(o.get("Size") or 0)
    else:
        for k in store.list_keys(""):
            raw = store.get_object(k)
            c = fams.setdefault(_family(k), [0, 0])
            c[0] += 1
            c[1] += len(raw or b"")
    return {"families": {f: {"objects": n, "bytes": b, "mean_bytes": round(b / n, 1) if n else None}
                         for f, (n, b) in sorted(fams.items())}}


def record_census(store, system_tenant: str = "acct-system", tenants: Optional[Iterable[str]] = None) -> dict:
    """Every anchored record by kind and verdict type (the system log apart), from the segments.
    tenants: only these logs (a sampled audit)."""
    kinds, verdicts, sys_verdicts = Counter(), Counter(), Counter()
    for t in (store.tenants() if tenants is None else tenants):
        for r in sorted(store.all(t), key=lambda r: int(r.n)):
            if not r.seg:
                continue
            seg = store.segment(t, int(r.n)) or {}
            for rec in seg.get("records") or []:
                kinds[str(rec.get("kind"))] += 1
                if rec.get("kind") == "verdict":
                    v = rec.get("verdict") or {}
                    (sys_verdicts if t == system_tenant else verdicts)[str(v.get("type"))] += 1
    out = {"records": dict(kinds), "verdicts": dict(verdicts), "system_log_verdicts": dict(sys_verdicts)}
    total = sum(kinds.values())
    out["verdict_fraction"] = round((sum(verdicts.values()) + sum(sys_verdicts.values())) / total, 6) if total else None
    return out


def statements_summary(store, dep: str, tenants: Iterable[str]) -> dict:
    """Per period: the statement's kind and partition statuses; per tenant: its opening's status
    counts (ok / stall / held) over the run."""
    from crypto.period_statements import opening_key, period_key
    from tools.replay_audit import stored_periods
    stored = stored_periods(store, dep)
    js = sorted(j for j, kinds in stored.items() if ".json" in kinds)
    periods, st_counts = [], {}
    for j in js:
        raw = store.get_object(period_key(dep, j))
        body = (json.loads(raw).get("body") or {}) if raw else {}
        parts = body.get("parts") or {}
        periods.append({"j": j, "kind": body.get("kind"),
                        "parts": dict(Counter(str((v or {}).get("status")) for v in parts.values())),
                        "outage": ".outage.json" in stored[j], "posted": ".receipt.json" in stored[j]})
    for t in tenants:
        c = Counter()
        for j in js:
            raw = store.get_object(opening_key(dep, j, t))
            if raw is not None:
                c[str(json.loads(raw).get("st", "none"))] += 1
            else:
                c["no_opening"] += 1
        st_counts[t] = dict(c)
    return {"periods": periods, "n_periods": len(js), "posted": sum(1 for p in periods if p["posted"]),
            "tenant_status": st_counts}


def public_view(store, dep: str, ver: int, client, policy_text: str) -> dict:
    """The judge's view of the public log: the frontier below the contract's leaf, every leaf from
    there to the current head, and the heads of the stored receipts plus the current one."""
    from crypto import audit_period as AP
    from crypto.period_statements import contract_receipt_key
    from crypto.public_witness import tree_head_json
    from tools.replay_audit import stored_periods
    rc = json.loads(store.get_object(contract_receipt_key(dep, ver)))
    js = sorted(j for j, kinds in stored_periods(store, dep).items() if ".receipt.json" in kinds)
    heads = [rc["tree_head"]] + AP.stored_receipt_heads(store, dep, js)
    heads.append(tree_head_json(client.get_tree_head()))
    return AP.build_view(client, policy_text, heads, int(rc["leaf_index"]))


def wait_due(store, dep: str, contract: dict, max_at_ms: Optional[int], wait_max_s: float) -> dict:
    """Wait until the statement of the period the latest sampled submission falls due in is stored
    with its public-log receipt."""
    from crypto.period_statements import deadline_ms, first_due_period, receipt_key
    if max_at_ms is None:
        return {"due_period": None, "reached": True, "waited_s": 0.0}
    j = first_due_period(int(max_at_ms), contract)
    t0 = time.time()
    while store.get_object(receipt_key(dep, j)) is None:
        if time.time() - t0 >= wait_max_s:
            return {"due_period": j, "reached": False, "waited_s": round(time.time() - t0, 1)}
        time.sleep(5.0)
    # Until the period's deadline is behind a head cosigned after it the judge answers PENDING:
    # wait for the deadline plus the time the witnesses take to cosign a newer head.
    until = deadline_ms(j, contract) + HEAD_SLACK_MS
    while time.time() * 1000 < until:
        if time.time() - t0 >= wait_max_s:
            return {"due_period": j, "reached": False, "waited_s": round(time.time() - t0, 1)}
        time.sleep(min(5.0, max(0.5, (until - time.time() * 1000) / 1000.0)))
    return {"due_period": j, "reached": True, "waited_s": round(time.time() - t0, 1)}


def judge_all(store, pk: bytes, contract_stmt: dict, complaints: List[dict], view: Optional[dict],
              bodies: dict, now_ms: int, *, k_salt=None, signer=None, client=None, check_verdict=None,
              spool_dir=None) -> dict:
    """Judge every complaint with the honest respondent's defense; tally the verdicts."""
    from crypto import audit_period as AP
    from tools import judge_time as JT
    cb = contract_stmt["body"]
    js = sorted(int(k) for k in bodies)
    tally, kinds, examples, times = Counter(), Counter(), [], []
    for c in complaints:
        t0 = time.perf_counter()
        try:
            d = AP.build_defense(store, pk, c, cb, js, k_salt=k_salt, signer=signer, client=client, view=view,
                                 spool_dir=spool_dir)
        except Exception as e:                                  # noqa: BLE001
            d = {}
            kinds[f"defense_error:{type(e).__name__}"] += 1
        r = JT.judge_safe(c, contract_stmt, view, bodies, d, int(now_ms), check_verdict)
        times.append(time.perf_counter() - t0)
        tally[r["verdict"]] += 1
        if r.get("kind"):
            kinds[f"{r['verdict']}({r['kind']})"] += 1
        if r["verdict"] != "MET" and len(examples) < 5:
            who = c.get("receipt") or (c.get("sub_record") or {})
            examples.append({"verdict": r["verdict"], "kind": r.get("kind"), "j": r.get("j"),
                             "stalls": r.get("stalls"), "tenant": who.get("tenant_id"),
                             "pos": who.get("pos")})
    times.sort()
    return {"judged": len(complaints), "verdicts": dict(tally), "kinds": dict(kinds), "examples": examples,
            "judge_s_p50": round(times[len(times) // 2], 3) if times else None,
            "judge_s_max": round(times[-1], 3) if times else None}


def stratified_sample(sizes: Dict[int, int], k: int, seed: str) -> dict:
    """k of the partitions: ranked by record count, cut into k strata of equal size (the heaviest
    and the lightest are both represented), one drawn at random from each. k <= 0 or k >= the
    number of partitions takes them all."""
    ranked = sorted(sizes, key=lambda p: (sizes[p], p))
    n = len(ranked)
    if k <= 0 or k >= n:
        strata, pick = [ranked], sorted(ranked)
    else:
        rng = random.Random(str(seed))
        strata = [ranked[i * n // k:(i + 1) * n // k] for i in range(k)]
        pick = sorted(rng.choice(s) for s in strata)
    return {"partitions": pick, "k": len(pick), "of": n, "seed": str(seed), "strata": strata,
            "records_sampled": sum(sizes[p] for p in pick), "records_total": sum(sizes.values())}


def tenant_partitions(store, tenants: Iterable[str]) -> Dict[str, int]:
    """The partition each log accounts (from its latest anchor; a tenant log holds one partition,
    the system logs are one per partition). A log without an anchor accounts nothing."""
    out = {}
    for t in tenants:
        a = store.latest(t)
        pl = (a.pos_last or {}) if a is not None else {}
        if "p" in pl:
            out[t] = int(pl["p"])
    return out


def count_check(store, where: Dict[str, int], ends: Dict[int, int], first: Dict[int, int]) -> dict:
    """Every partition's broker records from the first accounted offset to the end offset against the
    leaves its logs hold; after the drain they differ only if a record was lost or accounted twice."""
    leaves = Counter()
    for t, p in where.items():
        leaves[p] += int(store.latest(t).n)
    rows, bad = {}, []
    for p in sorted(set(ends) | set(leaves)):
        rec = int(ends.get(p, 0)) - int(first.get(p, 0))
        rows[str(p)] = {"records": rec, "leaves": leaves.get(p, 0)}
        if rec != leaves.get(p, 0):
            bad.append(p)
    return {"ok": not bad, "mismatch": bad, "records": sum(r["records"] for r in rows.values()),
            "leaves": sum(leaves.values()), "partitions": rows}


def sample_plan(store, tenants: List[str], ends: Dict[int, int], contract_body: dict, k: int, seed: str) -> dict:
    """The count check over every partition, the stratified sample, and the logs it audits."""
    fao = ((contract_body.get("broker") or {}).get("first_acct_offset") or {})
    first = {int(tk.rsplit("/", 1)[1]): int(o) for tk, o in fao.items()}
    where = tenant_partitions(store, tenants)
    counts = count_check(store, where, ends, first)
    sizes = {p: max(0, int(ends[p]) - first.get(p, 0)) for p in ends}
    s = stratified_sample(sizes, k, seed)
    chosen = set(s["partitions"])
    s["tenants"] = sorted(t for t, p in where.items() if p in chosen)
    s["counts"] = counts
    return s


def _bootstrap(settings) -> str:
    return ",".join(settings.kafka_bootstrap_servers)


def broker_ends(settings) -> Dict[int, int]:
    """Every partition's end offset (high watermark) of the run's topic."""
    from aiokafka import AIOKafkaConsumer
    from aiokafka.structs import TopicPartition
    from tools.replay_audit import _kafka_partitions
    boot, topic = _bootstrap(settings), settings.kafka_provenance_topic

    async def go():
        parts = await _kafka_partitions(boot, topic)
        c = AIOKafkaConsumer(bootstrap_servers=boot, enable_auto_commit=False)
        await c.start()
        try:
            ends = await c.end_offsets([TopicPartition(topic, p) for p in parts])
            return {int(tp.partition): int(o) for tp, o in ends.items()}
        finally:
            await c.stop()
    return asyncio.run(go())


def _settings_store():
    from config import settings
    from crypto.anchor_store import get_anchor_store
    return settings, get_anchor_store(settings)


def run_replay(settings, contract_path: str, pk_hex: str, workers: int, out_dir: str,
               partitions: Optional[List[int]] = None) -> dict:
    from tools import replay_audit
    argv = ["--contract", contract_path, "--key", pk_hex, "--state", os.path.join(out_dir, "state.json"),
            "--out", out_dir, "--bootstrap", _bootstrap(settings), "--topic", settings.kafka_provenance_topic,
            "--s3-bucket", str(settings.merkle_anchor_s3_bucket), "--s3-prefix", str(settings.merkle_anchor_s3_prefix),
            "--workers", str(max(1, workers)), "--read-idle-s", "30"]
    if partitions is not None:
        argv += ["--partitions", ",".join(str(p) for p in partitions)]
    if settings.merkle_anchor_s3_endpoint_url:
        argv += ["--s3-endpoint", str(settings.merkle_anchor_s3_endpoint_url)]
    t0, c0 = time.perf_counter(), _cpu()
    code = replay_audit.main(argv)
    wall, cpu = time.perf_counter() - t0, _cpu() - c0
    with open(os.path.join(out_dir, "report.json"), encoding="utf-8") as f:
        rep = json.load(f)
    n = int(rep.get("records") or 0)
    findings = rep.get("findings") or []
    return {"exit": code, "counts": rep.get("counts"), "records": n, "complaints": rep.get("complaints"),
            "incomplete": rep.get("incomplete"), "findings_by_type": dict(Counter(f.get("type") for f in findings)),
            "records_per_s": rep.get("records_per_s"), "wall_s": round(wall, 2), "cpu_s": round(cpu, 2),
            "cpu_us_per_record": round(cpu * 1e6 / n, 1) if n else None, "peak_rss_mb": _rss_mb(),
            "workers": workers, "partitions": partitions}


def audit(a) -> dict:
    settings, store = _settings_store()
    out: Dict[str, Any] = {"acct_mode": bool(settings.acct_mode), "bucket": settings.merkle_anchor_s3_bucket,
                           "prefix": settings.merkle_anchor_s3_prefix, "audit_mode": a.mode}
    if store is None:
        out["error"] = "anchoring disabled"
        return out
    out["census"] = section(lambda: census(store))
    tenants = list(store.tenants())
    out["tenants"] = len(tenants)
    if not out["acct_mode"]:
        return out
    from crypto.period_statements import contract_key, k_salt_from
    from crypto.signing import get_public_key, get_signer
    from tools.replay_audit import stored_periods
    dep, ver = settings.acct_deployment_id, int(settings.acct_contract_version)
    pk = get_public_key(settings)
    raw = store.get_object(contract_key(dep, ver))
    if raw is None or pk is None:
        out["error"] = "no published contract or no deployment key"
        return out
    contract = json.loads(raw)
    cb = contract["body"]
    spool_dir = settings.period_spool_dir or None
    work = tempfile.mkdtemp(prefix="acct_audit_")
    cpath = os.path.join(work, "contract.json")
    with open(cpath, "w", encoding="utf-8") as f:
        json.dump(contract, f)
    receipts = []
    if a.receipts and os.path.isfile(a.receipts):
        with open(a.receipts, encoding="utf-8") as f:
            receipts = [r for r in json.load(f) if isinstance(r, dict)][:JUDGE_SAMPLE]
    max_at = max((int(r["at_ms"]) for r in receipts if isinstance(r.get("at_ms"), int)), default=None)
    out["due"] = section(lambda: wait_due(store, dep, cb, max_at, WAIT_MAX_S))
    parts: Optional[List[int]] = None
    logs: Optional[List[str]] = None                       # None: every log
    if a.mode == "sampled":
        sp = section(lambda: sample_plan(store, tenants, broker_ends(settings), cb, a.sample_partitions,
                                         SAMPLE_SEED))
        if "error" in sp:
            out["audit_mode"] = "full"                     # no sample, so nothing is left out
        else:
            out["counts"] = sp.pop("counts")
            parts, logs = sp["partitions"], sp.pop("tenants")
            sp["tenants"] = len(logs)
        out["sample"] = sp
    out["replay"] = section(lambda: run_replay(settings, cpath, pk.hex(), REPLAY_WORKERS,
                                               os.path.join(work, "replay"), parts))

    def accounting():
        from crypto.audit_accounting import audit_accounting
        from tools.replay_audit import load_statements
        c0 = _cpu()
        rep = audit_accounting(store, pk, load_statements(store, dep), contract, tenants=logs)
        cpu = _cpu() - c0
        heads = [store.latest(t) for t in (tenants if logs is None else logs)]
        leaves = sum(int(a.n) for a in heads if a is not None)
        per = rep["tenants"]
        fs = [f for t in per.values() for f in (t.get("findings") or [])]
        verdicts, blob_bytes, unchk = Counter(), 0, 0
        for t in per.values():
            verdicts.update(t.get("verdicts") or {})
            blob_bytes += int(t.get("blob_bytes") or 0)
            unchk += int(t.get("u") or 0)
        return {"ok": rep.get("ok"), "findings_by_kind": dict(Counter(f.get("kind") for f in fs)),
                "findings_first": fs[:5], "verdicts": dict(verdicts), "blob_bytes": blob_bytes,
                "uncheckable": unchk, "leaves": leaves,
                "cpu_us_per_leaf": round(cpu * 1e6 / leaves, 1) if leaves else None}
    out["accounting"] = section(accounting)
    out["records"] = section(lambda: record_census(store, settings.acct_system_tenant, logs))
    out["statements"] = section(lambda: statements_summary(store, dep, tenants))

    from crypto.merkle_tree_storage import merkle_tree_storage
    from crypto.period_statements import _policy_text
    client = merkle_tree_storage._public_witness()
    policy = _policy_text(settings.merkle_public_witness_policy)
    view: Optional[dict] = None
    if client is not None and policy:
        v = section(lambda: {"view": public_view(store, dep, ver, client, policy)})
        view = v.pop("view", None)
        out["view"] = dict(v, leaves=len((view or {}).get("leaves") or []),
                           heads=len((view or {}).get("heads") or []))
    else:
        out["view"] = {"error": "no public log or no witness policy configured"}
    from crypto import audit_period as AP
    from tools.check_verdict import check_verdict
    js = sorted(stored_periods(store, dep))
    bodies = AP.stored_statements(store, dep, js)
    now = int(time.time() * 1000)
    if view is not None:
        # The public log as the honest respondent's defense explains it, and beside it the reading
        # from the bodies and heads the store holds.
        def public_with_defense():
            d = AP.build_defense(store, pk, {}, cb, js, signer=get_signer(settings), view=view,
                                 spool_dir=spool_dir)
            return _compact_statements(AP.audit_statements(view, d["bodies"], cb, now, heads=d["heads"]))
        out["statements_public"] = section(public_with_defense)
        out["statements_store_only"] = section(lambda: _compact_statements(AP.audit_statements(view, bodies, cb, now)))
    complaints = [{"receipt": r} for r in receipts]
    for p in sorted(glob.glob(os.path.join(work, "replay", "complaint-*.json")))[:MAX_COMPLAINTS]:
        with open(p, encoding="utf-8") as f:
            c = json.load(f)
        complaints.append(c.get("complaint") or c)
    out["judge"] = section(lambda: judge_all(
        store, pk, contract, complaints, view, bodies, now, k_salt=k_salt_from(settings),
        signer=get_signer(settings), client=client, check_verdict=check_verdict, spool_dir=spool_dir))
    out["judge"]["receipts_judged"] = len(receipts)
    out["judge"]["complaints_judged"] = len(complaints) - len(receipts)
    return out


def _compact_statements(r: dict) -> dict:
    keep = {k: v for k, v in r.items() if isinstance(v, (int, float, str, bool)) or v is None}
    for k, v in r.items():
        if isinstance(v, list):
            keep[k + "_n"] = len(v)
            keep[k + "_first"] = v[:5]
        elif isinstance(v, dict):
            keep[k] = {kk: vv for kk, vv in list(v.items())[:20]}
    return keep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    au = sub.add_parser("audit")
    au.add_argument("--receipts", help="JSON list of receipts v2 to judge (loadgen.py --receipts-sample-out)")
    au.add_argument("--mode", choices=("full", "sampled"), default="full",
                    help="sampled: replay, accounting and records on a stratified sample of partitions")
    au.add_argument("--sample-partitions", type=int, default=8, help="partitions in a sampled audit")
    sub.add_parser("anchors")
    a = ap.parse_args(argv)
    if a.cmd == "anchors":
        _, store = _settings_store()
        emit(anchors_dump(store) if store is not None else {"error": "anchoring disabled"})
    else:
        emit(audit(a))
    return 0


if __name__ == "__main__":
    sys.exit(main())
