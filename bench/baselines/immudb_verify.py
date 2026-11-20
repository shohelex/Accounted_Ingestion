from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path


def first_tx(c, ids, page=999) -> dict:
    """For every acknowledged id, the first transaction that wrote it (a redelivery writes it again
    in a later one; the first is when it became covered)."""
    want, first = set(ids), {}
    tx, top = 1, int(c.currentState().txId)
    while tx <= top:
        txs = getattr(c.txScan(tx, page), "txs", None) or []
        if not txs:
            break
        for t in txs:
            tid = int(t.header.id)
            for e in t.entries or []:
                # a key/value entry's key carries immudb's one-byte prefix; txById strips it the same way
                k = bytes(e.key[1:]).decode("utf-8", "replace")
                if k in want and k not in first:
                    first[k] = tid
        tx = int(txs[-1].header.id) + 1
    return first


def coverage(first: dict) -> dict:
    per_tx = {}
    for tid in first.values():
        per_tx[tid] = per_tx.get(tid, 0) + 1
    return {"basis": "immudb transaction id of the first write of each acknowledged event",
            "per_block": sorted([t, n] for t, n in per_tx.items())}


def verify(ids, addr, user="immudb", password="immudb", database="defaultdb", sample=500, page=1000,
           with_coverage=False):
    from immudb import ImmudbClient
    c = ImmudbClient(addr)
    c.login(user, password)
    c.useDatabase(database.encode())
    ids = list(dict.fromkeys(ids))
    missing = []
    t0 = time.perf_counter()
    for i in range(0, len(ids), page):
        keys = [k.encode() for k in ids[i:i + page]]
        found = c.getAll(keys) or {}
        missing += [k.decode() for k in keys if k not in found]
    lookup_s = time.perf_counter() - t0
    gone = set(missing)
    present = [k for k in ids if k not in gone]
    rnd = random.Random(7)
    picked = rnd.sample(present, min(sample, len(present)))
    proofs_ok = proofs_bad = rewritten = 0
    t0 = time.perf_counter()
    for k in picked:
        try:
            if c.verifiedGet(k.encode()).verified:
                proofs_ok += 1
            else:
                proofs_bad += 1
        except Exception:
            proofs_bad += 1
    proof_ms = (time.perf_counter() - t0) * 1000.0 / max(1, len(picked))
    for k in picked:
        try:
            if len(c.history(k.encode(), 0, 10, False) or []) > 1:
                rewritten += 1
        except Exception:
            pass
    state = c.currentState()
    r = {"acknowledged": len(ids), "present": len(present), "missing": len(missing),
         "missing_sample": missing[:20], "lookup_s": round(lookup_s, 2),
         "sampled": len(picked), "proofs_verified": proofs_ok, "proofs_failed": proofs_bad,
         "proof_ms_mean": round(proof_ms, 2), "sample_written_more_than_once": rewritten,
         "database_tx_id": state.txId}
    if not with_coverage:
        return r
    t0 = time.perf_counter()
    cov = coverage(first_tx(c, present))
    r["coverage_scan_s"] = round(time.perf_counter() - t0, 2)
    return r, cov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", type=Path, required=True, help="acknowledged event ids (loadgen.py --dump-ids)")
    ap.add_argument("--addr", required=True, help="immudb host:port")
    ap.add_argument("--user", default="immudb")
    ap.add_argument("--password", default="immudb")
    ap.add_argument("--database", default="defaultdb")
    ap.add_argument("--sample", type=int, default=500, help="ids whose proof and history are checked")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--coverage-out", type=Path,
                    help="acknowledged events per immudb transaction, for exposure_window.py")
    a = ap.parse_args()
    ids = [x.strip() for x in a.ids.read_text().splitlines() if x.strip()]
    if a.coverage_out:
        r, cov = verify(ids, a.addr, a.user, a.password, a.database, a.sample, with_coverage=True)
        a.coverage_out.write_text(json.dumps(cov))
    else:
        r = verify(ids, a.addr, a.user, a.password, a.database, a.sample)
    if a.out:
        a.out.write_text(json.dumps(r, indent=1))
    print(" ".join(f"{k}={r[k]}" for k in ("acknowledged", "present", "missing", "proofs_verified",
                                           "proofs_failed", "sample_written_more_than_once", "proof_ms_mean")))


if __name__ == "__main__":
    main()
