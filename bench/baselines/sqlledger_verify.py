from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sqlledger_common as sc          # noqa: E402
from ledger_digest import load as load_digests   # noqa: E402

VERIFY_TIMEOUT_S = 1800     # the verification walks every row of the ledger


def presence(rows, ids) -> dict:
    """rows: (event_id, block_id, commit_time). The per-id first block and the row count."""
    first_block, count = {}, {}
    for eid, block, _ct in rows:
        eid = str(eid)
        count[eid] = count.get(eid, 0) + 1
        b = int(block)
        if eid not in first_block or b < first_block[eid]:
            first_block[eid] = b
    acked = list(dict.fromkeys(ids))
    missing = [i for i in acked if i not in count]
    twice = sum(1 for i in acked if count.get(i, 0) > 1)
    return {"acked": acked, "first_block": first_block, "count": count, "missing": missing, "twice": twice,
            "rows": sum(count.values())}


def run_verification(conn, digests: list) -> dict:
    if not digests:
        return {"ledger_verified": None, "verify_error": "no digests in the log: nothing to verify against",
                "verify_s": 0.0}
    t0 = time.perf_counter()
    try:
        cur = conn.cursor()
        cur.execute(sc.VERIFY_WITH_DIGESTS, (json.dumps(digests),))
        try:                                   # drain any result set so the call has finished
            while cur.nextset():
                pass
        except Exception:
            pass
        return {"ledger_verified": True, "verify_error": None, "verify_s": round(time.perf_counter() - t0, 2)}
    except Exception as e:                     # the procedure throws on a mismatch
        # A session that timed out or died gave no answer: None, not False.
        unanswered = any(x in str(e) for x in ("connection timed out", "DBPROCESS is dead"))
        return {"ledger_verified": None if unanswered else False, "verify_error": str(e)[:600],
                "verify_s": round(time.perf_counter() - t0, 2)}


def verify(ids, digest_lines, conn) -> tuple[dict, dict]:
    t0 = time.perf_counter()
    cur = conn.cursor()
    cur.execute(sc.ROWS_WITH_BLOCKS)
    p = presence(iter(cur.fetchone, None), ids)          # row by row: the table can be large
    lookup_s = time.perf_counter() - t0
    digests, forks = sc.digests_for_verification(digest_lines)
    top = max((int(d["block_id"]) for d in digests), default=None)
    present = [i for i in p["acked"] if i in p["count"]]
    covered = [i for i in present if top is not None and p["first_block"][i] <= top]
    v = run_verification(conn, digests)
    per_block = {}
    for i in present:
        b = p["first_block"][i]
        per_block[b] = per_block.get(b, 0) + 1
    attempts = [r for r in digest_lines if r.get("system") == "sqlledger"]
    r = {"acknowledged": len(p["acked"]), "present": len(present), "missing": len(p["missing"]),
         "missing_sample": p["missing"][:20], "lookup_s": round(lookup_s, 2),
         "rows_in_table": p["rows"], "written_more_than_once": p["twice"],
         "covered_by_digest": len(covered), "present_not_covered": len(present) - len(covered),
         "digests_taken": sum(1 for x in attempts if x.get("ok")),
         "digests_failed": sum(1 for x in attempts if not x.get("ok")),
         "digests_used": len(digests), "highest_digest_block": top, "forked_blocks": forks,
         # sp_verify_database_ledger checks the whole ledger up to the digests, not one proof per event:
         # these count the acknowledged events in the blocks it accepted or refused.
         "covered_and_verified": len(covered) if v["ledger_verified"] else 0,
         "covered_and_refused": len(covered) if v["ledger_verified"] is False else 0,
         **v}
    cov = {"basis": "ledger block id of the first row of each acknowledged event",
           "per_block": sorted([b, n] for b, n in per_block.items())}
    return r, cov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", type=Path, required=True, help="acknowledged event ids (loadgen.py --dump-ids)")
    ap.add_argument("--addr", required=True, help="SQL Server host:port")
    ap.add_argument("--user")
    ap.add_argument("--password", help="default: MSSQL_PASSWORD")
    ap.add_argument("--database")
    ap.add_argument("--digests", type=Path, required=True, help="digest log (ledger_digest.py --out)")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--coverage-out", type=Path, help="acknowledged events per ledger block, for exposure_window.py")
    a = ap.parse_args()
    ids = [x.strip() for x in a.ids.read_text().splitlines() if x.strip()]
    s = sc.settings(a.addr, a.user, a.password, a.database)
    conn = sc.connect(s, autocommit=True, query_timeout=VERIFY_TIMEOUT_S)
    try:
        r, cov = verify(ids, load_digests(a.digests), conn)
    finally:
        conn.close()
    if a.out:
        a.out.write_text(json.dumps(r, indent=1))
    if a.coverage_out:
        a.coverage_out.write_text(json.dumps(cov))
    print(" ".join(f"{k}={r[k]}" for k in ("acknowledged", "present", "missing", "covered_by_digest",
                                           "present_not_covered", "ledger_verified", "digests_used",
                                           "written_more_than_once", "verify_s")))


if __name__ == "__main__":
    main()
