from __future__ import annotations

import argparse
import bisect
import csv
import gzip
import json
import statistics as st
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def ack_times(run: dict, attempts: list | None = None) -> list:
    """Absolute (Unix) times of every acknowledgement, sorted."""
    t0 = float((run.get("config") or {}).get("epoch_start") or 0.0)
    if attempts is not None:
        return sorted(t0 + done for _send, done, outcome in attempts if outcome == "admitted")
    by_done = ((run.get("attempts_per_second") or {}).get("admitted_by_completion")) or []
    out = []
    for i, n in enumerate(by_done):
        out.extend(t0 + i + (j + 0.5) / n for j in range(n))
    return out


def read_attempts(path: Path) -> list:
    raw = gzip.open(path, "rt", encoding="utf-8") if str(path).endswith(".gz") else open(path, encoding="utf-8")
    with raw as f:
        return [(float(r["send_s"]), float(r["done_s"]), r["outcome"]) for r in csv.DictReader(f)]


def coverage_from_blocks(cov: dict):
    """covered(digest) from sqlledger_verify.py's per-block counts."""
    blocks = sorted((int(b), int(n)) for b, n in cov.get("per_block", []))
    keys, cum, acc = [], [], 0
    for b, n in blocks:
        acc += n
        keys.append(b)
        cum.append(acc)

    def covered(d: dict) -> int:
        i = bisect.bisect_right(keys, int(d["coverage"]))
        return cum[i - 1] if i else 0
    return covered


def coverage_from_ticks(ticks: dict):
    """covered(digest) = every sink's committed count at the digest's t_before."""
    from sink_rate import written_at

    def covered(d: dict) -> int:
        return int(sum(written_at(s, float(d["t_before"])) for s in ticks.values()))
    return covered


def _quantile(sorted_xs: list, q: float):
    if not sorted_xs:
        return None
    i = min(len(sorted_xs) - 1, max(0, int(round(q * (len(sorted_xs) - 1)))))
    return round(sorted_xs[i], 3)


def exposure(acks: list, digests: list, covered, marks: list | None = None, grid_s: float = 0.1,
             t0: float | None = None) -> dict:
    """acks: sorted Unix times. digests: ledger_digest.py records (ok and failed). covered: f(record)."""
    ok = sorted((d for d in digests if d.get("ok")), key=lambda d: float(d["t_after"]))
    failed = [d for d in digests if not d.get("ok")]
    n = len(acks)
    base = {"acknowledged": n, "digests_ok": len(ok), "digests_failed": len(failed)}
    if not n:
        return {**base, "reason": "no acknowledged events"}
    # C at each digest: monotone, and capped by what had been acknowledged before the digest was asked for.
    steps, c = [], 0
    for d in ok:
        a_before = bisect.bisect_right(acks, float(d["t_before"]))
        c = max(c, min(int(covered(d)), a_before))
        steps.append((float(d["t_after"]), c))
    step_t = [t for t, _ in steps]

    def C(t):
        i = bisect.bisect_right(step_t, t)
        return steps[i - 1][1] if i else 0

    def A(t):
        return bisect.bisect_right(acks, t)

    # exposure per acknowledgement (k-th ack <-> first digest with C >= k)
    exp, j = [], 0
    for k in range(1, n + 1):
        while j < len(steps) and steps[j][1] < k:
            j += 1
        if j == len(steps):
            break
        exp.append(steps[j][0] - acks[k - 1])
    never = n - len(exp)
    exp_sorted = sorted(exp)
    # U(t) = A(t) - C(t): the maximum is reached just before a digest lands or at the last ack
    cands = [(t - 1e-6) for t in step_t if acks[0] <= t] + [acks[-1]]
    u_max, u_at = 0, None
    for t in cands:
        u = A(t) - C(t)
        if u > u_max:
            u_max, u_at = u, t
    grid, t = [], acks[0]
    while t <= acks[-1]:
        grid.append(A(t) - C(t))
        t += grid_s
    gaps = [b - a for a, b in zip(step_t, step_t[1:])]
    ref = t0 if t0 is not None else acks[0]
    out = {**base,
           "covered_at_end": steps[-1][1] if steps else 0, "never_covered": never,
           "exposure_s": {"p50": _quantile(exp_sorted, .5), "p90": _quantile(exp_sorted, .9),
                          "p99": _quantile(exp_sorted, .99), "max": _quantile(exp_sorted, 1.0),
                          "mean": round(st.fmean(exp), 3) if exp else None},
           "uncovered_events": {"max": u_max, "max_at_s": round(u_at - ref, 1) if u_at is not None else None,
                                "mean": round(st.fmean(grid), 1) if grid else None},
           "digest_gap_s": {"median": round(st.median(gaps), 2) if gaps else None,
                            "max": round(max(gaps), 2) if gaps else None},
           "first_digest_s": round(step_t[0] - ref, 2) if step_t else None}
    if marks:
        at = []
        for m in marks:
            if m.get("event") == "load_start":
                continue
            tm = float(m["t"])
            i = bisect.bisect_right(step_t, tm)
            at.append({"event": m["event"], "t_s": round(tm - ref, 1), "acknowledged": A(tm), "covered": C(tm),
                       "uncovered": A(tm) - C(tm),
                       "last_digest_age_s": round(tm - step_t[i - 1], 1) if i else None,
                       "next_digest_after_s": round(step_t[i] - tm, 1) if i < len(step_t) else None})
        out["at_marks"] = at
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True, help="loadgen.py report (JSON)")
    ap.add_argument("--digests", type=Path, required=True, help="digest log (ledger_digest.py --out)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--coverage", type=Path,
                   help="per-block counts (sqlledger_verify.py or immudb_verify.py --coverage-out)")
    g.add_argument("--ticks", type=Path, help="the sinks' logs with their SINK_TICK lines (see sink_rate.py)")
    ap.add_argument("--attempts", type=Path, help="loadgen.py --attempts-out")
    ap.add_argument("--marks", type=Path,
                    help='JSON lines {"event": name, "t": Unix time}, e.g. when a fault was injected; '
                         'the uncovered count is reported at each')
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    from ledger_digest import load
    run = json.loads(a.run.read_text())
    attempts = read_attempts(a.attempts) if a.attempts and a.attempts.exists() else None
    acks = ack_times(run, attempts)
    if a.coverage:
        covered, basis = coverage_from_blocks(json.loads(a.coverage.read_text())), "ledger blocks (exact)"
    else:
        from sink_rate import parse_ticks
        covered, basis = coverage_from_ticks(parse_ticks(a.ticks.read_text())), "sink committed counts at t_before"
    marks = load(a.marks) if a.marks else None
    r = exposure(acks, load(a.digests), covered, marks, t0=(run.get("config") or {}).get("epoch_start"))
    r["coverage_basis"] = basis
    r["ack_basis"] = "attempts file (done_s)" if attempts is not None else "admitted_by_completion, spread per second"
    if a.out:
        a.out.write_text(json.dumps(r, indent=1))
    e, u = r.get("exposure_s") or {}, r.get("uncovered_events") or {}
    print(f"exposure_s p50={e.get('p50')} p99={e.get('p99')} max={e.get('max')} "
          f"uncovered max={u.get('max')} mean={u.get('mean')} never_covered={r.get('never_covered')} "
          f"digests ok={r['digests_ok']} failed={r['digests_failed']}"
          + "".join(f" | at {m['event']}: uncovered={m['uncovered']}" for m in r.get("at_marks", [])))


if __name__ == "__main__":
    main()
