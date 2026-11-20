from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ledger_digest import load     # noqa: E402

MODES = ("undetected", "detected")


def next_digest_due(digests: list, period: float) -> float | None:
    """When the digester starts its next digest: the latest attempt's start plus the period."""
    starts = [float(r["t_before"]) for r in digests if "t_before" in r]
    return max(starts) + period if starts else None


def plan_undetected(digests: list, period: float, backup_done: float, hold: float, margin: float) -> tuple:
    """("restore_in", seconds) or ("retry", reason). The offline must come `margin` s before the next
    digest starts (the restore client counts the rows first, then goes offline)."""
    due = next_digest_due(digests, period)
    if due is None:
        return ("retry", "no digest has been attempted yet")
    latest = due - margin
    if backup_done >= latest:
        return ("retry", f"the backup ended {backup_done - due + margin:.1f} s too late: the next digest "
                         f"starts at {due:.3f}, the offline must come {margin:.0f} s before it")
    return ("restore_in", round(min(hold, latest - backup_done), 3))


def marks_of(faults: list) -> dict:
    """The last time of each event (a retried backup leaves an abandoned mark before the kept one)."""
    m = {}
    for r in faults:
        if "event" in r and "t" in r:
            m[r["event"]] = r
    return m


BLOCK_RE = re.compile(r"hash of block (\d+)")


def judge(mode: str, faults: list, digests: list) -> dict:
    m = marks_of(faults)
    need = ("store_backup", "store_backup_done", "store_offline")
    missing = [e for e in need if e not in m]
    if missing:
        return {"mode": mode, "valid": False, "reason": f"marks missing: {', '.join(missing)}"}
    b0, b1, off = (float(m[e]["t"]) for e in need)
    ok = [r for r in digests if r.get("ok")]
    overlapping = [r for r in ok if float(r["t_after"]) > b0 and float(r["t_before"]) < off]
    inside = [r for r in ok if float(r["t_before"]) > b1 and float(r["t_after"]) < off]

    def brief(r):
        return {"t_before": r["t_before"], "t_after": r["t_after"], "block_id": r.get("coverage"),
                "before_offline_s": round(off - float(r["t_after"]), 3)}
    out = {"mode": mode, "backup_t": b0, "backup_done_t": b1, "offline_t": off,
           "window_s": round(off - b1, 3),
           "digests_overlapping": [brief(r) for r in overlapping],
           "digests_inside": [brief(r) for r in inside]}
    if mode == "undetected":
        out["valid"] = not overlapping
        out["reason"] = ("no digest answered between the backup and the offline" if not overlapping else
                         f"{len(overlapping)} digest(s) answered between the backup and the offline: "
                         "the rollback is detectable, not the undetected variant")
    else:
        out["valid"] = bool(inside)
        out["reason"] = (f"{len(inside)} digest(s) taken after the backup and before the offline" if inside else
                         "no digest lies between the backup and the offline: nothing can detect the rollback")
        det = m.get("check_rollback_detected") or m.get("check_rollback_not_detected")
        if det is not None:
            detail = str(det.get("detail", ""))
            blk = BLOCK_RE.search(detail)
            out["detection"] = {
                "detected": det["event"] == "check_rollback_detected",
                "verified_at": det["t"],
                "after_offline_s": round(float(det["t"]) - off, 3),
                "after_restored_s": (round(float(det["t"]) - float(m["store_restored"]["t"]), 3)
                                     if "store_restored" in m else None),
                "failing_block": int(blk.group(1)) if blk else None,
                "failing_digest": next((brief(r) for r in inside if blk and r.get("coverage") == int(blk.group(1))),
                                       None),
                "error": detail[:300]}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="seconds to wait between the backup and the restore")
    p.add_argument("--digests", type=Path, required=True, help="digest log (ledger_digest.py --out)")
    p.add_argument("--period", type=float, required=True, help="the digest period, seconds")
    p.add_argument("--backup-done", type=float, required=True, help="Unix time the backup finished")
    p.add_argument("--hold", type=float, default=10.0, help="longest wait after the backup, seconds")
    p.add_argument("--margin", type=float, default=5.0, help="seconds between the offline and the next digest")
    j = sub.add_parser("judge", help="is the run the variant it claims")
    j.add_argument("--mode", choices=MODES, required=True)
    j.add_argument("--faults", type=Path, required=True,
                   help='JSON lines {"event", "t"[, "detail"]}: store_backup, store_backup_done, '
                        'store_offline, optionally store_restored and check_rollback_[not_]detected')
    j.add_argument("--digests", type=Path, required=True, help="digest log (ledger_digest.py --out)")
    j.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "plan":
        kind, val = plan_undetected(load(a.digests), a.period, a.backup_done, a.hold, a.margin)
        print(f"{kind} {val}")
        return 0
    r = judge(a.mode, load(a.faults), load(a.digests))
    if a.out:
        a.out.write_text(json.dumps(r, indent=1))
    line = (f"rollback {a.mode}: valid={r['valid']} window_s={r.get('window_s')} "
            f"digests_inside={len(r.get('digests_inside', []))} "
            f"digests_overlapping={len(r.get('digests_overlapping', []))}")
    d = r.get("detection")
    if d:
        line += (f" detected={d['detected']} failing_block={d['failing_block']} "
                 f"after_offline_s={d['after_offline_s']}")
    print(line + ("" if r["valid"] else f" -- {r['reason']}"))
    return 0 if r["valid"] else 3


if __name__ == "__main__":
    sys.exit(main())
