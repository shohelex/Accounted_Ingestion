from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

TICK = re.compile(r"SINK_TICK t=([0-9.]+) written=(\d+)")


def parse_ticks(text: str) -> dict:
    """{source: [(t, cumulative_written), ...]}; a line's first field names its source, and a sink that
    restarted from zero has its count carried across."""
    raw = {}
    for line in text.splitlines():
        m = TICK.search(line)
        if not m:
            continue
        src = line.split()[0] if not line.startswith("SINK_TICK") else "?"
        raw.setdefault(src, []).append((float(m.group(1)), int(m.group(2))))
    out = {}
    for src, pts in raw.items():
        carried, prev, acc = 0, 0, []
        for t, w in pts:                  # a drop is a restart
            if w < prev:
                carried += prev
            prev = w
            acc.append((t, carried + w))
        out[src] = acc
    return out


def written_at(series: list, t: float) -> float:
    """One source's committed count at Unix time t, interpolated between its ticks."""
    if not series or t <= series[0][0]:
        return float(series[0][1]) if series and t >= series[0][0] else 0.0
    for (t1, w1), (t2, w2) in zip(series, series[1:]):
        if t1 <= t <= t2:
            return w1 + (w2 - w1) * ((t - t1) / (t2 - t1) if t2 > t1 else 1.0)
    return float(series[-1][1])           # after its last tick: a sink that stopped holds its count


def committed_rate(run: dict, ticks: dict) -> dict:
    cfg = run.get("config") or {}
    t0, warm = cfg.get("epoch_start"), float(cfg.get("warmup_s") or 0)
    sched = float(cfg.get("schedule_s_actual") or cfg.get("duration_s") or 0)
    if t0 is None or sched <= warm:
        return {"committed_window_eps": None, "reason": "run has no epoch_start or no steady window"}
    if not ticks:
        return {"committed_window_eps": None, "reason": "no SINK_TICK lines"}
    start, end = t0 + warm, t0 + sched
    steady = end - start
    w_start = sum(written_at(s, start) for s in ticks.values())
    w_end = sum(written_at(s, end) for s in ticks.values())
    aps = run.get("attempts_per_second") or {}
    by_done = aps.get("admitted_by_completion") or []
    acked_before = sum(by_done[:int(warm)])
    acked_in_window = sum(by_done[int(warm):int(sched) + 1])
    backlog = max(0.0, acked_before - w_start)
    delta = w_end - w_start
    return {
        "window_s": round(steady, 3),
        "sinks": len(ticks),
        "written_at_window_start": round(w_start, 1),
        "written_at_window_end": round(w_end, 1),
        "acknowledged_before_window": acked_before,
        "backlog_at_window_start": round(backlog, 1),
        "backlog_drained_in_window": delta >= backlog,
        "committed_window_eps": round(max(0.0, delta - backlog) / steady, 2),
        "commit_eps_window_raw": round(delta / steady, 2),
        "acknowledged_window_eps": round(acked_in_window / steady, 2),
        "basis": ("sink SINK_TICK counts, window = warm-up end to emission end; warm-up backlog "
                  "subtracted (exact when backlog_drained_in_window, else a lower bound)"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path, help="loadgen.py report (JSON)")
    ap.add_argument("ticks", type=Path, help="the sinks' logs (docker compose logs), each line starting "
                                             "with the sink's name")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    r = committed_rate(json.loads(a.run.read_text()), parse_ticks(a.ticks.read_text()))
    if a.out:
        a.out.write_text(json.dumps(r, indent=1))
    print(" ".join(f"{k}={r.get(k)}" for k in ("committed_window_eps", "commit_eps_window_raw",
                                               "acknowledged_window_eps", "backlog_at_window_start",
                                               "backlog_drained_in_window", "sinks", "reason") if k in r))


if __name__ == "__main__":
    main()
