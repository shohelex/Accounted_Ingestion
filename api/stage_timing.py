from __future__ import annotations

import asyncio
import gc
import logging
import os
import time
from typing import Dict, List, Optional

ON = os.getenv("STAGE_TIMING", "").strip().lower() in ("1", "true", "yes", "on")
LOG_EVERY = 1000
PROBE_S = 0.1
logger = logging.getLogger("api.stage_timing")

_sums: Dict[str, float] = {}
_counts: Dict[str, int] = {}
_sends: List[float] = []
_n = 0
_loop_delays: List[float] = []
_probe: Optional[asyncio.Task] = None
# Collections of the oldest generation: count, total and longest time (each stops the event loop).
_gc = {"t0": 0.0, "n2": 0, "ms2": 0.0, "max2": 0.0}


def _gc_cb(phase, info):
    if info.get("generation") != 2:
        return
    if phase == "start":
        _gc["t0"] = time.perf_counter()
    elif _gc["t0"]:
        ms = (time.perf_counter() - _gc["t0"]) * 1000
        _gc["n2"] += 1
        _gc["ms2"] += ms
        _gc["max2"] = max(_gc["max2"], ms)


if ON:
    gc.callbacks.append(_gc_cb)


def add(name: str, t0: float) -> None:
    """Record the seconds since t0 under name."""
    if not ON:
        return
    dt = time.perf_counter() - t0
    _sums[name] = _sums.get(name, 0.0) + dt
    if name == "send":
        _sends.append(dt)


# How late a PROBE_S sleep wakes up: CPU work on the event loop shows here and in no await.
async def _loop_probe() -> None:
    while True:
        t0 = time.perf_counter()
        await asyncio.sleep(PROBE_S)
        _loop_delays.append(time.perf_counter() - t0 - PROBE_S)


def note(name: str) -> None:
    """Count one occurrence of name (reported as name_n on the next APISPLIT line)."""
    if ON:
        _counts[name] = _counts.get(name, 0) + 1


def event_done(t0: float) -> None:
    """One event's accept ended (acknowledged or not); every LOG_EVERY events, log and reset."""
    global _n, _probe
    if not ON:
        return
    add("accept", t0)
    if _probe is None:
        try:
            _probe = asyncio.get_running_loop().create_task(_loop_probe())
        except RuntimeError:
            pass
    _n += 1
    if _n < LOG_EVERY:
        return
    s = sorted(_sends)
    d = sorted(_loop_delays)

    def q(xs, f):
        return xs[min(len(xs) - 1, int(len(xs) * f))] * 1000 if xs else 0.0
    logger.warning("APISPLIT pid=%d n=%d %s send_n=%d send_p50=%.1f send_p99=%.1f loop_delay_mean=%.1f "
                   "loop_delay_p99=%.1f loop_delay_max=%.1f gc2_n=%d gc2_ms=%.0f gc2_max=%.0f frozen=%d gen2=%d",
                   os.getpid(), _n,
                   " ".join([f"{k}={v * 1000 / _n:.2f}" for k, v in sorted(_sums.items())]
                            + [f"{k}_n={v}" for k, v in sorted(_counts.items())]),
                   len(s), q(s, 0.5), q(s, 0.99),
                   (sum(d) / len(d) * 1000) if d else 0.0, q(d, 0.99), (d[-1] * 1000) if d else 0.0,
                   _gc["n2"], _gc["ms2"], _gc["max2"], gc.get_freeze_count(), len(gc.get_objects(generation=2)))
    _gc.update(n2=0, ms2=0.0, max2=0.0)
    _counts.clear()
    _sums.clear()
    _sends.clear()
    _loop_delays.clear()
    _n = 0
