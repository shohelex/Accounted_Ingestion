from __future__ import annotations

import gc
import logging
import os


def freeze_startup_heap(log: logging.Logger) -> int:
    """Move every object alive after start-up into the garbage collector's permanent generation, so
    full collections (which pause the event loop) skip them. GC_FREEZE=0 turns it off. Returns the
    number of objects frozen."""
    if os.getenv("GC_FREEZE", "1").strip().lower() in ("0", "false", "no", "off"):
        return 0
    gc.collect()
    gc.freeze()
    n = gc.get_freeze_count()
    log.warning(f"gc: {n} start-up objects moved to the permanent generation (GC_FREEZE=0 to keep them)")
    return n
