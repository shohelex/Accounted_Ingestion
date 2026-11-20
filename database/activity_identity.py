from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class EventIdCollision(ValueError):
    """A different event under an event_id that is already recorded; permanent for that event only."""


def _text(x: Any) -> str:
    x = getattr(x, "value", x)      # enums are stored by value
    return "" if x is None else str(x)


def _second(ts: Any) -> Optional[str]:
    """ISO 8601 to the second. Python datetimes and Neo4j temporals both print 'YYYY-MM-DDTHH:MM:SS...'."""
    if ts is None:
        return None
    s = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return s[:19]


def activity_conflict(existing: Dict[str, Any], tenant_id: Any, operation: Any,
                      resource: Any, timestamp: Any) -> bool:
    """True if the stored Activity describes a different event than the one given. Fields the
    stored node lacks are not compared."""
    for key, value in (("tenant_id", tenant_id), ("operation", operation), ("resource", resource)):
        if existing.get(key) is not None and _text(existing[key]) != _text(value):
            return True
    a, b = _second(existing.get("timestamp")), _second(timestamp)
    return a is not None and b is not None and a != b


def plan_group(items: List[Tuple[Any, Any, Any, Any, Any]],
               existing: Dict[Any, Dict[str, Any]]) -> Tuple[List[int], Dict[int, EventIdCollision]]:
    """For a group of events written in one transaction: (indices to write, {index: collision}).

    items are (event_id, tenant_id, operation, resource, timestamp) in arrival order; existing holds
    the stored fields of Activities already recorded under these ids. The first new occurrence of an
    id is written, a reuse with other content fails alone, and a redelivery is neither.
    """
    write: List[int] = []
    failed: Dict[int, EventIdCollision] = {}
    first: Dict[Any, Dict[str, Any]] = {}
    for i, (event_id, tenant_id, operation, resource, timestamp) in enumerate(items):
        prior = existing.get(event_id)
        where = "already recorded"
        if prior is None and event_id in first:
            prior, where = first[event_id], "earlier in the same group"
        if prior is None:
            first[event_id] = {"tenant_id": _text(tenant_id), "operation": _text(operation),
                               "resource": _text(resource), "timestamp": timestamp}
            write.append(i)
        elif activity_conflict(prior, tenant_id, operation, resource, timestamp):
            failed[i] = EventIdCollision(
                f"event_id collision: {event_id} {where} with different content")
    return write, failed
