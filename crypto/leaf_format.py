from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from crypto.incremental_merkle import _hash_leaf, canonicalize


def leaf_event_data(event: Any) -> Dict[str, Any]:
    """The fields of a ProvenanceEvent that its leaf commits to."""
    return {
        "event_id": event.event_id,
        "entity_id": event.entity.id,
        "agent_id": event.agent.id,
        "timestamp": event.timestamp.isoformat(),
        "operation": event.activity.operation.value,
        "resource": event.activity.resource,
        "event_type": "provenance_event",
    }


_CLIENT_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,63}$")


def flat_event_leaf_data(body: Dict[str, Any], tenant_id: str) -> Optional[Dict[str, Any]]:
    """The leaf data POST /events derives from a flat event for tenant_id, or None when the sender
    cannot know it in advance (no usable client event id or timestamp). The client uses it to
    check that a receipt names its event's leaf."""
    eid = body.get("event_id")
    ts = body.get("timestamp")
    if not (isinstance(eid, str) and _CLIENT_EVENT_ID.match(eid)) or not isinstance(ts, str):
        return None
    try:
        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return {
        "event_id": f"c_{tenant_id}_{eid}",
        "entity_id": body.get("resource"),
        "agent_id": body.get("user_id"),
        "timestamp": when.isoformat(),
        "operation": str(body.get("operation", "")).upper(),
        "resource": body.get("resource"),
        "event_type": "provenance_event",
    }


def leaf_hash_hex(event_data: Dict[str, Any]) -> str:
    """SHA-256(0x00 || canonical JSON of the leaf data), as the log computes it."""
    return _hash_leaf(canonicalize(event_data)).hex()


def leaf_id(event_data: Dict[str, Any]) -> str:
    return f"leaf_{leaf_hash_hex(event_data)[:16]}"


__all__ = ["leaf_event_data", "leaf_hash_hex", "leaf_id", "flat_event_leaf_data"]
