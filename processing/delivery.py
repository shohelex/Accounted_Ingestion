from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Tuple


def plan_offsets(events_batch: List[Dict[str, Any]],
                 unprocessed: Iterable[int]) -> Tuple[Dict[int, int], Dict[int, int]]:
    """Return (commits, seeks), both keyed by partition.

    events_batch  messages with 'partition' and 'offset'.
    unprocessed   indices into events_batch that have not been processed.

    commits[p]  offset to commit for partition p: the next offset to read. Only present when it
                advances past something processed in this batch.
    seeks[p]    offset to rewind partition p to: its first unprocessed event.
    """
    bad = set(unprocessed)
    by_partition: Dict[int, List[Tuple[int, int]]] = {}
    for i, msg in enumerate(events_batch):
        by_partition.setdefault(msg["partition"], []).append((int(msg["offset"]), i))
    commits: Dict[int, int] = {}
    seeks: Dict[int, int] = {}
    for p, items in by_partition.items():
        items.sort()
        first_bad = next((off for off, i in items if i in bad), None)
        if first_bad is None:
            commits[p] = items[-1][0] + 1
            continue
        seeks[p] = first_bad
        if first_bad > items[0][0]:
            commits[p] = first_bad
    return commits, seeks


class UndecodableRecord(ValueError):
    """A Kafka record whose value is not a UTF-8 JSON object (a tombstone, garbage, a JSON list)."""


def decode_record(value: Any) -> Dict[str, Any]:
    """The event carried by one Kafka record value, or UndecodableRecord. Decoded per record, not
    by a value_deserializer, which would fail the whole poll on one bad record."""
    if value is None:
        raise UndecodableRecord("record has no value (tombstone)")
    try:
        data = json.loads(value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else value)
    except (UnicodeDecodeError, ValueError, TypeError) as e:
        raise UndecodableRecord(f"record value is not UTF-8 JSON: {e}") from e
    if not isinstance(data, dict):
        raise UndecodableRecord(f"record value is JSON {type(data).__name__}, not an object")
    # The anchor stores refuse tenant ids outside the API's charset; producers that bypass the
    # API are caught here.
    from api.ingest_rules import valid_tenant_id
    if not valid_tenant_id(data.get("tenant_id")):
        raise UndecodableRecord(f"record carries an invalid tenant id: {data.get('tenant_id')!r}")
    return data


def is_permanent_event_error(exc: BaseException) -> bool:
    """An event that can never be processed, however often it is redelivered: malformed input
    or an event_id collision. Everything else is redelivered."""
    from pydantic import ValidationError
    if isinstance(exc, ValidationError):
        return True
    from database.activity_identity import EventIdCollision
    # UnicodeError: a string the database cannot encode (a lone surrogate). Other ValueError
    # subclasses are not assumed permanent.
    if isinstance(exc, (UnicodeError, EventIdCollision, UndecodableRecord)):
        return True
    return isinstance(exc, (KeyError, TypeError)) or type(exc) is ValueError


def identity_key(event_data: Dict[str, Any]) -> str:
    """Identity of one event across ingestion attempts, for duplicate suppression: (tenant,
    event_id)."""
    tenant = str(event_data.get("tenant_id", ""))
    event_id = event_data.get("event_id")
    if event_id:
        return f"id|{tenant}|{event_id}"
    # No event_id (the event fails validation anyway): only an identical record is a duplicate.
    body = json.dumps(event_data, sort_keys=True, default=str)
    return f"h|{tenant}|" + hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()


def outage_suspected(batch_size: int, unprocessed: int, dead: int) -> bool:
    """Every event in the batch failed and at least one failure is retryable: treat as an outage."""
    return unprocessed > 0 and unprocessed + dead >= batch_size


def should_dead_letter(counts: Dict[Any, int], key: Any, backend_up: bool,
                       max_redeliveries: int) -> bool:
    """Count one more delivery of ``key`` and say whether it has exhausted its redeliveries.
    A delivery counts only while the backend is up, so an outage of any length is waited out."""
    if not backend_up:
        return False
    counts[key] = counts.get(key, 0) + 1
    return counts[key] > max_redeliveries


_OUTAGE_NEO4J = {"ServiceUnavailable", "SessionExpired", "TransientError", "IncompleteCommit",
                 "WriteServiceUnavailable", "ReadServiceUnavailable", "SessionError"}

# S3 (and MinIO) refusals that mean "not now": throttling and server errors. The HTTP status is
# read where each client library puts it (_http_status).
_OUTAGE_CODES = {"SlowDown", "ServiceUnavailable", "Throttling", "ThrottlingException",
                 "RequestTimeout", "RequestTimeTooSkewed", "InternalError",
                 "XMinioServerNotInitialized", "XMinioStorageFull"}
# Connection failures of the HTTP clients under boto3 (not builtin ConnectionErrors).
_OUTAGE_CLIENT = {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
                  "ConnectionClosedError", "ProxyConnectionError", "HTTPClientError",
                  "ConnectionError", "NewConnectionError", "MaxRetryError", "ProtocolError"}


def _http_status(e: BaseException):
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        md = resp.get("ResponseMetadata") or {}
        return md.get("HTTPStatusCode"), (resp.get("Error") or {}).get("Code")
    for holder in (e, resp):
        for attr in ("status_code", "status", "code"):
            v = getattr(holder, attr, None) if holder is not None else None
            if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599:
                return v, None
    return None, None


def is_outage_error(exc: BaseException) -> bool:
    """Did this failure happen because the backend (database or write-once store) was
    unreachable? Judged from the exception and its cause chain, so a failure during an outage
    never counts even if the backend is up again when the batch ends. An exception with a boolean
    `outage` attribute is taken at its word."""
    e, hops = exc, 0
    while e is not None and hops < 8:
        declared = getattr(e, "outage", None)
        if isinstance(declared, bool):
            return declared
        if isinstance(e, (ConnectionError, TimeoutError, OSError)):
            return True
        name, mod = type(e).__name__, (type(e).__module__ or "")
        if mod.startswith("neo4j") and name in _OUTAGE_NEO4J:
            return True
        if mod.startswith(("aiokafka", "kafka")):
            return True
        if mod.startswith(("botocore", "urllib3", "httpx")) and name in _OUTAGE_CLIENT:
            return True
        status, code = _http_status(e)
        if code in _OUTAGE_CODES or (isinstance(status, int) and (status >= 500 or status == 429)):
            return True
        e = e.__cause__ if e.__cause__ is not None else e.__context__
        hops += 1
    return False
