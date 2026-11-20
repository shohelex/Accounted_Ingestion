from __future__ import annotations

import hashlib
import json
import re
import zlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

VALIDATOR = "acct-validate/1"
ROUTER = "acct-route/1"
MAX_BYTES = 1_048_576
MAX_INT_DIGITS = 4300
LENIENT_MAX_DEPTH = 512
_MAX_DEPTH = 64
_INT64 = (-(1 << 63), (1 << 63) - 1)

_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# What str(datetime) and datetime.isoformat() print, and nothing else: date, 'T' or ' ', time to
# the second, optional 3 or 6 fractional digits, optional 'Z' or +HH:MM offset. Parsing is then the
# same on every Python version that has datetime.fromisoformat.
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{3}|\.\d{6})?(Z|[+-]\d{2}:\d{2})?$")

SOURCES = ("cdn", "storage", "api", "vm", "cache", "database")
EVENT_TYPES = ("access", "modify", "create", "delete", "cache_hit", "cache_miss", "execute")
ENTITY_TYPES = ("file", "endpoint", "user", "vm", "bucket", "cache_entry", "database_table", "api_key")
AGENT_TYPES = ("user", "service", "cdn_node", "vm", "api_gateway", "cache_server")
OPERATIONS = ("GET", "POST", "PUT", "DELETE", "PATCH", "CACHE", "EXECUTE")

# (name, kind, required). Kinds: str, int, obj, ts, enum tuple. Optional fields may be null;
# "obj!" is an object that may be absent but not null (pydantic's Dict with a default).
_TOP: List[Tuple[str, Any, bool]] = [
    ("event_id", "str", True), ("tenant_id", "str", True), ("timestamp", "ts", True),
    ("source", SOURCES, True), ("event_type", EVENT_TYPES, True),
    ("entity", "obj", True), ("agent", "obj", True), ("activity", "obj", True),
    ("provenance_hash", "str", False), ("chain_position", "int", False),
    ("correlation_id", "str", False), ("parent_event_id", "str", False),
]
_NESTED: Dict[str, List[Tuple[str, Any, bool]]] = {
    "entity": [("type", ENTITY_TYPES, True), ("id", "str", True), ("hash", "str", False),
               ("size", "int", False), ("ip", "str", False), ("metadata", "obj!", False)],
    "agent": [("type", AGENT_TYPES, True), ("id", "str", True), ("ip", "str", False),
              ("user_agent", "str", False), ("metadata", "obj!", False)],
    "activity": [("operation", OPERATIONS, True), ("resource", "str", True),
                 ("duration_ms", "int", False), ("status_code", "int", False),
                 ("metadata", "obj!", False)],
}


class _Reject(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Reject("NOT_JSON")
        out[k] = v
    return out


def _no_constant(name):
    raise _Reject("NOT_JSON")


def _digits(s: str) -> int:
    return len(s) - (1 if s[:1] == "-" else 0)


def _strict_int(s: str) -> int:
    if _digits(s) > MAX_INT_DIGITS:
        raise _Reject("NOT_JSON")
    return int(s)


def parse(raw: Optional[bytes]) -> Tuple[Optional[str], Optional[dict]]:
    """(code, None) for bytes that are not one JSON object, else (None, the object)."""
    if raw is None:
        return "TOMBSTONE", None
    if len(raw) > MAX_BYTES:
        return "TOO_LARGE", None
    try:
        text = bytes(raw).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "NOT_UTF8", None
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant,
                          parse_int=_strict_int)
    except _Reject as r:
        return r.code, None
    except (ValueError, RecursionError):
        return "NOT_JSON", None
    if not isinstance(data, dict):
        return "NOT_OBJECT", None
    if _depth(data) > _MAX_DEPTH:
        return "NOT_JSON", None
    return None, data


def _lenient_int(s: str) -> Any:
    # An oversized integer is kept as its digits: no tag field is an integer that large.
    return int(s) if _digits(s) <= MAX_INT_DIGITS else s


def _nesting(text: str) -> int:
    """The deepest bracket nesting of JSON text, outside strings."""
    best = depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def parse_for_tag(raw: Optional[bytes]) -> Optional[dict]:
    """The object whose "_acct" tag authenticates the record, or None when there is none.

    The strict parse when it succeeds. When the strict parse refuses the bytes as NOT_JSON or
    TOO_LARGE, a lenient parse of the same UTF-8 text: NaN and Infinity accepted, duplicate keys
    resolved by the last one, integers of any length (oversized ones kept as digit strings), and
    nesting up to LENIENT_MAX_DEPTH. A value that is not UTF-8, not an object, or a tombstone
    carries no tag. Only the tag, tenant_id and event_id of the result are ever read."""
    if raw is None:
        return None
    code, data = parse(raw)
    if code is None:
        return data
    if code not in ("NOT_JSON", "TOO_LARGE"):
        return None
    try:
        text = bytes(raw).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if _nesting(text) > LENIENT_MAX_DEPTH:
        return None
    try:
        data = json.loads(text, parse_int=_lenient_int)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _murmur2(data: bytes) -> int:
    """Kafka's murmur2 (org.apache.kafka.common.utils.Utils.murmur2), as the Java client and
    aiokafka's default partitioner compute it."""
    length = len(data)
    m, r = 0x5BD1E995, 24
    h = (0x9747B28C ^ length) & 0xFFFFFFFF
    for i in range(length // 4):
        k = data[4 * i] | (data[4 * i + 1] << 8) | (data[4 * i + 2] << 16) | (data[4 * i + 3] << 24)
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> r
        k = (k * m) & 0xFFFFFFFF
        h = (h * m) & 0xFFFFFFFF
        h ^= k
    rest, tail = length % 4, length & ~3
    if rest >= 3:
        h ^= data[tail + 2] << 16
    if rest >= 2:
        h ^= data[tail + 1] << 8
    if rest >= 1:
        h ^= data[tail]
        h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return h


def partition_of(key: bytes, route: Any) -> Optional[int]:
    """The partition the published partitioner `route` puts a record keyed `key` on, or None
    when the route is not one of acct-route/1's:

      {"fn": "murmur2", "n": N}   Kafka's Java client and aiokafka: (murmur2(key) & 0x7fffffff) % N
      {"fn": "crc32", "n": N}     librdkafka's "consistent" partitioner: crc32(key) % N
    """
    if not isinstance(route, dict) or not isinstance(key, (bytes, bytearray)):
        return None
    fn = route.get("fn")
    if fn in ("murmur2", "crc32"):
        n = route.get("n")
        if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
            return None
        h = (_murmur2(bytes(key)) & 0x7FFFFFFF) if fn == "murmur2" else zlib.crc32(bytes(key))
        return h % n
    return None


def _depth(x: Any) -> int:
    best, stack = 0, [(x, 1)]
    while stack:
        v, d = stack.pop()
        best = max(best, d)
        if isinstance(v, dict):
            stack.extend((c, d + 1) for c in v.values())
        elif isinstance(v, list):
            stack.extend((c, d + 1) for c in v)
    return best


def _encodable(k: str) -> bool:
    try:
        k.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def surrogate_path(value: Any, path: str = "$") -> Optional[str]:
    """The path of the first key or string that cannot be encoded as UTF-8, or None. Keys are
    visited in the object's order, which json.loads keeps from the bytes."""
    if isinstance(value, str):
        return None if _encodable(value) else path
    if isinstance(value, dict):
        for k, v in value.items():
            if not _encodable(k):
                return f"{path}.<key>"
            bad = surrogate_path(v, f"{path}.{k}")
            if bad is not None:
                return bad
        return None
    if isinstance(value, list):
        for i, v in enumerate(value):
            bad = surrogate_path(v, f"{path}[{i}]")
            if bad is not None:
                return bad
    return None


def _check_field(obj: dict, name: str, kind: Any, required: bool, label: str) -> None:
    if name not in obj:
        if required:
            raise _Reject(f"MISSING_FIELD:{label}")
        return
    v = obj[name]
    if v is None:
        if required or kind == "obj!":
            raise _Reject(f"TYPE:{label}")
        return
    if kind == "str":
        if not isinstance(v, str):
            raise _Reject(f"TYPE:{label}")
    elif kind == "int":
        if isinstance(v, bool) or not isinstance(v, int) or not _INT64[0] <= v <= _INT64[1]:
            raise _Reject(f"TYPE:{label}")
    elif kind in ("obj", "obj!"):
        if not isinstance(v, dict):
            raise _Reject(f"TYPE:{label}")
    elif kind == "ts":
        if not isinstance(v, str) or _TS.match(v) is None:
            raise _Reject("TIMESTAMP")
        try:
            _parse_ts(v)
        except ValueError:
            raise _Reject("TIMESTAMP")
    elif isinstance(kind, tuple):
        if not isinstance(v, str):
            raise _Reject(f"TYPE:{label}")
        if v not in kind:
            raise _Reject(f"ENUM:{label}")


def _parse_ts(v: str) -> datetime:
    s = v[:-1] + "+00:00" if v.endswith("Z") else v
    return datetime.fromisoformat(s[:10] + "T" + s[11:])


def leaf_data_of(data: dict) -> dict:
    """The leaf data (crypto.leaf_format.leaf_event_data) of a record the validator accepted."""
    return {
        "event_id": data["event_id"],
        "entity_id": data["entity"]["id"],
        "agent_id": data["agent"]["id"],
        "timestamp": _parse_ts(data["timestamp"]).isoformat(),
        "operation": data["activity"]["operation"],
        "resource": data["activity"]["resource"],
        "event_type": "provenance_event",
    }


def content_hash_of(leaf: dict) -> str:
    """SHA-256(0x00 || canonical JSON), as crypto.leaf_format.leaf_hash_hex computes it."""
    body = json.dumps(leaf, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(b"\x00" + body).hexdigest()


def check_object(data: dict) -> Optional[str]:
    """The code for a parsed record object, or None."""
    try:
        bad = surrogate_path(data)
        if bad is not None:
            return f"SURROGATE:{bad}"
        for name, kind, required in _TOP:
            _check_field(data, name, kind, required, name)
            if name == "tenant_id" and _TENANT_ID.match(data["tenant_id"]) is None:
                return "TENANT"
        for parent, fields in _NESTED.items():
            for name, kind, required in fields:
                _check_field(data[parent], name, kind, required, f"{parent}.{name}")
    except _Reject as r:
        return r.code
    acct = data.get("_acct")
    if isinstance(acct, dict) and isinstance(acct.get("leaf_hash"), str):
        if acct["leaf_hash"] != content_hash_of(leaf_data_of(data)):
            return "SUB_MISMATCH"
    return None


def validate_record(raw: Optional[bytes]) -> Optional[str]:
    """None if the record value is valid, else its rejection code."""
    code, data = parse(raw)
    if code is not None:
        return code
    return check_object(data)


__all__ = ["VALIDATOR", "ROUTER", "MAX_BYTES", "validate_record", "parse", "parse_for_tag",
           "partition_of", "check_object", "leaf_data_of", "content_hash_of", "surrogate_path"]
