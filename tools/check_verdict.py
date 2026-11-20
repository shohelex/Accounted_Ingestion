#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import zlib
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from acct_common import NS_SUB, canon, ed25519_ok, record_hash, sub_body  # noqa: E402

# Copy of crypto/validate_record.py; keep the two identical.

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


# End of the copy.

VERDICT_TYPES = ("DUP", "COLLIDE", "MALFORMED", "UNCHECKABLE", "UNAUTH", "GAP")
_LOWER_HEX = frozenset("0123456789abcdef")


def _hex(s: Any, n: int) -> bool:
    return isinstance(s, str) and len(s) == n and set(s) <= _LOWER_HEX


def _well_formed_tag(acct: Any) -> bool:
    # A sub is 32 hex digits (128 random bits); processing/decide.py applies the same rule.
    return (isinstance(acct, dict) and acct.get("v") == 1
            and _hex(acct.get("sub"), 32)
            and isinstance(acct.get("at_ms"), int) and not isinstance(acct.get("at_ms"), bool)
            and _hex(acct.get("leaf_hash"), 64) and isinstance(acct.get("contract"), str)
            and _hex(acct.get("sig"), 128))


def _sub_msg(tenant_id: str, event_id: str, t: dict) -> bytes:
    return NS_SUB + canon(sub_body(tenant_id, event_id, t["leaf_hash"], t["sub"], t["at_ms"], t["contract"]))


def tag_verifies(data: dict, pubkey: bytes) -> bool:
    """Does a parsed record value carry a tag the deployment signed for its tenant and event id?"""
    acct = data.get("_acct")
    if not _well_formed_tag(acct):
        return False
    if not isinstance(data.get("tenant_id"), str) or not isinstance(data.get("event_id"), str):
        return False
    return ed25519_ok(pubkey, acct["sig"], _sub_msg(data["tenant_id"], data["event_id"], acct))


def record_sub(acct: Any) -> Optional[dict]:
    if not _well_formed_tag(acct):
        return None
    return {k: acct.get(k) for k in ("sub", "at_ms", "leaf_hash", "contract", "sig")}


def _safe_leaf(data: dict) -> Optional[dict]:
    try:
        return leaf_data_of(data)
    except Exception:
        return None


def _blob(record: dict, blobs: Callable[[str], Optional[bytes]]) -> Tuple[Optional[bytes], str]:
    raw = record["verdict"].get("raw")
    if not isinstance(raw, dict) or not _hex(raw.get("sha256"), 64) or not isinstance(raw.get("len"), int):
        return None, "no raw reference"
    sha = raw["sha256"]
    if raw.get("blob") != f"blobs/{sha}.bin":
        return None, "raw.blob is not blobs/<sha256>.bin"
    b = blobs(sha) if blobs is not None else None
    if b is None:
        return None, f"blob {sha[:16]} not available"
    b = bytes(b)
    if hashlib.sha256(b).hexdigest() != sha or len(b) != raw["len"]:
        return None, "blob does not hash to raw.sha256"
    return b, ""


def _content_matches_blob(record: dict, data: Optional[dict],
                          tag_data: Optional[dict] = None) -> Tuple[bool, str]:
    """An embedded event must be the blob's own (strict parse), an embedded tag the blob's own
    (parse_for_tag, which is the strict parse whenever that succeeds)."""
    ev = record.get("event")
    if ev is not None and (data is None or _safe_leaf(data) != ev):
        return False, "embedded event is not the blob's"
    tag_data = data if tag_data is None else tag_data
    if record.get("sub") is not None and (tag_data is None
                                          or record_sub(tag_data.get("_acct")) != record["sub"]):
        return False, "embedded tag is not the blob's"
    return True, ""


def _check_misrouted(record: dict, v: dict, b: bytes, pubkey: Optional[bytes]) -> Tuple[bool, str]:
    """MALFORMED(PARTITION) under acct-route/1: the blob carries a valid tag of tenant t, the route
    puts t on another partition than the record's, and the verdict is not in t's log. Whether the
    route is the contract's is checked by the audit, which holds the contract."""
    if v.get("code") != "PARTITION":
        return False, f"MALFORMED under {ROUTER} with code {v.get('code')!r}"
    if pubkey is None:
        return False, "MALFORMED(PARTITION): the deployment key is needed to check the tag"
    tag_data = parse_for_tag(b)
    if tag_data is None or not tag_verifies(tag_data, pubkey):
        return False, "MALFORMED(PARTITION): the blob carries no valid tag"
    tenant = tag_data.get("tenant_id")
    if not isinstance(tenant, str) or _TENANT_ID.match(tenant) is None:
        return False, "MALFORMED(PARTITION): the tag's tenant id is not one a log can hold"
    pos = record.get("pos") or {}
    q = partition_of(tenant.encode("utf-8"), v.get("route"))
    if not isinstance(q, int) or not isinstance(pos.get("p"), int) or q == pos["p"]:
        return False, f"MALFORMED(PARTITION): the route puts {tenant!r} on {q!r}, the record is on {pos.get('p')!r}"
    if record.get("tenant_id") == tenant:
        return False, "MALFORMED(PARTITION): the verdict is in the tenant's own log"
    _, data = parse(b)
    ok, why = _content_matches_blob(record, data, tag_data)
    return (ok, f"MALFORMED(PARTITION): {why}" if not ok else f"MALFORMED(PARTITION->{q})")


def _gap_contradicted(record: dict, g: dict, broker) -> Optional[str]:
    """What the broker says about a GAP's range: a reason when it holds records there."""
    if broker is None:
        return None
    pos = record.get("pos") or {}
    held = broker(pos.get("topic"), pos.get("p"), g["from"], g["to"])
    if held:
        return f"GAP: the broker holds offsets {sorted(held)[:5]} in [{g['from']}, {g['to']})"
    return None


def _tag_binds_event(record: dict, pubkey: Optional[bytes]) -> Tuple[bool, str]:
    sub, ev = record.get("sub"), record.get("event")
    if sub is None:
        return True, ""
    if not isinstance(ev, dict) or sub.get("leaf_hash") != content_hash_of(ev):
        return False, "tag names another content hash than the embedded event"
    if pubkey is not None and not ed25519_ok(pubkey, sub.get("sig"),
                                             _sub_msg(record["tenant_id"], ev.get("event_id"), sub)):
        return False, "tag signature does not verify"
    return True, ""


def check_verdict(record: dict, prefix_records: Dict[int, dict],
                  blobs: Callable[[str], Optional[bytes]], *,
                  pubkey: Optional[bytes] = None,
                  broker: Optional[Callable[[str, int, int, int], Optional[List[int]]]] = None
                  ) -> Tuple[bool, str]:
    """Does this anchored verdict record state a true claim? prefix_records maps seq to the earlier
    records of the same log, blobs maps a sha256 to the stored bytes, pubkey checks tags (UNAUTH
    needs it), and broker(topic, p, from, to) lists held offsets; without it a GAP is "unconfirmed"."""
    try:
        if not isinstance(record, dict) or record.get("v") != 2 or record.get("kind") != "verdict":
            return False, "not a v2 verdict record"
        v = record.get("verdict")
        seq = record.get("seq")
        if not isinstance(v, dict) or v.get("type") not in VERDICT_TYPES or not isinstance(seq, int):
            return False, "malformed verdict"
        vt = v["type"]
        ev = record.get("event")
        if vt in ("DUP", "COLLIDE"):
            ref = v.get("ref")
            if not isinstance(ref, int) or not 0 <= ref < seq:
                return False, f"{vt}: ref must be an earlier seq of the same log"
            ref_rec = prefix_records.get(ref)
            if not isinstance(ref_rec, dict) or ref_rec.get("seq") != ref:
                return False, f"{vt}: referent {ref} not in the anchored prefix"
            if record_hash(ref_rec) != v.get("ref_leaf"):
                return False, f"{vt}: ref_leaf is not the referent's record hash"
            if ref_rec.get("v") != 2 or ref_rec.get("kind") != "event" \
                    or ref_rec.get("tenant_id") != record.get("tenant_id"):
                return False, f"{vt}: referent is not an event record of this tenant"
            rev = ref_rec.get("event")
            if not isinstance(ev, dict) or not isinstance(rev, dict) \
                    or rev.get("event_id") != ev.get("event_id"):
                return False, f"{vt}: referent has another event id"
            same = content_hash_of(rev) == content_hash_of(ev)
            if same != (vt == "DUP"):
                return False, f"{vt}: content hashes {'equal' if same else 'differ'}"
            ok, why = _tag_binds_event(record, pubkey)
            return (ok, why or f"{vt} of seq {ref}")
        if vt == "MALFORMED":
            if v.get("validator") == ROUTER:
                b, why = _blob(record, blobs)
                if b is None:
                    return False, f"MALFORMED: {why}"
                return _check_misrouted(record, v, b, pubkey)
            if v.get("validator") != VALIDATOR:
                return False, f"MALFORMED under validator {v.get('validator')!r}, not {VALIDATOR}"
            b, why = _blob(record, blobs)
            if b is None:
                return False, f"MALFORMED: {why}"
            got = validate_record(b)
            if got is None or got != v.get("code"):
                return False, f"MALFORMED: the validator returns {got!r}, the verdict says {v.get('code')!r}"
            _, data = parse(b)
            tag_data = parse_for_tag(b)
            ok, why = _content_matches_blob(record, data, tag_data)
            if not ok:
                return False, f"MALFORMED: {why}"
            if pubkey is not None and record.get("sub") is not None and not tag_verifies(tag_data, pubkey):
                return False, "MALFORMED: embedded tag does not verify"
            # A tagged record is refused in its tenant's own log; one whose tenant id no log can
            # hold goes to a system log, never to a log named like the id.
            t = tag_data.get("tenant_id") if record.get("sub") is not None and tag_data else None
            if isinstance(t, str):
                holdable = _TENANT_ID.match(t) is not None
                if holdable and record.get("tenant_id") != t:
                    return False, "MALFORMED: a record with a valid tag is refused in its tenant's log"
                if not holdable and record.get("tenant_id") == t:
                    return False, "MALFORMED: an invalid tenant id is not a log"
            return True, f"MALFORMED({got})"
        if vt == "UNAUTH":
            if pubkey is None:
                return False, "UNAUTH: the deployment key is needed to check the tag"
            b, why = _blob(record, blobs)
            if b is None:
                return False, f"UNAUTH: {why}"
            _, data = parse(b)
            tag_data = parse_for_tag(b)
            if tag_data is not None and tag_verifies(tag_data, pubkey):
                return False, "UNAUTH: the blob carries a valid tag"
            if record.get("sub") is not None:
                return False, "UNAUTH: an unauthenticated record embeds no tag"
            claimed = tag_data.get("tenant_id") if tag_data else None
            if isinstance(claimed, str) and record.get("tenant_id") == claimed:
                return False, "UNAUTH: an unauthenticated record is never in the log it claims"
            ok, why = _content_matches_blob(record, data)
            return (ok, f"UNAUTH: {why}" if not ok else "UNAUTH")
        if vt == "GAP":
            g = v.get("gap")
            pos = record.get("pos") or {}
            if not isinstance(g, dict) or not isinstance(g.get("from"), int) \
                    or not isinstance(g.get("to"), int) or not g["from"] < g["to"] \
                    or pos.get("o") != g["from"]:
                return False, "GAP: malformed range"
            bad = _gap_contradicted(record, g, broker)
            if bad:
                return False, bad
            return True, f"GAP[{g['from']},{g['to']})" + ("" if broker is not None else " unconfirmed")
        return True, "UNCHECKABLE: counted against the budget"
    except Exception as e:  # a malformed record is a failed check, never a crash
        return False, f"check failed: {type(e).__name__}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("record", nargs="?", help="JSON file: the verdict record")
    ap.add_argument("--prefix", help="JSON file: list of the tenant's anchored records")
    ap.add_argument("--blobs", help="JSON file: {sha256: base64 bytes}, or a directory of <sha>.bin")
    ap.add_argument("--key", help="deployment public key (hex)")
    ap.add_argument("--validate", help="only run the validator on this raw file")
    a = ap.parse_args(argv)
    if a.validate:
        with open(a.validate, "rb") as f:
            print(validate_record(f.read()) or "VALID")
        return 0
    if not a.record:
        ap.error("a verdict record or --validate is required")
    with open(a.record, encoding="utf-8") as f:
        rec = json.load(f)
    prefix: Dict[int, dict] = {}
    if a.prefix:
        with open(a.prefix, encoding="utf-8") as f:
            for r in json.load(f):
                prefix[int(r["seq"])] = r
    table: Dict[str, bytes] = {}
    blobdir = a.blobs if a.blobs and os.path.isdir(a.blobs) else None
    if a.blobs and blobdir is None:
        with open(a.blobs, encoding="utf-8") as f:
            table = {k: base64.b64decode(v) for k, v in json.load(f).items()}

    def blobs(sha: str) -> Optional[bytes]:
        if sha in table:
            return table[sha]
        if blobdir:
            p = os.path.join(blobdir, f"{sha}.bin")
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    return fh.read()
        return None

    ok, why = check_verdict(rec, prefix, blobs, pubkey=bytes.fromhex(a.key) if a.key else None)
    print(("OK " if ok else "FAIL ") + why)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
