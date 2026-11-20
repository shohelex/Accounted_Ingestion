from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from crypto.incremental_merkle import _hash_internal, _hash_leaf
from crypto.leaf_format import leaf_hash_hex
from crypto.signing import ACK_NS, ANCHOR_NS

# Each namespace ends in its only NUL byte, so none is a prefix of another and a signature over one
# statement type cannot be replayed as another.
NS_SUB = b"acct/sub/v1\x00"
NS_ACK2 = b"acct/ack/v2\x00"
NS_STMT = b"acct/stmt/v1\x00"
NS_AGG = b"acct/agg/v1\x00"
NS_AGG_PAD = b"acct/agg-pad/v1\x00"
NS_SALT = b"acct/salt/v1\x00"

# Every namespace signed with the deployment key.
SIGNED_NAMESPACES: Tuple[bytes, ...] = (
    ANCHOR_NS, ACK_NS, NS_ACK2, NS_SUB, NS_STMT, b"sigsum.org/v1/tree-leaf\x00",
)

VERDICT_TYPES: tuple = ("DUP", "COLLIDE", "MALFORMED", "UNCHECKABLE", "UNAUTH", "GAP")
RECORD_VERSION = 2
KINDS = ("event", "verdict")


def _check_value(x: Any, path: str = "$") -> None:
    if x is None or isinstance(x, (str, bool, int)):
        return
    if isinstance(x, float):
        raise TypeError(f"canon: float at {path}; accounted structures use integers only")
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str):
                raise TypeError(f"canon: non-string key {k!r} at {path}")
            _check_value(v, f"{path}.{k}")
        return
    if isinstance(x, (list, tuple)):
        for i, v in enumerate(x):
            _check_value(v, f"{path}[{i}]")
        return
    raise TypeError(f"canon: value of type {type(x).__name__} at {path}")


def canon(obj) -> bytes:
    """JSON with sorted keys, no whitespace, ASCII only. Floats are refused: two spellings of one
    number would give two encodings."""
    _check_value(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def signed(ns: bytes, body: dict) -> bytes:
    """The bytes a signature over body in namespace ns covers."""
    if ns.count(b"\x00") != 1 or not ns.endswith(b"\x00"):
        raise ValueError("a namespace ends in its only NUL byte")
    return ns + canon(body)


def sub_body(tenant_id: str, event_id: str, leaf_hash: str, sub: str, at_ms: int,
             contract: str) -> dict:
    """What the submission tag's signature covers (namespace NS_SUB)."""
    return {"tenant_id": str(tenant_id), "event_id": str(event_id), "leaf_hash": str(leaf_hash),
            "sub": str(sub), "at_ms": int(at_ms), "contract": str(contract)}


def ack2_body(tenant_id: str, event_id: str, leaf_hash: str, sub: str, at_ms: int,
              topic: str, p: int, o: int, contract: str) -> dict:
    """What the receipt v2 signature covers (namespace NS_ACK2). The receipt's other fields are not
    signed."""
    return {"tenant_id": str(tenant_id), "event_id": str(event_id), "leaf_hash": str(leaf_hash),
            "sub": str(sub), "at_ms": int(at_ms), "topic": str(topic), "p": int(p), "o": int(o),
            "contract": str(contract)}


def acct_tag(sub: str, at_ms: int, leaf_hash: str, contract: str, sig: str) -> dict:
    """The "_acct" key of a Kafka record value."""
    return {"v": 1, "sub": str(sub), "at_ms": int(at_ms), "leaf_hash": str(leaf_hash),
            "contract": str(contract), "sig": str(sig)}


def record_sub(acct: Optional[dict]) -> Optional[dict]:
    """The "sub" field of an accounting record: the "_acct" tag without its version key."""
    if not isinstance(acct, dict):
        return None
    return {k: acct.get(k) for k in ("sub", "at_ms", "leaf_hash", "contract", "sig")}


@dataclass(frozen=True)
class Position:
    """A broker position: topic, partition, offset, and the broker's LogAppendTime in ms. The
    offset may exceed 64 bits; canon writes every digit."""
    topic: str
    p: int
    o: int
    bt_ms: int

    def to_json(self) -> dict:
        return {"topic": self.topic, "p": int(self.p), "o": int(self.o), "bt_ms": int(self.bt_ms)}

    @staticmethod
    def from_json(d: dict) -> "Position":
        return Position(str(d["topic"]), int(d["p"]), int(d["o"]), int(d["bt_ms"]))


def pos_last_of(record: dict) -> dict:
    """The {topic, p, o} of a record's position (the anchor record's pos_last form)."""
    pos = record["pos"]
    return {"topic": str(pos["topic"]), "p": int(pos["p"]), "o": int(pos["o"])}


def event_template(tenant_id: str, pos: Position, sub: Optional[dict], event: dict) -> dict:
    """An event record without its seq (the writer's template; add_records assigns the seq)."""
    if not isinstance(event, dict):
        raise TypeError("an event record carries its leaf data")
    return {"v": RECORD_VERSION, "kind": "event", "tenant_id": str(tenant_id),
            "pos": pos.to_json(), "sub": sub, "event": event, "verdict": None}


def verdict_template(tenant_id: str, pos: Position, sub: Optional[dict], event: Optional[dict],
                     vtype: str, *, ref: int = None, ref_leaf: str = None, raw: dict = None,
                     code: str = None, validator: str = None, attempts: int = None,
                     first_fail_ms: int = None, err: str = None, gap: dict = None) -> dict:
    """A verdict record without its seq. Every verdict field is present (null when unused), so two
    writers building the same verdict produce the same bytes."""
    if vtype not in VERDICT_TYPES:
        raise ValueError(f"unknown verdict type {vtype!r}")
    verdict = {"type": vtype, "ref": ref, "ref_leaf": ref_leaf, "raw": raw, "code": code,
               "validator": validator, "attempts": attempts, "first_fail_ms": first_fail_ms,
               "err": err, "gap": gap}
    return {"v": RECORD_VERSION, "kind": "verdict", "tenant_id": str(tenant_id),
            "pos": pos.to_json(), "sub": sub, "event": event, "verdict": verdict}


def with_seq(template: dict, seq: int) -> dict:
    out = dict(template)
    out["seq"] = int(seq)
    return out


def without_seq(record: dict) -> dict:
    out = dict(record)
    out.pop("seq", None)
    return out


def is_v2(leaf_data: Any) -> bool:
    return isinstance(leaf_data, dict) and leaf_data.get("v") == RECORD_VERSION \
        and leaf_data.get("kind") in KINDS


def record_hash(record: dict) -> str:
    """H(0x00 || canon(record)), hex: the record's leaf hash in the tenant's MMR."""
    return _hash_leaf(canon(record)).hex()


def content_hash(event: dict) -> str:
    """The leaf hash of an event's v1 leaf data; equals the receipt's leaf_hash."""
    return leaf_hash_hex(event)


def same_template(a: dict, b: dict) -> bool:
    """Equal as canonical bytes, ignoring seq."""
    return canon(without_seq(a)) == canon(without_seq(b))


def segment_body(tenant_id: str, frm: int, to: int, records: list) -> dict:
    """The segment object for leaves [frm, to) of a tenant's log."""
    if int(to) - int(frm) != len(records):
        raise ValueError("a segment holds exactly the records [from, to)")
    return {"v": 1, "tenant_id": str(tenant_id), "from": int(frm), "to": int(to),
            "records": list(records)}


def mmr_extend(peaks: list, leaf_hashes_hex: list) -> tuple:
    """Extend MMR peaks [[hex, height], ...] (largest first) by leaf hashes; return (new_peaks,
    root_hex). The fold is IncrementalMerkleLog's. The empty log's root is ""."""
    stack: List[Tuple[bytes, int]] = [(bytes.fromhex(h), int(ht)) for h, ht in (peaks or [])]
    for lh in leaf_hashes_hex:
        carry = (bytes.fromhex(lh), 0)
        while stack and stack[-1][1] == carry[1]:
            top = stack.pop()
            carry = (_hash_internal(top[0], carry[0]), carry[1] + 1)
        stack.append(carry)
    new_peaks = [[h.hex(), ht] for h, ht in stack]
    return new_peaks, mmr_root_hex(new_peaks)


def mmr_root_hex(peaks: list) -> str:
    if not peaks:
        return ""
    acc = bytes.fromhex(peaks[-1][0])
    for h, _ in reversed(peaks[:-1]):
        acc = _hash_internal(bytes.fromhex(h), acc)
    return acc.hex()


def mmr_size(peaks: list) -> int:
    return sum(1 << int(ht) for _, ht in (peaks or []))


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def salt_hex(k_salt: bytes, dep: str, j: int, tenant_id: str) -> str:
    """The tenant's salt for period j: the first 16 bytes of HMAC-SHA256(K_salt, NS_SALT ||
    canon([dep, j, t])), as 32 hex characters."""
    return _hmac(k_salt, NS_SALT + canon([str(dep), int(j), str(tenant_id)]))[:16].hex()


# A tenant's status for the period in an aggregate leaf (agg alg v2).
TENANT_STATES = ("ok", "stall", "held")
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


def agg_leaf(salt: str, tenant_id: str, n: int, rh: str, pos_last: Optional[dict], u: int,
             st: Optional[str] = None, late: Optional[int] = None) -> bytes:
    """H(0x00 || NS_AGG || canon({salt, tenant_id, n, rh, pos_last, u[, st][, late]})): 32 bytes.
    st (the tenant's status) and late (its records overdue at t_s) enter only when given (alg v2)."""
    body = {"salt": str(salt), "tenant_id": str(tenant_id), "n": int(n), "rh": str(rh),
            "pos_last": pos_last, "u": int(u)}
    if st is not None:
        body["st"] = str(st)
    if late is not None:
        body["late"] = int(late)
    return _hash_leaf(NS_AGG + canon(body))


def agg_pad(k_salt: bytes, dep: str, j: int, i: int) -> bytes:
    """Padding leaf i of period j: H(0x00 || NS_AGG_PAD || HMAC(K_salt, canon([dep, j, i])))."""
    return _hash_leaf(NS_AGG_PAD + _hmac(k_salt, canon([str(dep), int(j), int(i)])))


def agg_order_key(k_salt: bytes, dep: str, j: int, tenant_id: str) -> bytes:
    """Sort key of a tenant's leaf in period j: HMAC(K_salt, "order" || canon([dep, j, t]))."""
    return _hmac(k_salt, b"order" + canon([str(dep), int(j), str(tenant_id)]))


def agg_tree(leaves: list) -> tuple:
    """RFC 6962 tree over leaf hashes whose count is a power of two. Returns (root, paths), where
    paths[i] lists the sibling hashes of leaf i from the bottom up."""
    size = len(leaves)
    if size == 0 or size & (size - 1):
        raise ValueError("the aggregate tree has a power-of-two number of leaves")
    level = [bytes(x) for x in leaves]
    paths: List[List[bytes]] = [[] for _ in range(size)]
    idx = list(range(size))
    while len(level) > 1:
        for leaf in range(size):
            paths[leaf].append(level[idx[leaf] ^ 1])
            idx[leaf] //= 2
        level = [_hash_internal(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], paths


def verify_agg_opening(opening: dict, root_hex: str, size: int) -> bool:
    """Does the opening {j, tenant_id, salt, n, rh, pos_last, u, [st, late], index, size, path}
    lead to root_hex in a tree of size leaves? Types are checked strictly, as in
    period_statements.verify_opening, so every checker reads the same evidence the same way."""
    try:
        if not isinstance(opening, dict) or not isinstance(root_hex, str) or type(size) is not int:
            return False
        o = opening
        if type(o.get("size")) is not int or o["size"] != size or size <= 0 or size & (size - 1):
            return False
        idx, n, u = o.get("index"), o.get("n"), o.get("u")
        if type(idx) is not int or type(n) is not int or type(u) is not int or not 0 <= idx < size:
            return False
        if not all(isinstance(o.get(k), str) for k in ("salt", "tenant_id", "rh")):
            return False
        st, late = o.get("st"), o.get("late")
        if st is not None and st not in TENANT_STATES or late is not None and (type(late) is not int or late < 0):
            return False
        path = o.get("path")
        if not isinstance(path, list) or (1 << len(path)) != size or not all(isinstance(x, str) for x in path):
            return False
        acc = agg_leaf(o["salt"], o["tenant_id"], n, o["rh"], o.get("pos_last"), u, st, late)
        i = idx
        for sib_hex in path:
            if len(sib_hex) != 64 or not _HEXDIGITS.issuperset(sib_hex):
                return False
            sib = bytes.fromhex(sib_hex)
            acc = _hash_internal(acc, sib) if i % 2 == 0 else _hash_internal(sib, acc)
            i //= 2
        return acc.hex() == root_hex
    except (KeyError, TypeError, ValueError):
        return False


def contract_hash(body: dict) -> str:
    """What receipts and submission tags carry as "contract": SHA-256 of the canonical CONTRACT
    statement body in force."""
    return sha256_hex(canon(body))


def stmt_message(body: dict) -> bytes:
    """The 32-byte public-log message of a period or contract statement: SHA-256(NS_STMT ||
    canon(body))."""
    return hashlib.sha256(NS_STMT + canon(body)).digest()


__all__ = [
    "NS_SUB", "NS_ACK2", "NS_STMT", "NS_AGG", "NS_AGG_PAD", "NS_SALT", "SIGNED_NAMESPACES",
    "VERDICT_TYPES", "RECORD_VERSION", "canon", "sha256_hex", "signed", "sub_body", "ack2_body",
    "acct_tag", "record_sub", "Position", "pos_last_of", "event_template",
    "verdict_template", "with_seq", "without_seq", "is_v2", "record_hash", "content_hash",
    "same_template", "segment_body", "mmr_extend", "mmr_root_hex", "mmr_size", "salt_hex",
    "agg_leaf", "agg_pad", "agg_order_key", "agg_tree", "TENANT_STATES",
    "verify_agg_opening", "contract_hash", "stmt_message",
]
