#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from typing import Any, List, Optional, Tuple

NS_SUB = b"acct/sub/v1\x00"
NS_ACK2 = b"acct/ack/v2\x00"
NS_STMT = b"acct/stmt/v1\x00"
NS_AGG = b"acct/agg/v1\x00"
NS_AGG_PAD = b"acct/agg-pad/v1\x00"
NS_SALT = b"acct/salt/v1\x00"
ANCHOR_NS = b"acct/anchor/v1\x00"

# peaks_from: the MMR peaks at seg.from, carried only by the first v2 anchor after v1 records.
ANCHOR_V2_FIELDS = ("v", "peaks", "seg", "pos_last", "u", "acct_from", "peaks_from")
ANCHOR_FIELDS = ("tenant_id", "n", "root", "ts", "prev_hash", "record_hash", "witnesses", "sig",
                 "reached_at") + ANCHOR_V2_FIELDS
ANCHOR_REQUIRED = ("tenant_id", "n", "root", "ts", "prev_hash", "record_hash")

MAX_DEPTH = 64          # nesting beyond this is malformed evidence
TENANT_STATES = ("ok", "stall", "held")
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


# strict values

def is_int(x) -> bool:
    return type(x) is int


def is_num(x) -> bool:
    return type(x) in (int, float)


def hex_bytes(x, nbytes: int) -> Optional[bytes]:
    """Exactly 2 * nbytes hex digits (bytes.fromhex alone would skip whitespace)."""
    if not isinstance(x, str) or len(x) != 2 * nbytes or not _HEXDIGITS.issuperset(x):
        return None
    return bytes.fromhex(x)


def depth_ok(x) -> bool:
    """No value nested deeper than MAX_DEPTH (counted as canon counts it)."""
    stack = [(x, 0)]
    while stack:
        v, d = stack.pop()
        if d > MAX_DEPTH:
            return False
        if isinstance(v, dict):
            stack.extend((c, d + 1) for c in v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend((c, d + 1) for c in v)
    return True


def _check_value(x, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("canon: nested too deeply")
    if x is None or isinstance(x, (str, bool, int)):
        return
    if isinstance(x, float):
        raise TypeError("canon: floats are not allowed")
    if isinstance(x, dict):
        for k, v in x.items():
            if not isinstance(k, str):
                raise TypeError("canon: non-string key")
            _check_value(v, depth + 1)
        return
    if isinstance(x, (list, tuple)):
        for v in x:
            _check_value(v, depth + 1)
        return
    raise TypeError(f"canon: value of type {type(x).__name__}")


def canon(obj) -> bytes:
    """Sorted-key JSON without whitespace, over str, int, bool, None, lists and str-keyed objects:
    the encoding every accounted-mode signature covers. Floats are refused."""
    _check_value(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def _anchor_canon(obj) -> bytes:
    # The anchor record body keeps its float timestamps; this is the encoding it is hashed with.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def h_leaf(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def h_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def ed25519_ok(public_key, sig, data: bytes) -> bool:
    """public_key as raw bytes or hex, sig as hex (or raw bytes)."""
    if not sig or not public_key or not isinstance(sig, (str, bytes)):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pk = bytes.fromhex(public_key) if isinstance(public_key, str) else bytes(public_key)
        sg = bytes.fromhex(sig) if isinstance(sig, str) else sig
        Ed25519PublicKey.from_public_bytes(pk).verify(sg, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# tag, receipt and complaint

def sub_body(tenant_id, event_id, leaf_hash, sub, at_ms, contract) -> dict:
    return {"tenant_id": str(tenant_id), "event_id": str(event_id), "leaf_hash": str(leaf_hash),
            "sub": str(sub), "at_ms": int(at_ms), "contract": str(contract)}


def ack2_body(tenant_id, event_id, leaf_hash, sub, at_ms, topic, p, o, contract) -> dict:
    return {"tenant_id": str(tenant_id), "event_id": str(event_id), "leaf_hash": str(leaf_hash),
            "sub": str(sub), "at_ms": int(at_ms), "topic": str(topic), "p": int(p), "o": int(o),
            "contract": str(contract)}


def parse_complaint(complaint, public_key) -> Optional[dict]:
    """The fields of a complaint ({"receipt"} or {"sub_record"}), or None when they are not of
    their types or the signature does not verify under public_key."""
    try:
        if not isinstance(complaint, dict):
            return None
        if "receipt" in complaint:
            r = complaint["receipt"]
            pos = r["pos"]
            strs = (r["tenant_id"], r["event_id"], r["leaf_hash"], r["sub"], pos["topic"], r["contract"])
            ints = (r["at_ms"], pos["p"], pos["o"])
            if not all(isinstance(x, str) for x in strs) or not all(is_int(x) for x in ints):
                return None
            body = ack2_body(r["tenant_id"], r["event_id"], r["leaf_hash"], r["sub"], r["at_ms"],
                             pos["topic"], pos["p"], pos["o"], r["contract"])
            if not ed25519_ok(public_key, r.get("sig"), NS_ACK2 + canon(body)):
                return None
            return dict(body, form="receipt", pos={"topic": body["topic"], "p": body["p"], "o": body["o"]})
        s = complaint["sub_record"]
        acct = s["acct"]
        strs = (s["tenant_id"], s["event_id"], acct["leaf_hash"], acct["sub"], acct["contract"])
        if not all(isinstance(x, str) for x in strs) or not is_int(acct["at_ms"]):
            return None
        body = sub_body(s["tenant_id"], s["event_id"], acct["leaf_hash"], acct["sub"], acct["at_ms"],
                        acct["contract"])
        if not ed25519_ok(public_key, acct.get("sig"), NS_SUB + canon(body)):
            return None
        return dict(body, form="sub", pos=None)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def verify_receipt_v2(receipt, public_key) -> bool:
    return isinstance(receipt, dict) and receipt.get("v") == 2 \
        and parse_complaint({"receipt": receipt}, public_key) is not None


def verify_sub_tag(tenant_id, event_id, acct, public_key) -> bool:
    """The "_acct" tag of a broker record: signed by the deployment for this tenant and event."""
    return parse_complaint({"sub_record": {"tenant_id": tenant_id, "event_id": event_id, "acct": acct}},
                           public_key) is not None


# records and anchors

def content_hash(event) -> str:
    """The leaf hash of an event's leaf data (the receipt's leaf_hash)."""
    if not depth_ok(event):
        raise ValueError("nested too deeply")
    return h_leaf(json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
                  .encode("utf-8")).hex()


def record_hash(record: dict) -> str:
    return h_leaf(canon(record)).hex()


def anchor_shape_ok(a) -> bool:
    """An anchor record as stored: only its own fields, each of its type."""
    if not isinstance(a, dict) or any(k not in ANCHOR_FIELDS for k in a) or any(k not in a for k in ANCHOR_REQUIRED):
        return False
    if not depth_ok(a):
        return False
    if not all(isinstance(a[k], str) for k in ("tenant_id", "root", "prev_hash", "record_hash")):
        return False
    if not is_int(a["n"]) or not is_num(a["ts"]):
        return False
    for k, ok in (("sig", lambda x: isinstance(x, str)), ("reached_at", is_num), ("v", is_int), ("u", is_int),
                  ("acct_from", is_int), ("seg", lambda x: isinstance(x, dict)),
                  ("pos_last", lambda x: isinstance(x, dict)), ("peaks", lambda x: isinstance(x, list)),
                  ("peaks_from", lambda x: isinstance(x, list)), ("witnesses", lambda x: isinstance(x, list))):
        if a.get(k) is not None and not ok(a[k]):
            return False
    return True


def anchor_record_hash(a: dict) -> str:
    """The record hash of an anchor record, v1 or v2 (crypto/anchor_store._record_hash)."""
    body = {"tenant_id": a["tenant_id"], "n": a["n"], "root": a["root"], "ts": a["ts"],
            "prev_hash": a["prev_hash"]}
    if a.get("witnesses"):
        body["witnesses"] = [[str(t), int(n), str(h)] for t, n, h in a["witnesses"]]
    if a.get("reached_at") is not None:
        body["reached_at"] = a["reached_at"]
    for k in ANCHOR_V2_FIELDS:
        if a.get(k) is not None:
            body[k] = a[k]
    return hashlib.sha256(_anchor_canon(body)).hexdigest()


def anchor_statement(tenant_id: str, n: int, record_hash_hex: str) -> bytes:
    return ANCHOR_NS + str(tenant_id).encode() + b"\x00" + str(int(n)).encode() + b"\x00" \
        + bytes.fromhex(record_hash_hex)


def verify_anchor(a, public_key) -> bool:
    """Well formed, its record hash recomputes, and the deployment signed it."""
    try:
        return anchor_shape_ok(a) and anchor_record_hash(a) == a["record_hash"] and ed25519_ok(
            public_key, a.get("sig"), anchor_statement(a["tenant_id"], a["n"], a["record_hash"]))
    except (KeyError, TypeError, ValueError):
        return False


# MMR

def mmr_root_hex(peaks: list) -> str:
    if not peaks:
        return ""
    acc = bytes.fromhex(peaks[-1][0])
    for h, _ in reversed(peaks[:-1]):
        acc = h_node(bytes.fromhex(h), acc)
    return acc.hex()


def mmr_extend(peaks: list, leaf_hashes_hex: list) -> Tuple[list, str]:
    stack = [(bytes.fromhex(h), int(ht)) for h, ht in (peaks or [])]
    for lh in leaf_hashes_hex:
        carry = (bytes.fromhex(lh), 0)
        while stack and stack[-1][1] == carry[1]:
            top = stack.pop()
            carry = (h_node(top[0], carry[0]), carry[1] + 1)
        stack.append(carry)
    out = [[h.hex(), ht] for h, ht in stack]
    return out, mmr_root_hex(out)


def expected_sides(index: int, size: int):
    """The left/right pattern of the MMR inclusion proof of leaf index in a log of size leaves: the
    path inside its mountain, one "right" for the smaller mountains, one "left" per larger one."""
    if not 0 <= index < size:
        return None
    heights = [h for h in range(size.bit_length() - 1, -1, -1) if size >> h & 1]
    offset = 0
    for p, h in enumerate(heights):
        if index < offset + (1 << h):
            local = index - offset
            sides = ["right" if not (local >> level) & 1 else "left" for level in range(h)]
            if p < len(heights) - 1:
                sides.append("right")
            sides.extend(["left"] * p)
            return sides
        offset += 1 << h
    return None


def mmr_inclusion_ok(leaf_hash_hex: str, index, size, proof, root_hex) -> bool:
    try:
        if not (is_int(index) and is_int(size)) or not isinstance(proof, list) or not isinstance(root_hex, str):
            return False
        sides = expected_sides(index, size)
        if sides is None:
            return False
        pr = []
        for x in proof:
            sib = hex_bytes(x[0], 32) if isinstance(x, (list, tuple)) and len(x) == 2 else None
            if sib is None:
                return False
            pr.append((sib, x[1]))
        if [s for _, s in pr] != sides:
            return False
        acc = bytes.fromhex(leaf_hash_hex)
        for sib, side in pr:
            acc = h_node(acc, sib) if side == "right" else h_node(sib, acc)
        return acc.hex() == root_hex
    except (TypeError, ValueError):
        return False


def mmr_proof(leaf_hashes_hex: List[str], index: int) -> List[list]:
    """The inclusion proof [[sibling hex, side], ...] of leaf `index` in the MMR over all
    leaf_hashes_hex (crypto/incremental_merkle.IncrementalMerkleLog.inclusion_proof)."""
    size = len(leaf_hashes_hex)
    if not 0 <= index < size:
        raise IndexError(index)
    heights = [h for h in range(size.bit_length() - 1, -1, -1) if size >> h & 1]
    leaves = [bytes.fromhex(h) for h in leaf_hashes_hex]

    def perfect_root(xs):
        while len(xs) > 1:
            xs = [h_node(xs[i], xs[i + 1]) for i in range(0, len(xs), 2)]
        return xs[0]
    peaks, offset, target, local, lo = [], 0, None, 0, 0
    for p, h in enumerate(heights):
        chunk = leaves[offset:offset + (1 << h)]
        peaks.append(perfect_root(chunk))
        if target is None and index < offset + (1 << h):
            target, local, lo = p, index - offset, offset
        offset += 1 << h
    proof: List[list] = []
    level, idx = leaves[lo:lo + (1 << heights[target])], local
    while len(level) > 1:
        proof.append([level[idx ^ 1].hex(), "right" if idx % 2 == 0 else "left"])
        level = [h_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    right = peaks[target + 1:]
    if right:
        acc = right[-1]
        for pk in reversed(right[:-1]):
            acc = h_node(pk, acc)
        proof.append([acc.hex(), "right"])
    for pk in reversed(peaks[:target]):
        proof.append([pk.hex(), "left"])
    return proof


def check_segment(anchor: dict, segment_bytes: bytes, prev_peaks: Optional[list]) -> Tuple[bool, str, list]:
    """Does this segment belong to this (verified) anchor record? Checks its SHA-256, the range
    [seg.from, n), seq = index for every record, and, given the predecessor's peaks (default: the
    record's peaks_from), that extending them by the segment gives the root."""
    seg = anchor.get("seg") or {}
    if prev_peaks is None and anchor.get("peaks_from") is not None:
        prev_peaks = anchor["peaks_from"]
    try:
        if sha256(segment_bytes).hex() != seg.get("sha256"):
            return False, "SEG_BAD: hash differs from the anchor record", []
        body = json.loads(segment_bytes)
        frm, to = int(body["from"]), int(body["to"])
        records = list(body["records"])
        if (frm, to) != (int(seg["from"]), int(seg["to"])) or to != int(anchor["n"]) \
                or len(records) != to - frm or body.get("tenant_id") != anchor["tenant_id"]:
            return False, "SEG_BAD: range or tenant differs from the anchor record", []
        for i, r in enumerate(records):
            if not isinstance(r, dict) or int(r.get("seq", -1)) != frm + i:
                return False, f"SEG_BAD: record {frm + i} has another seq", []
        if prev_peaks is not None:
            _, root = mmr_extend(prev_peaks, [record_hash(r) for r in records])
            if root != anchor["root"]:
                return False, "ROOT_BAD: the segment does not extend the predecessor to the root", []
            peaks = anchor.get("peaks")
            if peaks is not None and mmr_root_hex(peaks) != anchor["root"]:
                return False, "ROOT_BAD: the record's peaks do not give its root", []
        return True, "ok", records
    except (KeyError, TypeError, ValueError) as e:
        return False, f"SEG_BAD: {type(e).__name__}", []


# aggregate and statements

def agg_leaf(salt: str, tenant_id: str, n: int, rh: str, pos_last, u: int, st=None, late=None) -> bytes:
    """A tenant's aggregate leaf; st and late enter the body only when given (agg alg v2)."""
    body = {"salt": str(salt), "tenant_id": str(tenant_id), "n": int(n), "rh": str(rh),
            "pos_last": pos_last, "u": int(u)}
    if st is not None:
        body["st"] = str(st)
    if late is not None:
        body["late"] = int(late)
    return h_leaf(NS_AGG + canon(body))


def verify_agg_opening(opening: Any, root_hex, size) -> bool:
    """Does the opening {j, tenant_id, salt, n, rh, pos_last, u, [st, late], index, size, path}
    lead to root_hex in a tree of size leaves? Types are checked strictly."""
    try:
        if not isinstance(opening, dict) or not isinstance(root_hex, str) or not is_int(size):
            return False
        o = opening
        if not is_int(o.get("size")) or o["size"] != size or size <= 0 or size & (size - 1):
            return False
        i, n, u = o.get("index"), o.get("n"), o.get("u")
        if not (is_int(i) and is_int(n) and is_int(u)) or not 0 <= i < size:
            return False
        if not all(isinstance(o.get(k), str) for k in ("salt", "tenant_id", "rh")):
            return False
        st, late = o.get("st"), o.get("late")
        if st is not None and st not in TENANT_STATES or late is not None and (not is_int(late) or late < 0):
            return False
        path = o.get("path")
        if not isinstance(path, list) or (1 << len(path)) != size:
            return False
        acc = agg_leaf(o["salt"], o["tenant_id"], n, o["rh"], o.get("pos_last"), u, st, late)
        for sib_hex in path:
            sib = hex_bytes(sib_hex, 32)
            if sib is None:
                return False
            acc = h_node(acc, sib) if i % 2 == 0 else h_node(sib, acc)
            i //= 2
        return acc.hex() == root_hex
    except (KeyError, TypeError, ValueError):
        return False


def stmt_message(body: dict) -> bytes:
    """The 32-byte public-log message of a statement: SHA-256(NS_STMT || canon(body))."""
    return sha256(NS_STMT + canon(body))


def verify_statement(signed_stmt, public_key) -> bool:
    """A stored statement {"body", "sig"}: Ed25519 over NS_STMT || canon(body)."""
    try:
        return isinstance(signed_stmt, dict) and isinstance(signed_stmt.get("body"), dict) and \
            ed25519_ok(public_key, signed_stmt.get("sig"), NS_STMT + canon(signed_stmt["body"]))
    except (KeyError, TypeError, ValueError):
        return False


def contract_hash(body: dict) -> str:
    """What receipts and tags carry as "contract": SHA-256 of the canonical contract body."""
    return sha256(canon(body)).hex()


def same_key(a, b) -> bool:
    """Two hex public keys name the same key (hex case does not matter)."""
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()
