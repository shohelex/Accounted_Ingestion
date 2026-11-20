#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys

ANCHOR_NS = b"acct/anchor/v1\x00"
ACK_NS = b"acct/ack/v1\x00"
ACK2_NS = b"acct/ack/v2\x00"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def h_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def h_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def fold(leaf_hash: bytes, proof) -> bytes:
    running = leaf_hash
    for sibling_hex, side in proof:
        sibling = bytes.fromhex(sibling_hex)
        if side == "right":
            running = h_node(running, sibling)
        elif side == "left":
            running = h_node(sibling, running)
        else:
            raise ValueError(f"invalid side {side!r}")
    return running


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


def record_hash(a: dict) -> str:
    body = {"tenant_id": a["tenant_id"], "n": a["n"], "root": a["root"],
            "ts": a["ts"], "prev_hash": a["prev_hash"]}
    if a.get("witnesses"):
        body["witnesses"] = [[str(t), int(n), str(h)] for t, n, h in a["witnesses"]]
    if a.get("reached_at") is not None:
        body["reached_at"] = a["reached_at"]
    # v2 fields are committed only when present.
    for k in ("v", "peaks", "seg", "pos_last", "u", "acct_from", "peaks_from"):
        if a.get(k) is not None:
            body[k] = a[k]
    return hashlib.sha256(canonical(body)).hexdigest()


def ed25519_ok(public_key, sig, data: bytes) -> bool:
    """public_key and sig as hex strings or raw bytes."""
    if not sig or not public_key:
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pk = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
        sg = bytes.fromhex(sig) if isinstance(sig, str) else sig
        Ed25519PublicKey.from_public_bytes(pk).verify(sg, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def anchor_statement(tenant_id: str, n: int, record_hash_hex: str) -> bytes:
    return ANCHOR_NS + str(tenant_id).encode() + b"\x00" + str(int(n)).encode() + b"\x00" \
        + bytes.fromhex(record_hash_hex)


def ack_statement(tenant_id: str, event_id: str, leaf_hash_hex: str, accepted_at: str) -> bytes:
    return ACK_NS + str(tenant_id).encode() + b"\x00" + str(event_id).encode() + b"\x00" \
        + bytes.fromhex(leaf_hash_hex) + b"\x00" + str(accepted_at).encode()


def verify_ack(ack: dict, public_key_hex: str) -> bool:
    """A v1 acknowledgement, or a receipt v2 (accounted mode: signed over the broker position)."""
    if ack.get("v") == 2:
        try:
            pos = ack["pos"]
            body = {"tenant_id": str(ack["tenant_id"]), "event_id": str(ack["event_id"]),
                    "leaf_hash": str(ack["leaf_hash"]), "sub": str(ack["sub"]), "at_ms": int(ack["at_ms"]),
                    "topic": str(pos["topic"]), "p": int(pos["p"]), "o": int(pos["o"]),
                    "contract": str(ack["contract"])}
        except (KeyError, TypeError, ValueError):
            return False
        return ed25519_ok(public_key_hex, ack.get("sig"), ACK2_NS + canonical(body))
    return ed25519_ok(public_key_hex, ack.get("sig"),
                      ack_statement(ack["tenant_id"], ack["event_id"], ack["leaf_hash"], ack["accepted_at"]))


def verify_bundle(bundle: dict, public_key_hex: str = None, ack: dict = None,
                  insecure_self_key: bool = False) -> dict:
    """Every check by name; "verified" is True only if all that apply pass, and never without a
    pinned key unless insecure_self_key."""
    leaf, anchor = bundle["leaf"], bundle["anchor"]
    key = public_key_hex or (bundle.get("public_key") if insecure_self_key else None)
    data = json.loads(leaf["data"])
    lh = h_leaf(canonical(data))
    # An accounting record (v2) carries the event's leaf data under "event": the receipt names that
    # data's hash, the log's leaf is the record's. A verdict record is not the event's inclusion.
    v2 = data.get("v") == 2 and data.get("kind") in ("event", "verdict")
    kind = data.get("kind") if v2 else "event"
    if not v2:
        event = data
    else:
        event = data.get("event") if isinstance(data.get("event"), dict) else {}
    content = h_leaf(canonical(event)).hex()
    index, size = int(leaf["index"]), int(bundle["mmr_size"])
    sides = expected_sides(index, size)
    out = {
        "leaf_hash_matches_data": lh.hex() == leaf["hash"],
        "event_record": kind == "event",
        "event_id_matches": event.get("event_id") == bundle["event_id"],
        "index_in_range": 0 <= index < size == int(anchor["n"]),
        "index_matches_proof": sides is not None and [s for _, s in bundle["proof"]] == sides,
        "tenant_matches": anchor["tenant_id"] == bundle["tenant_id"],
        "inclusion": fold(lh, bundle["proof"]).hex() == anchor["root"],
        "record_hash": record_hash(anchor) == anchor["record_hash"],
        "signature": ed25519_ok(key, anchor.get("sig"),
                                anchor_statement(anchor["tenant_id"], anchor["n"], anchor["record_hash"]))
        if key else None,
        "key_pinned": public_key_hex is not None,
    }
    if ack is not None:
        out["ack_signature"] = verify_ack(ack, key) if key else None
        same = (ack.get("event_id") == bundle["event_id"] and ack.get("tenant_id") == bundle["tenant_id"])
        if ack.get("v") == 2:
            # the record must be the one at the receipt's broker position, with its submission tag
            pos = ack.get("pos") or {}
            rpos = (data.get("pos") or {}) if v2 else {}
            same = same and v2 and ack.get("leaf_hash") == content \
                and (rpos.get("topic"), rpos.get("p"), rpos.get("o")) == (pos.get("topic"), pos.get("p"), pos.get("o")) \
                and (data.get("sub") or {}).get("sub") == ack.get("sub")
        else:
            same = same and ack.get("leaf_hash") in (leaf["hash"], content) \
                and (not v2 or ack.get("leaf_hash") == content)
        out["ack_matches_bundle"] = bool(same)
    checks = {k: v for k, v in out.items() if k != "key_pinned"}
    out["verified"] = all(v is True for v in checks.values()) and (out["key_pinned"] or insecure_self_key)
    out["record_kind"] = kind
    if kind == "verdict":
        out["verdict_type"] = (data.get("verdict") or {}).get("type")
    if bundle.get("duplicate_leaf_indexes"):
        out["duplicate_leaf_indexes"] = list(bundle["duplicate_leaf_indexes"])
    if insecure_self_key and not out["key_pinned"]:
        out["warning"] = "signature checked against the key inside the bundle (--insecure-self-key)"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", help="proof bundle (JSON)")
    ap.add_argument("--key", help="deployment public key (hex), from a channel you trust")
    ap.add_argument("--insecure-self-key", action="store_true",
                    help="without --key, check against the key inside the bundle (proves nothing "
                         "about who signed it)")
    ap.add_argument("--ack", help="the signed acknowledgement returned with HTTP 200 (JSON file)")
    a = ap.parse_args()
    with open(a.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    bundle = bundle.get("bundle", bundle)
    ack = None
    if a.ack:
        with open(a.ack, encoding="utf-8") as f:
            ack = json.load(f)
        ack = ack.get("receipt", ack)
    result = verify_bundle(bundle, a.key, ack, insecure_self_key=a.insecure_self_key)
    print(json.dumps(result, indent=1))
    if not result["key_pinned"]:
        print("error: no --key given; nothing is verified without a pinned deployment key"
              if not a.insecure_self_key else
              "warning: signature checked against the key inside the bundle (--insecure-self-key)",
              file=sys.stderr)
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
