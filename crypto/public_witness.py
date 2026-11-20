from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LEAF_NAMESPACE = b"sigsum.org/v1/tree-leaf\x00"
TREE_PREFIX = "sigsum.org/v1/tree/"
COSIG_PREFIX = "cosignature/v1\n"


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def key_hash(public_key_raw: bytes) -> bytes:
    return sha256(public_key_raw)


def leaf_signed_data(checksum: bytes) -> bytes:
    return LEAF_NAMESPACE + checksum


def tree_leaf(checksum: bytes, signature: bytes, kh: bytes) -> bytes:
    assert len(checksum) == 32 and len(signature) == 64 and len(kh) == 32
    return checksum + signature + kh


def leaf_hash(leaf: bytes) -> bytes:
    return sha256(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def tree_head_note(log_key_hash: bytes, size: int, root: bytes) -> bytes:
    return (TREE_PREFIX + log_key_hash.hex() + "\n" + str(size) + "\n"
            + base64.b64encode(root).decode() + "\n").encode()


def cosignature_note(timestamp: int, log_key_hash: bytes, size: int, root: bytes) -> bytes:
    return COSIG_PREFIX.encode() + f"time {timestamp}\n".encode() + tree_head_note(log_key_hash, size, root)


def verify_inclusion(lh: bytes, leaf_index: int, tree_size: int, path: List[bytes], root: bytes) -> bool:
    """RFC 6962 / RFC 9162 section 2.1.3.2 inclusion check."""
    if tree_size < 1 or leaf_index >= tree_size:
        return False
    if tree_size == 1:
        return not path and lh == root
    fn, sn, r = leaf_index, tree_size - 1, lh
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if fn & 1 == 0:                       # RFC 9162 2.1.3.2 step 4.b.ii
                while fn & 1 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def frontier_from_path(last_leaf_hash: bytes, size: int, path: List[bytes]) -> List[bytes]:
    """The frontier of a tree of `size` leaves from the inclusion proof of its last leaf: the path's
    siblings are the perfect subtrees covering [0, size - 1), smallest first."""
    heights = [h for h in range(size.bit_length() - 1, -1, -1) if (size - 1) >> h & 1]
    if len(heights) != len(path):
        raise ValueError("the path does not match a last leaf")
    stack: List[Tuple[bytes, int]] = list(zip(reversed(path), heights))
    carry = (last_leaf_hash, 0)
    while stack and stack[-1][1] == carry[1]:
        top = stack.pop()
        carry = (node_hash(top[0], carry[0]), carry[1] + 1)
    stack.append(carry)
    return [h for h, _ in stack]


def _verify(pub_raw: bytes, sig: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class TreeHead:
    size: int
    root_hash: str                      # hex
    signature: str                      # hex
    cosignatures: List[List[str]] = field(default_factory=list)   # [key_hash hex, timestamp, sig hex]

    @staticmethod
    def parse(text: str) -> "TreeHead":
        kv = _parse_kv(text)
        cos = [c.split(" ") for c in kv.get("cosignature", [])]
        return TreeHead(int(kv["size"][0]), kv["root_hash"][0], kv["signature"][0], cos)


def tree_head_json(th: TreeHead) -> Dict[str, Any]:
    return asdict(th)


@dataclass
class WitnessReceipt:
    """Everything a third party needs to verify, offline, that `message` was in a witnessed log."""
    log_url: str
    log_key_hash: str                   # hex
    message: str                        # hex, 32 bytes
    checksum: str                       # hex
    signature: str                      # hex, over the leaf namespace + checksum
    public_key: str                     # hex, submitter's Ed25519 key
    key_hash: str                       # hex
    leaf_index: int
    tree_head: TreeHead
    inclusion_path: List[str]           # hex node hashes
    submitted_at: float
    included_at: float
    latency_ms: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "WitnessReceipt":
        d = json.loads(s)
        d["tree_head"] = TreeHead(**d["tree_head"])
        return WitnessReceipt(**d)


def _parse_kv(text: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


@dataclass
class WitnessPolicy:
    """Which logs and witnesses are trusted, and which combination of witnesses must cosign. The
    text format is Sigsum's trust policy: lines "log <key> [url]", "witness <name> <key> [url]",
    "group <name> <threshold|all|any> <member>...", "quorum <name|none>"; '#' starts a comment."""
    logs: Dict[str, bytes] = field(default_factory=dict)          # key hash hex -> public key
    witnesses: Dict[str, bytes] = field(default_factory=dict)     # name -> public key
    groups: Dict[str, Tuple[int, List[str]]] = field(default_factory=dict)
    quorum: Optional[str] = None                                  # None means "none"

    @staticmethod
    def parse(text: str) -> "WitnessPolicy":
        p = WitnessPolicy()
        have_quorum = False
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            kind = parts[0]
            if kind == "log" and len(parts) >= 2:
                key = bytes.fromhex(parts[1])
                p.logs[key_hash(key).hex()] = key
            elif kind == "witness" and len(parts) >= 3:
                name = parts[1]
                if name in p.witnesses or name in p.groups:
                    raise ValueError(f"duplicate name {name!r} in witness policy")
                p.witnesses[name] = bytes.fromhex(parts[2])
            elif kind == "group" and len(parts) >= 4:
                name, thr, members = parts[1], parts[2], parts[3:]
                if name in p.witnesses or name in p.groups:
                    raise ValueError(f"duplicate name {name!r} in witness policy")
                for m in members:
                    if m not in p.witnesses and m not in p.groups:
                        raise ValueError(f"group {name!r} names unknown member {m!r}")
                k = len(members) if thr == "all" else 1 if thr == "any" else int(thr)
                if not 1 <= k <= len(members):
                    raise ValueError(f"group {name!r} threshold {thr!r} out of range")
                p.groups[name] = (k, list(members))
            elif kind == "quorum" and len(parts) == 2:
                if have_quorum:
                    raise ValueError("more than one quorum line in witness policy")
                have_quorum = True
                q = parts[1]
                if q != "none" and q not in p.witnesses and q not in p.groups:
                    raise ValueError(f"quorum names unknown {q!r}")
                p.quorum = None if q == "none" else q
            else:
                raise ValueError(f"cannot parse witness policy line: {raw!r}")
        if not have_quorum:
            raise ValueError("witness policy has no quorum line")
        return p

    def witness_names_by_key_hash(self) -> Dict[str, str]:
        return {key_hash(k).hex(): name for name, k in self.witnesses.items()}

    def satisfied(self, names) -> bool:
        """Does this set of witnesses (whose cosignatures verified) meet the quorum?"""
        names = set(names)

        def ok(name):
            if name in self.witnesses:
                return name in names
            k, members = self.groups[name]
            return sum(1 for m in members if ok(m)) >= k
        return True if self.quorum is None else ok(self.quorum)


def load_policy(value: Optional[str]) -> Optional[WitnessPolicy]:
    """A policy from settings: a path to a Sigsum policy file, or the policy text itself."""
    if not value:
        return None
    text = open(value, encoding="utf-8").read() if os.path.isfile(value) else value
    return WitnessPolicy.parse(text)


def verify_tree_head(th: TreeHead, log_key_hash: bytes, log_public_key: Optional[bytes],
                     policy: Optional[WitnessPolicy]) -> Dict[str, Any]:
    """The log's signature on a tree head and the witness cosignatures against the policy."""
    root = bytes.fromhex(th.root_hash)
    out: Dict[str, Any] = {
        "log_signature_ok": None,
        "cosignatures": len(th.cosignatures),
        "cosignatures_verified": 0,
        "cosignatures_bad": 0,
        "cosignatures_unknown_key": 0,
        "witness_policy": "configured" if policy is not None else "missing",
        "quorum_ok": False,
    }
    if log_public_key is None and policy is not None:
        log_public_key = policy.logs.get(log_key_hash.hex())
    if log_public_key is not None:
        out["log_key_hash_ok"] = key_hash(log_public_key) == log_key_hash
        out["log_signature_ok"] = bool(out["log_key_hash_ok"]) and _verify(
            log_public_key, bytes.fromhex(th.signature), tree_head_note(log_key_hash, th.size, root))
    names = policy.witness_names_by_key_hash() if policy is not None else {}
    good = set()
    for wkh, ts, wsig in th.cosignatures:
        name = names.get(wkh)
        if name is None:
            out["cosignatures_unknown_key"] += 1
            continue
        try:
            ok = _verify(policy.witnesses[name], bytes.fromhex(wsig),
                         cosignature_note(int(ts), log_key_hash, th.size, root))
        except ValueError:
            ok = False
        if ok:
            good.add(name)
            out["cosignatures_verified"] += 1
        else:
            out["cosignatures_bad"] += 1
    out["quorum_ok"] = policy is not None and policy.satisfied(good)
    out["head_verified"] = bool(out["log_signature_ok"] is True and out["cosignatures_bad"] == 0
                                and out["quorum_ok"])
    return out


class SigsumClient:
    """Submit 32-byte messages to a Sigsum log and fetch witnessed inclusion receipts (synchronous).
    ``token`` is the sigsum-token header value for rate-limited logs."""

    def __init__(self, base_url: str, private_key: Ed25519PrivateKey,
                 log_public_key: Optional[bytes] = None, token: Optional[str] = None,
                 timeout_s: float = 20.0, max_wait_s: float = 120.0, transport=None,
                 policy: Optional[WitnessPolicy] = None):
        import httpx
        self.base_url = base_url.rstrip("/")
        self._key = private_key
        self.public_key = private_key.public_key().public_bytes_raw()
        self.key_hash = key_hash(self.public_key)
        if log_public_key is None and policy is not None and len(policy.logs) == 1:
            log_public_key = next(iter(policy.logs.values()))
        self.log_public_key = log_public_key
        self.policy = policy
        self.log_key_hash = key_hash(log_public_key) if log_public_key else None
        self.token = token
        self.max_wait_s = max_wait_s
        self._http = httpx.Client(timeout=timeout_s, transport=transport)

    def sign_message(self, message: bytes) -> Tuple[bytes, bytes]:
        checksum = sha256(message)
        return checksum, self._key.sign(leaf_signed_data(checksum))

    def add_leaf(self, message: bytes) -> int:
        """One add-leaf request; returns the HTTP status (200 committed, 202 accepted)."""
        checksum, sig = self.sign_message(message)
        body = f"message={message.hex()}\nsignature={sig.hex()}\npublic_key={self.public_key.hex()}\n"
        headers = {"sigsum-token": self.token} if self.token else {}
        resp = self._http.post(self.base_url + "/add-leaf", content=body.encode(), headers=headers)
        if resp.status_code not in (200, 202):
            raise RuntimeError(f"add-leaf {resp.status_code}: {resp.text[:200]}")
        return resp.status_code

    def get_tree_head(self) -> TreeHead:
        resp = self._http.get(self.base_url + "/get-tree-head")
        resp.raise_for_status()
        return TreeHead.parse(resp.text)

    def get_inclusion_proof(self, size: int, lh: bytes) -> Optional[Tuple[int, List[bytes]]]:
        resp = self._http.get(f"{self.base_url}/get-inclusion-proof/{size}/{lh.hex()}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        kv = _parse_kv(resp.text)
        return int(kv["leaf_index"][0]), [bytes.fromhex(h) for h in kv.get("node_hash", [])]

    def get_leaves(self, start: int, end: int) -> List[Tuple[bytes, bytes, bytes]]:
        """Leaves [start, end) as (checksum, signature, key_hash). The log may return fewer."""
        resp = self._http.get(f"{self.base_url}/get-leaves/{start}/{end}")
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        out = []
        for line in _parse_kv(resp.text).get("leaf", []):
            c, s, k = line.split(" ")
            out.append((bytes.fromhex(c), bytes.fromhex(s), bytes.fromhex(k)))
        return out

    def check_head(self, th: TreeHead) -> Dict[str, Any]:
        return verify_tree_head(th, self.log_key_hash or b"", self.log_public_key, self.policy)

    def witness(self, message: bytes) -> WitnessReceipt:
        """Submit until committed, wait for a tree head that includes the leaf (and, with a policy,
        carries a witness quorum), verify the proof and return the receipt. Raises after max_wait_s."""
        t0 = time.time()
        checksum, sig = self.sign_message(message)
        lh = leaf_hash(tree_leaf(checksum, sig, self.key_hash))
        self.submit(message)
        delay = 0.5
        while True:
            th = self.get_tree_head()
            proof = self._proof(th, lh)
            if proof is not None:
                if self.log_public_key is None and self.policy is None:
                    break
                head = self.check_head(th)
                if head["log_signature_ok"] is False or head["cosignatures_bad"]:
                    raise RuntimeError(f"tree head of size {th.size} fails verification: {head}")
                if self.policy is None or head["quorum_ok"]:
                    break
            if time.time() - t0 > self.max_wait_s:
                raise TimeoutError("no tree head that includes the leaf and satisfies the witness "
                                   "policy in time")
            time.sleep(delay)
            delay = min(delay * 2, 5.0)
        return self._receipt(message, checksum, sig, th, proof, t0, time.time())

    def receipt_if_included(self, message: bytes) -> Optional[WitnessReceipt]:
        """The receipt of `message` from the current tree head, without submitting it, when the log
        already includes our leaf under a head that verifies; otherwise None."""
        t0 = time.time()
        checksum, sig = self.sign_message(message)
        lh = leaf_hash(tree_leaf(checksum, sig, self.key_hash))
        th = self.get_tree_head()
        proof = self._proof(th, lh)
        if proof is None:
            return None
        if self.log_public_key is not None or self.policy is not None:
            head = self.check_head(th)
            if head["log_signature_ok"] is False or head["cosignatures_bad"] or \
                    (self.policy is not None and not head["quorum_ok"]):
                return None
        return self._receipt(message, checksum, sig, th, proof, t0, t0)

    def _proof(self, th: TreeHead, lh: bytes) -> Optional[Tuple[int, List[bytes]]]:
        """(leaf index, path) of leaf hash lh under th when it verifies, else None."""
        root = bytes.fromhex(th.root_hash)
        if th.size == 1:
            proof: Optional[Tuple[int, List[bytes]]] = (0, []) if lh == root else None
        else:
            proof = self.get_inclusion_proof(th.size, lh) if th.size >= 2 else None
        if proof is None or not verify_inclusion(lh, proof[0], th.size, proof[1], root):
            return None
        return proof

    def _receipt(self, message: bytes, checksum: bytes, sig: bytes, th: TreeHead,
                 proof: Tuple[int, List[bytes]], t0: float, t1: float) -> WitnessReceipt:
        return WitnessReceipt(
            log_url=self.base_url, log_key_hash=self.log_key_hash.hex() if self.log_key_hash else "",
            message=message.hex(), checksum=checksum.hex(), signature=sig.hex(),
            public_key=self.public_key.hex(), key_hash=self.key_hash.hex(), leaf_index=proof[0],
            tree_head=th, inclusion_path=[h.hex() for h in proof[1]], submitted_at=t0, included_at=t1,
            latency_ms=round((t1 - t0) * 1000.0, 1))

    def submit(self, message: bytes, max_wait_s: Optional[float] = None) -> float:
        """Submit until the log commits to publishing (200), without waiting for inclusion; returns
        the time of the committing request."""
        t0 = time.time()
        limit = self.max_wait_s if max_wait_s is None else max_wait_s
        delay = 0.5
        while self.add_leaf(message) != 200:
            if time.time() - t0 > limit:
                raise TimeoutError("add-leaf not committed in time")
            time.sleep(delay)
            delay = min(delay * 2, 5.0)
        return time.time()

    def leaves_range(self, start: int, end: int, page: int = 512) -> List[Dict[str, Any]]:
        """Every leaf in [start, end), of every submitter, as {index, checksum, signature, key_hash}.
        Raises if the log returns fewer."""
        out: List[Dict[str, Any]] = []
        i = start
        while i < end:
            chunk = self.get_leaves(i, min(i + page, end))
            if not chunk:
                raise RuntimeError(f"log returned no leaves at {i} of [{start}, {end})")
            for c, s, k in chunk:
                out.append({"index": i, "checksum": c.hex(), "signature": s.hex(), "key_hash": k.hex()})
                i += 1
        return out

    def frontier(self, size: int) -> List[str]:
        """The roots of the perfect subtrees covering leaves [0, size), largest first (hex)."""
        if size <= 0:
            return []
        last = self.get_leaves(size - 1, size)
        if not last:
            raise RuntimeError(f"log returned no leaf at {size - 1}")
        lh = leaf_hash(tree_leaf(*last[0]))
        if size == 1:
            return [lh.hex()]
        proof = self.get_inclusion_proof(size, lh)
        if proof is None or proof[0] != size - 1:
            raise RuntimeError(f"no inclusion proof for the last leaf of a tree of size {size}")
        return [h.hex() for h in frontier_from_path(lh, size, proof[1])]

    def leaves_by_key(self, start: int, end: Optional[int] = None, page: int = 512) -> List[Tuple[int, bytes]]:
        """(leaf index, checksum) of every leaf in [start, end) signed with this client's key."""
        end = end if end is not None else self.get_tree_head().size
        out: List[Tuple[int, bytes]] = []
        i = start
        while i < end:
            chunk = self.get_leaves(i, min(i + page, end))
            if not chunk:
                break
            for j, (c, _s, kh) in enumerate(chunk):
                if kh == self.key_hash:
                    out.append((i + j, c))
            i += len(chunk)
        return out


__all__ = ["SigsumClient", "WitnessReceipt", "TreeHead", "WitnessPolicy", "load_policy",
           "verify_tree_head", "verify_inclusion", "leaf_hash", "tree_leaf", "key_hash", "leaf_signed_data",
           "tree_head_note", "cosignature_note", "node_hash", "sha256", "frontier_from_path",
           "tree_head_json"]
