#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import bisect
import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from acct_common import (canon, content_hash, contract_hash, ed25519_ok, h_leaf, h_node,  # noqa: E402
                         hex_bytes, is_int, mmr_inclusion_ok, parse_complaint, record_hash, same_key,
                         sha256, stmt_message, verify_anchor, verify_statement)
from acct_common import verify_agg_opening as verify_opening  # noqa: E402
import check_verdict as CV  # noqa: E402

TREE_PREFIX = "sigsum.org/v1/tree/"
COSIG_PREFIX = "cosignature/v1\n"
GENESIS_PREV = "0" * 64
AGG_ALG_ST = "acct/agg/v2"


def _items(src) -> List[Any]:
    """The statements in a bodies map {"<j>": stmt | [stmt]} or list."""
    out: List[Any] = []
    vals = src.values() if isinstance(src, dict) else src if isinstance(src, list) else []
    for v in vals:
        out.extend(v if isinstance(v, list) else [v])
    return out


def _dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _list(x) -> list:
    return x if isinstance(x, list) else []


# contract

def period_ms(c: dict) -> int:
    return int(c["period_s"]) * 1000


def period_end_ms(j: int, c: dict) -> int:
    return int(c["t0_ms"]) + (int(j) + 1) * period_ms(c)


def deadline_ms(j: int, c: dict) -> int:
    return period_end_ms(j, c) + int(c["delta_pub_s"]) * 1000


def first_due_period(a_ms: int, c: dict) -> int:
    """The first period ending at or after the submission time plus theta (and not before the
    contract took effect)."""
    x = int(a_ms) + int(c["theta_s"]) * 1000 - int(c["t0_ms"])
    j0 = -(-x // period_ms(c)) - 1
    return max(j0, int(c.get("effective_j", 0) or 0), 0)


def _contract_ok(cb) -> bool:
    """The contract fields the judge computes with have the right types."""
    if not isinstance(cb, dict) or cb.get("kind") != "contract" or not isinstance(cb.get("dep"), str):
        return False
    for k in ("t0_ms", "period_s", "delta_pub_s", "theta_s", "delta_s", "stall_budget", "window_periods",
              "unchk_budget"):
        if not is_int(cb.get(k)):
            return False
    e = cb.get("effective_j", 0)
    return (e is None or is_int(e)) and cb["period_s"] > 0 and isinstance(cb.get("broker"), dict)


# the tenant's partition

murmur2 = CV._murmur2  # Kafka's key hash


def partition_of(c: dict, tenant_id) -> Optional[int]:
    """The tenant's partition from the contract: broker.partitioner (murmur2 or crc32) over the
    frozen partition count."""
    b = c.get("broker")
    if not isinstance(b, dict) or not isinstance(tenant_id, str) or b.get("kind", "kafka") != "kafka":
        return None
    route = {"fn": b.get("partitioner", "murmur2"), "n": b.get("partitions")}
    return CV.partition_of(tenant_id.encode("utf-8"), route)


def _tp(pos) -> Optional[str]:
    if not isinstance(pos, dict) or not isinstance(pos.get("topic"), str) or not is_int(pos.get("p")):
        return None
    return f"{pos['topic']}/{pos['p']}"


def mmr_proof_ok(record, index, n, proof, root_hex) -> bool:
    try:
        return mmr_inclusion_ok(record_hash(record), index, n, proof, root_hex)
    except (TypeError, ValueError):
        return False


def segment_hash(seg: dict) -> str:
    return sha256(canon(seg)).hex()


def _seg(a: dict) -> Optional[dict]:
    """The anchor's segment descriptor, when well formed."""
    s = a.get("seg")
    if isinstance(s, dict) and is_int(s.get("from")) and is_int(s.get("to")) and isinstance(s.get("sha256"), str):
        return s
    return None


# the public-log view

def parse_policy(text: str) -> dict:
    """Sigsum trust policy: log, witness, group and quorum lines."""
    pol = {"logs": {}, "witnesses": {}, "groups": {}, "quorum": None}
    have_quorum = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "log" and len(parts) >= 2:
            key = bytes.fromhex(parts[1])
            pol["logs"][sha256(key).hex()] = key
        elif parts[0] == "witness" and len(parts) >= 3:
            if parts[1] in pol["witnesses"] or parts[1] in pol["groups"]:
                raise ValueError(f"duplicate name {parts[1]!r}")
            pol["witnesses"][parts[1]] = bytes.fromhex(parts[2])
        elif parts[0] == "group" and len(parts) >= 4:
            name, thr, members = parts[1], parts[2], parts[3:]
            if name in pol["witnesses"] or name in pol["groups"]:
                raise ValueError(f"duplicate name {name!r}")
            for m in members:
                if m not in pol["witnesses"] and m not in pol["groups"]:
                    raise ValueError(f"unknown member {m!r}")
            k = len(members) if thr == "all" else 1 if thr == "any" else int(thr)
            if not 1 <= k <= len(members):
                raise ValueError(f"threshold {thr!r} out of range")
            pol["groups"][name] = (k, members)
        elif parts[0] == "quorum" and len(parts) == 2:
            if have_quorum:
                raise ValueError("two quorum lines")
            have_quorum = True
            q = parts[1]
            if q != "none" and q not in pol["witnesses"] and q not in pol["groups"]:
                raise ValueError(f"quorum names unknown {q!r}")
            pol["quorum"] = None if q == "none" else q
        else:
            raise ValueError(f"cannot parse policy line {raw!r}")
    if not have_quorum:
        raise ValueError("no quorum line")
    return pol


def _quorum(pol: dict, good) -> bool:
    # parse_policy admits only members defined earlier, so groups do not nest cyclically.
    def ok(name):
        if name in pol["witnesses"]:
            return name in good
        k, members = pol["groups"][name]
        return sum(1 for m in members if ok(m)) >= k
    return pol["quorum"] is not None and ok(pol["quorum"])


def tree_head_note(lkh: bytes, size: int, root: bytes) -> bytes:
    return (TREE_PREFIX + lkh.hex() + "\n" + str(size) + "\n"
            + base64.b64encode(root).decode() + "\n").encode()


def _cosig_ts(x) -> Optional[int]:
    """A cosignature's time: an integer, or its decimal string (the Sigsum ASCII form)."""
    if is_int(x):
        return x
    if isinstance(x, str) and x.isdigit() and x.isascii():
        return int(x)
    return None


def head_quorum_time_ms(head, lkh: bytes, log_key: bytes, pol: dict) -> Optional[int]:
    """When a witness quorum had cosigned this head (ms), or None if the head is malformed, the
    log's signature fails, or no quorum cosigned it (always under quorum none)."""
    if not isinstance(head, dict) or not is_int(head.get("size")) or head["size"] < 0:
        return None
    root = hex_bytes(head.get("root_hash"), 32)
    if root is None or not ed25519_ok(log_key, head.get("signature"), tree_head_note(lkh, head["size"], root)):
        return None
    names = {sha256(k).hex(): name for name, k in pol["witnesses"].items()}
    good: List[Tuple[int, str]] = []
    for cs in _list(head.get("cosignatures")):
        if not isinstance(cs, (list, tuple)) or len(cs) != 3:
            continue
        wkh, ts, wsig = cs
        ts = _cosig_ts(ts)
        name = names.get(wkh) if isinstance(wkh, str) else None
        if name is None or ts is None:
            continue
        note = COSIG_PREFIX.encode() + f"time {ts}\n".encode() + tree_head_note(lkh, head["size"], root)
        if ed25519_ok(pol["witnesses"][name], wsig, note):
            good.append((ts, name))
    good.sort()
    have = set()
    for ts, name in good:
        have.add(name)
        if _quorum(pol, have):
            return ts * 1000
    return None


def _frontier_map(size: int, nodes: List[str]) -> Dict[Tuple[int, int], bytes]:
    heights = [h for h in range(size.bit_length() - 1, -1, -1) if size >> h & 1]
    if not isinstance(nodes, list) or len(heights) != len(nodes):
        raise ValueError("the frontier has one node per set bit of its size")
    out, off = {}, 0
    for h, node in zip(heights, nodes):
        b = hex_bytes(node, 32)
        if b is None:
            raise ValueError("frontier node is not 32 bytes of hex")
        out[(off, 1 << h)] = b
        off += 1 << h
    return out


def tree_root(frontier_size: int, fmap: Dict[Tuple[int, int], bytes], leaf_hashes: List[bytes],
              size: int) -> bytes:
    """RFC 6962 root of the first `size` leaves, from the frontier at frontier_size and the leaf
    hashes from there on. Raises ValueError when the data do not determine it."""
    def mth(lo: int, hi: int) -> bytes:
        n = hi - lo
        if (lo, n) in fmap:
            return fmap[(lo, n)]
        if hi <= frontier_size and n & (n - 1) == 0:
            raise ValueError("a perfect subtree left of the frontier is not a frontier node")
        if n == 1:
            return leaf_hashes[lo - frontier_size]
        k = 1
        while k * 2 < n:
            k *= 2
        return h_node(mth(lo, lo + k), mth(lo + k, hi))
    if size < frontier_size or size - frontier_size > len(leaf_hashes) or size < 1:
        raise ValueError("head size outside the view")
    return mth(0, size)


def frontier_nodes(frontier_size: int, fmap, leaf_hashes: List[bytes], size: int) -> List[bytes]:
    """The frontier at `size` (largest subtree first), from the frontier at frontier_size and the
    leaves from there on."""
    out, off = [], 0
    for h in [h for h in range(size.bit_length() - 1, -1, -1) if size >> h & 1]:
        out.append(_subtree(frontier_size, fmap, leaf_hashes, off, 1 << h))
        off += 1 << h
    return out


def _subtree(frontier_size, fmap, leaf_hashes, lo, n) -> bytes:
    """The root of the perfect subtree [lo, lo + n)."""
    def mth(a: int, b: int) -> bytes:
        m = b - a
        if (a, m) in fmap:
            return fmap[(a, m)]
        if b <= frontier_size:
            raise ValueError("a perfect subtree left of the frontier is not a frontier node")
        if m == 1:
            return leaf_hashes[a - frontier_size]
        return h_node(mth(a, a + m // 2), mth(a + m // 2, b))
    return mth(lo, lo + n)


def _leaves(raw, start: int) -> Optional[List[Tuple[int, str, str, bytes]]]:
    """[(index, checksum hex, key_hash hex, leaf hash)] of leaves contiguous from start, or None."""
    if not isinstance(raw, list):
        return None
    out = []
    for k, lf in enumerate(raw):
        if not isinstance(lf, dict) or not is_int(lf.get("index")) or lf["index"] != start + k:
            return None
        ck, sg, kh = (hex_bytes(lf.get("checksum"), 32), hex_bytes(lf.get("signature"), 64),
                      hex_bytes(lf.get("key_hash"), 32))
        if ck is None or sg is None or kh is None:
            return None
        out.append((lf["index"], lf["checksum"], lf["key_hash"], h_leaf(ck + sg + kh)))
    return out


def verify_view(view, c: dict, extra_heads=(), prefix=None) -> dict:
    """The complainant's view combined with the respondent's view_prefix (used only if it folds
    into the view's frontier) and every head from either side that verifies against the policy and
    recomputes from the frontier and leaves. time_ms and first_ms are the latest and earliest quorum
    times of those heads."""
    out: Dict[str, Any] = {"ok": False, "reason": None, "time_ms": None, "first_ms": None,
                           "heads": [], "leaves": [], "frontier_size": None, "prefix_used": False}
    if not isinstance(view, dict):
        out["reason"] = "malformed view"
        return out
    text = view.get("policy")
    if not isinstance(text, str) or sha256(text.encode()).hex() != c.get("witness_policy_sha256"):
        out["reason"] = "witness policy does not match the contract"
        return out
    try:
        pol = parse_policy(text)
    except (ValueError, TypeError) as e:
        out["reason"] = f"malformed policy: {e}"
        return out
    lkh_hex = view.get("log_key_hash") or (next(iter(pol["logs"])) if len(pol["logs"]) == 1 else None)
    if not isinstance(lkh_hex, str) or lkh_hex not in pol["logs"]:
        out["reason"] = "log key not in the policy"
        return out
    lkh, log_key = bytes.fromhex(lkh_hex), pol["logs"][lkh_hex]
    fr = view.get("frontier")
    try:
        fs = fr["size"]
        if not is_int(fs) or fs < 0:
            raise ValueError("frontier size")
        fmap = _frontier_map(fs, fr["nodes"])
    except (KeyError, TypeError, ValueError) as e:
        out["reason"] = f"malformed view: {e}"
        return out
    leaves = _leaves(view.get("leaves", []), fs)
    if leaves is None:
        out["reason"] = "leaves are malformed or not contiguous from the frontier"
        return out
    heads_in = list(_list(view.get("heads"))) + list(extra_heads or [])
    if isinstance(prefix, dict):
        try:
            pfr = prefix["frontier"]
            pfs = pfr["size"]
            if not is_int(pfs) or not 0 <= pfs < fs:
                raise ValueError("prefix frontier")
            pmap = _frontier_map(pfs, pfr["nodes"])
            pleaves = _leaves(prefix.get("leaves"), pfs)
            if pleaves is None or len(pleaves) != fs - pfs:
                raise ValueError("prefix leaves")
            want = [fmap[k] for k in sorted(fmap)]
            got = frontier_nodes(pfs, pmap, [x[3] for x in pleaves], fs) if fs else []
            if got != want:
                raise ValueError("prefix does not fold into the view's frontier")
            fs, fmap, leaves = pfs, pmap, pleaves + leaves
            heads_in += list(_list(prefix.get("heads")))
            out["prefix_used"] = True
        except (KeyError, TypeError, ValueError, IndexError):
            pass
    hashes = [x[3] for x in leaves]
    heads: List[Tuple[int, int]] = []
    for hd in heads_in:
        t = head_quorum_time_ms(hd, lkh, log_key, pol)
        if t is None:
            continue
        try:
            if tree_root(fs, fmap, hashes, hd["size"]).hex() != hd["root_hash"]:
                continue
        except (ValueError, IndexError, KeyError, TypeError):
            continue
        heads.append((hd["size"], t))
    if not heads:
        out["reason"] = "no tree head verifies against the policy and the leaves"
        return out
    top = max(s for s, _ in heads)
    out.update(ok=True, heads=sorted(set(heads)), time_ms=max(t for _, t in heads),
               first_ms=min(t for _, t in heads), frontier_size=fs,
               leaves=[(i, ck, kh) for i, ck, kh, _ in leaves if i < top])
    return out


class Timing:
    """Inclusion bounds of leaves from the verified heads: hi(i), the earliest quorum time of a
    head containing leaf i (it was included by then), and lo(i), the latest quorum time of a head
    not containing it (it was included after then), or None."""

    def __init__(self, heads: List[Tuple[int, int]]):
        hs = sorted(heads)
        self.sizes = [s for s, _ in hs]
        n = len(hs)
        self.suf_min = [0] * n
        m = None
        for k in range(n - 1, -1, -1):
            m = hs[k][1] if m is None else min(m, hs[k][1])
            self.suf_min[k] = m
        self.pre_max = [0] * n
        m = None
        for k in range(n):
            m = hs[k][1] if m is None else max(m, hs[k][1])
            self.pre_max[k] = m

    def hi(self, i: int) -> Optional[int]:
        k = bisect.bisect_right(self.sizes, i)          # first head with size > i
        return self.suf_min[k] if k < len(self.sizes) else None

    def lo(self, i: int) -> Optional[int]:
        k = bisect.bisect_right(self.sizes, i)          # heads [0, k) have size <= i
        return self.pre_max[k - 1] if k > 0 else None


# the judge

class _Ctx:
    def __init__(self, c, cbody, pk, vv, bodies, defense, extra_contracts, check_verdict, nm):
        self.c, self.cb, self.pk = c, cbody, pk
        self.vv = vv
        self.defense = defense
        self.check_verdict = check_verdict
        self.nm = nm
        self.T = Timing(vv["heads"])
        self.skh = cbody.get("sigsum_key_hash")
        # Contracts whose statements count: the complaint's, and signed contracts of the same
        # deployment, key, timing and broker (a later version of the same clause).
        self.allowed = {contract_hash(cbody)}
        explained = {sha256(stmt_message(cbody)).hex()}
        same = ("t0_ms", "period_s", "delta_pub_s", "broker", "pk", "dep")
        for st in extra_contracts:
            b = st.get("body") if isinstance(st, dict) else None
            try:
                if verify_statement(st, pk) and isinstance(b, dict) and b.get("kind") == "contract":
                    explained.add(sha256(stmt_message(b)).hex())
                    if all(canon(b.get(k)) == canon(cbody.get(k)) for k in same):
                        self.allowed.add(contract_hash(b))
            except (TypeError, ValueError):
                continue
        # Leaf checksum -> statement body (a valid statement of this clause), and every checksum
        # some supplied object explains.
        self.stmts: Dict[str, dict] = {}
        for st in _items(bodies) + _items(defense.get("bodies")):
            self._add(st, explained)
        for a in _list(defense.get("leaf_openings")):
            if verify_anchor(a, pk):
                explained.add(sha256(bytes.fromhex(a["record_hash"])).hex())
        self.explained = explained
        self.anchors = [a for a in _list(defense.get("anchors")) if verify_anchor(a, pk)]
        # Our leaves in the view with their inclusion bounds: statements by period, and the leaves
        # nothing supplied explains.
        self.by_j: Dict[int, List[Tuple[int, str, Optional[int], Optional[int]]]] = {}
        self.unexplained: List[Tuple[int, str, Optional[int], Optional[int]]] = []
        for i, ck, kh in vv["leaves"]:
            if kh != self.skh:
                continue
            item = (i, ck, self.T.hi(i), self.T.lo(i))
            if ck in self.stmts:
                self.by_j.setdefault(self.stmts[ck]["j"], []).append(item)
            elif ck not in explained:
                self.unexplained.append(item)

    def _add(self, st, explained):
        if not isinstance(st, dict) or not isinstance(st.get("body"), dict):
            return
        b = st["body"]
        try:
            msg = stmt_message(b)
        except (TypeError, ValueError):
            return
        ck = sha256(msg).hex()
        explained.add(ck)
        if not verify_statement(st, self.pk):
            return
        if is_int(b.get("v")) and b["v"] == 1 and b.get("dep") == self.cb["dep"] and b.get("kind") in ("head", "stall") \
                and is_int(b.get("j")) and b.get("contract") in self.allowed:
            self.stmts[ck] = b

    def early(self, hi, x) -> bool:
        return hi is not None and hi <= period_end_ms(x, self.cb)

    def late(self, lo, x) -> bool:
        return lo is not None and lo > deadline_ms(x, self.cb)

    def timely(self, hi, x) -> bool:
        return hi is not None and period_end_ms(x, self.cb) < hi <= deadline_ms(x, self.cb)

    def candidate(self, hi, lo, x) -> bool:
        return not self.early(hi, x) and not self.late(lo, x)

    def period(self, x: int) -> Tuple[Dict[str, dict], List[dict], List[str]]:
        """(S_x: checksum -> body of each statement for x proven timely, U_x: leaves that could be
        x's statement but are not proven so, the checksums of x's statements not proven timely)."""
        S: Dict[str, dict] = {}
        mine = self.by_j.get(x, [])
        for i, ck, hi, lo in mine:
            if self.timely(hi, x):
                S[ck] = self.stmts[ck]
        U: List[dict] = []
        late: List[str] = []
        for i, ck, hi, lo in mine:
            if ck in S:
                continue
            late.append(ck)
            if self.candidate(hi, lo, x):
                U.append({"index": i, "checksum": ck, "why": "undetermined"})
        for i, ck, hi, lo in self.unexplained:
            if self.candidate(hi, lo, x):
                U.append({"index": i, "checksum": ck, "why": "unexplained"})
        return S, U, late

    def covered(self, x: int) -> bool:
        return self.vv["first_ms"] <= period_end_ms(x, self.cb)

    def opening(self, j: int, body: dict, extra=None) -> Optional[dict]:
        t = self.c["tenant_id"]
        agg = _dict(body.get("agg"))
        for src in (extra or {}, _dict(self.defense.get("openings"))):
            op = src.get(str(j)) if isinstance(src, dict) else None
            if isinstance(op, dict) and op.get("tenant_id") == t and is_int(op.get("j")) and op["j"] == j \
                    and verify_opening(op, agg.get("root"), agg.get("size")):
                return op
        return None

    def is_stall(self, body: dict, tp: Optional[str]) -> bool:
        part = _dict(body.get("parts")).get(tp) if tp else None
        return isinstance(part, dict) and part.get("status") == "stall"

    def tenant_stall(self, body: dict, tp: Optional[str], x: int) -> Tuple[bool, bool]:
        """(the tenant is stalled by this statement, the stall is charged to its budget). A
        partition STALL stalls and charges the tenant unless its opening (agg alg v2) says ok (not
        stalled) or held (stalled by a co-tenant, not charged). Without an opening it is charged."""
        if not self.is_stall(body, tp):
            return False, False
        agg = _dict(body.get("agg"))
        if agg.get("alg") != AGG_ALG_ST or agg.get("root") is None:
            return True, True
        op = self.opening(x, body)
        st = None if op is None else op.get("st")
        return st != "ok", st not in ("ok", "held")

    def window(self, tp: Optional[str], j: int) -> Tuple[int, int]:
        """(periods of the window ending at j in which the tenant counts as stalled, of which
        certain). A period the view does not reach, or with a leaf nobody explained, counts."""
        w = int(self.cb["window_periods"])
        start = max(j - w + 1, int(self.cb.get("effective_j") or 0), 0)
        total = certain = 0
        for x in range(start, j + 1):
            if not self.covered(x):
                total += 1
                continue
            S, U, _ = self.period(x)
            if U:
                total += 1
                continue
            if any(self.tenant_stall(b, tp, x)[1] for b in S.values()):
                total += 1
                certain += 1
        return total, certain

    def anchor(self, tenant: str, n: int, rh: str) -> Optional[dict]:
        for a in self.anchors:
            if a["tenant_id"] == tenant and a["n"] == n and a["record_hash"] == rh:
                return a
        return None


def _matches(c: dict, rec) -> bool:
    if not isinstance(rec, dict) or rec.get("tenant_id") != c["tenant_id"]:
        return False
    if c["form"] == "receipt":
        pos = rec.get("pos")
        return isinstance(pos, dict) and pos.get("topic") == c["pos"]["topic"] and is_int(pos.get("p")) \
            and pos["p"] == c["pos"]["p"] and is_int(pos.get("o")) and pos["o"] == c["pos"]["o"]
    sub = rec.get("sub")
    return isinstance(sub, dict) and sub.get("sub") == c["sub"]


def _is_unchk(r) -> bool:
    return isinstance(r, dict) and r.get("kind") == "verdict" and isinstance(r.get("verdict"), dict) \
        and r["verdict"].get("type") == "UNCHECKABLE"


def _unchk_rank_ok(ctx: _Ctx, seq: int) -> Optional[bool]:
    """Is the UNCHECKABLE verdict at seq within the tenant's budget for its window? The rank is
    counted from the anchored records themselves: the verdicts in every segment from the first
    anchor inside the window (the chain starts at the last anchor before it) through seq. The
    anchors' own u fields are not used, so a promisor cannot lower the count by signing a smaller
    u. None when the defense does not carry the chain and every segment of it."""
    ev = _dict(ctx.defense.get("unchk")).get(str(seq))
    if not isinstance(ev, dict):
        return None
    chain = _list(ev.get("anchors"))
    segs = _dict(ev.get("segments"))
    t = ctx.c["tenant_id"]
    if not chain or not all(verify_anchor(a, ctx.pk) and a["tenant_id"] == t for a in chain):
        return None
    for prev, nxt in zip(chain, chain[1:]):
        if nxt["prev_hash"] != prev["record_hash"] or nxt["n"] <= prev["n"]:
            return None
    cover = chain[-1]
    sd = _seg(cover)
    if sd is None or not sd["from"] <= seq < sd["to"]:
        return None
    start = float(cover["ts"]) * 1000 - int(ctx.cb["window_periods"]) * period_ms(ctx.cb)
    first = chain[0]
    if first["prev_hash"] == GENESIS_PREV and float(first["ts"]) * 1000 >= start:
        counted, base_n = chain, 0
    elif len(chain) >= 2 and float(first["ts"]) * 1000 < start <= float(chain[1]["ts"]) * 1000:
        counted, base_n = chain[1:], first["n"]
    else:
        return None
    rank, at = 0, base_n
    for a in counted:
        sd = _seg(a)
        if a.get("v") != 2 or sd is None:
            if a is cover:
                return None
            at = a["n"]
            continue
        seg = segs.get(str(a["n"]))
        if a is cover and seg is None:
            seg = ev.get("segment")
        try:
            if not isinstance(seg, dict) or segment_hash(seg) != sd["sha256"] or sd["from"] != at or sd["to"] != a["n"]:
                return None
        except (TypeError, ValueError):
            return None
        for r in _list(seg.get("records")):
            if _is_unchk(r) and is_int(r.get("seq")) and r["seq"] <= seq:
                rank += 1
        at = a["n"]
    return rank <= int(ctx.cb["unchk_budget"])


def _blobs(defense: dict) -> Callable[[str], Optional[bytes]]:
    table = _dict(defense.get("blobs"))

    def get(key) -> Optional[bytes]:
        k = str(key)
        if k.startswith("blobs/"):
            k = k[len("blobs/"):]
        if k.endswith(".bin"):
            k = k[:-len(".bin")]
        v = table.get(k)
        try:
            return base64.b64decode(v) if isinstance(v, str) else None
        except (ValueError, TypeError):
            return None
    return get


def _call_checker(checker: Callable, rec: dict, prefix: dict, blobs: Callable, pk: bytes):
    """Passes the deployment key to a checker that takes one (UNAUTH needs it)."""
    try:
        return checker(rec, prefix, blobs, pubkey=pk)
    except TypeError:
        return checker(rec, prefix, blobs)


def _met(ctx: _Ctx, j: int, body: dict) -> Tuple[str, List[dict]]:
    """("met" | "unchk_budget" | "none", evidence) for the defense relative to statement body."""
    c = ctx.c
    op = ctx.opening(j, body)
    if op is None:
        return "none", [{"type": "no_opening", "j": j}]
    a = ctx.anchor(c["tenant_id"], op["n"], op["rh"])
    if a is None:
        return "none", [{"type": "no_anchor", "j": j, "n": op["n"]}]
    n = a["n"]
    proven: Dict[int, dict] = {}
    for e in _list(ctx.defense.get("records")):
        if not isinstance(e, dict) or not isinstance(e.get("record"), dict):
            continue
        idx = e.get("index")
        if not (is_int(e.get("n")) and e["n"] == n and is_int(idx) and is_int(e["record"].get("seq"))
                and e["record"]["seq"] == idx):
            continue
        if mmr_proof_ok(e["record"], idx, n, e.get("proof"), a["root"]):
            proven[idx] = e["record"]
    ev = [{"type": "opening", "j": j, "opening": op}, {"type": "anchor", "anchor": a}]
    for i, rec in sorted(proven.items()):
        if not _matches(c, rec):
            continue
        event = rec.get("event")
        try:
            differs = event is not None and content_hash(event) != c["leaf_hash"]
        except (TypeError, ValueError):
            differs = True
        if differs:
            # Anchored at the submission's place with other content: proof of loss, not of MET.
            ev.append({"type": "failing_verdict", "index": i, "record": rec, "why": "content differs"})
            continue
        if rec.get("kind") == "event":
            return "met", ev + [{"type": "record", "index": i, "record": rec}]
        if rec.get("kind") != "verdict":
            continue
        vtype = _dict(rec.get("verdict")).get("type")
        if vtype == "UNCHECKABLE":
            ok = _unchk_rank_ok(ctx, i)
            if ok is True:
                return "met", ev + [{"type": "verdict", "index": i, "record": rec}]
            if ok is False:
                return "unchk_budget", ev + [{"type": "verdict", "index": i, "record": rec}]
            continue
        if ctx.check_verdict is None:
            continue
        try:
            ok, why = _call_checker(ctx.check_verdict, rec, {k: v for k, v in proven.items() if k < i},
                                    _blobs(ctx.defense), ctx.pk)
        except Exception as e:                       # a checker failure is not a pass
            ok, why = False, f"checker raised {type(e).__name__}"
        if ok is True:
            return "met", ev + [{"type": "verdict", "index": i, "record": rec}]
        ev.append({"type": "failing_verdict", "index": i, "record": rec, "why": why})
    return "none", ev


def _nonmembership(ctx: _Ctx, j: int, body: dict) -> Optional[dict]:
    """Evidence that the complaint's submission is not in the head j's statement commits for its
    tenant, or None. Forms: "beyond" (receipt: o above the opening's pos_last), "adjacent" (receipt: two
    consecutive records straddling o), "scan" (any complaint: no record with its sub in any segment
    anchored since a - delta)."""
    c = ctx.c
    nm = _dict(ctx.nm.get(str(j)))
    op = ctx.opening(j, body, {str(j): nm.get("opening")} if isinstance(nm.get("opening"), dict) else None)
    if op is None:
        return None
    t = c["tenant_id"]
    if c["form"] == "receipt":
        pl = op.get("pos_last")
        if _tp(pl) is not None and _tp(pl) == _tp(c["pos"]) and is_int(pl.get("o")) and pl["o"] < c["pos"]["o"]:
            return {"form": "beyond", "opening": op}
    anchors = [a for a in _list(nm.get("anchors")) if verify_anchor(a, ctx.pk)] + ctx.anchors
    head = next((a for a in anchors if a["tenant_id"] == t and a["n"] == op["n"] and a["record_hash"] == op["rh"]),
                None)
    if head is None:
        return None
    n = head["n"]
    adj = nm.get("adjacent")
    if c["form"] == "receipt" and isinstance(adj, dict):
        l, r = _dict(adj.get("left")), _dict(adj.get("right"))
        li, ri = l.get("index"), r.get("index")
        lr, rr = _dict(l.get("record")), _dict(r.get("record"))
        lp, rp = lr.get("pos"), rr.get("pos")
        if is_int(li) and is_int(ri) and ri == li + 1 and ri < n and is_int(lr.get("seq")) and lr["seq"] == li \
                and is_int(rr.get("seq")) and rr["seq"] == ri \
                and mmr_proof_ok(lr, li, n, l.get("proof"), head["root"]) \
                and mmr_proof_ok(rr, ri, n, r.get("proof"), head["root"]) \
                and _tp(lp) is not None and _tp(lp) == _tp(c["pos"]) == _tp(rp) \
                and is_int(lp.get("o")) and is_int(rp.get("o")) and lp["o"] < c["pos"]["o"] < rp["o"]:
            return {"form": "adjacent", "opening": op, "anchor": head, "left": l, "right": r}
    scan = nm.get("scan")
    if isinstance(scan, dict):
        chain = _list(scan.get("anchors"))
        segs = _dict(scan.get("segments"))
        if not chain or not all(verify_anchor(a, ctx.pk) and a["tenant_id"] == t for a in chain):
            return None
        if chain[-1]["record_hash"] != head["record_hash"]:
            return None
        for prev, nxt in zip(chain, chain[1:]):
            if nxt["prev_hash"] != prev["record_hash"]:
                return None
        bound = c["at_ms"] - int(ctx.cb["delta_s"]) * 1000
        first = chain[0]
        if first["prev_hash"] != GENESIS_PREV:
            # The first anchor is the last one written before a - delta: nothing it or its
            # predecessors cover can hold the submission.
            if float(first["ts"]) * 1000 >= bound:
                return None
            scanned = chain[1:]
        else:
            scanned = chain
        for a in scanned:
            if a.get("v") != 2:
                continue
            seg = segs.get(str(a["n"]))
            sd = _seg(a)
            try:
                if sd is None or not isinstance(seg, dict) or segment_hash(seg) != sd["sha256"]:
                    return None
            except (TypeError, ValueError):
                return None
            for rec in _list(seg.get("records")):
                if _matches(c, rec) or (isinstance(rec, dict) and isinstance(rec.get("sub"), dict)
                                        and rec["sub"].get("sub") == c["sub"]):
                    return None
        return {"form": "scan", "opening": op, "anchors": len(chain)}
    return None


def _partition(ctx: _Ctx) -> Tuple[Optional[str], str]:
    """The complaint's partition: the signed position of a receipt; for a submission tag, the
    partition the contract's partitioner gives the tenant. An unsigned, claimed position is never
    used."""
    c = ctx.c
    if c["form"] == "receipt":
        return _tp(c["pos"]), "receipt"
    p = partition_of(ctx.cb, c["tenant_id"])
    topic = _dict(ctx.cb.get("broker")).get("topic")
    if p is None or not isinstance(topic, str):
        return None, "unknown"
    return f"{topic}/{p}", "contract"


def judge(complaint, contract, view, bodies, defense, now_ms: int,
          check_verdict: Optional[Callable] = None) -> dict:
    """Returns {"verdict", "kind", "j", "stalls", "evidence", "self_contained"}."""
    def out(verdict, kind=None, j=None, stalls=0, evidence=None, self_contained=False):
        return {"verdict": verdict, "kind": kind, "j": j, "stalls": stalls,
                "evidence": evidence or [], "self_contained": self_contained}

    try:
        cbody = contract["body"]
        pk = bytes.fromhex(cbody["pk"])
        if len(pk) != 32:
            raise ValueError("key length")
    except (KeyError, TypeError, ValueError, AttributeError):
        return out("REJECT", "contract")
    if not verify_statement(contract, pk) or not _contract_ok(cbody):
        return out("REJECT", "contract")
    c = parse_complaint(complaint, pk)
    if c is None:
        return out("REJECT", "signature")
    if c["contract"] != contract_hash(cbody):
        return out("REJECT", "contract")
    defense = defense if isinstance(defense, dict) else {}
    view = view if isinstance(view, dict) else {}
    vv = verify_view(view, cbody, _list(defense.get("heads")), defense.get("view_prefix"))
    if not vv["ok"]:
        return out("REJECT", "view", evidence=[{"type": "view", "reason": vv["reason"]}])
    j0 = first_due_period(c["at_ms"], cbody)
    if vv["first_ms"] > period_end_ms(j0, cbody):
        return out("REJECT", "view", evidence=[{"type": "view", "reason":
                   "no head covering the frontier was cosigned before the first due period ended"}])
    ctx = _Ctx(c, cbody, pk, vv, bodies, defense,
               _list(view.get("contracts")) + _list(defense.get("contracts")), check_verdict,
               _dict(complaint.get("nonmembership")))
    tp, how = _partition(ctx)
    if tp is None:
        return out("REJECT", "partition", evidence=[{"type": "partition", "reason":
                   "the contract does not determine the tenant's partition"}])
    tau = min(int(now_ms), int(vv["time_ms"]))
    E = int(cbody["stall_budget"])
    stalls = 0
    evidence: List[dict] = []
    j = j0
    while True:
        if deadline_ms(j, cbody) > tau:
            if j == j0:
                return out("PENDING", j=j0)
            return out("EXCUSED", j=j - 1, stalls=stalls, evidence=evidence)
        S, U, late = ctx.period(j)
        if not S:
            return out("VIOLATED", "silence", j, stalls, evidence + [{
                "type": "silence", "j": j, "deadline_ms": deadline_ms(j, cbody),
                "view_time_ms": vv["time_ms"], "late_statements": sorted(set(late)),
                "unexplained_leaves": U}], not U)
        if len(S) > 1:
            return out("VIOLATED", "equivocation", j, stalls, evidence + [{
                "type": "equivocation", "j": j, "bodies": [S[k] for k in sorted(S)]}], True)
        if U:
            # a leaf that may be a second statement for j, whose body the respondent did not show
            return out("VIOLATED", "equivocation", j, stalls, evidence + [{
                "type": "unopened_leaves", "j": j, "leaves": U}], False)
        mh = next(iter(S))
        body = S[mh]
        st, met_ev = _met(ctx, j, body)
        if st == "met":
            return out("MET", j=j, stalls=stalls, evidence=evidence + [
                {"type": "statement", "j": j, "checksum": mh}] + met_ev)
        if st == "unchk_budget":
            return out("VIOLATED", "unchk_budget", j, stalls, evidence + met_ev, True)
        stalled, charged = ctx.tenant_stall(body, tp, j)
        if not stalled:
            nm = _nonmembership(ctx, j, body)
            failing = [e for e in met_ev if e.get("type") == "failing_verdict"]
            kind = "false_head" if (nm is not None or failing) else "defense_failed"
            return out("VIOLATED", kind, j, stalls, evidence + [
                {"type": "statement", "j": j, "checksum": mh, "body": body, "partition": tp,
                 "partition_from": how}] + ([{"type": "nonmembership", **nm}] if nm else []) + failing,
                kind == "false_head")
        stalls += 1
        evidence.append({"type": "stall", "j": j, "checksum": mh, "partition": tp, "partition_from": how,
                         "charged": charged})
        wtotal, wcertain = ctx.window(tp, j)
        if stalls > E or wtotal > E:
            # Self-contained unless the window count needed periods the view does not reach or
            # leaves nobody explained.
            return out("VIOLATED", "stall_budget", j, stalls, evidence + [
                {"type": "window", "j": j, "stalled_periods": wtotal, "certain": wcertain}],
                stalls > E or wcertain > E)
        j += 1


def judge_safe(complaint, contract, view, bodies, defense, now_ms: int,
               check_verdict: Optional[Callable] = None) -> dict:
    """judge(), with any failure on malformed evidence reported as REJECT(malformed), not raised."""
    try:
        return judge(complaint, contract, view, bodies, defense, now_ms, check_verdict)
    except Exception as e:                           # noqa: BLE001  (evidence is untrusted)
        return {"verdict": "REJECT", "kind": "malformed", "j": None, "stalls": 0,
                "evidence": [{"type": "error", "error": type(e).__name__}], "self_contained": False}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("claim", help="claim bundle (JSON)")
    ap.add_argument("--key", required=True, help="deployment public key (hex), from a channel you trust")
    ap.add_argument("--now-ms", type=int, default=None, help="evaluation time (default: now)")
    args = ap.parse_args()
    with open(args.claim, encoding="utf-8") as f:
        claim = json.load(f)
    contract = _dict(claim.get("contract"))
    if not same_key(_dict(contract.get("body")).get("pk"), args.key):
        print(json.dumps({"verdict": "REJECT", "kind": "key", "detail":
                          "the contract does not name the pinned key"}, indent=2))
        return 2
    now = args.now_ms if args.now_ms is not None else int(time.time() * 1000)
    public = _dict(claim.get("public"))
    res = judge_safe(claim.get("complaint") or {}, contract, public, public.get("bodies"),
                     claim.get("defense"), now, CV.check_verdict)
    print(json.dumps(res, indent=2, sort_keys=True))
    v = res["verdict"]
    return 0 if v in ("MET", "EXCUSED", "PENDING") else 1 if v == "VIOLATED" else 2


if __name__ == "__main__":
    sys.exit(main())
