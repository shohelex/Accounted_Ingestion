from __future__ import annotations

import base64
import bisect
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from crypto.anchor_store import AnchorRecord, segment_key
from crypto.incremental_merkle import _hash_internal
from crypto.period_statements import (agg_key, aggregate, contract_hash, contract_key,
                                      contract_receipt_key, deadline_ms, first_due_period,
                                      leaf_checksum, opening_key, outage_key, outage_statement,
                                      period_end_ms, period_key, receipt_key, sign_statement, spool_ns,
                                      spooled_receipts)
from crypto.public_witness import (WitnessPolicy, cosignature_note, leaf_hash, node_hash,
                                   tree_head_json, tree_head_note, tree_leaf)
from crypto.records import NS_ACK2, NS_STMT, NS_SUB, ack2_body, canon, record_hash, sub_body
from crypto.signing import verify as _ed_verify

MAX_DEPTH = 64          # nesting beyond this is malformed evidence


def _int(x) -> bool:
    return type(x) is int


def _depth_ok(x) -> bool:
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


def _canon(x) -> bytes:
    if not _depth_ok(x):
        raise ValueError("nested too deeply")
    return canon(x)


def _stmt_msg(body: dict) -> bytes:
    return hashlib.sha256(NS_STMT + _canon(body)).digest()


def _ed(pk: bytes, sig, data: bytes) -> bool:
    if not isinstance(sig, str):
        return False
    try:
        return _ed_verify(pk, sig, data)
    except (TypeError, ValueError):
        return False


def _stmt_ok(stmt: Any, pk: bytes) -> bool:
    try:
        return isinstance(stmt, dict) and isinstance(stmt.get("body"), dict) and \
            _ed(pk, stmt.get("sig"), NS_STMT + _canon(stmt["body"]))
    except (TypeError, ValueError):
        return False


_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


def _hex(x, nbytes: int) -> Optional[bytes]:
    """Exactly 2 * nbytes hex digits (bytes.fromhex alone would skip whitespace)."""
    if not isinstance(x, str) or len(x) != 2 * nbytes or not _HEXDIGITS.issuperset(x):
        return None
    return bytes.fromhex(x)


def _d(x) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x) -> list:
    return x if isinstance(x, list) else []


def _statements(src) -> List[Any]:
    vals = src.values() if isinstance(src, dict) else src if isinstance(src, list) else []
    out: List[Any] = []
    for v in vals:
        out.extend(v if isinstance(v, list) else [v])
    return out


def _anchor_ok(a: Optional[AnchorRecord], pk: bytes) -> bool:
    try:
        return a is not None and a.verify_self() and a.verify_sig(pk)
    except Exception:
        return False


def mmr_proof_sparse(peaks_from: list, leaf_hashes: List[bytes], index: int, n: int) -> List[Tuple[str, str]]:
    """MMR inclusion proof of leaf `index` in the log of n leaves, from the peaks at an earlier size
    (an anchor record's peaks) and the leaf hashes from there to n."""
    blocks: Dict[Tuple[int, int], bytes] = {}
    frm = 0
    for h, ht in peaks_from or []:
        blocks[(frm, 1 << int(ht))] = bytes.fromhex(h)
        frm += 1 << int(ht)
    if not frm <= index < n or len(leaf_hashes) != n - frm:
        raise ValueError("the index or the leaves are outside the range the peaks allow")

    def node(a: int, size: int) -> bytes:
        if (a, size) in blocks:
            return blocks[(a, size)]
        if a + size <= frm:
            raise ValueError("a node left of the peaks is not a peak")
        if size == 1:
            return leaf_hashes[a - frm]
        v = _hash_internal(node(a, size // 2), node(a + size // 2, size // 2))
        blocks[(a, size)] = v
        return v

    mountains, off = [], 0
    for h in [h for h in reversed(range(n.bit_length())) if n >> h & 1]:
        mountains.append((off, 1 << h, h))
        off += 1 << h
    p = next(k for k, (a, s, _) in enumerate(mountains) if a <= index < a + s)
    mo, _, mh = mountains[p]
    proof: List[Tuple[str, str]] = []
    for level in range(mh):
        blk = (index - mo) >> level
        sib = mo + ((blk ^ 1) << level)
        proof.append((node(sib, 1 << level).hex(), "right" if blk % 2 == 0 else "left"))
    right = mountains[p + 1:]
    if right:
        comp = node(right[-1][0], right[-1][1])
        for a, s, _ in reversed(right[:-1]):
            comp = _hash_internal(node(a, s), comp)
        proof.append((comp.hex(), "right"))
    for a, s, _ in reversed(mountains[:p]):
        proof.append((node(a, s).hex(), "left"))
    return proof


def _fmap(fs: int, nodes) -> Dict[Tuple[int, int], bytes]:
    heights = [h for h in reversed(range(fs.bit_length())) if fs >> h & 1]
    if not isinstance(nodes, list) or len(heights) != len(nodes):
        raise ValueError("frontier size and nodes disagree")
    out, off = {}, 0
    for h, x in zip(heights, nodes):
        b = _hex(x, 32)
        if b is None:
            raise ValueError("frontier node")
        out[(off, 1 << h)] = b
        off += 1 << h
    return out


def _root(fs: int, fmap, hashes: List[bytes], size: int) -> bytes:
    if not fs <= size <= fs + len(hashes) or size < 1:
        raise ValueError("head outside the view")

    def mth(lo: int, hi: int) -> bytes:
        if (lo, hi - lo) in fmap:
            return fmap[(lo, hi - lo)]
        n = hi - lo
        if hi <= fs and n & (n - 1) == 0:
            raise ValueError("not a frontier node")
        if n == 1:
            return hashes[lo - fs]
        k = 1 << ((n - 1).bit_length() - 1)
        return node_hash(mth(lo, lo + k), mth(lo + k, hi))
    return mth(0, size)


def _perfect(fs: int, fmap, hashes: List[bytes], lo: int, n: int) -> bytes:
    if (lo, n) in fmap:
        return fmap[(lo, n)]
    if lo + n <= fs:
        raise ValueError("not a frontier node")
    if n == 1:
        return hashes[lo - fs]
    return node_hash(_perfect(fs, fmap, hashes, lo, n // 2), _perfect(fs, fmap, hashes, lo + n // 2, n // 2))


def _leaves(raw, start: int) -> Optional[List[Tuple[int, str, str, bytes]]]:
    if not isinstance(raw, list):
        return None
    out = []
    for k, lf in enumerate(raw):
        if not isinstance(lf, dict) or not _int(lf.get("index")) or lf["index"] != start + k:
            return None
        ck, sg, kh = _hex(lf.get("checksum"), 32), _hex(lf.get("signature"), 64), _hex(lf.get("key_hash"), 32)
        if ck is None or sg is None or kh is None:
            return None
        out.append((lf["index"], lf["checksum"], lf["key_hash"], leaf_hash(tree_leaf(ck, sg, kh))))
    return out


def _cosig_ts(x) -> Optional[int]:
    if _int(x):
        return x
    if isinstance(x, str) and x.isdigit() and x.isascii():
        return int(x)
    return None


def _quorum_time_ms(head, lkh: bytes, log_key: bytes, pol: WitnessPolicy) -> Optional[int]:
    if not isinstance(head, dict) or not _int(head.get("size")) or head["size"] < 0:
        return None
    size, root = head["size"], _hex(head.get("root_hash"), 32)
    if root is None or not _ed(log_key, head.get("signature"), tree_head_note(lkh, size, root)):
        return None
    if pol.quorum is None:
        return None
    names = pol.witness_names_by_key_hash()
    good = []
    for cs in _l(head.get("cosignatures")):
        if not isinstance(cs, (list, tuple)) or len(cs) != 3:
            continue
        wkh, ts, sig = cs
        ts = _cosig_ts(ts)
        name = names.get(wkh) if isinstance(wkh, str) else None
        if name is not None and ts is not None and _ed(pol.witnesses[name], sig, cosignature_note(ts, lkh, size, root)):
            good.append((ts, name))
    seen = set()
    for ts, name in sorted(good):
        seen.add(name)
        if pol.satisfied(seen):
            return ts * 1000
    return None


def check_view(view, contract: dict, extra_heads=(), prefix=None) -> dict:
    """The combined public-log view: the complainant's view, the respondent's prefix when it folds
    into the view's frontier, and every head from either side that verifies against the contract's
    policy and recomputes from the frontier and leaves."""
    res: Dict[str, Any] = {"ok": False, "reason": None, "time_ms": None, "first_ms": None,
                           "heads": [], "leaves": [], "frontier_size": None, "prefix_used": False}
    if not isinstance(view, dict):
        res["reason"] = "malformed view"
        return res
    text = view.get("policy")
    if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != contract.get("witness_policy_sha256"):
        res["reason"] = "witness policy does not match the contract"
        return res
    try:
        pol = WitnessPolicy.parse(text)
    except (ValueError, TypeError) as e:
        res["reason"] = f"malformed policy: {e}"
        return res
    lkh_hex = view.get("log_key_hash") or (next(iter(pol.logs)) if len(pol.logs) == 1 else None)
    if not isinstance(lkh_hex, str) or lkh_hex not in pol.logs:
        res["reason"] = "log key not in the policy"
        return res
    lkh, lk = bytes.fromhex(lkh_hex), pol.logs[lkh_hex]
    try:
        fs = view["frontier"]["size"]
        if not _int(fs) or fs < 0:
            raise ValueError("frontier size")
        fmap = _fmap(fs, view["frontier"]["nodes"])
    except (KeyError, TypeError, ValueError) as e:
        res["reason"] = f"malformed view: {e}"
        return res
    leaves = _leaves(view.get("leaves", []), fs)
    if leaves is None:
        res["reason"] = "leaves are malformed or not contiguous from the frontier"
        return res
    heads_in = list(_l(view.get("heads"))) + list(extra_heads or [])
    if isinstance(prefix, dict):
        try:
            pfs = prefix["frontier"]["size"]
            if not _int(pfs) or not 0 <= pfs < fs:
                raise ValueError("prefix frontier")
            pmap = _fmap(pfs, prefix["frontier"]["nodes"])
            pleaves = _leaves(prefix.get("leaves"), pfs)
            if pleaves is None or len(pleaves) != fs - pfs:
                raise ValueError("prefix leaves")
            ph = [x[3] for x in pleaves]
            got, off = [], 0
            for h in [h for h in reversed(range(fs.bit_length())) if fs >> h & 1]:
                got.append(_perfect(pfs, pmap, ph, off, 1 << h))
                off += 1 << h
            if got != [fmap[k] for k in sorted(fmap)]:
                raise ValueError("prefix does not fold into the view's frontier")
            fs, fmap, leaves = pfs, pmap, pleaves + leaves
            heads_in += list(_l(prefix.get("heads")))
            res["prefix_used"] = True
        except (KeyError, TypeError, ValueError, IndexError):
            pass
    hashes = [x[3] for x in leaves]
    heads = []
    for hd in heads_in:
        t = _quorum_time_ms(hd, lkh, lk, pol)
        if t is None:
            continue
        try:
            if _root(fs, fmap, hashes, hd["size"]).hex() == hd["root_hash"]:
                heads.append((hd["size"], t))
        except (ValueError, IndexError, KeyError, TypeError):
            pass
    if not heads:
        res["reason"] = "no tree head verifies against the policy and the leaves"
        return res
    top = max(s for s, _ in heads)
    res.update(ok=True, heads=sorted(set(heads)), time_ms=max(t for _, t in heads),
               first_ms=min(t for _, t in heads), frontier_size=fs,
               leaves=[(i, ck, kh) for i, ck, kh, _ in leaves if i < top])
    return res


class _Timing:
    """hi(i): the earliest quorum time of a head containing leaf i; lo(i): the latest of a head not
    containing it."""

    def __init__(self, heads):
        hs = sorted(heads)
        self.sizes = [s for s, _ in hs]
        self.suf, self.pre = [], []
        m = None
        for s, t in reversed(hs):
            m = t if m is None else min(m, t)
            self.suf.append(m)
        self.suf.reverse()
        m = None
        for s, t in hs:
            m = t if m is None else max(m, t)
            self.pre.append(m)

    def hi(self, i):
        k = bisect.bisect_right(self.sizes, i)
        return self.suf[k] if k < len(self.sizes) else None

    def lo(self, i):
        k = bisect.bisect_right(self.sizes, i)
        return self.pre[k - 1] if k else None


def _complaint(complaint: Any, pk: bytes) -> Optional[dict]:
    try:
        if not isinstance(complaint, dict):
            return None
        if "receipt" in complaint:
            r = complaint["receipt"]
            pos = r["pos"]
            vals = (r["tenant_id"], r["event_id"], r["leaf_hash"], r["sub"], r["at_ms"], pos["topic"],
                    pos["p"], pos["o"], r["contract"])
            if not all(isinstance(vals[k], str) for k in (0, 1, 2, 3, 5, 8)) or not all(_int(vals[k]) for k in (4, 6, 7)):
                return None
            b = ack2_body(*vals)
            if not _ed(pk, r.get("sig"), NS_ACK2 + _canon(b)):
                return None
            return dict(b, form="receipt", pos={"topic": b["topic"], "p": b["p"], "o": b["o"]})
        s = complaint["sub_record"]
        a = s["acct"]
        vals = (s["tenant_id"], s["event_id"], a["leaf_hash"], a["sub"], a["at_ms"], a["contract"])
        if not all(isinstance(vals[k], str) for k in (0, 1, 2, 3, 5)) or not _int(vals[4]):
            return None
        b = sub_body(*vals)
        if not _ed(pk, a.get("sig"), NS_SUB + _canon(b)):
            return None
        return dict(b, form="sub", pos=None)
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _same_submission(c: dict, rec) -> bool:
    if not isinstance(rec, dict) or rec.get("tenant_id") != c["tenant_id"]:
        return False
    if c["form"] == "receipt":
        p = rec.get("pos")
        return isinstance(p, dict) and p.get("topic") == c["pos"]["topic"] and _int(p.get("p")) \
            and p["p"] == c["pos"]["p"] and _int(p.get("o")) and p["o"] == c["pos"]["o"]
    s = rec.get("sub")
    return isinstance(s, dict) and s.get("sub") == c["sub"]


class _Periods:
    """The deployment's statements on the public log, per period: the ones included in time and
    the leaves of its key that no statement explains."""

    def __init__(self, cb, pk, vv, bodies):
        self.cb, self.pk = cb, pk
        self.T = _Timing(vv["heads"])
        self.allowed = {contract_hash(cb)}
        explained = {leaf_checksum(cb)}
        self.stmts: Dict[str, dict] = {}
        for st in _statements(bodies):
            self._add(st, explained)
        skh = cb.get("sigsum_key_hash")
        self.by_j: Dict[int, list] = {}
        self.unexplained: list = []
        for i, ck, kh in vv["leaves"]:
            if kh != skh:
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
            m = _stmt_msg(b)
        except (TypeError, ValueError):
            return
        ck = hashlib.sha256(m).hexdigest()
        explained.add(ck)
        if not _stmt_ok(st, self.pk):
            return
        if _int(b.get("v")) and b["v"] == 1 and b.get("dep") == self.cb["dep"] and b.get("kind") in ("head", "stall") \
                and _int(b.get("j")) and b.get("contract") in self.allowed:
            self.stmts[ck] = b

    def period(self, x):
        end = period_end_ms(x, self.cb["t0_ms"], self.cb["period_s"])
        D = deadline_ms(x, self.cb)
        mine = self.by_j.get(x, [])
        S = {ck: self.stmts[ck] for i, ck, hi, lo in mine if hi is not None and end < hi <= D}
        U, late = [], []

        def cand(hi, lo):
            return not (hi is not None and hi <= end) and not (lo is not None and lo > D)
        for i, ck, hi, lo in mine:
            if ck in S:
                continue
            late.append(ck)
            if cand(hi, lo):
                U.append({"index": i, "checksum": ck, "why": "undetermined"})
        for i, ck, hi, lo in self.unexplained:
            if cand(hi, lo):
                U.append({"index": i, "checksum": ck, "why": "unexplained"})
        return S, U, late


def audit_statements(view: dict, bodies: dict, contract: dict, now_ms: int, from_j: Optional[int] = None,
                     heads=()) -> dict:
    """Per period, from the public log: silence, late statements, equivocation, unexplained leaves
    of the deployment's key, and stall budget use per partition. Timing is the judge's."""
    cb = contract["body"] if "body" in contract else contract
    pk = bytes.fromhex(cb["pk"])
    vv = check_view(view, cb, heads)
    out: Dict[str, Any] = {"ok": False, "view": vv["reason"], "periods": 0, "silence": [], "late": [],
                           "equivocation": [], "unexplained": [], "stalls": {}, "over_budget": [],
                           "long_stalls": []}
    if not vv["ok"]:
        return out
    tau = min(int(now_ms), vv["time_ms"])
    J = _Periods(cb, pk, vv, bodies)
    j = int(from_j if from_j is not None else cb.get("effective_j", 0))
    E, W = int(cb["stall_budget"]), int(cb["window_periods"])
    stall_js: Dict[str, List[int]] = {}
    run: Dict[str, int] = {}
    while deadline_ms(j, cb) <= tau:
        out["periods"] += 1
        S, U, late = J.period(j)
        if late:
            out["late"].append(j)
        if U:
            out["unexplained"].append({"j": j, "leaves": U})
        if not S:
            out["silence"].append(j)
            run = {}
        elif len(S) > 1:
            out["equivocation"].append(j)
        else:
            parts = _d(next(iter(S.values())).get("parts"))
            for tp, p in parts.items():
                if isinstance(p, dict) and p.get("status") == "stall":
                    stall_js.setdefault(tp, []).append(j)
                    run[tp] = run.get(tp, 0) + 1
                    if run[tp] == E + 1:
                        out["long_stalls"].append({"partition": tp, "j": j})
                    in_window = sum(1 for x in stall_js[tp] if j - W < x <= j)
                    if in_window > E:
                        out["over_budget"].append({"partition": tp, "j": j, "used": in_window})
                else:
                    run[tp] = 0
        j += 1
    out["stalls"] = {tp: len(js) for tp, js in stall_js.items()}
    out["ok"] = not (out["silence"] or out["equivocation"] or out["over_budget"] or out["long_stalls"]
                     or out["unexplained"])
    return out


def _head_json(h) -> dict:
    return h if isinstance(h, dict) else tree_head_json(h)


def build_view(client, policy_text: str, heads: Iterable, frontier_size: int) -> dict:
    """The view a judge reads: the frontier at frontier_size, every leaf from there to the largest
    head, and the heads (dicts or TreeHead) with their cosignatures."""
    hs = [_head_json(h) for h in heads]
    top = max(int(h["size"]) for h in hs)
    lkh = client.log_key_hash.hex() if client.log_key_hash else None
    return {"policy": policy_text, "log_key_hash": lkh,
            "frontier": {"size": int(frontier_size), "nodes": client.frontier(int(frontier_size))},
            "leaves": client.leaves_range(int(frontier_size), top), "heads": hs}


def build_view_prefix(client, from_size: int, to_size: int, heads: Iterable = ()) -> dict:
    """An earlier frontier and the leaves up to a view's frontier: what a respondent adds to a
    complainant's view so that it reaches back over the budget window."""
    return {"frontier": {"size": int(from_size), "nodes": client.frontier(int(from_size))},
            "leaves": client.leaves_range(int(from_size), int(to_size)) if to_size > from_size else [],
            "heads": [_head_json(h) for h in heads]}


def _period_keys(store, dep: str) -> List[int]:
    pre = f"periods/{dep}/"
    out = set()
    for k in store.list_keys(pre):
        rest = k[len(pre):]
        if "/" not in rest and len(rest) >= 12 and rest[:12].isdigit():
            out.add(int(rest[:12]))
    return sorted(out)


def stored_statements(store, dep: str, js: Iterable[int]) -> Dict[str, Any]:
    """The statement bodies the store holds for these periods: under the period key, and the outage
    body when one was posted."""
    out: Dict[str, Any] = {}
    for j in js:
        items = []
        for key in (period_key(dep, j), outage_key(dep, j)):
            raw = store.get_object(key)
            if raw is not None:
                st = json.loads(raw)
                if st not in items:
                    items.append(st)
        if items:
            out[str(j)] = items[0] if len(items) == 1 else items
    return out


def stored_receipt_heads(store, dep: str, js: Iterable[int]) -> List[dict]:
    """The cosigned tree heads kept with the stored receipts: the checkpoints a view is built on."""
    out = []
    for j in js:
        raw = store.get_object(receipt_key(dep, j))
        if raw is not None:
            out.append(json.loads(raw)["tree_head"])
    return out


def _receipt(store, key: str) -> Optional[dict]:
    raw = store.get_object(key)
    return json.loads(raw) if raw is not None else None


def build_defense(store, pubkey: bytes, complaint: dict, contract: dict, js: Iterable[int], *,
                  k_salt: Optional[bytes] = None, signer=None, client=None, view: Optional[dict] = None,
                  spool_dir: Optional[str] = None) -> dict:
    """The honest respondent's defense from the store: statement bodies, contracts, receipt tree
    heads (also spooled ones), the tenant's openings and anchors, and the complaint's record with
    MMR proofs against every opened head. A signer regenerates outage bodies; a client adds a
    view_prefix reaching back over the budget window."""
    cb = contract["body"] if "body" in contract else contract
    dep = cb["dep"]
    c = _complaint(complaint, pubkey)
    js = sorted(set(list(js)) | set(_period_keys(store, dep)))
    d: Dict[str, Any] = {"bodies": stored_statements(store, dep, js), "openings": {}, "anchors": [],
                         "records": [], "blobs": {}, "unchk": {}, "segments": {}, "heads": [],
                         "contracts": [], "leaf_openings": []}
    if signer is not None:
        # An outage body may have been posted and never stored: regenerate one for every period up
        # to the view's latest head (or the last stored period). Its signature is deterministic.
        upto = max(js) + 1 if js else int(cb.get("effective_j") or 0)
        if isinstance(view, dict):
            try:
                vv = check_view(view, cb)
                if vv["ok"]:
                    upto = max(upto, (int(vv["time_ms"]) - int(cb["t0_ms"])) // (int(cb["period_s"]) * 1000))
            except (KeyError, TypeError, ValueError):
                pass
        for j in range(max(int(cb.get("effective_j") or 0), 0), upto + 1):
            o = sign_statement(signer, outage_statement(cb, j))
            cur = d["bodies"].get(str(j))
            items = cur if isinstance(cur, list) else [cur] if cur else []
            if o not in items:
                d["bodies"][str(j)] = items + [o] if items else o
    ver = 1
    while True:
        raw = store.get_object(contract_key(dep, ver))
        if raw is None:
            break
        d["contracts"].append(json.loads(raw))
        r = _receipt(store, contract_receipt_key(dep, ver))
        if r is not None:
            d["heads"].append(r["tree_head"])
        ver += 1
    d["heads"] += stored_receipt_heads(store, dep, js)
    for raw in spooled_receipts(spool_dir, spool_ns(cb)).values():
        head = json.loads(raw)["tree_head"]
        if head not in d["heads"]:
            d["heads"].append(head)
    if client is not None and isinstance(view, dict) and c is not None:
        try:
            d["view_prefix"] = _prefix_for(store, dep, cb, c, client, view)
        except Exception:
            pass
    if c is None:
        return d
    t = c["tenant_id"]
    chain = sorted((r for r in store.all(t) if _anchor_ok(r, pubkey)), key=lambda r: r.n)
    d["anchors"] = [r.to_json() for r in chain]
    for j in js:
        raw = store.get_object(opening_key(dep, j, t))
        if raw is not None:
            d["openings"][str(j)] = json.loads(raw)
        elif k_salt is not None:
            op = _rebuild_opening(store, dep, cb, j, t, k_salt, d["bodies"].get(str(j)))
            if op is not None:
                d["openings"][str(j)] = op
    # Every v2 record of the tenant, with the peaks in front of it.
    records: Dict[int, dict] = {}
    peaks_at: Dict[int, list] = {0: []}
    for a in chain:
        if a.peaks is not None:
            peaks_at[int(a.n)] = a.peaks
        if a.peaks_from is not None and a.seg:
            # The first v2 anchor after v1 records carries the peaks in front of its segment.
            peaks_at[int(a.seg["from"])] = a.peaks_from
        if a.v != 2 or not a.seg:
            continue
        raw = store.get_object(segment_key(t, a.n))
        if raw is None or hashlib.sha256(raw).hexdigest() != a.seg.get("sha256"):
            continue
        seg = json.loads(raw)
        d["segments"][str(a.n)] = seg
        for r in seg.get("records", []):
            records[int(r["seq"])] = r
    mine = [s for s, r in records.items() if _same_submission(c, r)]
    for s in mine:
        rec = records[s]
        need = {s}
        v = rec.get("verdict") or {}
        if isinstance(v.get("ref"), int):
            need.add(int(v["ref"]))
        raw_blob = (v.get("raw") or {}).get("blob")
        if raw_blob:
            b = store.get_object(raw_blob)
            if b is not None:
                d["blobs"][(v.get("raw") or {}).get("sha256")] = base64.b64encode(b).decode()
        if v.get("type") == "UNCHECKABLE":
            d["unchk"][str(s)] = _unchk_evidence(chain, d["segments"], s, cb)
        for op in d["openings"].values():
            n = int(op["n"])
            for i in sorted(need):
                if i >= n:
                    continue
                base = max((k for k in peaks_at if k <= i), default=None)
                if base is None or any(x not in records for x in range(base, n)):
                    continue
                proof = mmr_proof_sparse(peaks_at[base], [bytes.fromhex(record_hash(records[x]))
                                                          for x in range(base, n)], i, n)
                d["records"].append({"n": n, "index": i, "record": records[i], "proof": [list(p) for p in proof]})
    return d


def _rebuild_opening(store, dep, cb, j, t, k_salt, stmt) -> Optional[dict]:
    """The tenant's opening of period j's statement, rebuilt from the stored heads object, which is
    written before the statement."""
    for st in (stmt if isinstance(stmt, list) else [stmt] if stmt else []):
        agg = _d(_d(st.get("body")).get("agg"))
        if not isinstance(agg.get("root"), str):
            continue
        raw = store.get_object(agg_key(dep, j, agg["root"]))
        if raw is None:
            continue
        heads = json.loads(raw)
        root, size, ops = aggregate(k_salt, dep, j, heads["heads"], cb["agg_cap"], heads.get("st"))
        if root == agg["root"] and t in ops:
            return ops[t]
    return None


def _prefix_for(store, dep, cb, c, client, view) -> Optional[dict]:
    """A view_prefix reaching back before the budget window of the complaint's due period, from the
    stored receipt of the period just before the window, or the contract's receipt."""
    fs = int(view["frontier"]["size"])
    j0 = first_due_period(c["at_ms"], cb)
    start = max(j0 - int(cb["window_periods"]) + 1, int(cb.get("effective_j") or 0), 0)
    cands = []
    r = _receipt(store, receipt_key(dep, start - 1)) if start >= 1 else None
    if r is not None:
        cands.append(r["tree_head"])
    ver = 1
    while store.get_object(contract_key(dep, ver)) is not None:
        rc = _receipt(store, contract_receipt_key(dep, ver))
        if rc is not None:
            cands.append(rc["tree_head"])
        ver += 1
    cands = [h for h in cands if int(h["size"]) < fs]
    if not cands:
        return None
    head = max(cands, key=lambda h: int(h["size"]))
    return build_view_prefix(client, int(head["size"]), fs, [head])


def _unchk_evidence(chain: List[AnchorRecord], segments: dict, seq: int, cb: dict) -> dict:
    """The anchors from the last one before the verdict's window through the one covering it, with
    their segments, so the judge can count the window's UNCHECKABLE verdicts."""
    cover_i = next((k for k, a in enumerate(chain) if a.seg and a.seg.get("from", 0) <= seq < a.seg.get("to", 0)), None)
    if cover_i is None:
        return {}
    cover = chain[cover_i]
    start = float(cover.ts) * 1000 - int(cb["window_periods"]) * int(cb["period_s"]) * 1000
    first = 0
    for k in range(cover_i, -1, -1):
        if float(chain[k].ts) * 1000 < start:
            first = k
            break
    part = chain[first:cover_i + 1]
    return {"anchors": [a.to_json() for a in part], "segment": segments.get(str(cover.n)),
            "segments": {str(a.n): segments[str(a.n)] for a in part if str(a.n) in segments}}


__all__ = ["audit_statements", "check_view", "build_view", "build_view_prefix", "build_defense",
           "stored_statements", "stored_receipt_heads", "mmr_proof_sparse"]
