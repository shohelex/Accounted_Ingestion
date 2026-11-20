from __future__ import annotations

import heapq
import json
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from crypto import records as R
from crypto.anchor_store import GENESIS_PREV, AnchorStore, blob_key, segment_key
from crypto.signing import verify
from tools.check_verdict import check_verdict

Pos = Tuple[str, int, int]
STATE_VERSION = 1


def _tpkey(topic: str, p: int) -> str:
    return f"{topic}/{int(p)}"


def anchored_view(store, pubkey: Optional[bytes], tenants: Optional[Iterable[str]] = None,
                  system_tenant: str = "acct-system") -> Dict[str, Any]:
    """The whole anchored view, verified: per tenant the signed chain from genesis up to its first
    break, with its segments. Returns {"index": {(topic, p, o): (tenant, seq, record)},
    "logs": {tenant: {seq: record}}, "heads": {tenant: AnchorRecord}, "findings": [...]}."""
    findings: List[dict] = []
    index: Dict[Pos, Tuple[str, int, dict]] = {}
    logs: Dict[str, Dict[int, dict]] = {}
    heads: Dict[str, Any] = {}
    for t in (list(tenants) if tenants is not None else store.tenants()):
        prev_hash, prev, peaks = GENESIS_PREV, None, []
        peaks_known = True
        log: Dict[int, dict] = {}
        last: Dict[str, int] = {}
        one_tp: Optional[str] = None
        for rec in sorted(store.all(t), key=lambda r: int(r.n)):
            ok = rec.tenant_id == t and rec.verify_self() and (pubkey is None or rec.verify_sig(pubkey))
            if not ok:
                findings.append({"type": "CHAIN_BAD", "tenant": t, "n": int(rec.n),
                                 "reason": "record fails its hash or signature"})
                continue
            if rec.prev_hash != prev_hash:
                if prev is not None and int(rec.n) == int(prev.n):
                    continue                           # a second record at one n: not in the chain
                findings.append({"type": "CHAIN_BAD", "tenant": t, "n": int(rec.n),
                                 "reason": "does not link to the previous record"})
                break
            if rec.seg is not None:
                raw = store.get_object(segment_key(t, rec.n))
                if raw is None:
                    findings.append({"type": "SEG_MISSING", "tenant": t, "n": int(rec.n)})
                    break
                if R.sha256_hex(raw) != rec.seg.get("sha256"):
                    findings.append({"type": "SEG_BAD", "tenant": t, "n": int(rec.n),
                                     "reason": "hash differs from the anchor record"})
                    break
                seg = json.loads(raw)
                recs = seg.get("records") or []
                frm = int(rec.seg["from"])
                if (int(seg.get("from", -1)), int(seg.get("to", -1))) != (frm, int(rec.seg["to"])) \
                        or int(rec.seg["to"]) != int(rec.n) or len(recs) != int(rec.n) - frm \
                        or frm != (int(prev.n) if prev is not None else 0):
                    findings.append({"type": "SEG_BAD", "tenant": t, "n": int(rec.n),
                                     "reason": "range differs from the chain"})
                    break
                if any(int(r.get("seq", -1)) != frm + k for k, r in enumerate(recs)):
                    findings.append({"type": "SEG_BAD", "tenant": t, "n": int(rec.n),
                                     "reason": "seq is not the leaf index"})
                    break
                pf = rec.peaks_from
                if pf is not None and (R.mmr_root_hex(pf) != (prev.root if prev is not None else "")
                                       or R.mmr_size(pf) != frm):
                    findings.append({"type": "ROOT_BAD", "tenant": t, "n": int(rec.n),
                                     "reason": "peaks_from do not give the predecessor's root"})
                    break
                if peaks_known or pf is not None or (prev is not None and prev.peaks is not None):
                    base = prev.peaks if (prev is not None and prev.peaks is not None) else \
                        (pf if pf is not None else peaks)
                    new_peaks, root = R.mmr_extend(base, [R.record_hash(r) for r in recs])
                    if root != rec.root:
                        findings.append({"type": "ROOT_BAD", "tenant": t, "n": int(rec.n)})
                        break
                    peaks, peaks_known = new_peaks, True
                else:
                    findings.append({"type": "ROOT_UNCHECKED", "tenant": t, "n": int(rec.n),
                                     "reason": "the predecessor is a v1 record without peaks"})
                    peaks_known = False
                for k, r in enumerate(recs):
                    seq = frm + k
                    log[seq] = r
                    p = r.get("pos") or {}
                    try:
                        key = (str(p["topic"]), int(p["p"]), int(p["o"]))
                    except (KeyError, TypeError, ValueError):
                        findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                         "reason": "record without a position"})
                        continue
                    tk = _tpkey(key[0], key[1])
                    one_tp = one_tp or tk
                    if tk != one_tp:
                        findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                         "reason": f"on {tk}, the log is on {one_tp}"})
                    if tk in last and key[2] <= last[tk]:
                        findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                         "reason": f"offset {key[2]} after {last[tk]} on {tk}"})
                    last[tk] = max(last.get(tk, -1), key[2])
                    if key in index and index[key][0] != t:
                        findings.append({"type": "DUPPOS_CROSS", "pos": list(key),
                                         "tenants": [index[key][0], t]})
                    index.setdefault(key, (t, seq, r))
            else:
                peaks_known = False                    # a v1 record: no segment, no peaks
            prev, prev_hash = rec, rec.record_hash
            heads[t] = rec
        logs[t] = log
    return {"index": index, "logs": logs, "heads": heads, "findings": findings}


def _latest_head_W(statements: Optional[dict], pubkey: Optional[bytes]) -> Tuple[Optional[int], Dict[str, int]]:
    """W per partition from the latest HEAD statement whose signature verifies."""
    best_j, parts = None, {}
    for j, st in (statements or {}).items():
        body = (st or {}).get("body") if isinstance(st, dict) else None
        if not isinstance(body, dict) or body.get("kind") != "head":
            continue
        if pubkey is not None and not verify(pubkey, st.get("sig"), R.NS_STMT + R.canon(body)):
            continue
        if best_j is None or int(body.get("j", j)) > best_j:
            best_j = int(body.get("j", j))
            parts = {k: int(v["W"]) for k, v in (body.get("parts") or {}).items()
                     if isinstance(v, dict) and v.get("W") is not None}
    return best_j, parts


def _records_after(store, tenant_id: str, n: int) -> list:
    if isinstance(store, AnchorStore):
        return store.records_after(tenant_id, n)
    return sorted((r for r in store.all(tenant_id) if int(r.n) > int(n)), key=lambda r: int(r.n))


def _extend_chain(store, pubkey: Optional[bytes], t: str, cp: Optional[dict],
                  findings: List[dict]) -> Tuple[List[dict], dict]:
    """The anchors of t written since its checkpoint entry cp, verified and linked to the chain;
    their segments are read later, per partition. Returns (plans, new checkpoint entry); a plan's
    base is the MMR peaks its segment must extend to root, or None when unknown."""
    cp = dict(cp or {"n": 0, "rh": GENESIS_PREV, "root": "", "peaks": [], "tp": None, "carry": []})
    prev_n, prev_hash, prev_root = int(cp["n"]), cp["rh"], cp.get("root", "")
    prev_peaks = cp.get("peaks")
    plans: List[dict] = []
    for rec in _records_after(store, t, int(cp["n"]) if cp.get("rh") != GENESIS_PREV else -1):
        ok = rec.tenant_id == t and rec.verify_self() and (pubkey is None or rec.verify_sig(pubkey))
        if not ok:
            findings.append({"type": "CHAIN_BAD", "tenant": t, "n": int(rec.n),
                             "reason": "record fails its hash or signature"})
            continue
        if rec.prev_hash != prev_hash:
            if prev_hash != GENESIS_PREV and int(rec.n) == prev_n:
                continue                               # a second record at one n: not in the chain
            findings.append({"type": "CHAIN_BAD", "tenant": t, "n": int(rec.n),
                             "reason": "does not link to the previous record"})
            break
        if rec.seg is not None:
            frm = int(rec.seg["from"])
            pf = rec.peaks_from
            if pf is not None:
                if R.mmr_root_hex(pf) != prev_root or R.mmr_size(pf) != frm:
                    findings.append({"type": "ROOT_BAD", "tenant": t, "n": int(rec.n),
                                     "reason": "peaks_from do not give the predecessor's root"})
                    break
                base = [list(p) for p in pf]
            else:
                base = prev_peaks
            if base is None:
                findings.append({"type": "ROOT_UNCHECKED", "tenant": t, "n": int(rec.n),
                                 "reason": "the predecessor is a v1 record without peaks"})
            pl = rec.pos_last or {}
            tp = _tpkey(pl["topic"], pl["p"]) if pl else None
            try:
                o_first, o_last = int(rec.seg["o_first"]), int(rec.seg["o_last"])
            except (KeyError, TypeError, ValueError):
                o_first = o_last = int((pl or {}).get("o", -1))
            plans.append({"n": int(rec.n), "frm": frm, "sha": rec.seg.get("sha256"), "base": base,
                          "check_root": base is not None, "root": rec.root,
                          "o_first": o_first, "o_last": o_last, "tp": tp, "prev_n": prev_n})
            cp["tp"] = cp.get("tp") or tp
            prev_peaks = [list(p) for p in rec.peaks] if rec.peaks is not None else None
        else:
            prev_peaks = None                         # a v1 record: no segment, no peaks
        prev_n, prev_hash, prev_root = int(rec.n), rec.record_hash, rec.root
    cp.update({"n": prev_n, "rh": prev_hash, "root": prev_root, "peaks": prev_peaks})
    return plans, cp


def plan_replay(store, pubkey: Optional[bytes], checkpoint: Optional[dict] = None
                ) -> Dict[str, Any]:
    """Extend every tenant's verified chain from the checkpoint (from genesis without one) and group
    the anchors whose segments must be read by partition. Returns {"parts": {tk: {tenant: [plan]}},
    "chains": {tenant: entry}, "findings": [...]}."""
    findings: List[dict] = []
    chains_in = ((checkpoint or {}).get("chains") or {})
    parts: Dict[str, Dict[str, List[dict]]] = {}
    chains: Dict[str, dict] = {}
    for t in store.tenants():
        cp = chains_in.get(t)
        plans, entry = _extend_chain(store, pubkey, t, cp, findings)
        carry = [dict(c, carry=True) for c in (cp or {}).get("carry") or []]
        tk = entry.get("tp")
        if tk is None:
            chains[t] = entry
            continue
        mine = carry + plans
        entry["carry"] = [{"n": p["n"], "frm": p["frm"], "sha": p["sha"], "o_first": p["o_first"],
                           "o_last": p["o_last"], "prev_n": p.get("prev_n")} for p in mine]
        chains[t] = entry
        if mine:
            parts.setdefault(tk, {})[t] = mine
    return {"parts": parts, "chains": chains, "findings": findings}


class _LazyLog:
    """seq -> anchored record of one tenant, read from the store on demand (the referents of DUP
    and COLLIDE verdicts). Only records of a verified anchor and segment are returned."""

    def __init__(self, store, tenant: str, pubkey: Optional[bytes], below: int):
        self.store, self.tenant, self.pubkey, self.below = store, tenant, pubkey, int(below)
        self._segments: "OrderedDict[int, Tuple[int, list]]" = OrderedDict()

    def get(self, seq, default=None):
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            return default
        if not 0 <= seq < self.below:
            return default
        for n, (frm, recs) in self._segments.items():
            if frm <= seq < n:
                return recs[seq - frm]
        rec = self.store.first_at_or_after(self.tenant, seq + 1)
        if rec is None or rec.seg is None or not rec.verify_self() \
                or (self.pubkey is not None and not rec.verify_sig(self.pubkey)):
            return default
        raw = self.store.get_object(segment_key(self.tenant, rec.n))
        if raw is None or R.sha256_hex(raw) != rec.seg.get("sha256"):
            return default
        recs = json.loads(raw).get("records") or []
        frm = int(rec.seg["from"])
        self._segments[int(rec.n)] = (frm, recs)
        while len(self._segments) > 16:
            self._segments.popitem(last=False)
        return recs[seq - frm] if 0 <= seq - frm < len(recs) else default

    def __contains__(self, seq):
        return self.get(seq) is not None


def _tenant_stream(store, t: str, plans: List[dict], tk: str, findings: List[dict]) -> Iterator[tuple]:
    """(o, to, tenant, seq, record) for every record of t's plans on partition tk, each segment
    verified against its anchor (or the hash a carried plan holds). Stops at the first failure."""
    last_o = None
    for a in plans:
        raw = store.get_object(segment_key(t, a["n"]))
        if raw is None:
            findings.append({"type": "SEG_MISSING", "tenant": t, "n": a["n"]})
            return
        if R.sha256_hex(raw) != a["sha"]:
            findings.append({"type": "SEG_BAD", "tenant": t, "n": a["n"],
                             "reason": "hash differs from the anchor record"})
            return
        seg = json.loads(raw)
        recs = seg.get("records") or []
        frm = int(a["frm"])
        if (int(seg.get("from", -1)), int(seg.get("to", -1))) != (frm, a["n"]) \
                or len(recs) != a["n"] - frm \
                or (a.get("prev_n") is not None and frm != int(a["prev_n"])):
            findings.append({"type": "SEG_BAD", "tenant": t, "n": a["n"],
                             "reason": "range differs from the chain"})
            return
        if any(int(r.get("seq", -1)) != frm + k for k, r in enumerate(recs)):
            findings.append({"type": "SEG_BAD", "tenant": t, "n": a["n"],
                             "reason": "seq is not the leaf index"})
            return
        if a.get("check_root") and not a.get("carry"):
            _, root = R.mmr_extend(a["base"], [R.record_hash(r) for r in recs])
            if root != a["root"]:
                findings.append({"type": "ROOT_BAD", "tenant": t, "n": a["n"]})
                return
        # Records are yielded in offset order, as the merge needs. A record at or below an offset an
        # earlier segment already yielded is reported and left out of the join.
        seg_last, ready = last_o, []
        for k, r in enumerate(recs):
            seq = frm + k
            p = r.get("pos") or {}
            try:
                o = int(p["o"])
                here = _tpkey(p["topic"], p["p"])
            except (KeyError, TypeError, ValueError):
                findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                 "reason": "record without a position"})
                continue
            if here != tk:
                findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                 "reason": f"on {here}, the log is on {tk}"})
                continue
            if seg_last is not None and o <= seg_last:
                findings.append({"type": "NONMONOTONE", "tenant": t, "seq": seq,
                                 "reason": f"offset {o} after {seg_last} on {tk}"})
            seg_last = o if seg_last is None else max(seg_last, o)
            if last_o is not None and o <= last_o:
                continue
            to = o + 1
            v = r.get("verdict") if r.get("kind") == "verdict" else None
            if isinstance(v, dict) and v.get("type") == "GAP" and isinstance(v.get("gap"), dict):
                try:
                    to = max(to, int(v["gap"]["to"]))
                except (TypeError, ValueError, KeyError):
                    pass
            ready.append((o, to, t, seq, r))
        ready.sort(key=lambda x: (x[0], x[3]))
        for item in ready:
            yield item
        last_o = seg_last


class _NoSource:
    """The consumer's source where the auditor has none: the route comes from the contract alone."""

    def partitions_for_topic(self, topic):
        return None


def _route_for(contract: dict, topic: str):
    """The partitioner the writer applies, from the contract."""
    from processing.sources import route_for
    body = contract.get("body", contract) if isinstance(contract, dict) else {}
    try:
        return route_for(_NoSource(), {"body": body}, topic)
    except Exception:
        return None


def _bound(rec: dict, d, raw: Optional[bytes]) -> Tuple[bool, str]:
    """Is the anchored verdict rec the verdict of this broker record? Its tag, event and blob hash
    must be the record's own; a GAP verdict here is contradicted by the record."""
    v = rec.get("verdict") or {}
    if v.get("type") == "GAP":
        return False, "a GAP verdict at a position that holds a broker record"
    ref = v.get("raw")
    if isinstance(ref, dict):
        b = raw if raw is not None else b""
        if ref.get("sha256") != R.sha256_hex(b) or ref.get("len") != len(b):
            return False, "the verdict's blob is not this broker record's bytes"
    if d.sub_valid:
        if rec.get("sub") != d.sub:
            return False, "the verdict's tag is not this broker record's"
    elif rec.get("sub") is not None:
        return False, "a tag is embedded for a record that carries none"
    ev = rec.get("event")
    if ev is not None and ev != d.event:
        return False, "the verdict's event is not this broker record's"
    return True, ""


class _Density:
    """On a dense partition, [first, W) of the latest signed HEAD must be covered by anchored
    records (a GAP verdict covers its range). Fed in offset order; upto is kept in the checkpoint."""

    def __init__(self, first: Optional[int], upto: Optional[int], W: Optional[int]):
        self.first, self.W = first, W
        self.upto = upto if upto is not None else first
        self.missing: List[List[int]] = []

    def feed(self, o: int, to: int) -> None:
        if self.upto is None:
            self.upto = o                           # the first anchored offset (no contract value)
        if to <= self.upto:
            return
        if o > self.upto:
            if self.W is None or self.upto >= self.W:
                return
            end = min(o, self.W)
            self.missing.append([self.upto, end - 1])
            if o > self.W:
                self.upto = self.W
                return
        self.upto = max(self.upto, to)

    def close(self) -> None:
        if self.W is not None and self.upto is not None and self.upto < self.W:
            self.missing.append([self.upto, self.W - 1])
            self.upto = self.W


def replay_partition(tk: str, broker_iter: Iterable[dict], marker: Optional[dict], store,
                     plans_by_tenant: Dict[str, List[dict]], contract: dict, pubkey: bytes,
                     now_ms: int, audit_from: Optional[int], density_state: Optional[dict] = None,
                     W: Optional[int] = None, head_j: Optional[int] = None) -> dict:
    """One partition's broker records (ascending offsets) against the merged anchored records of
    its tenants. Returns a partial report for merge_reports. audit_from advances only over offsets
    the read delivered."""
    from processing import decide as D
    body = contract.get("body", contract) if isinstance(contract, dict) else {}
    theta_ms = int(body.get("theta_s", 300)) * 1000
    delta_ms = int(body.get("delta_s", 45)) * 1000
    system = str(body.get("system_tenant", "acct-system"))
    broker_cfg = body.get("broker") or {}
    dense = bool(broker_cfg.get("dense", False))
    topic, _, part = tk.rpartition("/")
    p = int(part)
    route = _route_for(contract, topic)
    sys_log = f"{system}-{p}"
    counts: Dict[str, int] = {}
    findings: List[dict] = []
    complaints: List[dict] = []
    lo = int(audit_from) if audit_from is not None else None
    first_acct = (broker_cfg.get("first_acct_offset") or {}).get(tk)
    dstate = density_state or {}
    density = _Density(int(first_acct) if first_acct is not None else dstate.get("first"),
                       dstate.get("upto"), W) if dense else None
    density_from = "contract" if first_acct is not None else "anchored"
    stamp = {"v": 1, "contract": contract if isinstance(contract, dict) and "body" in contract else None}

    def bump(k):
        counts[k] = counts.get(k, 0) + 1

    streams = [_tenant_stream(store, t, plans, tk, findings) for t, plans in sorted(plans_by_tenant.items())]
    anchored = heapq.merge(*streams, key=lambda x: x[0])
    pending_hits: Dict[int, List[tuple]] = {}
    gaps: List[Tuple[int, int]] = []                 # anchored GAP ranges seen
    nxt: Optional[tuple] = None
    exhausted = False

    def pull_until(o: Optional[int]) -> None:
        nonlocal nxt, exhausted
        while True:
            if nxt is None and not exhausted:
                nxt = next(anchored, None)
                exhausted = nxt is None
            e = nxt
            if e is None or (o is not None and e[0] > o):
                return
            nxt = None
            if density is not None:
                density.feed(e[0], e[1])
            if e[1] > e[0] + 1:
                gaps.append((e[0], e[1]))
            if lo is not None and e[0] < lo:
                continue
            pending_hits.setdefault(e[0], []).append(e)

    log_start = hw = None
    if marker is not None:
        log_start, hw = int(marker["log_start"]), int(marker["hw"])
    start = max(lo if lo is not None else -1, log_start if log_start is not None else -1)
    first_pending: Optional[int] = None
    first_unread: Optional[int] = None
    # dense: the next offset the read must deliver
    expect: Optional[int] = start if (dense and start >= 0) else None
    last_read: Optional[int] = None
    n_records = 0
    gap_entries: List[tuple] = []                   # anchored GAPs with no broker record at `from`
    gap_held: Dict[Tuple[int, int], List[int]] = {}  # offsets read inside each GAP's range

    def in_gap(a: int, b: int) -> bool:
        return any(g0 <= a and b <= g1 for g0, g1 in gaps)

    def phantom(o2: int, entries: List[tuple], reason: str) -> None:
        for (_, to, t, seq, r) in entries:
            v = r.get("verdict") if r.get("kind") == "verdict" else None
            if isinstance(v, dict) and v.get("type") == "GAP":
                gap_entries.append((o2, to, t, seq, r))   # checked against the read at the end
                continue
            findings.append({"type": "PHANTOM", "pos": [topic, p, o2], "tenant": t, "seq": seq,
                             "reason": reason})

    def flush_below(o: int) -> None:
        for o2 in sorted(k for k in pending_hits if k < o):
            ents = pending_hits.pop(o2)
            if log_start is not None and o2 < log_start:
                continue
            phantom(o2, ents, "no broker record at this position")

    for r in broker_iter:
        o = int(r["o"])
        if o < start:
            continue
        if dense:
            if expect is not None and o > expect and first_unread is None:
                pull_until(o)
                if not in_gap(expect, o):
                    first_unread = expect           # an offset inside the read was not delivered
            expect = o + 1
        last_read = o
        n_records += 1
        pull_until(o)
        for g0, g1 in gaps:
            if g0 <= o < g1:
                gap_held.setdefault((g0, g1), []).append(o)
        flush_below(o)
        hits = pending_hits.pop(o, [])
        if len({h[2] for h in hits}) > 1:
            findings.append({"type": "DUPPOS_CROSS", "pos": [topic, p, o],
                             "tenants": sorted({h[2] for h in hits})})
        raw = r.get("value")
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        d = D.decode_and_authenticate(raw, pubkey)
        expected_log = D.log_tenant(d, sys_log, p, route)
        hit = next((h for h in hits if h[2] == expected_log), None)
        recent = int(r.get("bt_ms", 0)) > now_ms - theta_ms - delta_ms
        pos = [topic, p, o]
        if not d.sub_valid:
            if hit is None:
                if hits:
                    findings.append({"type": "UNAUTH_MISSING", "pos": pos,
                                     "reason": f"an unauthenticated record is accounted in "
                                               f"{hits[0][2]}'s log, not in {expected_log}"})
                    bump("UNAUTH_MISSING")
                elif recent:
                    bump("PENDING")
                    first_pending = o if first_pending is None else min(first_pending, o)
                else:
                    bump("UNAUTH_MISSING")
                    findings.append({"type": "UNAUTH_MISSING", "pos": pos,
                                     "reason": "no verdict at the position of an unauthenticated record"})
                continue
            rec = hit[4]
            if rec.get("kind") != "verdict":
                bump("UNAUTH_MISSING")
                findings.append({"type": "UNAUTH_MISSING", "pos": pos,
                                 "reason": "an event record at an unauthenticated position"})
                continue
            ok, why = _bound(rec, d, raw)
            if ok:
                ok, why = _run_check(rec, store, hit, pubkey)
            if ok:
                bump("UNAUTH_OK")
            else:
                bump("UNAUTH_MISSING")
                findings.append({"type": "UNJUSTIFIED", "pos": pos, "tenant": hit[2], "seq": hit[3],
                                 "why": why})
            continue
        acct = dict(d.sub, v=1)
        complaint = {"sub_record": {"acct": acct, "tenant_id": d.tenant_id, "event_id": d.event_id,
                                    "pos": {"topic": topic, "p": p, "o": o}}}
        if hit is None:
            if not hits and recent:
                bump("PENDING")
                first_pending = o if first_pending is None else min(first_pending, o)
                continue
            bump("MISSING")
            complaints.append(dict(stamp, **{"class": "MISSING", "complaint": complaint}))
            for h in hits:
                findings.append({"type": "PHANTOM", "pos": pos, "tenant": h[2],
                                 "reason": f"the record of {expected_log} is anchored in {h[2]}'s log"})
            continue
        rec = hit[4]
        if rec.get("kind") == "event":
            if R.content_hash(rec.get("event") or {}) == d.sub.get("leaf_hash") \
                    and rec.get("sub") == d.sub:
                bump("OK")
            else:
                bump("MISMATCH")
                complaints.append(dict(stamp, **{"class": "MISMATCH", "complaint": complaint,
                                                 "found": {"tenant": hit[2], "seq": hit[3]}}))
            continue
        ok, why = _bound(rec, d, raw)
        if ok:
            ok, why = _run_check(rec, store, hit, pubkey)
        if ok:
            bump("OK_VERDICT")
        else:
            bump("UNJUSTIFIED")
            complaints.append(dict(stamp, **{"class": "UNJUSTIFIED", "complaint": complaint,
                                             "found": {"tenant": hit[2], "seq": hit[3], "why": why}}))
            findings.append({"type": "UNJUSTIFIED", "pos": pos, "tenant": hit[2], "seq": hit[3],
                             "why": why})

    # How far the read went. A streaming reader sets "complete" on its marker when it stops, so it
    # is read here, after the records.
    complete = None
    if marker is not None and marker.get("complete") is not None:
        complete = bool(marker["complete"])
    if hw is not None:
        if dense:
            if expect is None:
                reached = start if start >= 0 else (log_start or 0)
            else:
                reached = expect
            if reached < hw and first_unread is None and complete is not True:
                first_unread = reached
        else:
            done = complete if complete is not None else (last_read is not None and last_read + 1 >= hw)
            if not done and first_unread is None:
                first_unread = (last_read + 1) if last_read is not None else max(start, log_start or 0)
    read_to = first_unread if first_unread is not None else hw
    # The anchored records above the last record read.
    pull_until(None)
    for o2 in sorted(pending_hits):
        ents = pending_hits[o2]
        if log_start is not None and o2 < log_start:
            continue
        if read_to is not None and o2 < read_to:
            phantom(o2, ents, "no broker record at this position")
    # Where the read covered a GAP's range, the records it delivered there are the broker's answer.
    for (o2, to, t, seq, r) in gap_entries:
        covered = o2 >= start and read_to is not None and to <= read_to
        held = sorted(gap_held.get((o2, to), []))

        def broker(topic_, p_, frm, to_, _held=held, _covered=covered):
            return [x for x in _held if frm <= x < to_] if _covered else None
        ok, why = _run_check(r, store, (None, None, t, seq, r), pubkey, broker=broker)
        if not ok:
            findings.append({"type": "UNJUSTIFIED", "pos": [topic, p, o2], "tenant": t, "seq": seq,
                             "why": why})
    if density is not None:
        density.close()
        for m in density.missing:
            findings.append({"type": "HOLE", "partition": tk, "missing": [m], "W": W,
                             "head_j": head_j, "from": density_from})
    marks = [x for x in (first_pending, first_unread) if x is not None]
    if hw is not None:
        marks.append(hw)
    elif last_read is not None:
        marks.append(last_read + 1)
    new_from = min(marks) if marks else lo
    wm: Dict[str, Any] = {}
    if marker is not None:
        wm.update({"log_start": log_start, "hw": hw})
    if W is not None:
        wm.update({"W": W, "head_j": head_j})
    if dense:
        wm["density_from"] = density_from
    return {"counts": counts, "findings": findings, "complaints": complaints,
            "audit_from": {tk: new_from} if new_from is not None else {}, "records": n_records,
            "watermarks": {tk: wm} if wm else {},
            "incomplete": [tk] if first_unread is not None and first_unread != first_pending else [],
            "density": ({tk: {"first": density.first, "upto": density.upto}} if density is not None
                        and density.upto is not None else {})}


def _run_check(rec: dict, store, hit: tuple, pubkey: bytes,
               broker: Optional[Callable] = None) -> Tuple[bool, str]:
    """check_verdict on an anchored verdict, with the referents read from the store on demand and,
    for a GAP, the broker's answer from this run's read."""

    def blobs(sha: str) -> Optional[bytes]:
        return store.get_object(blob_key(sha))
    kw = {"pubkey": pubkey}
    if broker is not None:
        kw["broker"] = broker
    try:
        return check_verdict(rec, _LazyLog(store, hit[2], pubkey, hit[3]), blobs, **kw)
    except Exception as e:
        return False, f"check_verdict raised {type(e).__name__}"


def merge_reports(parts: List[dict], plan: dict, checkpoint: Optional[dict], audit_from: Dict[str, int],
                  t_start: float) -> dict:
    counts: Dict[str, int] = {}
    findings = list(plan["findings"])
    complaints: List[dict] = []
    watermarks: Dict[str, dict] = {}
    new_from = dict(audit_from)
    incomplete: List[str] = []
    density = dict(((checkpoint or {}).get("density") or {}))
    n = 0
    for rep in parts:
        for k, v in rep["counts"].items():
            counts[k] = counts.get(k, 0) + v
        findings += rep["findings"]
        complaints += rep["complaints"]
        watermarks.update(rep["watermarks"])
        new_from.update(rep["audit_from"])
        incomplete += rep["incomplete"]
        density.update(rep.get("density") or {})
        n += rep["records"]
    # The next run reads again every anchor that can hold a position at or above its audit_from,
    # or above the end of the partition's accounted prefix, where the density check resumes.
    chains = {}
    for t, entry in plan["chains"].items():
        e = dict(entry)
        tk = e.get("tp")
        marks = [x for x in (new_from.get(tk), (density.get(tk) or {}).get("upto")) if x is not None] \
            if tk is not None else []
        keep_from = min(marks) if marks else None
        if keep_from is not None:
            e["carry"] = [c for c in e.get("carry") or [] if int(c["o_last"]) >= int(keep_from)]
        chains[t] = e
    dur = time.perf_counter() - t_start
    return {"counts": counts, "findings": findings, "complaints": complaints,
            "watermarks": watermarks, "audit_from": new_from, "records": n,
            "incomplete": sorted(set(incomplete)),
            "checkpoint": {"v": STATE_VERSION, "audit_from": new_from, "chains": chains,
                           "density": density},
            "duration_s": dur, "records_per_s": (n / dur) if dur > 0 else None}


def split_by_partition(broker_records: Iterable[dict]) -> Tuple[Dict[str, List[dict]], Dict[str, dict]]:
    """{tk: records in offset order}, {tk: marker} from a flat list of records and markers."""
    recs: Dict[str, List[dict]] = {}
    markers: Dict[str, dict] = {}
    for m in broker_records:
        tk = _tpkey(m["topic"], m["p"])
        if "o" not in m:
            if "hw" in m:
                markers[tk] = m
            continue
        recs.setdefault(tk, []).append(m)
    for lst in recs.values():
        lst.sort(key=lambda r: int(r["o"]))
    return recs, markers


def audit_broker_replay(broker_records: Iterable[dict], store, statements: Optional[dict],
                        contract: dict, pubkey: bytes, now_ms: int,
                        audit_from: Optional[Dict[str, int]] = None,
                        checkpoint: Optional[dict] = None) -> dict:
    """The replay audit. broker_records: {"topic", "p", "o", "bt_ms", "key", "value"} records and
    {"topic", "p", "log_start", "hw"[, "complete"]} partition markers. checkpoint: the previous
    report's "checkpoint", for an incremental run. Each complaint is a claim for tools/check_breach.py."""
    t_start = time.perf_counter()
    audit_from = dict(audit_from if audit_from is not None else ((checkpoint or {}).get("audit_from") or {}))
    plan = plan_replay(store, pubkey, checkpoint)
    recs, markers = split_by_partition(broker_records)
    head_j, head_W = _latest_head_W(statements, pubkey)
    density = (checkpoint or {}).get("density") or {}
    tks = sorted(set(recs) | set(markers) | set(plan["parts"]))
    reports = []
    for tk in tks:
        if tk not in recs and tk not in markers:
            # Not in the broker read: nothing to replay, but segments and density are still checked.
            reports.append(replay_partition(tk, [], None, store, plan["parts"].get(tk, {}), contract,
                                            pubkey, now_ms, audit_from.get(tk), density.get(tk),
                                            head_W.get(tk), head_j))
            reports[-1]["audit_from"] = {}
            continue
        reports.append(replay_partition(tk, recs.get(tk, []), markers.get(tk), store,
                                        plan["parts"].get(tk, {}), contract, pubkey, now_ms,
                                        audit_from.get(tk), density.get(tk), head_W.get(tk), head_j))
    for tk, W in head_W.items():
        if tk not in tks:
            reports.append({"counts": {}, "findings": [], "complaints": [], "audit_from": {},
                            "records": 0, "incomplete": [], "watermarks": {tk: {"W": W, "head_j": head_j}}})
    return merge_reports(reports, plan, checkpoint, audit_from, t_start)


__all__ = ["anchored_view", "audit_broker_replay", "plan_replay", "replay_partition",
           "merge_reports", "split_by_partition"]
