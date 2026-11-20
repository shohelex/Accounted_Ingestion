from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from crypto import records as R
from crypto.anchor_store import GENESIS_PREV, blob_key, segment_key
from tools.check_verdict import check_verdict

_LIMIT = 50

# Findings that do not make the audit fail. A GAP claims the broker never delivered its offsets,
# which only the broker's records can refute (broker_records).
WARNINGS = frozenset({"DUP_EVENT_ID", "GAP"})


def _finding(kind: str, **kw) -> dict:
    return dict(kind=kind, **kw)


def load_chain(store, tenant_id: str, pubkey: Optional[bytes]) -> Tuple[List[Any], List[dict]]:
    """The tenant's valid anchor chain from genesis, following prev_hash, and findings for every
    record that is not on it (bad hash or signature, a second record at a place: a fork)."""
    findings: List[dict] = []
    recs = sorted(store.all(tenant_id), key=lambda r: int(r.n))
    good = []
    for r in recs:
        ok = r.tenant_id == tenant_id
        try:
            ok = ok and r.verify_self() and (pubkey is None or r.verify_sig(pubkey))
        except Exception:
            ok = False
        if ok:
            good.append(r)
        else:
            findings.append(_finding("ANCHOR_BAD", tenant=tenant_id, n=int(r.n)))
    chain, head = [], GENESIS_PREV
    for r in good:
        if r.prev_hash == head and (not chain or int(r.n) > int(chain[-1].n)):
            chain.append(r)
            head = r.record_hash
        else:
            findings.append(_finding("OFF_CHAIN", tenant=tenant_id, n=int(r.n)))
    return chain, findings


def load_segments(store, tenant_id: str, chain: List[Any]) -> Tuple[List[Tuple[Any, List[dict]]], List[dict]]:
    """(anchor, its segment's records) for every v2 anchor of the chain whose segment verifies:
    present, hashing to seg.sha256, covering [from, to) = [previous n, n), and, when the previous
    anchor carries peaks, extending them to this anchor's root and peaks."""
    out: List[Tuple[Any, List[dict]]] = []
    findings: List[dict] = []
    prev_n, prev_peaks = 0, None
    for a in chain:
        seg = a.seg
        if a.v != 2 or not isinstance(seg, dict):
            prev_n, prev_peaks = int(a.n), None
            continue
        raw = store.get_object(segment_key(tenant_id, int(a.n)))
        if raw is None:
            findings.append(_finding("SEG_MISSING", tenant=tenant_id, n=int(a.n)))
            prev_n, prev_peaks = int(a.n), a.peaks
            continue
        if hashlib.sha256(raw).hexdigest() != seg.get("sha256"):
            findings.append(_finding("SEG_BAD", tenant=tenant_id, n=int(a.n), why="hash"))
            prev_n, prev_peaks = int(a.n), a.peaks
            continue
        try:
            body = json.loads(raw)
            records = list(body["records"])
            ok = (body.get("tenant_id") == tenant_id and int(body["from"]) == int(seg["from"])
                  and int(body["to"]) == int(seg["to"]) == int(a.n)
                  and int(seg["to"]) - int(seg["from"]) == len(records)
                  and int(seg["from"]) == prev_n)
        except Exception:
            ok, records = False, []
        if not ok:
            findings.append(_finding("SEG_BAD", tenant=tenant_id, n=int(a.n), why="range"))
            prev_n, prev_peaks = int(a.n), a.peaks
            continue
        peaks = a.peaks
        try:
            hashes = [R.record_hash(r) for r in records]
            if prev_peaks is not None:
                new_peaks, root = R.mmr_extend(prev_peaks, hashes)
                root_ok = root == a.root and [list(p) for p in new_peaks] == [list(p) for p in (peaks or [])]
            else:
                # The predecessor carries no peaks: check the peaks against the root and the count.
                root_ok = peaks is not None and R.mmr_root_hex(peaks) == a.root \
                    and R.mmr_size(peaks) == int(a.n)
        except Exception:
            root_ok = False
        if not root_ok:
            findings.append(_finding("ROOT_BAD", tenant=tenant_id, n=int(a.n)))
        out.append((a, records))
        prev_n, prev_peaks = int(a.n), peaks
    return out, findings


def _tp_key(pos: dict) -> str:
    return f"{pos['topic']}/{int(pos['p'])}"


def _watermarks(statements: Optional[dict]) -> Dict[str, int]:
    """W per partition from the latest period statement, keyed "topic/p"."""
    if not statements:
        return {}
    best_j, best = None, None
    for j, s in statements.items():
        body = s.get("body", s) if isinstance(s, dict) else None
        if not isinstance(body, dict) or not isinstance(body.get("parts"), dict):
            continue
        jj = int(body.get("j", j))
        if best_j is None or jj > best_j:
            best_j, best = jj, body
    if best is None:
        return {}
    return {tp: int(v["W"]) for tp, v in best["parts"].items() if isinstance(v, dict) and "W" in v}


def broker_reader(records: Optional[Iterable[dict]]):
    """check_verdict's broker argument from retained broker records ({"topic", "p", "o", ...}) and
    one {"topic", "p", "log_start", "hw"} marker per partition. Below the log start it answers None."""
    if records is None:
        return None
    held: Dict[Tuple[str, int], set] = defaultdict(set)
    start: Dict[Tuple[str, int], int] = {}
    for r in records:
        key = (str(r.get("topic")), int(r.get("p", -1)))
        if "o" in r:
            held[key].add(int(r["o"]))
        elif "log_start" in r:
            start[key] = int(r["log_start"])

    def read(topic, p, frm, to):
        key = (str(topic), int(p))
        if key not in start and key not in held:
            return None
        if int(frm) < start.get(key, 0):
            return None
        return sorted(o for o in held.get(key, ()) if int(frm) <= o < int(to))
    return read


def _contract_route_ok(route: Any, broker: dict) -> bool:
    """Is a MALFORMED(PARTITION) verdict's route the contract's partitioner and partition count?"""
    if not isinstance(route, dict):
        return False
    fn = route.get("fn")
    if broker.get("partitioner") is not None and fn != broker["partitioner"]:
        return False
    n = broker.get("partitions")
    if n is None:
        return True
    if fn in ("murmur2", "crc32"):
        return route.get("n") == int(n)
    return False


def audit_logs(logs: Dict[str, List[Tuple[Any, List[dict]]]], *,
               blobs: Callable[[str], Optional[bytes]], pubkey: Optional[bytes],
               contract: Optional[dict] = None, watermarks: Optional[Dict[str, int]] = None,
               findings_in: Optional[Dict[str, List[dict]]] = None,
               broker_records: Optional[Iterable[dict]] = None) -> Dict[str, Any]:
    """The audit over loaded anchored logs: tenant -> [(anchor, segment records), ...] in chain
    order. With broker_records (the broker's retained records) GAP verdicts are checked too."""
    broker = broker_reader(broker_records)
    gaps: Dict[str, List[List[int]]] = defaultdict(list)
    c = (contract or {}).get("body", contract or {})
    contract_broker = c.get("broker") or {}
    sys_t = c.get("system_tenant") or "acct-system"
    beta = int(c.get("unchk_budget", 10))
    window_s = int(c.get("window_periods", 7200)) * int(c.get("period_s", 360))
    dense = bool(contract_broker.get("dense", True))
    tenants_out: Dict[str, Any] = {}
    positions: Dict[Tuple[str, int], List[Tuple[str, int]]] = defaultdict(list)   # (tp, o) -> [(t, seq)]
    covered: Dict[str, List[Tuple[int, int]]] = defaultdict(list)               # tp -> [o, o_end)
    ok = True

    for t, segs in sorted(logs.items()):
        findings: List[dict] = list((findings_in or {}).get(t, ()))
        by_seq: Dict[int, dict] = {}
        verdicts: Counter = Counter()
        events = 0
        u = 0
        blob_bytes = 0
        unchk_ts: List[Tuple[float, int]] = []
        eids: Dict[str, List[int]] = defaultdict(list)
        last_by_tp: Dict[str, int] = {}
        tps = set()
        for a, records in segs:
            base = int(a.seg["from"])
            for i, rec in enumerate(records):
                seq = base + i
                if not R.is_v2(rec):
                    findings.append(_finding("NOT_V2", tenant=t, seq=seq))
                    continue
                if rec.get("seq") != seq:
                    findings.append(_finding("SEQ_NOT_DENSE", tenant=t, seq=seq, found=rec.get("seq")))
                if rec.get("tenant_id") != t:
                    findings.append(_finding("TENANT_MISMATCH", tenant=t, seq=seq))
                by_seq[seq] = rec
                pos = rec.get("pos") or {}
                tpk = _tp_key(pos)
                o = int(pos["o"])
                tps.add(tpk)
                if tpk in last_by_tp and o <= last_by_tp[tpk]:
                    findings.append(_finding("NONMONOTONE", tenant=t, seq=seq, tp=tpk, o=o,
                                             after=last_by_tp[tpk]))
                last_by_tp[tpk] = max(o, last_by_tp.get(tpk, o))
                positions[(tpk, o)].append((t, seq))
                if rec["kind"] == "event":
                    events += 1
                    covered[tpk].append((o, o + 1))
                    ev = rec.get("event") or {}
                    if ev.get("event_id"):
                        eids[ev["event_id"]].append(seq)
                    continue
                vt = (rec.get("verdict") or {}).get("type")
                verdicts[vt] += 1
                raw = rec["verdict"].get("raw")
                if isinstance(raw, dict) and isinstance(raw.get("len"), int):
                    blob_bytes += raw["len"]
                if vt == "GAP":
                    g = rec["verdict"].get("gap") or {}
                    covered[tpk].append((int(g.get("from", o)), int(g.get("to", o + 1))))
                    gaps[tpk].append([g.get("from"), g.get("to")])
                    findings.append(_finding("GAP", tenant=t, seq=seq, tp=tpk, **{"from": g.get("from"), "to": g.get("to")}))
                else:
                    covered[tpk].append((o, o + 1))
                if vt == "UNCHECKABLE":
                    u += 1
                    unchk_ts.append((float(a.ts or 0.0), seq))
                if vt == "MALFORMED" and (rec["verdict"] or {}).get("code") == "PARTITION" \
                        and not _contract_route_ok(rec["verdict"].get("route"), contract_broker):
                    findings.append(_finding("ROUTE_BAD", tenant=t, seq=seq,
                                             route=rec["verdict"].get("route")))
                ok_v, why = check_verdict(R.with_seq(rec, seq) if "seq" not in rec else rec,
                                          by_seq, blobs, pubkey=pubkey, broker=broker)
                if not ok_v:
                    findings.append(_finding("UNJUSTIFIED_VERDICT", tenant=t, seq=seq, type=vt, why=why))
            # the anchor's own claims about the records it covers
            if a.u is not None and int(a.u) != u:
                findings.append(_finding("U_BAD", tenant=t, n=int(a.n), claimed=int(a.u), counted=u))
            if records and R.is_v2(records[-1]):
                if a.pos_last != R.pos_last_of(records[-1]):
                    findings.append(_finding("POS_LAST_BAD", tenant=t, n=int(a.n)))
        if t != sys_t and len(tps) > 1:
            findings.append(_finding("MULTI_PARTITION", tenant=t, partitions=sorted(tps)))
        for eid, seqs in eids.items():
            if len(seqs) > 1:
                findings.append(_finding("DUP_EVENT_ID", tenant=t, event_id=eid, seqs=seqs[:_LIMIT]))
        # UNCHECKABLE verdicts in any window of window_s seconds, by their anchors' write time.
        unchk_ts.sort()
        lo = 0
        over: List[int] = []
        for hi, (ts, seq) in enumerate(unchk_ts):
            while unchk_ts[lo][0] <= ts - window_s:
                lo += 1
            if hi - lo + 1 > beta:
                over.append(seq)
        if over:
            findings.append(_finding("UNCHK_BUDGET", tenant=t, beta=beta, over_budget_seqs=over[:_LIMIT],
                                     count=len(over)))
        bad = [f for f in findings if f["kind"] not in WARNINGS]
        ok = ok and not bad
        tenants_out[t] = {"records": len(by_seq), "events": events, "verdicts": dict(verdicts),
                          "u": u, "blob_bytes": blob_bytes, "findings": findings[:_LIMIT], "finding_count": len(findings),
                          "ok": not bad}

    partitions: Dict[str, Any] = {}
    dup_by_tp: Dict[str, List[dict]] = defaultdict(list)
    for (tpk, o), who in positions.items():
        if len(who) > 1:
            dup_by_tp[tpk].append({"o": o, "records": [list(x) for x in who]})
    wm = watermarks or {}
    for tpk in sorted(set(covered) | set(dup_by_tp) | set(wm)):
        spans = sorted(covered.get(tpk, []))
        merged: List[List[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        holes: List[List[int]] = []
        w = wm.get(tpk)
        if dense and merged:
            upto = w if w is not None else merged[-1][1]
            for (s1, e1), (s2, _) in zip(merged, merged[1:]):
                if s2 < upto:
                    holes.append([e1, min(s2, upto)])
            if w is not None and merged[-1][1] < w:
                holes.append([merged[-1][1], w])
        partitions[tpk] = {"accounted_through": merged[0][1] if merged else None,
                           "first": merged[0][0] if merged else None,
                           "W": w, "holes": holes[:_LIMIT], "dup": dup_by_tp.get(tpk, [])[:_LIMIT],
                           "gaps": gaps.get(tpk, [])[:_LIMIT], "gaps_checked": broker is not None}
        if holes or dup_by_tp.get(tpk):
            ok = False
    return {"tenants": tenants_out, "partitions": partitions, "ok": bool(ok)}


def audit_accounting(store, pubkey: bytes, statements: Optional[dict], contract: Optional[dict],
                     broker_records: Optional[Iterable[dict]] = None,
                     tenants: Optional[Iterable[str]] = None) -> dict:
    """The accounting audit from the store: every tenant chain (or only `tenants`), its segments and
    blobs, and the watermarks of the latest period statement (statements: j -> {"body", "sig"})."""
    logs: Dict[str, List[Tuple[Any, List[dict]]]] = {}
    pre: Dict[str, List[dict]] = {}
    for t in (store.tenants() if tenants is None else list(tenants)):
        chain, f1 = load_chain(store, t, pubkey)
        segs, f2 = load_segments(store, t, chain)
        logs[t] = segs
        pre[t] = f1 + f2

    def blobs(sha: str) -> Optional[bytes]:
        try:
            return store.get_object(blob_key(sha))
        except Exception:
            return None

    return audit_logs(logs, blobs=blobs, pubkey=pubkey, contract=contract,
                      watermarks=_watermarks(statements), findings_in=pre,
                      broker_records=broker_records)


__all__ = ["audit_accounting", "audit_logs", "load_chain", "load_segments", "broker_reader", "WARNINGS"]
