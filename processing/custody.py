from __future__ import annotations

import asyncio
import bisect
import json
import logging
import weakref
from typing import Dict, Iterable, List, Optional, Tuple

from crypto import records as R
from crypto.anchor_store import segment_key

logger = logging.getLogger(__name__)

FETCHED, APPENDED, COVERED = "fetched", "appended", "covered"


class CoverageMismatch(Exception):
    """The store's anchored record at a seq is not the template this writer appended there."""

    def __init__(self, tenant_id: str, seq: int, expected: str, found: Optional[str]):
        super().__init__(f"coverage mismatch for {tenant_id} at seq {seq}: expected {expected}, "
                         f"anchored {found}")
        self.tenant_id, self.seq, self.expected, self.found = tenant_id, seq, expected, found


def _tp(tp) -> Tuple[str, int]:
    return (str(tp[0]), int(tp[1]))


def _alarm(kind: str, message: str) -> None:
    logger.error(f"INTEGRITY ALARM [{kind}]: {message}")


class _Entry:
    __slots__ = ("tenant", "state", "seq", "rh", "to")

    def __init__(self, tenant: str, to: int):
        self.tenant, self.state, self.seq, self.rh, self.to = tenant, FETCHED, None, None, int(to)


class CoverageTracker:
    """What this writer fetched, appended and has seen covered, per partition. Kept in memory,
    not in the database; a crash loses it, and the new owner replays from the committed offset.

    dense: the source's offsets are consecutive (Kafka), so a commit also needs every offset
    between the committed one and the commit to have an entry.
    """

    def __init__(self, dense: bool = False):
        self.dense = bool(dense)
        self._by_tp: Dict[Tuple[str, int], Dict[int, _Entry]] = {}
        # The committed offset as this writer knows it (before the first commit, where the first
        # fetch started). Kept across reset(), dropped on revoked().
        self._floor: Dict[Tuple[str, int], int] = {}
        # tenant -> {seq: (tp, offset)} for entries waiting for an anchor
        self._waiting: Dict[str, Dict[int, Tuple[Tuple[str, int], int]]] = {}
        self._anchored_n: Dict[str, int] = {}                  # highest anchor n seen per tenant
        # tenant -> [(from, to, record hashes)] of the last anchors seen, for records whose seq
        # arrives after their anchor (add_records anchors before it returns)
        self._recent: Dict[str, List[Tuple[int, int, List[str]]]] = {}
        # A mismatch found while noting, raised again by refresh().
        self._mismatch: Optional[CoverageMismatch] = None
        self.stats = {"segment_gets": 0, "own_anchors": 0, "covered": 0, "mismatches": 0,
                      "ignored_notes": 0}

    def note_fetched(self, tp, offset: int, tenant_id: str, upto: Optional[int] = None) -> None:
        """A record fetched at offset (or a GAP verdict for [offset, upto))."""
        tp = _tp(tp)
        offset = int(offset)
        if offset < self._floor.get(tp, offset):
            return
        self._floor.setdefault(tp, offset)
        e = self._by_tp.setdefault(tp, {}).get(offset)
        if e is None:
            self._by_tp[tp][offset] = _Entry(tenant_id, upto if upto is not None else offset + 1)
        elif upto is not None:
            e.to = max(e.to, int(upto))

    def _entry(self, tp, offset: int) -> Optional[_Entry]:
        e = (self._by_tp.get(tp) or {}).get(int(offset))
        if e is None:
            # Not fetched in the current run of this partition: the note must not create coverage.
            self.stats["ignored_notes"] += 1
        return e

    def _raise(self, m: CoverageMismatch) -> None:
        self.stats["mismatches"] += 1
        if self._mismatch is None:
            self._mismatch = m
        raise m

    def note_appended(self, tp, offset: int, tenant_id: str, seq: int, record_hash: str) -> None:
        tp = _tp(tp)
        e = self._entry(tp, offset)
        if e is None or e.state == COVERED:
            return
        prior = self._waiting.setdefault(tenant_id, {}).get(int(seq))
        if prior is not None and prior != (tp, int(offset)):
            # Two of this writer's records got one seq: the tail lost the first.
            _alarm("coverage", f"{tenant_id} seq {seq} given to {tp}:{offset}, already {prior}")
            self._raise(CoverageMismatch(tenant_id, int(seq), str(record_hash), None))
        e.tenant, e.state, e.seq, e.rh = tenant_id, APPENDED, int(seq), str(record_hash)
        self._waiting[tenant_id][int(seq)] = (tp, int(offset))
        # The anchor may already be here: add_records writes it before it returns the seqs.
        for frm, to, hashes in self._recent.get(tenant_id, []):
            if frm <= int(seq) < to:
                if hashes[int(seq) - frm] != e.rh:
                    _alarm("coverage", f"{tenant_id} seq {seq} at {tp}:{offset}: anchored "
                                       f"{hashes[int(seq) - frm]}, appended {e.rh}")
                    self._raise(CoverageMismatch(tenant_id, int(seq), e.rh, hashes[int(seq) - frm]))
                self._cover(tp, int(offset), e)
                break

    def note_verified(self, tp, offset: int) -> None:
        tp = _tp(tp)
        e = self._entry(tp, offset)
        if e is not None:
            self._cover(tp, int(offset), e)

    def _cover(self, tp, offset: int, e: _Entry) -> None:
        if e.state != COVERED:
            e.state = COVERED
            self.stats["covered"] += 1
            if e.seq is not None:
                self._waiting.get(e.tenant, {}).pop(e.seq, None)

    def note_anchor(self, tenant_id: str, rec, segment: Optional[dict]) -> None:
        """An anchor this process wrote, with its segment. Raises CoverageMismatch if the segment
        disagrees with what this writer appended."""
        if segment is None or rec.seg is None:
            return
        self.stats["own_anchors"] += 1
        self._apply_segment(tenant_id, rec, segment)

    def _apply_segment(self, tenant_id: str, rec, segment: dict) -> None:
        frm, to = int(rec.seg["from"]), int(rec.seg["to"])
        self._anchored_n[tenant_id] = max(self._anchored_n.get(tenant_id, 0), int(rec.n))
        waiting = self._waiting.get(tenant_id, {})
        recs = segment.get("records") or []
        recent = self._recent.setdefault(tenant_id, [])
        recent.append((frm, to, [R.record_hash(r) for r in recs]))
        del recent[:-4]                                     # the last few anchors are enough
        for seq in sorted(s for s in waiting if frm <= s < to):
            tp, off = waiting[seq]
            e = self._by_tp.get(tp, {}).get(off)
            if e is None:
                waiting.pop(seq, None)
                continue
            found = R.record_hash(recs[seq - frm]) if 0 <= seq - frm < len(recs) else None
            if found != e.rh:
                _alarm("coverage", f"{tenant_id} seq {seq} at {tp}:{off}: anchored {found}, "
                                   f"appended {e.rh}")
                self._raise(CoverageMismatch(tenant_id, seq, e.rh, found))
            self._cover(tp, off, e)

    async def refresh(self, store, pubkey: bytes) -> None:
        """Poll the store for anchors covering the records still waiting. Raises CoverageMismatch
        on a disagreement, first any noted earlier."""
        m, self._mismatch = self._mismatch, None
        if m is not None:
            raise m
        for tenant_id in [t for t, w in self._waiting.items() if w]:
            while self._waiting.get(tenant_id):
                lowest = min(self._waiting[tenant_id])
                rec = await asyncio.to_thread(store.first_at_or_after, tenant_id, lowest + 1)
                if rec is None or rec.seg is None:
                    break
                if not (rec.verify_self() and (pubkey is None or rec.verify_sig(pubkey))):
                    break
                raw = await asyncio.to_thread(store.get_object, segment_key(tenant_id, rec.n))
                self.stats["segment_gets"] += 1
                if raw is None or R.sha256_hex(raw) != rec.seg.get("sha256"):
                    _alarm("coverage", f"segment of {tenant_id} at n={rec.n} missing or not the one "
                                       f"its anchor names")
                    break
                segment = json.loads(raw)
                if int(rec.seg["from"]) > lowest:
                    # The first anchor after `lowest` starts above it: the chain lacks the record.
                    e_tp, e_off = self._waiting[tenant_id][lowest]
                    e = self._by_tp.get(e_tp, {}).get(e_off)
                    self.stats["mismatches"] += 1
                    raise CoverageMismatch(tenant_id, lowest, e.rh if e else "", None)
                self._apply_segment(tenant_id, rec, segment)

    def committable(self, tp) -> Optional[int]:
        """The offset to commit for tp: the end of the unbroken run of covered entries that starts
        at the committed offset (a commit releases every record below it). None when that would
        not advance past what is committed."""
        tp = _tp(tp)
        entries = self._by_tp.get(tp) or {}
        if not entries:
            return None
        floor = self._floor.get(tp)
        c = None
        expect = floor if (self.dense and floor is not None) else None
        for o in sorted(entries):
            e = entries[o]
            if expect is not None and o != expect:
                break                        # an offset between them was never fetched here
            if e.state != COVERED:
                break
            c = e.to
            expect = e.to if self.dense else None
        if c is None:
            return None
        return c if c > (floor if floor is not None else 0) else None

    def forget_below(self, tp, offset: int) -> None:
        """Called after a commit of offset on tp succeeded."""
        tp = _tp(tp)
        self._floor[tp] = max(self._floor.get(tp, 0), int(offset))
        entries = self._by_tp.get(tp) or {}
        for o in [o for o in entries if o < offset]:
            e = entries.pop(o)
            if e.seq is not None:
                self._waiting.get(e.tenant, {}).pop(e.seq, None)

    def _drop(self, tp) -> None:
        for e in (self._by_tp.pop(tp, None) or {}).values():
            if e.seq is not None:
                self._waiting.get(e.tenant, {}).pop(e.seq, None)

    def reset(self, tp) -> None:
        """Forget tp's entries; the writer fetches again from the committed offset, which stays
        the floor."""
        self._drop(_tp(tp))

    def revoked(self, tp) -> None:
        """tp went to another consumer: forget it, floor included."""
        tp = _tp(tp)
        self._drop(tp)
        self._floor.pop(tp, None)

    def reset_tenant(self, tenant_id: str) -> Dict[Tuple[str, int], int]:
        """After reset_tenant_tail on this tenant: its uncovered entries go back to "fetched";
        other tenants' entries are kept. Returns {tp: lowest offset reset}."""
        self._recent.pop(tenant_id, None)
        low: Dict[Tuple[str, int], int] = {}
        for tp, entries in self._by_tp.items():
            for o in [o for o, e in entries.items() if e.tenant == tenant_id and e.state != COVERED]:
                entries[o].state, entries[o].seq, entries[o].rh = FETCHED, None, None
                low[tp] = min(low.get(tp, o), o)
        self._waiting.pop(tenant_id, None)
        if self._mismatch is not None and self._mismatch.tenant_id == tenant_id:
            self._mismatch = None
        return low

    def uncovered(self, tp) -> List[int]:
        return sorted(o for o, e in (self._by_tp.get(_tp(tp)) or {}).items() if e.state != COVERED)


def plan_commits_caa(tracker: CoverageTracker, tps: Iterable) -> Dict[Tuple[str, int], int]:
    """{tp: offset} to commit: only offsets below which every fetched record is covered."""
    out = {}
    for tp in tps:
        c = tracker.committable(tp)
        if c is not None:
            out[tp] = c
    return out


class _Chain:
    """A tenant's verified anchors with segments, as far as this process has read them. Anchors
    are write-once, so each later call verifies only those above the highest n seen."""
    __slots__ = ("anchors", "firsts", "max_n", "trimmed")

    def __init__(self):
        self.anchors: list = []
        self.firsts: List[int] = []
        self.max_n = -1
        self.trimmed = False


_chains: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _chain(store, tenant_id: str) -> _Chain:
    try:
        per = _chains.setdefault(store, {})
    except TypeError:                          # a store that cannot be weakly referenced
        per = {}
    ch = per.get(tenant_id)
    if ch is None:
        ch = per[tenant_id] = _Chain()
    return ch


def _records_after(store, tenant_id: str, n: int) -> list:
    from crypto.anchor_store import AnchorStore
    if isinstance(store, AnchorStore):
        return store.records_after(tenant_id, n)
    return sorted((r for r in store.all(tenant_id) if int(r.n) > int(n)), key=lambda r: int(r.n))


# Anchors kept per tenant. Redeliveries are at or above the committed offset, so they fall in the
# latest anchors; a position below the oldest kept one is looked up without the cache.
_ANCHORS_KEPT = 4096


def _verified(store, pubkey: Optional[bytes], tenant_id: str, after: int) -> list:
    return sorted((r for r in _records_after(store, tenant_id, after)
                   if r.seg is not None and r.verify_self()
                   and (pubkey is None or r.verify_sig(pubkey))), key=lambda r: int(r.n))


async def _refresh_chain(store, pubkey: Optional[bytes], tenant_id: str) -> _Chain:
    ch = _chain(store, tenant_id)
    new = await asyncio.to_thread(_verified, store, pubkey, tenant_id, ch.max_n)
    for r in new:
        if int(r.n) <= ch.max_n:
            continue
        ch.anchors.append(r)
        ch.firsts.append(int(r.seg["o_first"]))
        ch.max_n = int(r.n)
    if len(ch.anchors) > _ANCHORS_KEPT:
        del ch.anchors[:-_ANCHORS_KEPT]
        del ch.firsts[:-_ANCHORS_KEPT]
        ch.trimmed = True
    return ch


async def verify_redelivery(store, pubkey: bytes, tenant_id: str, pos: R.Position,
                            template: dict) -> str:
    """For a fetched record at or below the tenant's anchored pos_last: is the anchored record at
    its position this writer's template?

    "covered"   the anchored record at pos equals template (ignoring seq).
    "mismatch"  another record is anchored at pos.
    "absent"    nothing is anchored at pos although pos <= pos_last.
    "beyond"    pos is above the latest anchor's pos_last: the record belongs in the tail.

    Anchors must verify (hash and signature) and segments must have the hash their anchor names.
    A log's offsets increase on its one partition, so the segment holding pos is found by binary
    search. A store that does not answer raises; it is never read as "absent".
    """
    ch = await _refresh_chain(store, pubkey, tenant_id)
    if not ch.anchors:
        return "beyond"
    pl = ch.anchors[-1].pos_last
    same_tp = pl is not None and (str(pl["topic"]), int(pl["p"])) == (pos.topic, int(pos.p))
    if pl is None or not same_tp or int(pos.o) > int(pl["o"]):
        return "beyond"
    anchors, firsts = ch.anchors, ch.firsts
    if int(pos.o) < firsts[0] and ch.trimmed:
        # below what the cache keeps: this lookup reads the whole chain
        anchors = await asyncio.to_thread(_verified, store, pubkey, tenant_id, -1)
        firsts = [int(r.seg["o_first"]) for r in anchors]
    k = bisect.bisect_right(firsts, int(pos.o)) - 1
    if k < 0 or int(pos.o) > int(anchors[k].seg["o_last"]):
        return _report("absent", tenant_id, pos)
    rec = anchors[k]
    raw = await asyncio.to_thread(store.get_object, segment_key(tenant_id, rec.n))
    if raw is None or R.sha256_hex(raw) != rec.seg.get("sha256"):
        _alarm("anchored-mismatch", f"segment of {tenant_id} at n={rec.n} missing or altered")
        return _report("absent", tenant_id, pos)
    for r in json.loads(raw).get("records", []):
        p = r.get("pos") or {}
        try:
            here = (str(p.get("topic")), int(p.get("p")), int(p.get("o")))
        except (TypeError, ValueError):
            continue
        if here == (pos.topic, int(pos.p), int(pos.o)):
            return _report("covered" if R.same_template(r, template) else "mismatch", tenant_id, pos)
    return _report("absent", tenant_id, pos)


def _report(outcome: str, tenant_id: str, pos: R.Position) -> str:
    if outcome in ("absent", "mismatch"):
        _alarm("anchored-mismatch", f"{tenant_id} at {pos.topic}/{pos.p}:{pos.o}: {outcome} in "
                                    f"anchored data; the partition does not commit past it")
    return outcome


__all__ = ["CoverageMismatch", "CoverageTracker", "plan_commits_caa", "verify_redelivery"]
