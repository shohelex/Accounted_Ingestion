from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from crypto import records as R
from crypto.validate_record import (ROUTER, VALIDATOR, content_hash_of, leaf_data_of, parse,
                                    parse_for_tag, partition_of, validate_record, check_object)

logger = logging.getLogger(__name__)

_HEX = set("0123456789abcdef")
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _hex(s: Any, n: int) -> bool:
    return isinstance(s, str) and len(s) == n and set(s) <= _HEX


def _system_tenant() -> str:
    from config import settings
    return settings.acct_system_tenant


@dataclass
class Decoded:
    """One fetched record value, parsed and authenticated.

    tenant_id    the record's claimed tenant (a str), or None
    sub          the accounting record's "sub" field (record_sub of a well-formed "_acct"), or None
    sub_valid    the tag's signature verifies under the deployment key for (tenant_id, event_id)
    event        the canonical leaf data of the event, when the consumer's parse succeeds and the
                 leaf data is canonically encodable
    graph_event  the parsed ProvenanceEvent, for the graph write
    content_hash H(0x00 || canon(event)), or None
    raw          the record value's bytes (None for a tombstone)
    undecodable  the validator's code when the bytes are not one JSON object, else None. Such a
                 record may still be sub_valid: its tag is read with parse_for_tag
    """
    tenant_id: Optional[str]
    sub: Optional[dict]
    sub_valid: bool
    event: Optional[dict]
    graph_event: Any
    content_hash: Optional[str]
    raw: Optional[bytes]
    undecodable: Optional[str]
    event_id: Optional[str] = None
    parse_error: Optional[str] = None      # class name of the consumer parse's exception
    # The validator's parse of raw (crypto.validate_record.parse), reused by decide(). Never modified.
    data: Any = field(default=None, repr=False, compare=False)


# A sub is 32 hex digits (128 random bits), as in tools/check_verdict.py.
SUB_HEX_LENGTHS = (32,)


def _well_formed_tag(acct: Any) -> bool:
    return (isinstance(acct, dict) and acct.get("v") == 1
            and any(_hex(acct.get("sub"), n) for n in SUB_HEX_LENGTHS)
            and isinstance(acct.get("at_ms"), int) and not isinstance(acct.get("at_ms"), bool)
            and _hex(acct.get("leaf_hash"), 64) and isinstance(acct.get("contract"), str)
            and _hex(acct.get("sig"), 128))


def tag_verifies(data: dict, pubkey: Optional[bytes]) -> bool:
    """Does the record carry a submission tag the deployment signed for its own tenant and event
    id? (tools/check_verdict.py applies the same test.)"""
    acct = data.get("_acct")
    if pubkey is None or not _well_formed_tag(acct):
        return False
    tenant_id, event_id = data.get("tenant_id"), data.get("event_id")
    if not isinstance(tenant_id, str) or not isinstance(event_id, str):
        return False
    from crypto.signing import verify
    try:
        msg = R.signed(R.NS_SUB, R.sub_body(tenant_id, event_id, acct["leaf_hash"], acct["sub"],
                                            acct["at_ms"], acct["contract"]))
    except (TypeError, ValueError):
        return False
    return verify(pubkey, acct["sig"], msg)


def decode_and_authenticate(raw: Optional[bytes], pubkey: Optional[bytes],
                            contract_hash: Optional[str] = None, parsed=None) -> Decoded:
    """Parse and authenticate one record value. Never raises.

    A tag is authenticated by its signature alone; a tag naming another contract than
    contract_hash (one signed under an earlier version) is logged, not refused. parsed is
    parse(raw) when the caller already has it.
    """
    raw_b = bytes(raw) if raw is not None else None
    code, data = parsed if parsed is not None else parse(raw_b)
    if code is not None:
        # Bytes the strict parse refuses may still carry the deployment's tag: parse_for_tag
        # decides, as check_verdict and the replay audit do, so such a record is never UNAUTH.
        tagged = parse_for_tag(raw_b)
        if tagged is not None and tag_verifies(tagged, pubkey):
            return Decoded(tagged["tenant_id"], R.record_sub(tagged["_acct"]), True, None, None, None,
                           raw_b, code, event_id=tagged["event_id"])
        return Decoded(None, None, False, None, None, None, raw_b, code)
    tenant_id = data.get("tenant_id") if isinstance(data.get("tenant_id"), str) else None
    event_id = data.get("event_id") if isinstance(data.get("event_id"), str) else None
    acct = data.get("_acct")
    sub = R.record_sub(acct) if _well_formed_tag(acct) else None
    sub_valid = sub is not None and tag_verifies(data, pubkey)
    if sub_valid and contract_hash and sub["contract"] != contract_hash:
        logger.info("record tag names contract %s, not the one in force", sub["contract"][:16])

    graph_event = event = chash = None
    parse_error = None
    try:
        from schemas import ProvenanceEvent
        from crypto.leaf_format import leaf_event_data
        graph_event = ProvenanceEvent(**{k: v for k, v in data.items() if k != "_acct"})
        leaf = leaf_event_data(graph_event)
        R.canon(leaf)                   # an accounting record must be canonically encodable
        event, chash = leaf, R.content_hash(leaf)
    except Exception as e:              # any parse failure is decided below, never raised
        parse_error = type(e).__name__
        graph_event = None
    return Decoded(tenant_id, sub, sub_valid, event, graph_event, chash, raw_b, None,
                   event_id=event_id, parse_error=parse_error, data=data)


@dataclass(frozen=True)
class Prior:
    """An earlier event record of the same tenant and event id."""
    seq: int
    content_hash: str
    record_hash: str


@dataclass
class _Pending:
    token: int
    content_hash: str
    o: int


class EventIdIndex:
    """event id -> the earliest event record of the tenant with that id, over accounting records,
    never over graph nodes. Sources: lookup() (the database's copy, not trusted) and note()
    (records this writer appended). Records decided but not yet appended in the current batch
    are "pending"; their referents' seqs are filled in after the append.

    A prior must lie at an earlier broker position than the record being decided (before=), so
    the decision for a position is the same on every delivery.
    """

    def __init__(self, lookup: Optional[Callable[[str, str], Awaitable[List[Tuple[int, dict]]]]] = None,
                 max_memory: int = 200_000):
        self._lookup = lookup
        self._mem: Dict[Tuple[str, str], List[Tuple[int, str, str, int]]] = {}
        self._pending: Dict[Tuple[str, str], List[_Pending]] = {}
        self._max = max_memory
        self._next_token = 0

    async def find(self, tenant_id: str, event_id: str,
                   before: Optional[R.Position] = None) -> Optional[Prior]:
        best: Optional[Prior] = None
        cands: List[Tuple[int, str, str, int]] = list(self._mem.get((tenant_id, event_id), ()))
        if self._lookup is not None:
            for seq, rec in (await self._lookup(tenant_id, event_id)) or ():
                c = _as_candidate(tenant_id, event_id, seq, rec)
                if c is not None:
                    cands.append(c)
        for seq, chash, rhash, o in cands:
            if before is not None and o >= int(before.o):
                continue
            if best is None or seq < best.seq:
                best = Prior(seq, chash, rhash)
        return best

    def note(self, tenant_id: str, event_id: str, seq: int, content_hash: str,
             record_hash: str = "", o: int = -1) -> None:
        lst = self._mem.setdefault((tenant_id, event_id), [])
        if all(s != seq for s, _, _, _ in lst):
            lst.append((int(seq), content_hash, record_hash, int(o)))
        if len(self._mem) > self._max:
            self._mem.pop(next(iter(self._mem)))

    def forget_from(self, tenant_id: str, n: int) -> None:
        """Drop what this writer remembers at seq >= n (after a tail reset)."""
        for key in [k for k in self._mem if k[0] == tenant_id]:
            kept = [c for c in self._mem[key] if c[0] < n]
            if kept:
                self._mem[key] = kept
            else:
                del self._mem[key]

    def add_pending(self, tenant_id: str, event_id: str, content_hash: str, o: int) -> int:
        self._next_token += 1
        self._pending.setdefault((tenant_id, event_id), []).append(
            _Pending(self._next_token, content_hash, int(o)))
        return self._next_token

    def pending(self, tenant_id: str, event_id: str,
                before: Optional[R.Position] = None) -> Optional[_Pending]:
        for p in self._pending.get((tenant_id, event_id), ()):
            if before is None or p.o < int(before.o):
                return p
        return None

    def clear_pending(self) -> None:
        self._pending.clear()


def _as_candidate(tenant_id: str, event_id: str, seq: Any, rec: Any):
    """A database row as a candidate referent, or None when it is not an event record of this
    tenant with this id."""
    try:
        if not R.is_v2(rec) or rec.get("kind") != "event" or rec.get("tenant_id") != tenant_id:
            return None
        ev = rec.get("event")
        if not isinstance(ev, dict) or ev.get("event_id") != event_id:
            return None
        if int(rec.get("seq", seq)) != int(seq):
            return None
        return (int(seq), R.content_hash(ev), R.record_hash(rec), int(rec["pos"]["o"]))
    except Exception:
        return None


@dataclass
class Decision:
    """kind: "event", "verdict", or "skip" (verdicts switched off). tenant_id is the log the record
    goes to. blob, when set, must be written with put_once at template["verdict"]["raw"]["blob"]
    before the template is appended."""
    kind: str
    tenant_id: str
    template: dict
    graph_event: Any
    blob: Optional[bytes]
    pending_ref: Optional[int] = None      # token of a same-batch referent not yet appended
    token: Optional[int] = None            # this event's pending token, for later referents

    @property
    def vtype(self) -> Optional[str]:
        v = self.template.get("verdict") if self.template else None
        return v.get("type") if v else None


def _blob_event(d: Decoded) -> Optional[dict]:
    """The consumer's leaf data, to embed in a verdict, when the standalone derivation from the
    bytes gives the same (the checker compares them); else None."""
    if d.event is None:
        return None
    _, data = parse(d.raw)
    try:
        return d.event if data is not None and leaf_data_of(data) == d.event else None
    except Exception:
        return None


def _parse_agrees(d: Decoded, data=None) -> bool:
    """For bytes the validator accepts: the consumer's parse (d) derives the validator's leaf
    data and the content hash the tag names. data: the validator's parse of d.raw, if known."""
    if data is None:
        _, data = parse(d.raw)
    return (data is not None and d.graph_event is not None and d.event is not None
            and isinstance(d.sub, dict) and d.event == leaf_data_of(data)
            and d.content_hash == content_hash_of(d.event)
            and d.content_hash == d.sub.get("leaf_hash"))


def api_record_problem(raw: Optional[bytes]) -> Optional[str]:
    """The API's check before it sends a tagged record, on one parse of the bytes: the validator's
    code, "VALIDATOR_GAP" when this consumer would not decide the record as an event, or None."""
    code, data = parse(raw)
    if code is not None:
        return code
    code = check_object(data)
    if code is not None:
        return code
    d = decode_and_authenticate(raw, None, parsed=(None, data))
    return None if d.undecodable is None and _parse_agrees(d, data) else "VALIDATOR_GAP"


def misrouted(d: Decoded, p: int, route: Optional[dict]) -> Optional[int]:
    """The partition the route puts the record's tenant on, when that is not p; else None."""
    if route is None or not d.sub_valid or not isinstance(d.tenant_id, str) \
            or _TENANT_ID.match(d.tenant_id) is None:
        return None
    q = partition_of(d.tenant_id.encode("utf-8"), route)
    return q if q is not None and q != int(p) else None


def log_tenant(d: Decoded, system_log: str, p: Optional[int] = None,
               route: Optional[dict] = None) -> str:
    """The log a record's accounting record goes to: its tenant's, when the record carries a
    valid tag for a tenant id a log can hold and arrived on that tenant's partition; the
    partition's system log otherwise."""
    if (not d.sub_valid or not isinstance(d.tenant_id, str)
            or _TENANT_ID.match(d.tenant_id) is None):
        return system_log
    if p is not None and misrouted(d, p, route) is not None:
        return system_log
    return d.tenant_id


def raw_ref(raw: Optional[bytes]) -> dict:
    b = raw if raw is not None else b""
    h = hashlib.sha256(b).hexdigest()
    return {"sha256": h, "len": len(b), "blob": f"blobs/{h}.bin"}


async def decide(d: Decoded, pos: R.Position, index: EventIdIndex, exhausted: bool, *,
                 system_tenant: Optional[str] = None, attempts: Optional[int] = None,
                 first_fail_ms: Optional[int] = None, err: Optional[str] = None,
                 verdicts: bool = True, route: Optional[dict] = None) -> Decision:
    """The record for one fetched position.

    exhausted  the position failed on processor_max_redeliveries counted deliveries; attempts,
               first_fail_ms and err (exception class name) describe those failures.
    verdicts   False: anything that would be a verdict is a "skip" decision (baseline).
    route      the source's partitioner (crypto/validate_record.partition_of). With it, a validly
               tagged record read from another partition than its tenant's is
               MALFORMED(PARTITION) in this partition's system log.
    """
    sys_t = system_tenant or _system_tenant()
    raw = d.raw if d.raw is not None else b""

    def verdict(tenant: str, vtype: str, *, sub=None, event=None, with_raw=False, **kw) -> Decision:
        tpl = R.verdict_template(tenant, pos, sub, event, vtype,
                                 raw=raw_ref(d.raw) if with_raw else None, **kw)
        kind = "verdict" if verdicts else "skip"
        return Decision(kind, tenant, tpl, None, raw if with_raw else None)

    if not d.sub_valid:
        # No tag verifies, on the strict parse or on parse_for_tag: nothing authenticates it.
        return verdict(sys_t, "UNAUTH", event=None if d.undecodable else _blob_event(d),
                       with_raw=True)

    q = misrouted(d, pos.p, route)
    if q is not None:
        tpl = R.verdict_template(sys_t, pos, d.sub, None if d.undecodable else _blob_event(d),
                                 "MALFORMED", raw=raw_ref(d.raw), code="PARTITION",
                                 validator=ROUTER)
        tpl["verdict"]["route"] = dict(route)
        return Decision("verdict" if verdicts else "skip", sys_t, tpl, None, raw)

    # validate_record(d.raw), on the parse decode_and_authenticate already made of the same bytes.
    if d.data is not None:
        code = check_object(d.data)
    elif d.undecodable is not None:
        code = d.undecodable
    else:
        code = validate_record(d.raw)
    # A signed record under a tenant id no log can hold goes to the system log.
    tenant = log_tenant(d, sys_t)
    if code:
        return verdict(tenant, "MALFORMED", sub=d.sub, event=_blob_event(d), with_raw=True,
                       code=code, validator=VALIDATOR)

    # The validator accepted the bytes but the consumer's parse disagrees: nobody can check
    # the verdict, so it is UNCHECKABLE and counted in the budget.
    if not _parse_agrees(d, d.data):
        return verdict(tenant, "UNCHECKABLE", sub=d.sub, event=d.event, with_raw=True,
                       code="VALIDATOR_GAP", err=d.parse_error)

    event_id = d.event["event_id"]
    prior = await index.find(tenant, event_id, before=pos)
    if prior is not None:
        vtype = "DUP" if prior.content_hash == d.content_hash else "COLLIDE"
        return verdict(tenant, vtype, sub=d.sub, event=d.event,
                       ref=prior.seq, ref_leaf=prior.record_hash)
    pend = index.pending(tenant, event_id, before=pos)
    if pend is not None:
        vtype = "DUP" if pend.content_hash == d.content_hash else "COLLIDE"
        dec = verdict(tenant, vtype, sub=d.sub, event=d.event)
        dec.pending_ref = pend.token
        return dec
    if exhausted:
        return verdict(tenant, "UNCHECKABLE", sub=d.sub, event=d.event, code="POISON",
                       attempts=attempts, first_fail_ms=first_fail_ms, err=err)
    return Decision("event", tenant, R.event_template(tenant, pos, d.sub, d.event), d.graph_event,
                    None)


def resolve_ref(decision: Decision, seq: int, record_hash: str) -> None:
    """Fill in a same-batch referent once it has been appended."""
    v = decision.template["verdict"]
    v["ref"], v["ref_leaf"] = int(seq), str(record_hash)
    decision.pending_ref = None


def gap_decision(pos: R.Position, frm: int, to: int, *, system_tenant: Optional[str] = None,
                 verdicts: bool = True) -> Decision:
    """GAP(from, to): the broker delivered offset `to` right after `from - 1`; recorded in the
    system log at position `from`."""
    sys_t = system_tenant or _system_tenant()
    gpos = R.Position(pos.topic, pos.p, int(frm), pos.bt_ms)
    tpl = R.verdict_template(sys_t, gpos, None, None, "GAP", gap={"from": int(frm), "to": int(to)})
    return Decision("verdict" if verdicts else "skip", sys_t, tpl, None, None)


__all__ = ["Decoded", "Decision", "EventIdIndex", "Prior", "decode_and_authenticate", "decide",
           "resolve_ref", "gap_decision", "raw_ref", "tag_verifies", "log_tenant", "misrouted",
           "api_record_problem"]
