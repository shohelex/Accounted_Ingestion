import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import json
import re
import secrets
import time
from fastapi import APIRouter, Path, HTTPException, Depends, status, Response, Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from schemas import (
    EntityType, SourceType, EventType, ProvenanceEvent, ProvenanceEntity, ProvenanceAgent,
    ProvenanceActivity, AgentType, OperationType
)
from api import stage_timing as _stage
from api.dependencies import get_current_user, get_tenant_id, request_client_ip
from api.ingest_rules import (AdmissionWindow, OffsetReuseGuard, source_allowed, tenant_admission,
                              unrepresentable_value, unstorable_string)
from config import settings
from crypto.merkle_tree_storage import merkle_tree_storage
from processing.event_processor import stream_processor
from processing.stops import StopWatch

logger = logging.getLogger(__name__)

router = APIRouter()

# The Kafka producer, set at startup (api/main.py).
kafka_producer = None

_CLIENT_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,63}$")


def _client_event_id(event_data: Dict[str, Any], tenant_id: str) -> "str | None":
    """A caller-supplied event_id, prefixed with the tenant, so a retry after an error is
    idempotent and one tenant cannot occupy another's ids (Activity.id is globally unique)."""
    v = event_data.get("event_id")
    if isinstance(v, str) and _CLIENT_EVENT_ID.match(v):
        return f"c_{tenant_id}_{v}"
    return None


def _signed_ack(event: "ProvenanceEvent") -> "dict | None":
    """The v1 receipt: this event, with this leaf hash, was accepted for this tenant at this time
    and will be anchored within the stated bound. None when no signing key is configured."""
    from crypto.signing import ack_statement, get_signer
    signer = get_signer(settings)
    if signer is None:
        return None
    from crypto.leaf_format import leaf_event_data, leaf_hash_hex
    leaf_hash = leaf_hash_hex(leaf_event_data(event))
    accepted_at = datetime.utcnow().isoformat()
    k = max(1, int(settings.merkle_anchor_batch_k))
    b = max(1, int(settings.merkle_append_batch_b))
    # The time bound a sender can hold us to is T plus the heartbeat's period and lease slack.
    from crypto.merkle_tree_storage import anchor_timing
    timing = anchor_timing(float(settings.merkle_anchor_max_age_s or 0))
    return {
        "v": 1, "tenant_id": event.tenant_id, "event_id": event.event_id,
        "leaf_hash": leaf_hash, "accepted_at": accepted_at,
        "sig": signer.sign(ack_statement(event.tenant_id, event.event_id, leaf_hash, accepted_at)),
        "key": signer.public_key_hex,
        "bound": {"queued_events": int(settings.ingest_max_partition_lag
                                       or settings.ingest_max_consumer_lag or 0),
                  "leaves": k + b - 1,
                  "seconds": timing["bound_s"] if timing else 0.0},
    }


def _now_ms() -> int:
    return int(time.time() * 1000)


# The contract in force: its hash is signed into every submission tag and receipt. Read from the
# write-once store, verified against the deployment key, and cached per contract version.
_contract_cache: Dict[str, Any] = {"ver": None, "hash": None, "body": None}


def _acct_contract() -> "tuple[str | None, dict | None]":
    ver = int(settings.acct_contract_version)
    if _contract_cache["ver"] == ver and _contract_cache["hash"]:
        return _contract_cache["hash"], _contract_cache["body"]
    from crypto.merkle_tree_storage import _get_anchor_store
    from crypto.records import NS_STMT, canon, contract_hash
    from crypto.signing import get_public_key, verify
    store = _get_anchor_store()
    pub = get_public_key(settings)
    if store is None or pub is None:
        return None, None
    dep = str(settings.acct_deployment_id)
    raw = store.get_object(f"contract/{dep}/{ver:06d}.json")
    if raw is None:
        return None, None
    try:
        signed_contract = json.loads(raw)
        body = signed_contract["body"]
        if not verify(pub, signed_contract.get("sig"), NS_STMT + canon(body)):
            logger.error("INTEGRITY ALARM [contract]: the stored contract does not verify under the "
                         "deployment key; refusing to acknowledge")
            return None, None
    except (ValueError, KeyError, TypeError):
        return None, None
    h = contract_hash(body)
    _contract_cache.update(ver=ver, hash=h, body=body)
    return h, body


def _sub_tag(event: "ProvenanceEvent", contract: str) -> dict:
    """The submission tag, signed before the send and carried inside the broker record ("_acct"):
    the deployment's signature over (tenant, event id, leaf hash, sub, a), with which the replay
    audit turns any unaccounted record into a complaint. sub is 128 random bits."""
    from crypto.leaf_format import leaf_event_data, leaf_hash_hex
    from crypto.records import NS_SUB, acct_tag, signed, sub_body
    from crypto.signing import get_signer
    signer = get_signer(settings)
    if signer is None:
        raise RuntimeError("accounted mode needs a signing key (merkle_signing_seed)")
    leaf_hash = leaf_hash_hex(leaf_event_data(event))
    sub = secrets.token_hex(16)
    at_ms = _now_ms()
    sig = signer.sign(signed(NS_SUB, sub_body(event.tenant_id, event.event_id, leaf_hash, sub,
                                              at_ms, contract)))
    return acct_tag(sub, at_ms, leaf_hash, contract, sig)


def _ack_v2(event: "ProvenanceEvent", tag: dict, md, contract_body: Optional[dict] = None) -> dict:
    """Receipt v2, signed after the broker acknowledged the record, over the position it assigned.
    Raises if the broker returned no position."""
    from crypto.records import NS_ACK2, ack2_body, signed
    from crypto.signing import get_signer
    topic = getattr(md, "topic", None)
    p = getattr(md, "partition", None)
    o = getattr(md, "offset", None)
    if md is None or topic is None or not isinstance(p, int) or not isinstance(o, int) or o < 0:
        raise RuntimeError("the broker returned no record position")
    signer = get_signer(settings)
    body = ack2_body(event.tenant_id, event.event_id, tag["leaf_hash"], tag["sub"], tag["at_ms"],
                     topic, p, o, tag["contract"])
    theta = int(settings.acct_theta_s)
    period = int(settings.acct_period_s)
    e_budget = int(settings.acct_stall_budget)
    delta_pub = int(settings.acct_delta_pub_s)
    if contract_body:
        theta = int(contract_body.get("theta_s", theta))
        period = int(contract_body.get("period_s", period))
        e_budget = int(contract_body.get("stall_budget", e_budget))
        delta_pub = int(contract_body.get("delta_pub_s", delta_pub))
    return {
        "v": 2, "tenant_id": event.tenant_id, "event_id": event.event_id,
        "leaf_hash": tag["leaf_hash"], "sub": tag["sub"], "at_ms": tag["at_ms"],
        "accepted_at": datetime.fromtimestamp(tag["at_ms"] / 1000.0, timezone.utc)
                               .replace(tzinfo=None).isoformat(),
        "pos": {"topic": topic, "p": p, "o": o},
        "contract": tag["contract"],
        "bound": {"theta_s": theta, "theta_max_s": theta + (e_budget + 1) * period + delta_pub,
                  "period_s": period},
        "key": signer.public_key_hex,
        "sig": signer.sign(signed(NS_ACK2, body)),
    }


def acct_not_started_ms(contract_body: Optional[dict], now_ms: int) -> int:
    """Milliseconds until the contract's first period begins; 0 once it has. Nothing is
    acknowledged before then: the judge starts no complaint before that period."""
    if not contract_body:
        return 0
    start_ms = (int(contract_body.get("t0_ms", 0))
                + int(contract_body.get("effective_j", 0)) * int(contract_body.get("period_s", 0)) * 1000)
    return max(0, start_ms - int(now_ms))


def acct_timing_problems(contract_body: Optional[dict]) -> List[str]:
    """Why the contract's delta does not cover this API's send bound plus twice the clock skew and
    the broker's skew. Empty when it does, or when there is no contract."""
    from crypto.period_statements import p10_problems
    from processing.sources import send_bound_ms
    return p10_problems(contract_body, send_bound_ms(),
                        int(settings.acct_broker_skew_ms), int(settings.acct_clock_skew_ms))


_timing_alarmed: set = set()


def _expected_partition(tenant_id: str, contract_body: Optional[dict]) -> "int | None":
    """The partition the contract's partitioner puts the tenant on (broker.partitioner over
    broker.partitions, as the consumer computes it), or None when the contract does not fix it."""
    from crypto.validate_record import partition_of
    route = None
    broker = (contract_body or {}).get("broker") or {}
    if str(broker.get("kind", "kafka")) == "kafka" and broker.get("partitions"):
        route = {"fn": str(broker.get("partitioner") or "murmur2"), "n": int(broker["partitions"])}
    return partition_of(str(tenant_id).encode("utf-8"), route) if route else None


def _refuse(detail: str, retry_after: str = "5") -> HTTPException:
    return HTTPException(status_code=503, detail=detail, headers={"Retry-After": retry_after})


def _anchored_many(store, pub, tenant_id: str, positions) -> dict:
    """{(topic, p, o): (anchor record, record)} for those of the positions the tenant's verified
    anchors cover, read from hash-checked segments (one segment read per covering anchor)."""
    import bisect
    from crypto import records as R
    from crypto.anchor_store import segment_key
    latest = store.latest(tenant_id)
    if latest is not None and not store.acceptable(tenant_id, latest):
        latest = store.latest_after(tenant_id, -1)
    pl = getattr(latest, "pos_last", None) if latest is not None else None
    if not pl:
        return {}
    todo = [q for q in positions if (q[0], int(q[1])) == (pl["topic"], int(pl["p"]))
            and int(q[2]) <= int(pl["o"])]
    if not todo:
        return {}
    anchors = sorted((r for r in store.all(tenant_id) if getattr(r, "seg", None) and "o_first" in r.seg),
                     key=lambda r: int(r.seg["o_first"]))
    firsts = [int(r.seg["o_first"]) for r in anchors]
    by_anchor: dict = {}
    for q in todo:
        k = bisect.bisect_right(firsts, int(q[2])) - 1
        if k >= 0 and int(q[2]) <= int(anchors[k].seg["o_last"]):
            by_anchor.setdefault(k, []).append(q)
    out = {}
    for k, qs in by_anchor.items():
        a = anchors[k]
        if not a.verify_self() or (pub is not None and not a.verify_sig(pub)):
            continue
        raw = store.get_object(segment_key(tenant_id, a.n))
        if raw is None or R.sha256_hex(raw) != a.seg.get("sha256"):
            continue
        want = {(q[0], int(q[1]), int(q[2])) for q in qs}
        for rec in json.loads(raw).get("records", []):
            q = rec.get("pos") or {}
            key = (q.get("topic"), q.get("p"), q.get("o"))
            if key in want:
                out[key] = (a, rec)
    return out


# Waiting requests per event loop and tenant; one poller per tenant serves all of them.
_cover_waiters: Dict[Any, Dict[str, Any]] = {}


async def _cover_poller(key, tenant_id: str, poll_s: float) -> None:
    from crypto.merkle_tree_storage import _get_anchor_store
    from crypto.signing import get_public_key
    entry = _cover_waiters[key]
    store, pub = _get_anchor_store(), get_public_key(settings)
    try:
        while True:
            entry["waiters"] = [w for w in entry["waiters"] if not w[2].done()]
            if not entry["waiters"] or store is None:
                return
            found = await asyncio.to_thread(_anchored_many, store, pub, tenant_id,
                                             [w[0] for w in entry["waiters"]])
            for pos, sub, fut in entry["waiters"]:
                if pos in found and not fut.done():
                    anchor, rec = found[pos]
                    fut.set_result(None if rec.get("sub") != sub else {
                        "n": int(anchor.n), "record_hash": anchor.record_hash, "seq": int(rec["seq"]),
                        "kind": rec.get("kind"), "verdict": (rec.get("verdict") or {}).get("type")})
            await asyncio.sleep(poll_s)
    finally:
        entry["task"] = None


async def _await_anchor_cover(tenant_id: str, tag: dict, md, timeout_s: float,
                              poll_s: float) -> "dict | None":
    """Wait until a verified anchor covers the record at the broker position md and that record
    carries this submission's tag; return what the anchor says about it. None at the timeout, or
    when another submission's record is anchored at the position."""
    from crypto import records as R
    loop = asyncio.get_running_loop()
    key = (id(loop), tenant_id)
    entry = _cover_waiters.setdefault(key, {"waiters": [], "task": None})
    fut = loop.create_future()
    entry["waiters"].append(((md.topic, int(md.partition), int(md.offset)), R.record_sub(tag), fut))
    if entry["task"] is None:
        entry["task"] = asyncio.create_task(_cover_poller(key, tenant_id, poll_s))
    try:
        return await asyncio.wait_for(asyncio.shield(fut), timeout_s)
    except asyncio.TimeoutError:
        return None
    finally:
        if not fut.done():
            fut.cancel()
        if not entry["waiters"] and entry["task"] is None:
            _cover_waiters.pop(key, None)


async def _submit_accounted(provenance_event: "ProvenanceEvent", tenant_id: str) -> dict:
    """Accounted mode: acknowledge only what the broker acknowledged, with a receipt over its
    position. There is no direct-processing fallback. Every refusal is a 503; a refused event may
    still be in the broker, where it is accounted like any other record."""
    if not settings.provenance_tracking_enabled:
        raise _refuse("Provenance tracking is disabled; the event is not acknowledged")
    if kafka_producer is None:
        raise _refuse("The broker is not available; accounted mode acknowledges only through it")
    contract, contract_body = _acct_contract()
    if contract is None:
        raise _refuse("No verified contract is published for this deployment; not acknowledging")
    timing = acct_timing_problems(contract_body)
    if timing:
        for p in timing:
            if p not in _timing_alarmed:
                _timing_alarmed.add(p)
                logger.error(f"INTEGRITY ALARM [timing]: {p}; not acknowledging")
        raise _refuse("The contract's delta does not cover the send bound (P10); not acknowledging")
    wait_ms = acct_not_started_ms(contract_body, _now_ms())
    if wait_ms:
        raise _refuse("The contract's first period has not begun; not acknowledging",
                      retry_after=str(max(1, -(-wait_ms // 1000))))
    value = _checked_record_value(provenance_event)
    # Signed before the send and outside its error handling: a signing failure queues nothing.
    tag = _sub_tag(provenance_event, contract)
    value["_acct"] = tag
    return await _send_accounted(provenance_event, tenant_id, value, tag, contract_body)


async def _send_accounted(provenance_event: "ProvenanceEvent", tenant_id: str, value: dict,
                          tag: dict, contract_body: Optional[dict]) -> dict:
    """The send and the receipt of _submit_accounted, from a signed tag. Raises (503) whenever the
    event is not acknowledged."""
    from processing.decide import api_record_problem
    from processing.sources import delivery_timeout_ms
    raw = json.dumps(value, default=str, allow_nan=False).encode("utf-8")
    problem = api_record_problem(raw)
    if problem is not None and problem != "VALIDATOR_GAP":
        logger.error(f"INTEGRITY ALARM [record]: the tagged record of {provenance_event.event_id} "
                     f"fails the validator; not sending it")
        raise _refuse("The event could not be recorded; not acknowledged")
    if problem == "VALIDATOR_GAP":
        # The consumer's parse would not derive the same event: it could only be UNCHECKABLE.
        logger.error(f"INTEGRITY ALARM [record]: the consumer's parse of {provenance_event.event_id} "
                     f"disagrees with the record validator; not sending it")
        raise _refuse("The event could not be recorded; not acknowledged")
    # The broker's acknowledgement must arrive within the delivery timeout of the tag's time a,
    # counted from a and checked again on the answer.
    send_ms = delivery_timeout_ms()
    timeout_s = max(0.001, (int(tag["at_ms"]) + send_ms - _now_ms()) / 1000.0)
    want = _expected_partition(tenant_id, contract_body)
    guard = settings.ingest_offset_reuse_guard
    if guard and want is not None:
        closed = _offset_guard.closed(kafka_producer, (settings.kafka_provenance_topic, want))
        if closed:
            raise _refuse("The broker reused positions on this tenant's partition; not accepting "
                          "until an operator reopens it", retry_after="60")
    # Nothing sent to a partition the consumers stopped is ever accounted.
    t_stop = time.perf_counter()
    stopped = want is not None and await _partition_stopped(want)
    _stage.add("stopped", t_stop)
    if stopped:
        raise _refuse("This tenant's partition was stopped by the consumers; not accepting",
                      retry_after="60")
    t_send = time.perf_counter()
    try:
        md = await asyncio.wait_for(
            kafka_producer.send_and_wait(settings.kafka_provenance_topic, value=value,
                                         key=str(tenant_id).encode("utf-8")),
            timeout=timeout_s)
        _stage.add("send", t_send)
    except Exception as kafka_error:
        _stage.add("send_failed", t_send)
        logger.warning(f"Kafka send failed in accounted mode, not acknowledging: {kafka_error}")
        raise _refuse("The broker did not acknowledge the event; retry with the same event_id")
    if _now_ms() - int(tag["at_ms"]) > send_ms:
        logger.warning(f"the broker acknowledged {provenance_event.event_id} "
                       f"{_now_ms() - int(tag['at_ms'])} ms after its tag's time, past the delivery "
                       f"timeout of {send_ms} ms; not acknowledging")
        raise _refuse("The broker acknowledged the event too late; retry with the same event_id")
    if guard and md is not None and getattr(md, "offset", None) is not None:
        # A reused offset means the broker lost acknowledged records; the consumer accounts
        # nothing past it, so the partition is closed.
        why = _offset_guard.observe(kafka_producer, (md.topic, int(md.partition)), int(md.offset))
        if why:
            logger.error(f"INTEGRITY ALARM [offset-reuse]: {why}; not acknowledging "
                         f"{provenance_event.event_id}, and the partition stays closed until an "
                         f"operator reopens it")
            raise _refuse("The broker reused a position on this tenant's partition; not "
                          "acknowledged", retry_after="60")
    if want is None and md is not None and getattr(md, "partition", None) is not None \
            and await _partition_stopped(int(md.partition)):
        # Without the contract's partitioner the partition is known only after the send.
        raise _refuse("This tenant's partition was stopped by the consumers; not acknowledged",
                      retry_after="60")
    if want is not None and getattr(md, "partition", None) != want:
        # The consumer refuses a tenant's record on another partition (MALFORMED(PARTITION)).
        logger.error(f"INTEGRITY ALARM [partitions]: tenant {tenant_id!r} was written to partition "
                     f"{getattr(md, 'partition', None)}, the contract's partitioner says {want}; not "
                     f"acknowledging")
        raise _refuse("The broker put the event on a partition the contract does not map this "
                      "tenant to; not acknowledged")
    try:
        receipt_v2 = _ack_v2(provenance_event, tag, md, contract_body)
    except RuntimeError as e:
        logger.error(f"No receipt for {provenance_event.event_id}: {e}")
        raise _refuse("The broker returned no record position; retry with the same event_id")
    out = {
        "status": "queued",
        "message": "Provenance activity queued for processing",
        "activity_id": provenance_event.event_id,
        "processing": "async_kafka",
        # The judge accepts only receipt_v2; the v1 receipt is for older clients.
        "receipt": _signed_ack(provenance_event) if settings.acct_v1_receipt else None,
        "receipt_v2": receipt_v2,
    }
    # Baseline "acknowledge after anchor": answer only once a write-once anchor covers the record.
    if settings.acct_ack_after_anchor:
        timeout_s = float(settings.acct_ack_anchor_timeout_s)
        anchored = await _await_anchor_cover(tenant_id, tag, md, timeout_s,
                                             float(settings.acct_ack_anchor_poll_s))
        if anchored is None:
            raise _refuse("No anchor covered the event within the acknowledgement timeout; "
                          "retry with the same event_id", retry_after=str(int(max(1, timeout_s))))
        out.update(status="anchored", message="Provenance activity anchored",
                   processing="anchored", anchored=anchored)
    return out


# The consumer-lag probe's answer, refreshed at most every ingest_lag_probe_interval_s. When the
# probe fails, its last good answer is reused for ingest_lag_stale_s; after that the lag is
# unknown and the route refuses (503) unless ingest_admission_fail_closed is False.
_lag_cache = {'value': None, 'checked_at': 0.0, 'good_at': 0.0, 'good': None}


def _admission_caps():
    return int(settings.ingest_max_partition_lag or 0), int(settings.ingest_max_consumer_lag or 0)


async def _probe_lag():
    """Ask Kafka: {'total', 'by_partition', 'n_partitions'}. Raises if Kafka cannot be asked."""
    from aiokafka import AIOKafkaConsumer
    from aiokafka.admin import AIOKafkaAdminClient
    from aiokafka.structs import TopicPartition

    bootstrap = settings.kafka_bootstrap_servers
    topic = settings.kafka_provenance_topic
    group = settings.kafka_consumer_group

    # The committed offsets are read through the admin client: joining the group would rebalance it.
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap)
    await admin.start()
    try:
        committed = await admin.list_consumer_group_offsets(group) or {}
    finally:
        await admin.close()

    # A consumer without group_id, for the end offsets, stays outside the group.
    consumer = AIOKafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    await consumer.start()
    try:
        # Every partition counts; one without a commit lags from its first retained record.
        parts = consumer.partitions_for_topic(topic)
        if not parts:
            # An unassigned consumer may hold no topic metadata yet.
            md = await consumer._client.fetch_all_metadata()
            parts = md.partitions_for_topic(topic)
        parts = parts or {tp.partition for tp in committed if tp.topic == topic}
        tps = [TopicPartition(topic, p) for p in sorted(parts)]
        ends = await consumer.end_offsets(tps) if tps else {}
        starts = await consumer.beginning_offsets(tps) if tps else {}
    finally:
        await consumer.stop()

    by_partition = {}
    for tp in tps:
        meta = committed.get(tp)
        done = meta.offset if meta is not None and meta.offset >= 0 else starts.get(tp, 0)
        by_partition[tp.partition] = max(0, ends.get(tp, 0) - done)
    return {'total': sum(by_partition.values()), 'by_partition': by_partition,
            'n_partitions': len(tps)}


async def _consumer_lag():
    """The processor group's lag for admission: {'total', 'by_partition', 'n_partitions'}, None
    when admission is off (both caps 0), or {'error': str} when the lag is unknown."""
    now = time.monotonic()
    interval = settings.ingest_lag_probe_interval_s
    if _lag_cache['checked_at'] and now - _lag_cache['checked_at'] < interval:
        return _lag_cache['value']
    _lag_cache['checked_at'] = now
    if not any(_admission_caps()):
        _lag_cache['value'] = None
        return None
    try:
        value = await _probe_lag()
        _lag_cache.update(value=value, good=value, good_at=now)
        return value
    except Exception as e:
        stale = float(settings.ingest_lag_stale_s or 0.0)
        if _lag_cache['good'] is not None and now - _lag_cache['good_at'] <= stale:
            logger.warning(f'Consumer-lag probe failed, reusing the answer from '
                           f'{now - _lag_cache["good_at"]:.1f}s ago: {e}')
            _lag_cache['value'] = _lag_cache['good']
        else:
            logger.warning(f'Consumer-lag probe failed, lag unknown: {e}')
            _lag_cache['value'] = {'error': f'{type(e).__name__}: {e}'}
        return _lag_cache['value']


# Positions the broker returned to this process's producer.
_offset_guard = OffsetReuseGuard()

# The partitions the consumers stopped, from their markers in the anchor store: the same answer in
# every API process and after a restart.
_stop_watch = StopWatch()


async def _partition_stopped(p) -> "str | None":
    """Why partition p is refused because the consumers stopped it, or None. The markers are listed
    at most every ingest_lag_probe_interval_s; an unlistable store leaves the last answer."""
    if p is None or not settings.ingest_stop_markers:
        return None
    topic = settings.kafka_provenance_topic
    try:
        from crypto.merkle_tree_storage import _get_anchor_store
        store = _get_anchor_store()
    except Exception as e:
        logger.warning(f"stop markers not read, no anchor store: {e}")
        store = None
    if store is not None:
        await _stop_watch.refresh(store, topic, float(settings.ingest_lag_probe_interval_s),
                                  time.monotonic())
    return _stop_watch.refuse(topic, int(p))


def _no_json_constant(name):
    raise ValueError(f"{name} is not a JSON number")


def _max_record_depth() -> int:
    """The record validator's nesting limit."""
    from crypto.validate_record import _MAX_DEPTH
    return int(_MAX_DEPTH)


# Recent admissions per partition and tenant, for tenant_admission.
_admissions = AdmissionWindow(float(settings.ingest_tenant_window_s or 10.0))


def _tenant_admitted(tenant_id: str, lag: dict) -> "tuple[bool, str | None]":
    """tenant_admission on the tenant's partition; an admission is counted in the window."""
    from processing.admission import partition_for
    cap = int(settings.ingest_max_partition_lag or 0)
    if not getattr(settings, "ingest_tenant_isolation", True) or cap <= 0:
        return True, None
    by_p = lag.get('by_partition') or {}
    p = partition_for(str(tenant_id).encode("utf-8"), lag.get('n_partitions') or (max(by_p) + 1 if by_p else 1))
    now = time.monotonic()
    ok, why = tenant_admission(
        tenant_id, int(by_p.get(p, 0)), cap, _admissions.recent(p, now),
        float(settings.ingest_tenant_soft_fraction), float(settings.ingest_tenant_share_slack))
    if ok:
        _admissions.note(p, tenant_id, now)
    return ok, why


# Room for the "_acct" tag inside the record value.
_TAG_ROOM = 512


def _checked_record_value(provenance_event: "ProvenanceEvent") -> dict:
    """The broker record value, refused (400, 413) when the record validator would refuse it, so
    that a tagged record is never MALFORMED because of what the API wrote."""
    from crypto.validate_record import MAX_BYTES, validate_record
    value = provenance_event.dict()
    try:
        raw = json.dumps(value, default=str, allow_nan=False).encode("utf-8")
    except (ValueError, RecursionError) as e:
        raise _bad_request(f"The event cannot be recorded: {e}")
    if len(raw) + _TAG_ROOM > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"The event is {len(raw)} bytes; records are "
                                                    f"limited to {MAX_BYTES - _TAG_ROOM}")
    code = validate_record(raw)
    if code is not None:
        raise _bad_request(f"The event would be refused by the record validator: {code}")
    return value


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


# Events of this process between _accept_event's entry and its return.
_inflight = 0


async def _accept_event(event_data: Any, tenant_id: str, current_user: Dict[str, Any],
                        sender_ip: str) -> dict:
    """_accept_event_inner behind the process's in-flight cap (ingest_max_inflight_per_process)."""
    global _inflight
    cap = int(settings.ingest_max_inflight_per_process or 0)
    if cap and _inflight >= cap:
        # Refused before any work: a longer send queue would wait past the producer's timeout.
        _stage.note("busy")
        raise _refuse("This API process has too many events in flight; retry", retry_after="1")
    _inflight += 1
    t0 = time.perf_counter()
    try:
        return await _accept_event_inner(event_data, tenant_id, current_user, sender_ip)
    finally:
        _inflight -= 1
        _stage.event_done(t0)


async def _accept_event_inner(event_data: Any, tenant_id: str, current_user: Dict[str, Any],
                              sender_ip: str) -> dict:
    """Check, tag, send and acknowledge one decoded event, for POST /events and /events/batch.
    Raises HTTPException whenever the event is not acknowledged."""
    if not isinstance(event_data, dict):
        raise _bad_request("The event must be a JSON object")
    problem = unrepresentable_value(event_data, _max_record_depth())
    if problem is not None:
        raise _bad_request(f"The event cannot be recorded: {problem}")

    bad_path = unstorable_string(event_data)
    if bad_path is not None:
        raise _bad_request(f"Field {bad_path} is not valid Unicode text (lone surrogate)")

    required_fields = ['event_type', 'user_id', 'resource', 'operation']
    missing_fields = [field for field in required_fields if field not in event_data]
    if missing_fields:
        raise _bad_request(f"Missing required fields: {missing_fields}")
    for field in ('user_id', 'resource', 'operation'):
        if not isinstance(event_data[field], str):
            raise _bad_request(f"Field {field} must be a string")

    try:
        event_type = EventType(event_data['event_type'])
    except ValueError:
        raise _bad_request(f"Invalid event_type: {event_data['event_type']}")

    try:
        operation = OperationType(event_data['operation'].upper())
    except ValueError:
        raise _bad_request(f"Invalid operation: {event_data['operation']}")

    # An unknown source is recorded as "api"; the source must be one the credential may submit.
    try:
        source_type = SourceType(event_data.get('source', 'api'))
    except ValueError:
        source_type = SourceType.API
    if not source_allowed(source_type.value, current_user, settings.ingest_default_sources):
        raise HTTPException(status_code=403,
                            detail=f"This credential may not submit records of source "
                                   f"'{source_type.value}'")

    # The leaf commits to the event id and the timestamp, so a retry is the same leaf only if
    # both are the client's: a client event_id requires a client timestamp.
    client_eid = _client_event_id(event_data, tenant_id)
    if event_data.get("event_id") is not None and client_eid is None:
        raise _bad_request("Invalid event_id: 8-64 characters of A-Z, a-z, 0-9, '_', '.', ':' "
                           "or '-', starting with a letter or digit")
    raw_ts = event_data.get('timestamp')
    if client_eid is not None and not raw_ts:
        raise _bad_request("A client-supplied event_id requires a timestamp, so that a retry "
                           "records the same leaf")
    if raw_ts is not None and not isinstance(raw_ts, str):
        raise _bad_request("timestamp must be an ISO 8601 string")
    try:
        timestamp = (datetime.fromisoformat(raw_ts.replace('Z', '+00:00')) if raw_ts
                     else datetime.utcnow())
    except ValueError:
        raise _bad_request(f"Invalid timestamp: {raw_ts}")

    # The entity's address is the sender's only when the sender is the origin, so an intermediate
    # layer does not overwrite it.
    is_authoritative = event_data.get('is_origin', False) or event_data.get('authoritative_source', False)
    entity_ip = sender_ip if is_authoritative else None

    # Activity.id is unique across all tenants, so a server-minted id has 128 random bits.
    provenance_event = ProvenanceEvent(
        event_id=client_eid or f"ext_{secrets.token_hex(16)}",
        timestamp=timestamp,
        tenant_id=tenant_id,
        source=source_type,
        event_type=event_type,
        entity=ProvenanceEntity(
            type=EntityType.ENDPOINT,
            id=event_data['resource'],
            ip=entity_ip,
            metadata={
                'source': event_data.get('source', 'external'),
                'details': event_data.get('details', {}),
                'sender_verified': True if entity_ip else False,
                'sender_ip': sender_ip,
                'is_authoritative': is_authoritative
            }
        ),
        agent=ProvenanceAgent(
            type=AgentType.CDN_NODE if source_type == SourceType.CDN else AgentType.USER,
            id=event_data['user_id'],
            ip=event_data.get('user_ip'),
            metadata={
                'received_from': current_user.get('user_id', 'unknown')
            }
        ),
        activity=ProvenanceActivity(
            operation=operation,
            resource=event_data['resource'],
            metadata=event_data.get('details', {})
        )
    )

    # Again on the event as recorded: details sit two levels deeper there than in the request.
    problem = unrepresentable_value(provenance_event.dict(), _max_record_depth())
    if problem is not None:
        raise _bad_request(f"The event cannot be recorded: {problem}")

    logger.debug(f"Receiving provenance activity: {provenance_event.event_id} for user {current_user.get('user_id', 'unknown')}")

    # Admission: nothing is acknowledged that the consumers are not draining.
    t_lag = time.perf_counter()
    lag = await _consumer_lag()
    _stage.add("lag", t_lag)
    if lag is not None:
        from processing.admission import admit
        if lag.get('error'):
            admitted, why = (not settings.ingest_admission_fail_closed,
                             f"consumer lag unknown ({lag['error']})")
        else:
            admitted, why = admit(lag['by_partition'], lag['n_partitions'],
                                  str(tenant_id).encode("utf-8"),
                                  *_admission_caps())
            if admitted:
                admitted, why = _tenant_admitted(tenant_id, lag)
        if not admitted:
            logger.warning(f"Refusing ingest for {tenant_id}: {why}")
            raise _refuse(f"Ingestion temporarily unavailable: {why}. Retry later.")

    if settings.acct_mode:
        return await _submit_accounted(provenance_event, tenant_id)

    if kafka_producer:
        # Signed before the send: a signing failure must not follow an accepted record.
        receipt = _signed_ack(provenance_event)
        try:
            # Keyed by tenant: one partition, and so one consumer, appends to a tenant's log.
            # send_and_wait: the client is acknowledged only once the broker has the record.
            await kafka_producer.send_and_wait(
                settings.kafka_provenance_topic,
                value=provenance_event.dict(),
                key=str(tenant_id).encode("utf-8"),
            )
        except Exception as kafka_error:
            logger.warning(f"Kafka send failed: {kafka_error}, falling back to direct processing")
        else:
            return {
                "status": "queued",
                "message": "Provenance activity queued for processing",
                "activity_id": provenance_event.event_id,
                "processing": "async_kafka",
                "receipt": receipt,
            }

    # Direct processing (no Kafka, or the send failed; processing is idempotent). The receipt is
    # signed after the graph write and the log append; with tracking off nothing is acknowledged.
    if stream_processor.processors and settings.provenance_tracking_enabled:
        await stream_processor.processors[0]._process_single_event(provenance_event.dict())
        logger.info(f"Processed directly: {provenance_event.event_id}")

        return {
            "status": "success",
            "message": "Provenance activity processed",
            "activity_id": provenance_event.event_id,
            "processing": "direct_sync",
            "receipt": _signed_ack(provenance_event),
        }
    # The event may or may not be queued; a retry with the same event_id is idempotent.
    logger.error("No processors available")
    raise HTTPException(status_code=500, detail={
        "message": "Event not acknowledged; retry with the same event_id",
        "activity_id": provenance_event.event_id})


@router.post("/events")
async def receive_provenance_event(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    current_user = Depends(get_current_user)
):
    """Receive one event. It is acknowledged only once it is durable (in the broker, or in the
    graph and the log on the direct path), with a signed receipt when a signing key is set."""
    try:
        sender_ip = request_client_ip(request)
        body = await request.body()
        if not body:
            raise _bad_request("Empty request body")
        try:
            event_data = json.loads(body.decode('utf-8'), parse_constant=_no_json_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            # ValueError includes NaN/Infinity and integers too long to parse.
            raise _bad_request("Invalid JSON data")

        return await _accept_event(event_data, tenant_id, current_user, sender_ip)
    except HTTPException:
        raise
    except ClientDisconnect:
        # The client left before its body was read; nothing was sent or acknowledged.
        _note_client_gone()
        raise HTTPException(status_code=499, detail="Client closed the request before it was read")
    except Exception as e:
        logger.error(f"Error processing provenance activity: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


def _max_batch() -> int:
    return max(1, int(settings.ingest_max_batch or 500))


@router.post("/events/batch")
async def receive_provenance_events_batch(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    current_user = Depends(get_current_user)
):
    """Receive {"events": [event, ...]}; each event is handled as POST /events handles it. The
    answer has one result per event, in order: {"status_code": 200, ...receipt} when it is
    acknowledged, else {"status_code": 4xx/5xx, "detail": ...}."""
    try:
        sender_ip = request_client_ip(request)
        body = await request.body()
        if not body:
            raise _bad_request("Empty request body")
        try:
            data = json.loads(body.decode("utf-8"), parse_constant=_no_json_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _bad_request("Invalid JSON data")
        events = data.get("events") if isinstance(data, dict) else None
        if not isinstance(events, list) or not events:
            raise _bad_request('The body must be {"events": [ ... ]} with at least one event')
        if len(events) > _max_batch():
            raise _bad_request(f"At most {_max_batch()} events per batch")
    except HTTPException:
        raise
    except ClientDisconnect:
        _note_client_gone()
        raise HTTPException(status_code=499, detail="Client closed the request before it was read")

    async def one(ev):
        try:
            out = await _accept_event(ev, tenant_id, current_user, sender_ip)
            return dict(out, status_code=200)
        except HTTPException as e:
            return {"status_code": e.status_code, "detail": e.detail}
        except Exception as e:
            logger.error(f"Error processing provenance activity in a batch: {type(e).__name__}: {e}")
            return {"status_code": 500, "detail": "Internal server error"}

    results = await asyncio.gather(*(one(ev) for ev in events))
    # Every value is already JSON; FastAPI's generic encoder would cost more than the rest.
    body = json.dumps({"accepted": sum(1 for r in results if r["status_code"] == 200),
                       "results": list(results)}, default=str, separators=(",", ":"))
    return Response(content=body, media_type="application/json")


_client_gone = {"n": 0, "logged_at": 0.0, "logged_n": 0}


def _note_client_gone() -> None:
    """Counts requests whose client left before the body was read; one log line per 10 s."""
    _client_gone["n"] += 1
    now = time.monotonic()
    if now - _client_gone["logged_at"] >= 10.0:
        logger.warning(f"{_client_gone['n'] - _client_gone['logged_n']} request(s) closed by the client "
                       f"before they were read ({_client_gone['n']} since start); nothing acknowledged")
        _client_gone.update(logged_at=now, logged_n=_client_gone["n"])


@router.get("/proof/{event_id}")
async def get_event_proof(
    event_id: str = Path(..., description="Event id, as returned in the acknowledgement"),
    tenant_id: str = Depends(get_tenant_id),
    current_user = Depends(get_current_user)
):
    """Proof bundle for one event: leaf, inclusion proof against the first anchored root that
    covers it, and the signed anchor record. Verify offline with tools/verify_bundle.py."""
    out = await merkle_tree_storage.proof_bundle(tenant_id, event_id)
    if out["status"] == "ok":
        return out
    if out["status"] == "unknown":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=out)
    if out["status"] == "pending":
        return JSONResponse(status_code=202, content=out, headers={"Retry-After": "5"})
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=out)
