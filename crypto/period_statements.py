from __future__ import annotations

import asyncio
import functools
import hashlib
import hmac
import json
import logging
import os
import random
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Tuple

from crypto.anchor_store import AnchorRecord, WriteConflict, encode_tenant
from crypto.records import (NS_STMT, TENANT_STATES, agg_leaf, agg_order_key, agg_pad, agg_tree, canon,
                            contract_hash, salt_hex, signed, stmt_message, verify_agg_opening)
from crypto.validate_record import partition_of as route_partition

logger = logging.getLogger(__name__)

GENESIS = "0" * 64
AGG_ALG = "acct/agg/v1"
# Leaves that also carry the tenant's own status ("st": "ok" | "stall") for the period.
AGG_ALG_ST = "acct/agg/v2"
# The maker starts on period j this long after it ends (or twice the clock skew, if larger): the
# judge does not count a statement included before its period ended.
MAKER_MARGIN_MS = 2000
# A process that finds the statement already stored resubmits its leaf only if no receipt appears
# within this long; _post caps the wait at end(j) + 3/8 delta_pub_s.
FOLLOWER_GRACE_MS = 20_000
MAX_SUBMITS_PER_PERIOD = 3
# Store reads and writes a maker runs at once (heads, openings).
IO_CONCURRENCY = 32
# The mark of period j (the public log's size while j runs) is taken this long after the deadline of
# j - 1, so no statement of an earlier period can appear after it.
MARK_DELAY_MS = 1000
# Bounds on the scan of a stalled partition's overdue records. A scan that stops early leaves every
# tenant of the partition stalled.
OVERDUE_SCAN_CAP = 200_000
OVERDUE_SCAN_S = 10.0
# How long the status read waits for the records at W.
STATUS_READ_S = 10.0
LOG_APPEND_TIME = 1          # aiokafka ConsumerRecord.timestamp_type for LogAppendTime


def backup_make_delay_ms(contract: dict) -> int:
    """How much later than the dedicated maker a backup maker makes a body of its own: delta_pub_s / 8."""
    return int(contract["delta_pub_s"]) * 125


def period_of(t_ms: int, t0_ms: int, period_s: int) -> int:
    return (int(t_ms) - int(t0_ms)) // (int(period_s) * 1000)


def period_end_ms(j: int, t0_ms: int, period_s: int) -> int:
    return int(t0_ms) + (int(j) + 1) * int(period_s) * 1000


def deadline_ms(j: int, contract: dict) -> int:
    """The time by which the statement for period j must be included on the public log."""
    return period_end_ms(j, contract["t0_ms"], contract["period_s"]) + int(contract["delta_pub_s"]) * 1000


def maker_margin_ms(contract: dict) -> int:
    return max(MAKER_MARGIN_MS, 2 * int(contract.get("clock_skew_ms") or 0))


def store_by_ms(j: int, contract: dict) -> int:
    """Regular bodies are stored and submitted only before end(j) + delta_pub_s / 2. A leaf
    submitted by then is on the log before the outage window opens."""
    return period_end_ms(j, contract["t0_ms"], contract["period_s"]) + int(contract["delta_pub_s"]) * 500


def outage_from_ms(j: int, contract: dict) -> int:
    """The outage body is posted only from end(j) + 3/4 delta_pub_s."""
    return period_end_ms(j, contract["t0_ms"], contract["period_s"]) + int(contract["delta_pub_s"]) * 750


def first_due_period(a_ms: int, contract: dict) -> int:
    """The first period ending at or after a_ms + theta_s."""
    p = int(contract["period_s"]) * 1000
    x = int(a_ms) + int(contract["theta_s"]) * 1000 - int(contract["t0_ms"])
    return max(-(-x // p) - 1, int(contract.get("effective_j", 0) or 0), 0)


def part_status(W: int, hw: int, oldest_ms: Optional[int], t_s_ms: int, theta_s: int, delta_s: int) -> str:
    """ok if nothing is outstanding or the oldest outstanding record is younger than theta_s - delta_s
    at t_s, else stall. An unknown append time is a stall."""
    if int(W) >= int(hw):
        return "ok"
    if oldest_ms is not None and int(oldest_ms) > int(t_s_ms) - (int(theta_s) - int(delta_s)) * 1000:
        return "ok"
    return "stall"


def tp_key(topic: str, p: int) -> str:
    return f"{topic}/{int(p)}"


def partition_of(contract: dict, tenant_id: str) -> Optional[int]:
    """The tenant's partition from the contract alone: broker.partitioner (murmur2 or crc32) of the
    tenant id over the frozen broker.partitions. None when the contract does not say."""
    b = contract.get("broker") if isinstance(contract, dict) else None
    if not isinstance(b, dict) or not isinstance(tenant_id, str) or b.get("kind", "kafka") != "kafka":
        return None
    return route_partition(tenant_id.encode("utf-8"),
                           {"fn": b.get("partitioner", "murmur2"), "n": b.get("partitions")})


def tp_of(contract: dict, tenant_id: str) -> Optional[str]:
    p = partition_of(contract, tenant_id)
    b = contract.get("broker") or {}
    return None if p is None or not isinstance(b.get("topic"), str) else tp_key(b["topic"], p)


def period_key(dep: str, j: int) -> str:
    return f"periods/{dep}/{int(j):012d}.json"


def outage_key(dep: str, j: int) -> str:
    """Where the outage body of j is kept once posted (the period key may hold a regular body that
    was stored but never posted)."""
    return f"periods/{dep}/{int(j):012d}.outage.json"


def opening_key(dep: str, j: int, tenant_id: str) -> str:
    return f"periods/{dep}/{int(j):012d}.open/{encode_tenant(tenant_id)}.json"


def receipt_key(dep: str, j: int) -> str:
    return f"periods/{dep}/{int(j):012d}.receipt.json"


# The receipt spool: a maker's own directory for receipts the store refused. A receipt's cosigned
# tree head is the only proof of when its statement was included; build_defense reads the spool.

def spool_ns(contract: dict) -> str:
    """The spool's directory for one contract, so receipts of another contract are never loaded."""
    return f"{encode_tenant(contract['dep'])}-{contract_hash(contract)[:16]}"


def spool_path(spool_dir: str, ns: str, j: int) -> str:
    return os.path.join(spool_dir, ns, f"{int(j):012d}.receipt.json")


def spool_receipt(spool_dir: str, ns: str, j: int, raw: bytes) -> None:
    """Write one receipt durably: a temporary file, fsync, then rename over the final name."""
    path = spool_path(spool_dir, ns, j)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        fd = os.open(os.path.dirname(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass                           # directories cannot be fsynced on every platform


def spooled_receipts(spool_dir: Optional[str], ns: str) -> Dict[int, bytes]:
    """{j: receipt bytes} from one contract's spool; files that do not parse as receipts are
    skipped."""
    out: Dict[int, bytes] = {}
    if not spool_dir:
        return out
    d = os.path.join(spool_dir, ns)
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for name in sorted(names):
        if not name.endswith(".receipt.json"):
            continue
        try:
            j = int(name.split(".", 1)[0])
            with open(os.path.join(d, name), "rb") as f:
                raw = f.read()
            if isinstance(json.loads(raw).get("tree_head"), dict):
                out[j] = raw
        except (OSError, ValueError, AttributeError):
            continue
    return out


def agg_key(dep: str, j: int, root_hex: str) -> str:
    """The heads an aggregate was built from. Keyed by root, so racing makers never conflict here
    and any process can rebuild the winning statement's openings."""
    return f"periods/{dep}/{int(j):012d}.agg/{root_hex}.json"


def contract_key(dep: str, ver: int) -> str:
    return f"contract/{dep}/{int(ver):06d}.json"


def contract_receipt_key(dep: str, ver: int) -> str:
    return f"contract/{dep}/{int(ver):06d}.receipt.json"


def statement_hash(body: dict) -> str:
    """The hash a later statement's "prev" names, and the public leaf message: SHA-256(NS_STMT ||
    canon(body))."""
    return stmt_message(body).hex()


def leaf_checksum(body: dict) -> str:
    """The checksum of the body's public leaf: SHA-256 of its 32-byte message."""
    return hashlib.sha256(stmt_message(body)).hexdigest()


def sign_statement(signer, body: dict) -> dict:
    return {"body": body, "sig": signer.sign(signed(NS_STMT, body))}


def verify_statement(stmt: Any, pubkey: Optional[bytes]) -> bool:
    from crypto.signing import verify
    try:
        return pubkey is not None and isinstance(stmt.get("sig"), str) and \
            verify(pubkey, stmt.get("sig"), signed(NS_STMT, stmt["body"]))
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def contract_body(*, dep: str, ver: int, effective_j: int, t0_ms: int, period_s: int, delta_pub_s: int,
                  theta_s: int, delta_s: int, stall_budget: int, window_periods: int, unchk_budget: int,
                  agg_cap: int, pk: str, sigsum_key_hash: str, witness_policy_sha256: str,
                  topic: str, partitions: int, system_tenant: str, retention_s: int,
                  validator: str = "acct-validate/1",
                  first_acct_offset: Optional[Dict[str, int]] = None,
                  clock_skew_ms: Optional[int] = None, partitioner: Optional[str] = None,
                  admission: Optional[Dict[str, int]] = None) -> dict:
    """The CONTRACT statement body. broker.partitions freezes the partition count, so every maker
    builds the same outage statement and the judge can compute a tenant's partition;
    broker.first_acct_offset is where the density audit starts on each partition."""
    for name, val in (("period_s", period_s), ("theta_s", theta_s), ("delta_s", delta_s),
                      ("delta_pub_s", delta_pub_s), ("partitions", partitions)):
        if int(val) <= 0:
            raise ValueError(f"{name} must be positive")
    if int(theta_s) <= 2 * int(delta_s):
        raise ValueError("theta_s must exceed 2 * delta_s")
    if int(delta_pub_s) >= int(period_s):
        raise ValueError("delta_pub_s must be shorter than period_s")
    skew_s = (int(clock_skew_ms) if clock_skew_ms is not None else 1000) / 1000.0
    if (int(stall_budget) + 1) * int(period_s) + int(delta_pub_s) <= 2 * int(delta_s) + 2 * skew_s:
        # The broker must still hold a record when the auditor reads it, at theta_s + delta_s.
        raise ValueError("(stall_budget + 1) * period_s + delta_pub_s must exceed "
                         "2 delta_s + 2 clock skews")
    broker = {"kind": "kafka", "dense": True, "topic": str(topic), "partitions": int(partitions),
              "partitioner": str(partitioner or "murmur2")}
    if broker["partitioner"] not in ("murmur2", "crc32"):
        raise ValueError("the Kafka partitioner must be murmur2 or crc32 (acct-route/1)")
    if first_acct_offset is not None:
        fao = {}
        for k, v in first_acct_offset.items():
            t, _, p = str(k).rpartition("/")
            if t != str(topic) or not p.isdigit() or int(p) >= int(partitions) or type(v) is not int or v < 0:
                raise ValueError(f"first_acct_offset entry {k!r}: {v!r} does not name a partition of the topic")
            fao[tp_key(t, int(p))] = int(v)
        broker["first_acct_offset"] = fao
    body = {"v": 1, "kind": "contract", "dep": str(dep), "ver": int(ver), "effective_j": int(effective_j),
            "t0_ms": int(t0_ms), "period_s": int(period_s), "delta_pub_s": int(delta_pub_s),
            "theta_s": int(theta_s), "delta_s": int(delta_s), "stall_budget": int(stall_budget),
            "window_periods": int(window_periods), "unchk_budget": int(unchk_budget),
            "agg_cap": int(agg_cap), "pk": str(pk), "sigsum_key_hash": str(sigsum_key_hash),
            "witness_policy_sha256": str(witness_policy_sha256), "validator": str(validator),
            "broker": broker, "system_tenant": str(system_tenant), "retention_s": int(retention_s)}
    if clock_skew_ms is not None:
        body["clock_skew_ms"] = int(clock_skew_ms)
    if admission is not None:
        # The per-tenant admission rule (api/ingest_rules.tenant_admission), in integers.
        adm = {k: int(admission[k]) for k in ("soft_permille", "slack_permille", "window_s")}
        if not (0 <= adm["soft_permille"] <= 1000 and adm["slack_permille"] >= 0 and adm["window_s"] > 0):
            raise ValueError("admission: soft_permille in [0, 1000], slack_permille >= 0, window_s > 0")
        body["admission"] = adm
    if 2 * maker_margin_ms(body) >= int(delta_pub_s) * 1000:
        raise ValueError("the maker's margin (twice the clock skew) must be well inside delta_pub_s / 2")
    return body


def theta_max_s(contract: dict) -> int:
    return int(contract["theta_s"]) + (int(contract["stall_budget"]) + 1) * int(contract["period_s"]) \
        + int(contract["delta_pub_s"])


def p10_problems(contract: Optional[dict], send_ms: int, broker_skew_ms: int,
                 clock_skew_ms: int = 1000) -> List[str]:
    """Problems with the rule delta_s >= send bound + 2 * clock skew + broker skew, where send_ms is
    how late after its tag's time a record may reach the broker. Otherwise a late record escapes the
    HEAD rule. Empty when the rule holds or there is no contract."""
    if not contract:
        return []
    try:
        delta_ms = int(contract["delta_s"]) * 1000
    except (KeyError, TypeError, ValueError):
        return ["P10: the contract has no delta_s"]
    eps = int(contract.get("clock_skew_ms") or clock_skew_ms)
    need = int(send_ms) + 2 * eps + int(broker_skew_ms)
    if need > delta_ms:
        return [f"P10: the contract's delta is {delta_ms} ms, but the send bound ({int(send_ms)} ms) "
                f"plus twice the clock skew ({eps} ms) and the broker's skew ({int(broker_skew_ms)} ms) "
                f"needs {need} ms"]
    return []


def k_salt_from(settings) -> Optional[bytes]:
    """The salt key: acct_salt_seed, else derived from the signing seed under a label of its own."""
    seed = settings.acct_salt_seed
    if seed:
        return bytes.fromhex(seed)
    sk = settings.merkle_signing_seed
    if sk:
        return hmac.new(bytes.fromhex(sk), b"acct/k-salt/v1\x00", hashlib.sha256).digest()
    return None


def _pad_order_key(k_salt: bytes, dep: str, j: int, i: int) -> bytes:
    # "order-pad" and a tenant's "order[" differ in their sixth byte, so no pad key equals a
    # tenant's key.
    return hmac.new(k_salt, b"order-pad" + canon([str(dep), int(j), int(i)]), hashlib.sha256).digest()


def aggregate(k_salt: bytes, dep: str, j: int, heads: Dict[str, dict], cap: int,
              st: Optional[Dict[str, Any]] = None) -> Tuple[str, int, Dict[str, dict]]:
    """(root hex, size, openings) of the salted aggregate over tenant heads {t: {n, rh, pos_last, u}},
    padded to a power of two of at least cap. Slots are placed by a keyed per-period order, so an
    index reveals nothing about the tenants. With st (tenant_status), leaves are alg v2."""
    size = 1
    while size < max(int(cap), 1):
        size *= 2
    while size < len(heads):
        size *= 2
    slots: List[Tuple[bytes, Any]] = [(agg_order_key(k_salt, dep, j, t), t) for t in heads]
    slots += [(_pad_order_key(k_salt, dep, j, i), i) for i in range(size - len(heads))]
    slots.sort(key=lambda s: s[0])
    leaves: List[bytes] = []
    openings: Dict[str, dict] = {}
    for idx, (_, item) in enumerate(slots):
        if isinstance(item, int):
            leaves.append(agg_pad(k_salt, dep, j, item))
            continue
        t, h = item, heads[item]
        salt = salt_hex(k_salt, dep, j, t)
        u = int(h.get("u") or 0)
        s, late = None, None
        if st is not None:
            v = st.get(t, {"st": "stall", "late": 0})
            s, late = (v, 0) if isinstance(v, str) else (str(v.get("st", "stall")), int(v.get("late") or 0))
        leaves.append(agg_leaf(salt, t, int(h["n"]), str(h["rh"]), h.get("pos_last"), u, s, late))
        op = {"j": int(j), "tenant_id": t, "salt": salt, "n": int(h["n"]), "rh": str(h["rh"]),
              "pos_last": h.get("pos_last"), "u": u, "index": idx, "size": size}
        if s is not None:
            op["st"], op["late"] = s, late
        openings[t] = op
    root, paths = agg_tree(leaves)
    for t, op in openings.items():
        op["path"] = [p.hex() for p in paths[op["index"]]]
    return root.hex(), size, openings


def verify_opening(opening: Any, root_hex: Optional[str], size: Any) -> bool:
    """Does the opening lead to root_hex in a tree of `size` leaves (records.verify_agg_opening)?"""
    return verify_agg_opening(opening, root_hex, size)


def build_statement(contract: dict, j: int, t_s_ms: int, parts: dict, heads: dict, k_salt: bytes,
                    prev_hash: str, window_used: dict, stalled_since: dict,
                    cause: str = "behind", tenant_st: Optional[Dict[str, str]] = None) -> Tuple[dict, Dict[str, dict]]:
    """The statement body for period j and the tenants' openings. parts: {tp: (W, hw, oldest_ms)};
    heads: {t: {n, rh, pos_last, u}}; tenant_st, when given, makes the aggregate alg v2."""
    dep = contract["dep"]
    pout: Dict[str, dict] = {}
    stalled: List[str] = []
    for tp in sorted(parts):
        W, hw, oldest = parts[tp][:3]
        st = part_status(W, hw, oldest, t_s_ms, contract["theta_s"], contract["delta_s"])
        pout[tp] = {"W": int(W), "hw": int(hw), "oldest_ms": None if oldest is None else int(oldest),
                    "status": st}
        if st == "stall":
            stalled.append(tp)
    root, size, openings = aggregate(k_salt, dep, j, heads, contract["agg_cap"], tenant_st)
    body = {"v": 1, "kind": "stall" if stalled else "head", "dep": dep, "j": int(j),
            "t_s_ms": int(t_s_ms), "prev": prev_hash, "contract": contract_hash(contract),
            "agg": {"alg": AGG_ALG if tenant_st is None else AGG_ALG_ST, "root": root, "size": size},
            "parts": pout, "stall": None}
    if stalled:
        body["stall"] = {"parts": stalled,
                         "since_j": min(int(stalled_since.get(tp, j)) for tp in stalled),
                         "cause": cause,
                         "window_used": {tp: int(window_used.get(tp, 1)) for tp in stalled}}
    return body, openings


def outage_statement(contract: dict, j: int) -> dict:
    """The STALL body of every partition for period j when the store could not be used in time: a
    function of the contract and j alone, so makers that cannot coordinate post identical bytes."""
    topic = contract["broker"]["topic"]
    tps = [tp_key(topic, p) for p in range(int(contract["broker"]["partitions"]))]
    return {"v": 1, "kind": "stall", "dep": contract["dep"], "j": int(j),
            "t_s_ms": period_end_ms(j, contract["t0_ms"], contract["period_s"]), "prev": GENESIS,
            "contract": contract_hash(contract), "agg": {"alg": AGG_ALG, "root": None, "size": 0},
            "parts": {tp: {"W": None, "hw": None, "oldest_ms": None, "status": "stall"} for tp in tps},
            "stall": {"parts": tps, "since_j": int(j), "cause": "store_unavailable", "window_used": None}}


def _late_entry(v) -> Tuple[int, int]:
    """(highest overdue offset, overdue count) of one tenant in an overdue scan's result."""
    if isinstance(v, dict):
        return int(v["o"]), int(v.get("n", 1))
    return int(v), 1


def tenant_status(contract: dict, heads: Dict[str, dict], status: Dict[str, str],
                  overdue: Dict[str, Tuple[bool, Dict[str, Any]]]) -> Dict[str, dict]:
    """Each tenant's own status for the period, {t: {"st", "late"}}: ok when its partition is ok or
    a complete scan finds all its overdue records inside its head; held when stalled but within its
    fair share while a co-tenant is over its own (not charged); stall otherwise."""
    slack = int((contract.get("admission") or {}).get("slack_permille", 250)) / 1000.0
    over: Dict[str, set] = {}
    counts: Dict[str, Dict[str, int]] = {}
    for tp, (complete, found) in overdue.items():
        n = {t: _late_entry(v)[1] for t, v in (found or {}).items()}
        counts[tp] = n
        total, k = sum(n.values()), len([t for t, c in n.items() if c > 0])
        over[tp] = {t for t, c in n.items() if complete and k > 1 and total > 0
                    and c / total > (1.0 / k) * (1.0 + slack)}
    out: Dict[str, dict] = {}
    for t, h in heads.items():
        pl = h.get("pos_last") if isinstance(h.get("pos_last"), dict) else None
        tp = tp_key(pl["topic"], pl["p"]) if pl and "topic" in pl and "p" in pl else tp_of(contract, t)
        late = int(counts.get(tp, {}).get(t, 0))
        if tp is None or tp not in status:
            out[t] = {"st": "stall", "late": late}
            continue
        if status[tp] == "ok":
            out[t] = {"st": "ok", "late": late}
            continue
        complete, found = overdue.get(tp, (False, {}))
        if complete and t not in (found or {}):
            stalled = False
        elif complete:
            o, _ = _late_entry(found[t])
            stalled = not (pl and tp_key(pl["topic"], pl["p"]) == tp and int(pl["o"]) >= o)
        else:
            stalled = True
        if not stalled:
            out[t] = {"st": "ok", "late": late}
        elif over.get(tp) and t not in over[tp]:
            out[t] = {"st": "held", "late": late}
        else:
            out[t] = {"st": "stall", "late": late}
    return out



async def read_broker_status(topic: str, group: str,
                             bootstrap: Optional[List[str]] = None) -> Dict[str, Tuple[int, int, Optional[int]]]:
    """{tp: (W, hw, oldest_ms)} for every partition of the topic: the group's committed offset, the
    high watermark, and the LogAppendTime of the record at W (None when unknown or not stamped by
    the broker). Reads the committed offsets without joining the group."""
    from aiokafka import AIOKafkaConsumer
    from aiokafka.admin import AIOKafkaAdminClient
    from aiokafka.structs import TopicPartition
    if bootstrap is None:
        from config import settings
        bootstrap = settings.kafka_bootstrap_servers
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap)
    await admin.start()
    try:
        committed = await admin.list_consumer_group_offsets(group) or {}
    finally:
        await admin.close()
    consumer = AIOKafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    await consumer.start()
    try:
        parts = consumer.partitions_for_topic(topic)
        if not parts:
            # An unassigned consumer keeps no metadata for the topic; the full metadata has it.
            md = await consumer._client.fetch_all_metadata()
            parts = md.partitions_for_topic(topic)
        if not parts:
            raise RuntimeError(f"topic {topic}: no partitions in the broker's metadata")
        tps = [TopicPartition(topic, p) for p in sorted(parts)]
        ends = await consumer.end_offsets(tps)
        starts = await consumer.beginning_offsets(tps)
        out: Dict[str, Tuple[int, int, Optional[int]]] = {}
        need = []
        for tp in tps:
            meta = committed.get(tp)
            start = starts.get(tp, 0)
            W = meta.offset if meta is not None and meta.offset >= 0 else start
            hw = ends.get(tp, 0)
            if W < start:
                logger.error(f"INTEGRITY ALARM [period]: committed offset {W} of {tp} is below the log "
                             f"start {start}: records were released unanchored")
            out[tp_key(topic, tp.partition)] = (int(W), int(hw), None)
            if start <= W < hw:
                need.append((tp, W))
        if need:
            consumer.assign([tp for tp, _ in need])
            for tp, W in need:
                consumer.seek(tp, W)
            want = {tp: W for tp, W in need}
            deadline = time.monotonic() + STATUS_READ_S
            while want and time.monotonic() < deadline:
                batch = await consumer.getmany(*want.keys(), timeout_ms=1000, max_records=len(want))
                for tp, recs in batch.items():
                    for r in recs:
                        if tp in want and r.offset == want[tp]:
                            if getattr(r, "timestamp_type", LOG_APPEND_TIME) != LOG_APPEND_TIME:
                                logger.error(f"INTEGRITY ALARM [period]: {tp} does not stamp LogAppendTime "
                                             "(message.timestamp.type); its status is stall")
                            else:
                                W, hw, _ = out[tp_key(topic, tp.partition)]
                                out[tp_key(topic, tp.partition)] = (W, hw, int(r.timestamp))
                            want.pop(tp)
                            consumer.pause(tp)
                            break
    finally:
        await consumer.stop()
    return out


async def scan_overdue_kafka(topic: str, p: int, W: int, hw: int, until_ms: int,
                             bootstrap: Optional[List[str]] = None, cap: int = OVERDUE_SCAN_CAP,
                             budget_s: float = OVERDUE_SCAN_S) -> Tuple[bool, Dict[str, dict]]:
    """(complete, {tenant: {"o": highest offset, "n": count} of its records appended at or before
    until_ms}) over one partition from W on, keyed by the record key (the tenant id). Complete when
    a later record or hw was reached; a record without LogAppendTime makes it incomplete."""
    from aiokafka import AIOKafkaConsumer
    from aiokafka.structs import TopicPartition
    if bootstrap is None:
        from config import settings
        bootstrap = settings.kafka_bootstrap_servers
    late: Dict[str, dict] = {}
    if W >= hw:
        return True, late
    consumer = AIOKafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    await consumer.start()
    try:
        tp = TopicPartition(topic, int(p))
        consumer.assign([tp])
        consumer.seek(tp, int(W))
        seen, deadline = 0, time.monotonic() + budget_s
        while time.monotonic() < deadline and seen < cap:
            batch = await consumer.getmany(tp, timeout_ms=500, max_records=1000)
            recs = batch.get(tp, [])
            if not recs:
                continue
            for r in recs:
                seen += 1
                if getattr(r, "timestamp_type", LOG_APPEND_TIME) != LOG_APPEND_TIME:
                    return False, late
                if r.offset >= hw or int(r.timestamp) > until_ms:
                    return True, late
                try:
                    t = bytes(r.key).decode("utf-8") if r.key is not None else None
                except (TypeError, UnicodeDecodeError):
                    t = None
                if t is not None:
                    e = late.setdefault(t, {"o": -1, "n": 0})
                    e["o"], e["n"] = max(e["o"], int(r.offset)), e["n"] + 1
            if recs[-1].offset + 1 >= hw:
                return True, late
        return False, late
    finally:
        await consumer.stop()


def _authentic(rec: Optional[AnchorRecord], tenant_id: str, pubkey: Optional[bytes]) -> bool:
    if rec is None or rec.tenant_id != tenant_id:
        return False
    try:
        return rec.verify_self() and (pubkey is None or rec.verify_sig(pubkey))
    except Exception:
        return False


def _head_dict(rec: AnchorRecord) -> dict:
    return {"n": int(rec.n), "rh": rec.record_hash, "pos_last": rec.pos_last, "u": int(rec.u or 0)}


def _head_of(store, tenant_id: str, pubkey: Optional[bytes], after: int = -1) -> Optional[dict]:
    """The tenant's latest authenticated head above leaf count `after`, or None."""
    try:
        rec = store.latest_after(tenant_id, after)
    except Exception:
        rec = None
    if rec is not None and not _authentic(rec, tenant_id, pubkey):
        rec = next((r for r in sorted(store.all(tenant_id), key=lambda r: -int(r.n))
                    if int(r.n) > after and _authentic(r, tenant_id, pubkey)), None)
    return None if rec is None else _head_dict(rec)


async def read_heads(store, pubkey: Optional[bytes], tenants: Iterable[str],
                     cache: Optional[Dict[str, dict]] = None,
                     concurrency: int = IO_CONCURRENCY,
                     run: Optional[Callable[..., Awaitable]] = None) -> Dict[str, dict]:
    """Every tenant's latest authenticated anchor head {n, rh, pos_last, u}, from the store. With a
    cache of earlier heads only newer records are read. `run(fn, *args)` runs a blocking read."""
    cache = cache if cache is not None else {}
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    run = run or asyncio.to_thread

    async def one(t):
        async with sem:
            old = cache.get(t)
            new = await run(_head_of, store, t, pubkey, int(old["n"]) if old else -1)
            if new is not None:
                cache[t] = new
            return t, cache.get(t)
    out = {}
    for t, h in await asyncio.gather(*(one(t) for t in tenants)):
        if h is not None:
            out[t] = dict(h)
    return out


class _TooLate(Exception):
    """The regular body could not be stored and submitted before end(j) + delta_pub_s / 2."""


class _WindowClosed(Exception):
    """The thread that was to submit a leaf started after the leaf's submission window closed."""


class PeriodMaker:
    """Builds, stores and posts the statement of each period. Any number of processes may run one;
    put_once on the statement key decides which body is the statement. overdue(tp, W, hw, until_ms),
    when given, lets tenants of a stalled partition be declared ok (scan_overdue_kafka)."""

    def __init__(self, store, signer, k_salt: bytes, contract: dict,
                 broker_status: Callable[[], Awaitable[Dict[str, Tuple]]],
                 sigsum=None, clock: Optional[Callable[[], int]] = None,
                 pubkey: Optional[bytes] = None, sleep: Callable[[float], Awaitable] = asyncio.sleep,
                 overdue: Optional[Callable[..., Awaitable[Tuple[bool, Dict[str, int]]]]] = None,
                 io_concurrency: int = IO_CONCURRENCY,
                 broker_skew_ms: int = 1000, make_delay_ms: int = 0, spool_dir: Optional[str] = None):
        self.make_delay_ms = max(0, int(make_delay_ms))
        self.spool_dir = spool_dir or None
        # Threads of this maker's own, so a full default executor cannot delay it. Made on first use.
        self._pool = None
        self.store = store
        self.signer = signer
        self.k_salt = k_salt
        self.contract = contract
        self.dep = contract["dep"]
        self.broker_status = broker_status
        self.overdue = overdue
        self.io_concurrency = int(io_concurrency)
        self.sigsum = sigsum
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.pubkey = pubkey if pubkey is not None else signer.public_key_raw
        self.sleep = sleep
        self.done: Set[int] = set()
        self._first_seen: Dict[int, int] = {}
        self._submits: Dict[int, int] = {}
        self._pl_mark: Dict[int, int] = {}
        self._stalls: Dict[int, Set[str]] = {}       # period -> partitions it declared stalled
        self._heads: Dict[str, dict] = {}            # latest authenticated head per tenant
        # Periods whose statement this process stored: it posts them without a follower's grace.
        self._mine: Set[int] = set()
        # Leaf checksum -> period of every statement this process knows (made, stored or read).
        self._known: Dict[str, int] = {leaf_checksum(contract): -1}
        # Openings still to be written; the statement's leaf is posted first.
        self._openings_todo: Dict[int, Tuple[dict, Optional[Dict[str, dict]]]] = {}
        # Outage statements and receipts the store refused, written once it takes them again.
        self._unstored: Dict[int, dict] = {}
        self._unstored_receipts: Dict[int, bytes] = {}
        for j, raw in spooled_receipts(self.spool_dir, spool_ns(contract)).items():
            self._unstored_receipts.setdefault(j, raw)
        # Leaf index of each period's statement, from the receipts this process obtained.
        self._leaf_index: Dict[int, int] = {}
        self._openings_done: Set[int] = set()
        self.broker_skew_ms = int(broker_skew_ms)
        # Per partition the (W, append time at W) of the last status read.
        self._last_at_w: Dict[str, Tuple[int, int]] = {}
        self.time_alarms = 0

    def _check_time_at_w(self, parts: Dict[str, Tuple]) -> None:
        """Alarm when the append time at W goes back by more than the broker's skew while W does
        not: a HEAD could then leave overdue records out."""
        for tp, (W, _, old) in parts.items():
            if old is None:
                continue
            prev = self._last_at_w.get(tp)
            if prev is not None and int(W) >= prev[0] and int(old) < prev[1] - self.broker_skew_ms:
                self.time_alarms += 1
                logger.error(f"INTEGRITY ALARM [timing]: {tp}: the append time at W={int(W)} is "
                             f"{prev[1] - int(old)} ms before the one at W={prev[0]}, beyond the broker's "
                             f"skew of {self.broker_skew_ms} ms; HEAD statements no longer bound this "
                             "partition's overdue records")
            if prev is None or int(W) >= prev[0]:
                self._last_at_w[tp] = (int(W), int(old))

    def _end(self, j: int) -> int:
        return period_end_ms(j, self.contract["t0_ms"], self.contract["period_s"])

    async def _io(self, fn, *args):
        """fn(*args) on one of this maker's threads."""
        if self._pool is None:
            from concurrent.futures import ThreadPoolExecutor
            self._pool = ThreadPoolExecutor(max_workers=max(1, self.io_concurrency) + 4,
                                            thread_name_prefix="period-maker")
        return await asyncio.get_running_loop().run_in_executor(self._pool, functools.partial(fn, *args))

    async def _get(self, key: str) -> Optional[bytes]:
        return await self._io(self.store.get_object, key)

    async def _put(self, key: str, data: bytes) -> bool:
        return await self._io(self.store.put_once, key, data)

    async def _read_stmt(self, key: str, j: int) -> Optional[dict]:
        raw = await self._get(key)
        if raw is None:
            return None
        stmt = json.loads(raw)
        if not verify_statement(stmt, self.pubkey) or not isinstance(stmt.get("body"), dict) \
                or stmt["body"].get("j") != j:
            # The key is taken by a foreign object: only the outage body can declare this period.
            logger.error(f"INTEGRITY ALARM [period]: stored object {key} does not verify")
            return None
        self._note(stmt["body"])
        return stmt

    async def _stored_statement(self, j: int) -> Optional[dict]:
        return await self._read_stmt(period_key(self.dep, j), j)

    def _note(self, body: dict) -> None:
        j = int(body["j"])
        self._known[leaf_checksum(body)] = j
        self._stalls[j] = {tp for tp, p in (body.get("parts") or {}).items()
                           if isinstance(p, dict) and p.get("status") == "stall"}

    def _window_used(self, j: int, tps: Iterable[str]) -> Dict[str, int]:
        w = int(self.contract["window_periods"])
        return {tp: sum(1 for jj, s in self._stalls.items() if j - w < jj <= j and tp in s) for tp in tps}

    def _prune(self, cur: int) -> None:
        keep = cur - 4
        for d in (self._first_seen, self._submits, self._pl_mark, self._leaf_index):
            for j in [j for j in d if j < keep]:
                d.pop(j, None)
        for c in [c for c, j in self._known.items() if 0 <= j < keep]:
            self._known.pop(c, None)
        w = int(self.contract["window_periods"])
        for j in [j for j in self._stalls if j < cur - w]:
            self._stalls.pop(j, None)
        self._mine = {j for j in self._mine if j >= keep}
        self._openings_done = {j for j in self._openings_done if j >= keep}

    async def mark(self, j: int) -> None:
        """Record the public log's size while period j runs and after the deadline of j - 1: a leaf
        of ours after it, other than a known earlier statement, can only be a statement for j or
        later."""
        if self.sigsum is None or j in self._pl_mark:
            return
        try:
            th = await self._io(self.sigsum.get_tree_head)
            self._pl_mark[j] = int(th.size)
        except Exception as e:
            logger.warning(f"period statements: cannot read the public log's size: {e}")

    async def _start_of(self, j: int) -> Optional[int]:
        """Where the leaves for j can begin: the mark, else just after the leaf of j-1's statement."""
        if j in self._pl_mark:
            return self._pl_mark[j]
        if j - 1 in self._leaf_index:
            return self._leaf_index[j - 1] + 1
        try:
            raw = await self._get(receipt_key(self.dep, j - 1))
            if raw is not None:
                return int(json.loads(raw)["leaf_index"]) + 1
        except Exception:
            pass
        return None

    async def _our_leaves_since(self, j: int) -> Optional[List[Tuple[int, str]]]:
        """Our leaves since period j's start, other than statements known to be of earlier periods
        and the contract, or None when that cannot be told."""
        start = await self._start_of(j)
        if self.sigsum is None or start is None:
            return None
        try:
            leaves = await self._io(self.sigsum.leaves_by_key, start)
        except Exception:
            return None
        return [(int(i), c.hex()) for i, c in leaves if self._known.get(c.hex(), j) >= j]

    async def _make(self, j: int) -> dict:
        # Read order matters: the clock first, then W, hw and the time at W, then the heads, so
        # every anchor a commit before the W read relied on is in the aggregate.
        c = self.contract
        t_s = int(self.clock())
        raw_parts = await self.broker_status()
        parts = {tp: tuple(v[:3]) for tp, v in raw_parts.items()}
        # A read with no partition at all is a failed read; the period is left to the outage body.
        if not parts and int((c.get("broker") or {}).get("partitions") or 0) > 0:
            raise RuntimeError("the broker status lists no partition of the contract's topic")
        self._check_time_at_w(parts)
        status = {tp: part_status(W, hw, old, t_s, c["theta_s"], c["delta_s"]) for tp, (W, hw, old) in parts.items()}
        overdue: Dict[str, Tuple[bool, Dict[str, int]]] = {}
        if self.overdue is not None:
            # A record appended after this cannot be overdue at t_s, even with the broker's skew.
            until = t_s - (int(c["theta_s"]) - int(c["delta_s"])) * 1000 + int(c["delta_s"]) * 1000
            for tp in sorted(tp for tp, s in status.items() if s == "stall"):
                W, hw, _ = parts[tp]
                try:
                    overdue[tp] = await self.overdue(tp, W, hw, until)
                except Exception as e:
                    logger.warning(f"period statements: overdue scan of {tp} failed: {e}")
        tenants = await self._io(self.store.tenants)
        heads = await read_heads(self.store, self.pubkey, tenants, self._heads, self.io_concurrency, run=self._io)
        # Too late to store: the body could reach the log after an outage body is posted.
        if int(self.clock()) >= store_by_ms(j, c) - maker_margin_ms(c):
            raise _TooLate()
        prev = await self._stored_statement(j - 1)
        prev_hash = statement_hash(prev["body"]) if prev else GENESIS
        stalled_now = {tp for tp, s in status.items() if s == "stall"}
        since = {}
        for tp in stalled_now:
            pp = (prev["body"].get("parts") or {}).get(tp) if prev else None
            since[tp] = int(prev["body"]["stall"]["since_j"]) if (
                pp and pp.get("status") == "stall" and prev["body"].get("stall")) else j
        self._stalls[j] = set(stalled_now)
        st = tenant_status(c, heads, status, overdue)
        body, openings = build_statement(c, j, t_s, parts, heads, self.k_salt, prev_hash,
                                         self._window_used(j, stalled_now), since, tenant_st=st)
        agg = {"j": j, "heads": heads, "st": st}
        await self._put(agg_key(self.dep, j, body["agg"]["root"]), canon(agg))
        stmt = sign_statement(self.signer, body)
        await self._put(period_key(self.dep, j), canon(stmt))     # the lock: WriteConflict if we lost
        self._mine.add(j)
        self._note(body)
        self._openings_todo[j] = (body, openings)
        return stmt

    async def _write_openings(self, j: int, body: dict, openings: Optional[Dict[str, dict]] = None) -> None:
        if body["agg"].get("root") is None:
            self._openings_todo.pop(j, None)
            return
        if openings is None:
            raw = await self._get(agg_key(self.dep, j, body["agg"]["root"]))
            if raw is None:
                logger.error(f"INTEGRITY ALARM [period]: heads of the aggregate of j={j} are not stored")
                return
            agg = json.loads(raw)
            root, size, openings = aggregate(self.k_salt, self.dep, j, agg["heads"], self.contract["agg_cap"],
                                             agg.get("st"))
            if root != body["agg"]["root"] or size != body["agg"]["size"]:
                logger.error(f"INTEGRITY ALARM [period]: stored heads do not give the aggregate of j={j}")
                self._openings_todo.pop(j, None)
                return
        sem = asyncio.Semaphore(max(1, self.io_concurrency))
        failed = []

        async def one(t, op):
            async with sem:
                try:
                    await self._put(opening_key(self.dep, j, t), canon(op))
                except WriteConflict:
                    logger.error(f"INTEGRITY ALARM [period]: a different opening of {t} is stored for j={j}")
                except Exception as e:
                    failed.append((t, e))
        await asyncio.gather(*(one(t, op) for t, op in openings.items()))
        if failed:
            self._openings_todo[j] = (body, {t: openings[t] for t, _ in failed})
            raise failed[0][1]
        self._openings_todo.pop(j, None)
        self._openings_done.add(j)

    async def _retry_openings(self, limit: int = 4) -> None:
        for j in sorted(self._openings_todo)[:limit]:
            body, ops = self._openings_todo[j]
            try:
                await self._write_openings(j, body, ops)
            except Exception as e:
                logger.warning(f"period statements: openings of j={j} not completed: {e}")

    async def _receipt_if_included(self, msg: bytes):
        if self.sigsum is None:
            return None
        try:
            return await self._io(self.sigsum.receipt_if_included, msg)
        except Exception:
            return None

    async def _store_receipt(self, j: int, receipt) -> None:
        self._leaf_index[j] = int(receipt.leaf_index)
        try:
            await self._put(receipt_key(self.dep, j), receipt.to_json().encode())
        except WriteConflict:
            pass                       # another process's receipt for the same leaf is stored
        except Exception as e:
            raw = receipt.to_json().encode()
            self._unstored_receipts[j] = raw
            logger.warning(f"period statements: receipt for j={j} not stored yet: {e}")
            if self.spool_dir:
                try:
                    await asyncio.to_thread(spool_receipt, self.spool_dir, spool_ns(self.contract), j, raw)
                except OSError as e2:
                    logger.error(f"period statements: receipt for j={j} not spooled either: {e2}; the "
                                 "statement's inclusion time is held in this process only")

    async def _post(self, j: int, stmt: dict, follower: bool, outage: bool = False) -> dict:
        rk = receipt_key(self.dep, j)
        try:
            if await self._get(rk) is not None:
                return {"posted": True, "receipt": "stored"}
        except Exception:
            pass
        if self.sigsum is None:
            return {"posted": False, "reason": "no public log configured"}
        c = self.contract
        msg = stmt_message(stmt["body"])
        # Already on the log (posted by another process, or before a restart): no new submission.
        receipt = await self._receipt_if_included(msg)
        if receipt is not None:
            await self._store_receipt(j, receipt)
            return {"posted": True, "receipt": receipt}
        now = int(self.clock())
        if now >= deadline_ms(j, c):
            return {"posted": False, "reason": "deadline passed"}
        if not outage and now >= store_by_ms(j, c):
            return {"posted": False, "reason": "submission window of regular bodies closed"}
        if follower and j not in self._mine:
            first = self._first_seen.setdefault(j, now)
            last_call = store_by_ms(j, c) - int(c["delta_pub_s"]) * 125
            if now - first < FOLLOWER_GRACE_MS and now < last_call:
                return {"posted": False, "reason": "waiting for the maker's receipt"}
        if self._submits.get(j, 0) >= MAX_SUBMITS_PER_PERIOD:
            return {"posted": False, "reason": "submission limit for this period"}
        self._submits[j] = self._submits.get(j, 0) + 1
        remaining_s = max(5.0, (deadline_ms(j, c) - now) / 1000.0 + 30.0)
        prev_wait = self.sigsum.max_wait_s
        # The thread that sends the leaf may start late, so it checks the window again: a regular
        # leaf submitted after store_by could be missed by a maker posting the outage body.
        cutoff = deadline_ms(j, c) if outage else store_by_ms(j, c)

        def submit():
            if int(self.clock()) >= cutoff:
                raise _WindowClosed()
            return self.sigsum.witness(msg)
        try:
            self.sigsum.max_wait_s = remaining_s
            receipt = await self._io(submit)
        except _WindowClosed:
            logger.warning(f"period statements: j={j} not submitted: its "
                           f"{'deadline' if outage else 'submission window'} closed before the submission "
                           "could be sent")
            return {"posted": False, "reason": "deadline passed" if outage else
                    "submission window of regular bodies closed"}
        except Exception as e:
            # A later tick retries within the submission window.
            logger.warning(f"period statements: posting j={j} failed: {e}")
            return {"posted": False, "reason": f"public log: {type(e).__name__}"}
        finally:
            self.sigsum.max_wait_s = prev_wait
        if int(self.clock()) > deadline_ms(j, c):
            logger.error(f"INTEGRITY ALARM [period]: statement for j={j} included after its deadline")
        await self._store_receipt(j, receipt)
        return {"posted": True, "receipt": receipt}

    async def _flush_unstored(self) -> None:
        for j, stmt in sorted(self._unstored.items()):
            try:
                await self._put(outage_key(self.dep, j), canon(stmt))
                try:
                    await self._put(period_key(self.dep, j), canon(stmt))
                except WriteConflict:
                    pass               # a regular body stored but never posted holds the key
            except WriteConflict:
                logger.error(f"INTEGRITY ALARM [period]: another outage object is stored for j={j}")
            except Exception:
                return
            self._unstored.pop(j, None)
        for j, raw in sorted(self._unstored_receipts.items()):
            try:
                await self._put(receipt_key(self.dep, j), raw)
            except WriteConflict:
                pass
            except Exception:
                return
            self._unstored_receipts.pop(j, None)

    async def _post_regular(self, j: int, stmt: dict, follower: bool, outcome: str) -> dict:
        res = await self._post(j, stmt, follower=follower)
        # Openings once per process and period; a follower writes them too, in case the maker died.
        if j not in self._openings_done:
            todo = self._openings_todo.get(j)
            try:
                await self._write_openings(j, stmt["body"], todo[1] if todo else None)
            except Exception as e:
                self._openings_todo.setdefault(j, (stmt["body"], None))
                logger.warning(f"period statements: openings of j={j} not completed: {e}")
        return {"j": j, "outcome": outcome, "statement": stmt, **res}

    async def _outage(self, j: int, store_ok: bool) -> dict:
        body = outage_statement(self.contract, j)
        stmt = sign_statement(self.signer, body)
        mine = leaf_checksum(body)
        seen = await self._our_leaves_since(j)
        if seen is None:
            return {"j": j, "outcome": "deferred", "reason": "public log size at the period's start unknown"}
        if any(c != mine for _, c in seen):
            # A leaf of ours for j or later is on the log: a regular body was posted in time, and
            # posting the outage body now would equivocate.
            return {"j": j, "outcome": "deferred", "reason": "public log shows a leaf"}
        self._note(body)
        if store_ok:
            try:
                await self._put(outage_key(self.dep, j), canon(stmt))
                try:
                    await self._put(period_key(self.dep, j), canon(stmt))
                except WriteConflict:
                    pass               # a regular body that was stored but never posted
            except Exception:
                store_ok = False
        if not store_ok:
            self._unstored[j] = stmt
        res = await self._post(j, stmt, follower=False, outage=True)
        return {"j": j, "outcome": "outage", "statement": stmt, **res}

    async def publish_period(self, j: int) -> dict:
        """Make (or find) the statement of period j, store it, post its hash, then its openings."""
        if self._unstored or self._unstored_receipts:
            await self._flush_unstored()
        c = self.contract
        now = int(self.clock())
        end, D = self._end(j), deadline_ms(j, c)
        store_by, outage_from = store_by_ms(j, c), outage_from_ms(j, c)
        if now < end + maker_margin_ms(c):
            return {"j": j, "outcome": "early"}
        store_ok = True
        stmt = None
        try:
            posted_outage = await self._read_stmt(outage_key(self.dep, j), j)
            if posted_outage is not None:
                res = await self._post(j, posted_outage, follower=False, outage=True)
                return {"j": j, "outcome": "outage", "statement": posted_outage, **res}
            stmt = await self._stored_statement(j)
        except Exception as e:
            logger.warning(f"period statements: store unreadable for j={j}: {e}")
            stmt, store_ok = None, False
        if stmt is not None:
            if stmt["body"] == outage_statement(c, j):
                return await self._outage(j, store_ok)
            if now < store_by:
                return await self._post_regular(j, stmt, True, "stored")
            receipt = await self._receipt_if_included(stmt_message(stmt["body"]))
            if receipt is not None:
                await self._store_receipt(j, receipt)
                return await self._post_regular(j, stmt, True, "stored")
            try:
                if await self._get(receipt_key(self.dep, j)) is not None:
                    return await self._post_regular(j, stmt, True, "stored")
            except Exception:
                pass
            if now < outage_from:
                return {"j": j, "outcome": "waiting", "reason": "stored body not seen on the log yet"}
            # Stored but never posted in its window: its leaf can no longer appear, so the outage
            # body is the statement, if no leaf of ours shows otherwise.
            return await self._outage(j, store_ok)
        if now >= D:
            logger.error(f"INTEGRITY ALARM [period]: no statement for j={j} by its deadline")
            return {"j": j, "outcome": "missed"}
        if now < store_by:
            if not store_ok:
                return {"j": j, "outcome": "store_error"}
            if now < end + maker_margin_ms(c) + self.make_delay_ms:
                # A backup: the dedicated maker makes first; its stored body is re-posted above.
                return {"j": j, "outcome": "waiting", "reason": "a backup maker lets the dedicated maker make first"}
            try:
                stmt = await self._make(j)
            except WriteConflict:
                stmt = await self._stored_statement(j)
                if stmt is None:
                    return {"j": j, "outcome": "conflict"}
                return await self._post_regular(j, stmt, True, "stored")
            except _TooLate:
                return {"j": j, "outcome": "too_late", "reason": "reads ended after the store window"}
            except Exception as e:
                logger.warning(f"period statements: cannot make j={j}: {e}")
                return {"j": j, "outcome": "store_error"}
            return await self._post_regular(j, stmt, False, "made")
        if now < outage_from:
            return {"j": j, "outcome": "waiting", "reason": "between the store window and the outage window"}
        return await self._outage(j, store_ok)

    async def tick(self) -> List[dict]:
        c = self.contract
        now = int(self.clock())
        cur = period_of(now, c["t0_ms"], c["period_s"])
        if deadline_ms(cur - 1, c) + MARK_DELAY_MS <= now < self._end(cur):
            await self.mark(cur)
        out = []
        for j in (cur - 2, cur - 1):
            if j < int(c.get("effective_j", 0) or 0) or j in self.done:
                continue
            if now >= deadline_ms(j, c):
                self.done.add(j)
                continue
            r = await self.publish_period(j)
            if r.get("posted"):
                self.done.add(j)
            out.append(r)
        await self._retry_openings()
        self._prune(cur)
        return out

    def next_wakeup_ms(self, now: int) -> Optional[int]:
        """The next moment a tick has something new to do: a period's start of work, its outage
        window or its mark window."""
        c = self.contract
        cur = period_of(now, c["t0_ms"], c["period_s"])
        times = []
        for j in (cur - 1, cur):
            times += [self._end(j) + maker_margin_ms(c), outage_from_ms(j, c),
                      deadline_ms(j - 1, c) + MARK_DELAY_MS]
            if self.make_delay_ms:
                times.append(self._end(j) + maker_margin_ms(c) + self.make_delay_ms)
        later = [t for t in times if t > now]
        return min(later) if later else None

    async def run(self) -> None:
        tick_s = max(1.0, min(int(self.contract["period_s"]) / 12.0, 10.0,
                              int(self.contract["delta_pub_s"]) / 8.0))
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"period statements: tick failed: {e}")
            wait = tick_s * random.uniform(0.8, 1.2)
            now = int(self.clock())
            wake = self.next_wakeup_ms(now)
            if wake is not None:
                wait = min(wait, max(0.05, (wake - now) / 1000.0 + 0.05))
            await self.sleep(wait)


def _policy_text(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return open(value, encoding="utf-8").read() if os.path.isfile(value) else value


def contract_from_settings(settings, partitions: int, effective_j: Optional[int] = None, *,
                           first_acct_offset: Optional[Dict[str, int]] = None) -> dict:
    """The contract the settings describe (tools/publish_contract.py signs and publishes it)."""
    from crypto.signing import get_public_key
    from crypto.public_witness import key_hash
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pk = get_public_key(settings)
    if pk is None:
        raise ValueError("accounted mode needs merkle_signing_seed (or merkle_signing_public_key)")
    pw_seed = settings.merkle_public_witness_seed or settings.merkle_signing_seed
    skh = key_hash(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(pw_seed)).public_key()
                   .public_bytes_raw()).hex() if pw_seed else ""
    pol = _policy_text(settings.merkle_public_witness_policy)
    t0 = int(settings.acct_t0_ms)
    if effective_j is None:
        effective_j = period_of(int(time.time() * 1000), t0, int(settings.acct_period_s)) + 1
    return contract_body(
        dep=settings.acct_deployment_id, ver=int(settings.acct_contract_version), effective_j=effective_j,
        t0_ms=t0, period_s=int(settings.acct_period_s), delta_pub_s=int(settings.acct_delta_pub_s),
        theta_s=int(settings.acct_theta_s), delta_s=int(settings.acct_delta_s),
        stall_budget=int(settings.acct_stall_budget), window_periods=int(settings.acct_stall_window_periods),
        unchk_budget=int(settings.acct_unchk_budget), agg_cap=int(settings.acct_agg_cap), pk=pk.hex(),
        sigsum_key_hash=skh, witness_policy_sha256=hashlib.sha256(pol.encode()).hexdigest() if pol else "",
        topic=settings.kafka_provenance_topic, partitions=int(partitions),
        system_tenant=settings.acct_system_tenant, retention_s=7 * 86400,
        first_acct_offset=first_acct_offset,
        clock_skew_ms=int(settings.acct_clock_skew_ms),
        partitioner=settings.acct_partitioner,
        admission={"soft_permille": round(float(settings.ingest_tenant_soft_fraction) * 1000),
                   "slack_permille": round(float(settings.ingest_tenant_share_slack) * 1000),
                   "window_s": max(1, round(float(settings.ingest_tenant_window_s)))})


def load_contract(store, dep: str, ver: int, pubkey: Optional[bytes]) -> Optional[dict]:
    raw = store.get_object(contract_key(dep, ver))
    if raw is None:
        return None
    stmt = json.loads(raw)
    if not verify_statement(stmt, pubkey) or stmt["body"].get("kind") != "contract":
        logger.error(f"INTEGRITY ALARM [period]: stored contract {dep} v{ver} does not verify")
        return None
    return stmt["body"]


_maker: Optional[PeriodMaker] = None


def _default_maker(backup: bool = False) -> Optional[PeriodMaker]:
    """The deployment's maker, or None while something it needs is missing. A backup maker (in the
    API or a consumer) makes a body of its own only backup_make_delay_ms after the dedicated one."""
    global _maker
    if _maker is not None:
        return _maker
    from config import settings
    from crypto.anchor_store import get_anchor_store
    from crypto.signing import get_public_key, get_signer
    store, signer = get_anchor_store(settings), get_signer(settings)
    k_salt = k_salt_from(settings)
    if store is None or signer is None or k_salt is None:
        logger.error("period statements disabled: they need the anchor store, merkle_signing_seed and a salt key")
        return None
    contract = load_contract(store, settings.acct_deployment_id, int(settings.acct_contract_version),
                             get_public_key(settings))
    if contract is None:
        logger.error(f"period statements waiting: no published contract {settings.acct_deployment_id} "
                     f"v{settings.acct_contract_version} in the store (run tools/publish_contract.py)")
        return None
    from crypto.merkle_tree_storage import merkle_tree_storage
    sigsum = merkle_tree_storage._public_witness()
    if sigsum is None:
        logger.error("period statements: no public log configured (merkle_public_witness_url); statements "
                     "are stored but not posted, which the judge reads as silence")
    topic, group = settings.kafka_provenance_topic, settings.kafka_consumer_group

    async def broker_status():
        return await read_broker_status(topic, group)

    async def overdue(tp, W, hw, until_ms):
        t, _, p = tp.rpartition("/")
        return await scan_overdue_kafka(t, int(p), W, hw, until_ms)
    _maker = PeriodMaker(store, signer, k_salt, contract, broker_status, sigsum,
                         pubkey=get_public_key(settings), overdue=overdue,
                         broker_skew_ms=int(settings.acct_broker_skew_ms),
                         make_delay_ms=backup_make_delay_ms(contract) if backup else 0,
                         spool_dir=getattr(settings, "period_spool_dir", None))
    logger.info(f"period statements: {'a backup' if backup else 'the dedicated'} maker for "
                f"{contract['dep']} v{int(contract.get('ver', 0) or 0)}")
    return _maker


async def period_statement_loop(retry_s: float = 30.0,
                                sleep: Callable[[float], Awaitable] = asyncio.sleep,
                                backup: bool = False) -> None:
    """Run the deployment's statement maker (a backup with backup=True) until cancelled, waiting
    for the contract to be published first."""
    while True:
        m = _default_maker(backup=backup)
        if m is not None:
            break
        await sleep(retry_s)
    await m.run()


__all__ = ["period_of", "period_end_ms", "deadline_ms", "maker_margin_ms", "store_by_ms", "outage_from_ms",
           "backup_make_delay_ms", "first_due_period", "part_status", "tp_key", "partition_of", "tp_of",
           "period_key", "outage_key", "opening_key", "receipt_key", "agg_key", "contract_key",
           "contract_receipt_key", "contract_hash", "statement_hash", "leaf_checksum", "sign_statement",
           "verify_statement", "contract_body", "theta_max_s", "k_salt_from", "aggregate",
           "verify_opening", "build_statement", "outage_statement", "tenant_status", "read_broker_status",
           "scan_overdue_kafka", "read_heads", "PeriodMaker", "contract_from_settings", "load_contract",
           "period_statement_loop", "AGG_ALG", "AGG_ALG_ST", "TENANT_STATES"]
