import asyncio
import logging
import os
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
import json

from crypto.incremental_merkle import IncrementalMerkleLog, _Peak, _hash_leaf, canonicalize
from config import settings

logger = logging.getLogger(__name__)


# The anchor store (crypto.anchor_store), created on first use. None disables anchoring.
_anchor_store = None
_anchor_store_init = False


def _get_anchor_store():
    global _anchor_store, _anchor_store_init
    if not _anchor_store_init:
        _anchor_store_init = True
        try:
            from crypto.anchor_store import get_anchor_store
            _anchor_store = get_anchor_store(settings)
        except Exception as e:
            logger.warning(f"Anchor store unavailable, anchoring disabled: {e}")
            _anchor_store = None
    return _anchor_store


def tx_timeout_s() -> Optional[float]:
    """settings.neo4j_tx_timeout_s as a transaction timeout (None: no bound)."""
    try:
        t = float(settings.neo4j_tx_timeout_s or 0)
    except (TypeError, ValueError):
        return None
    return t if t > 0 else None


async def begin_tx(session):
    """Begin a transaction that the server ends after tx_timeout_s, which also releases the
    per-tenant locks of a process that died without closing its connection."""
    t = tx_timeout_s()
    if t is None:
        return await session.begin_transaction()
    return await session.begin_transaction(timeout=t)


def _peaks_to_json(peaks) -> str:
    return json.dumps([{"h": p.hash.hex(), "ht": p.height} for p in peaks])


def _peaks_from_json(raw):
    if not raw:
        return []
    return [_Peak(hash=bytes.fromhex(p["h"]), height=int(p["ht"]))
            for p in json.loads(raw)]


# Accounted ingestion: v2 records are appended by broker position under the tree lock and the
# writer epoch (add_records) and anchored only after _check_v2_segment accepts them; the segment
# is written to the store before the anchor record. The database holds a cache of the unanchored
# tail; reset_tenant_tail rebuilds it from the store and the broker.

class PositionConflict(Exception):
    """add_records found a different record, or none, at a position the tail claims to hold."""

    def __init__(self, tenant_id: str, pos, existing_seq: int):
        super().__init__(f"position conflict for {tenant_id} at {pos}: tail seq {existing_seq}")
        self.tenant_id, self.pos, self.existing_seq = tenant_id, pos, existing_seq


class FencedWriter(Exception):
    """The tenant's writer epoch moved on: another process owns the tail."""


class AnchorTamper(Exception):
    """The anchorer refused records that fail _check_v2_segment: the database tail was altered."""

    def __init__(self, tenant_id: str, reason: str):
        super().__init__(f"anchor refused for {tenant_id}: {reason}")
        self.tenant_id, self.reason = tenant_id, reason


class InjectedFault(RuntimeError):
    """An injected write failure (_injected_poison). Not an outage: the consumer counts it against
    the record."""
    outage = False


class AnchorDeferred(RuntimeError):
    """This process did not append the records it was asked to anchor: the anchor stays pending
    for the process that did."""


def _acct_mode() -> bool:
    return bool(settings.acct_mode)


def _system_tenant() -> str:
    return str(settings.acct_system_tenant)


def _tree_id(tenant_id: str) -> str:
    return f"global_persistent_{tenant_id}"


def _tp_key(topic: str, p: int) -> str:
    return f"{topic}/{int(p)}"


_INT64 = 1 << 63


def _db_offset(o) -> Any:
    """A broker offset as stored in MerkleNode.acct_o: an int if it fits Neo4j's int64, else its
    decimal string. Every query passes the same form, so equality lookups agree."""
    o = int(o)
    return o if -_INT64 <= o < _INT64 else str(o)


def _check_v2_segment(tenant_id: str, frm: int, rows: List[Dict[str, Any]], prev,
                      prev_peaks: list, root_hex: str, system_tenant: str,
                      own: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
    """May rows (leaf_index frm, frm+1, ...) be anchored on top of prev? Every row must be a v2
    record of this tenant with seq = its index, all on one (topic, p), with offsets strictly
    increasing above prev.pos_last; extending prev's peaks by the record hashes must give
    root_hex; records this process appended (own: seq -> hash) must be unchanged. Returns the
    anchor's v2 fields and the segment, or raises AnchorTamper. system_tenant is unused."""
    from crypto import records as R
    if not rows:
        raise AnchorTamper(tenant_id, "empty segment")
    records, hashes = [], []
    last: Dict[str, int] = {}
    prev_pl = prev.pos_last if prev is not None else None
    if prev_pl:
        last[_tp_key(prev_pl["topic"], prev_pl["p"])] = int(prev_pl["o"])
    tp0 = _tp_key(prev_pl["topic"], prev_pl["p"]) if prev_pl else None
    unchk = 0
    for k, row in enumerate(rows):
        idx = frm + k
        if int(row["i"]) != idx:
            raise AnchorTamper(tenant_id, f"leaf {idx} missing or duplicated in the tail")
        try:
            rec = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
        except (TypeError, ValueError):
            raise AnchorTamper(tenant_id, f"leaf {idx} is not JSON")
        if not R.is_v2(rec) or rec.get("tenant_id") != tenant_id or rec.get("seq") != idx:
            raise AnchorTamper(tenant_id, f"leaf {idx} is not a v2 record of this tenant at seq {idx}")
        try:
            pos = R.Position.from_json(rec["pos"])
            h = R.record_hash(rec)
        except (KeyError, TypeError, ValueError):
            raise AnchorTamper(tenant_id, f"leaf {idx} has no valid position or encoding")
        if rec["kind"] == "event" and (not isinstance(rec.get("event"), dict) or rec.get("verdict") is not None):
            raise AnchorTamper(tenant_id, f"leaf {idx}: event record without event")
        if rec["kind"] == "verdict":
            v = rec.get("verdict")
            if not isinstance(v, dict) or v.get("type") not in R.VERDICT_TYPES:
                raise AnchorTamper(tenant_id, f"leaf {idx}: verdict without a known type")
            if v["type"] == "UNCHECKABLE":
                unchk += 1
        key = _tp_key(pos.topic, pos.p)
        if tp0 is None:
            tp0 = key
        elif key != tp0:
            raise AnchorTamper(tenant_id, f"leaf {idx} is on {key}, the tenant's log is on {tp0}")
        if key in last and pos.o <= last[key]:
            raise AnchorTamper(tenant_id, f"leaf {idx} at offset {pos.o} does not follow {last[key]} on {key}")
        last[key] = pos.o
        if own and idx in own and own[idx] != h:
            raise AnchorTamper(tenant_id, f"leaf {idx} differs from the record this writer appended")
        records.append(rec)
        hashes.append(h)
    peaks, root = R.mmr_extend(prev_peaks, hashes)
    if root != root_hex:
        raise AnchorTamper(tenant_id, "the records do not extend the anchored peaks to the snapshot root")
    to = frm + len(records)
    seg_body = R.segment_body(tenant_id, frm, to, records)
    seg_bytes = R.canon(seg_body)
    first, lastrec = records[0]["pos"], records[-1]["pos"]
    prev_u = int(prev.u or 0) if prev is not None else 0
    first_v2 = prev is None or prev.v != 2
    return {
        "peaks": peaks, "root": root, "segment": seg_body, "segment_bytes": seg_bytes,
        "seg": {"from": frm, "to": to, "sha256": R.sha256_hex(seg_bytes),
                "o_first": int(first["o"]), "o_last": int(lastrec["o"])},
        "pos_last": R.pos_last_of(records[-1]), "u": prev_u + unchk,
        "acct_from": frm if first_v2 else None,
        # A predecessor without peaks (a v1 record) cannot start a proof: give the peaks at frm.
        "peaks_from": [list(p) for p in prev_peaks] if prev is not None and prev.peaks is None else None,
    }


# STAGE_TIMING=1 logs where append and anchor time goes. Measurement only.
_STAGE_TIMING = os.getenv("STAGE_TIMING", "").strip().lower() in ("1", "true", "yes", "on")
# Batches or anchors between two timing log lines.
_TIMING_EVERY = 20


class _AppendStats:
    batches = 0
    leaves = 0
    ms = 0.0
    qdepth = 0


class _AnchorStats:
    n = 0
    lock = 0.0        # MERGE the tip row and read it back
    auth = 0.0        # verify the tip's signature
    latest = 0.0      # store.latest_after: has anyone written past this tip?
    write = 0.0       # store.anchor: the record itself
    commit = 0.0      # SET the tip and commit


# Time-based anchoring, derived from T = merkle_anchor_max_age_s. Every process wakes every
# period * U(0.8, 1.2); the holder of a lease of 1.5 * period sweeps and renews it on each wake.
HEARTBEAT_JITTER = (0.8, 1.2)
# Allowance for the sweep's own store round trips and clock skew between hosts.
STALL_SLACK_S = 30.0


def anchor_timing(max_age_s: float) -> Optional[Dict[str, float]]:
    """The heartbeat's period and lease, and the bound they give, for T = max_age_s (None if 0).

    With at most one crashed lease holder at a time, every appended leaf is anchored within
    bound = T + lease + 1.2 * period (1.675 T with period = T / 4), plus the anchor write.
    The stall alarm fires on an unanchored leaf older than bound + STALL_SLACK_S.
    """
    t = float(max_age_s or 0)
    if t <= 0:
        return None
    period = max(1.0, t / 4.0)
    lease = 1.5 * period
    bound = t + lease + HEARTBEAT_JITTER[1] * period
    return {"max_age_s": t, "period_s": period, "lease_s": lease, "bound_s": bound,
            "stall_after_s": bound + STALL_SLACK_S}


def _unix_time(ts) -> Optional[float]:
    """Seconds since the epoch for a timestamp read back from the graph (naive UTC, as written)."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if hasattr(ts, "to_native"):
        ts = ts.to_native()
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.timestamp()
    return None


class _TenantAppendBatcher:
    """Group commit for one tenant's MMR appends. A submitter awaits its own future, so its offset
    is never committed before its append; the queue and flag handoffs contain no await."""

    def __init__(self, storage, tenant_id: str):
        self.storage = storage
        self.tenant_id = tenant_id
        self.queue: List[Tuple[Dict[str, Any], Any]] = []
        self.running = False

    def _max_batch(self) -> int:
        return max(1, int(settings.merkle_append_batch_b))

    async def submit(self, event_data: Dict[str, Any]) -> bool:
        fut = asyncio.get_running_loop().create_future()
        self.queue.append((event_data, fut))          # no await before the flag
        if not self.running:
            self.running = True
            asyncio.create_task(self._drain())
        return await fut

    async def _drain(self):
        try:
            while self.queue:
                cap = self._max_batch()
                batch = self.queue[:cap]
                del self.queue[:len(batch)]
                qdepth = len(self.queue)
                t0 = time.perf_counter()
                try:
                    ok = await self.storage.add_events_to_persistent_tree(
                        self.tenant_id, [d for d, _ in batch])
                    for _, f in batch:
                        if not f.done():
                            f.set_result(ok)
                except Exception as e:
                    for _, f in batch:
                        if not f.done():
                            f.set_exception(e)
                finally:
                    if _STAGE_TIMING:
                        _AppendStats.batches += 1
                        _AppendStats.leaves += len(batch)
                        _AppendStats.ms += (time.perf_counter() - t0) * 1000.0
                        _AppendStats.qdepth += qdepth
                        s = _AppendStats
                        if s.batches % _TIMING_EVERY == 0:
                            n = s.batches
                            logger.warning(
                                f"APPEND batches={n} avg_batch={s.leaves / n:.1f} "
                                f"avg_ms={s.ms / n:.0f} avg_queue_left={s.qdepth / n:.1f} "
                                f"=> {1000.0 * s.leaves / max(1e-9, s.ms):.1f} leaves/s")
        finally:
            # Clear the flag, then re-check, so an item queued meanwhile is not stranded.
            self.running = False
            if self.queue:
                self.running = True
                asyncio.create_task(self._drain())


# Busy time of add_records' parts, summed over one accounted batch; the writer logs and clears it.
ACCT_TIMING: Dict[str, float] = {}


def _tadd(name: str, t0: float) -> float:
    now = time.perf_counter()
    if _STAGE_TIMING:
        ACCT_TIMING[name] = ACCT_TIMING.get(name, 0.0) + (now - t0)
    return now


class MerkleTreeStorage:
    """Per-tenant Merkle logs that grow incrementally with new events."""

    def __init__(self):
        self._batchers: Dict[str, _TenantAppendBatcher] = {}
        self.alarms: Dict[str, int] = {}               # INTEGRITY ALARM count per kind
        self._anchor_pending: set = set()              # tenants with anchors recorded as pending
        self._anchor_last_try: Dict[str, float] = {}   # tenant -> when this process last looked
        self._anchor_listeners: list = []
        # What this process appended since its last reset of a tenant's tail: seq -> record hash,
        # seq -> position, and the writer epoch. Records from an older epoch are forgotten.
        self._own_records: Dict[str, Dict[int, str]] = {}
        self._own_pos: Dict[str, Dict[int, Tuple[str, int, int]]] = {}
        self._own_epoch: Dict[str, int] = {}
        # tenant -> lowest position a tail reset deleted that has not been appended again
        self._replay_from: Dict[str, Tuple[str, int, int]] = {}
        self._tampered: set = set()
        self._superseded: set = set()
        self._holder: Optional[str] = None
        self._pw_client = None
        self._pw_loaded = False

    def _batcher(self, tenant_id: str):
        """Group-commit batcher for one tenant's appends: one commit per batch instead of per leaf,
        same leaves and root. A batch takes whatever queued during the previous flush, up to
        merkle_append_batch_b; there is no timer."""
        b = self._batchers.get(tenant_id)
        if b is None:
            b = _TenantAppendBatcher(self, tenant_id)
            self._batchers[tenant_id] = b
        return b

    async def add_events_to_persistent_tree(self, tenant_id: str,
                                            events: List[Dict[str, Any]]) -> bool:
        """Append several events to the tenant's log in one transaction."""
        if not events:
            return True
        try:
            _t0 = time.perf_counter()
            tree_id = await self.get_or_create_persistent_tree(tenant_id)
            if not tree_id:
                return False
            _t1 = time.perf_counter()

            from database.graph_db import graph_db

            # Leaf hashes do not depend on position, so duplicates are dropped before any leaf
            # enters the in-memory log.
            prepared, seen = [], set()
            for ed in events:
                data = canonicalize(ed)
                leaf_id = f"leaf_{_hash_leaf(data).hex()[:16]}"
                if leaf_id in seen:
                    continue
                seen.add(leaf_id)
                prepared.append((leaf_id, data, ed))

            async with graph_db.driver.session() as session:
                tx = await begin_tx(session)
                settled = False
                try:
                    # Take the tree row's write lock before reading its state.
                    await self._lock_tree_for_append(tx, tree_id, tenant_id)
                    state = await self._read_persistent_state(tx, tree_id, tenant_id)
                    _t2 = time.perf_counter()

                    # One index seek on (tree_id, node_id) per candidate.
                    result = await tx.run(
                        """
                        UNWIND $ids AS wanted
                        MATCH (n:MerkleNode {tree_id: $tree_id, node_id: wanted})
                        RETURN collect(n.node_id) AS existing
                        """,
                        {"tree_id": tree_id, "ids": [p[0] for p in prepared]},
                    )
                    row = await result.single()
                    existing = set((row["existing"] if row else []) or [])
                    prepared = [p for p in prepared if p[0] not in existing]
                    _t3 = time.perf_counter()

                    if not prepared:
                        await tx.rollback()
                        settled = True
                        # A redelivery: pick up any anchor its first delivery left pending.
                        await self._anchor_after_append(tenant_id, tree_id, state["leaf_count"],
                                                        state["leaf_count"], replay=True)
                        return True

                    log = IncrementalMerkleLog()
                    log.peaks = list(state["peaks"])
                    n_before = state["leaf_count"]

                    rows = []
                    for offset, (leaf_id, data, ed) in enumerate(prepared):
                        leaf_hash = log.append(data)
                        rows.append({
                            "node_id": leaf_id,
                            "hash": leaf_hash.hex(),
                            "data": json.dumps(ed, default=str),
                            "leaf_index": n_before + offset,
                            "event_id": ed.get("event_id") if isinstance(ed, dict) else None,
                        })

                    new_root = log.root()
                    new_count = n_before + len(prepared)
                    new_version = state["version"] + 1
                    # The snapshot's timestamp is when the log reached new_count (reached_at).
                    appended_at = datetime.utcnow()
                    _t4 = time.perf_counter()

                    await tx.run(
                        """
                        UNWIND $rows AS r
                        CREATE (node:MerkleNode {
                            tree_id: $tree_id,
                            node_id: r.node_id,
                            hash: r.hash,
                            depth: 0,
                            is_leaf: true,
                            tenant_id: $tenant_id,
                            data: r.data,
                            leaf_index: r.leaf_index,
                            event_id: r.event_id,
                            created_at: $created_at
                        })
                        """,
                        {"rows": rows, "tree_id": tree_id,
                         "tenant_id": tenant_id, "created_at": appended_at},
                    )

                    _t5 = time.perf_counter()
                    await self._write_persistent_state(
                        tx, tree_id, tenant_id, list(log.peaks),
                        new_root.hex(), new_count, new_version,
                    )
                    _t5b = time.perf_counter()

                    # One snapshot per batch. A snapshot that crosses a multiple of k is created
                    # flagged pending, so its anchor point survives a crash before anchoring.
                    await tx.run(
                        """
                        CREATE (snap:MerkleRootSnapshot {
                            tree_id: $tree_id,
                            tenant_id: $tenant_id,
                            version: $version,
                            root_hash: $root_hash,
                            leaf_count: $leaf_count,
                            timestamp: $timestamp,
                            anchor_pending: CASE WHEN $pending THEN true ELSE null END
                        })
                        """,
                        {"tree_id": tree_id, "tenant_id": tenant_id,
                         "version": new_version, "root_hash": new_root.hex(),
                         "leaf_count": new_count, "timestamp": appended_at,
                         "pending": self._anchor_due(n_before, new_count)},
                    )

                    _t6 = time.perf_counter()
                    await tx.commit()
                    settled = True
                    if _STAGE_TIMING:
                        _t7 = time.perf_counter()
                        logger.warning(
                            f"APPENDSPLIT n={len(prepared)} tree={(_t1 - _t0) * 1000:.0f} "
                            f"read={(_t2 - _t1) * 1000:.0f} dup={(_t3 - _t2) * 1000:.0f} "
                            f"hash={(_t4 - _t3) * 1000:.0f} create={(_t5 - _t4) * 1000:.0f} "
                            f"state={(_t5b - _t5) * 1000:.0f} snap={(_t6 - _t5b) * 1000:.0f} "
                            f"commit={(_t7 - _t6) * 1000:.0f}")
                except Exception:
                    if not settled:
                        try:
                            await tx.rollback()
                        except Exception:
                            pass
                    raise

            # Anchor on crossing a multiple of k: a batch can jump over the exact multiple.
            await self._anchor_after_append(tenant_id, tree_id, n_before, new_count)
            return True

        except Exception as e:
            # Re-raised: the consumer tells an outage from the exception chain.
            logger.warning(f"Merkle append failed: {e}")
            raise

    async def get_or_create_persistent_tree(self, tenant_id: str) -> str:
        """The tenant's tree id; creates the tree row on first use."""
        from database.graph_db import graph_db

        global_tree_id = _tree_id(tenant_id)

        # MERGE is atomic against the uniqueness constraint, so concurrent writers create one row.
        merge_query = """
        MERGE (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
        ON CREATE SET
            tree.persistent     = true,
            tree.root_hash      = '',
            tree.max_depth      = 0,
            tree.leaf_count     = 0,
            tree.total_nodes    = 0,
            tree.version        = 0,
            tree.peaks_json     = '[]',
            tree.created_at     = $created_at,
            tree.updated_at     = $updated_at
        RETURN tree.tree_id as tree_id
        """

        try:
            async with graph_db.driver.session() as session:
                result = await session.run(merge_query, {
                    "tree_id": global_tree_id,
                    "tenant_id": tenant_id,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                })
                record = await result.single()
                return record["tree_id"] if record else global_tree_id

        except Exception as e:
            logger.error(f"Merkle tree row for {tenant_id} not created: {e}")
            raise

    async def add_event_to_persistent_tree(self, tenant_id: str,
                                         event_data: Dict[str, Any]) -> bool:
        """Append one event to the tenant's log; with merkle_append_batch_b > 1 through the
        tenant's group-commit batcher."""
        if max(1, int(settings.merkle_append_batch_b)) > 1:
            return await self._batcher(tenant_id).submit(event_data)
        return await self.add_events_to_persistent_tree(tenant_id, [event_data])

    async def _lock_tree_for_append(self, tx, tree_id: str, tenant_id: str) -> None:
        """Take the write lock on a tenant's MerkleTree row until the transaction ends. During a
        rebalance two consumers can append for one tenant; the second waits for the first."""
        await tx.run(
            """
            MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
            SET tree.append_lock_at = timestamp()
            """,
            {"tree_id": tree_id, "tenant_id": tenant_id},
        )

    async def _read_persistent_state(self, session, tree_id: str,
                                     tenant_id: str) -> Dict[str, Any]:
        """The MMR peaks, leaf count and version from the MerkleTree row."""
        result = await session.run(
            """
            MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
            RETURN tree.peaks_json     as peaks_json,
                   tree.leaf_count     as leaf_count,
                   tree.version        as version
            """,
            tree_id=tree_id, tenant_id=tenant_id,
        )
        record = await result.single()
        if record is None:
            return {"peaks": [], "leaf_count": 0, "version": 0}
        return {
            "peaks": _peaks_from_json(record["peaks_json"]),
            "leaf_count": int(record["leaf_count"] or 0),
            "version": int(record["version"] or 0),
        }

    async def _write_persistent_state(self, session, tree_id: str,
                                      tenant_id: str, peaks,
                                      root_hex: str, leaf_count: int,
                                      version: int) -> None:
        await session.run(
            """
            MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
            SET tree.peaks_json     = $peaks_json,
                tree.root_hash      = $root_hash,
                tree.leaf_count     = $leaf_count,
                tree.version        = $version,
                tree.updated_at     = $now
            """,
            tree_id=tree_id, tenant_id=tenant_id,
            peaks_json=_peaks_to_json(peaks),
            root_hash=root_hex,
            leaf_count=leaf_count, version=version,
            now=datetime.utcnow(),
        )

    # Anchoring.
    # Seconds between backfill attempts for a tenant while its anchor store is failing.
    _ANCHOR_RETRY_INTERVAL_S = 5.0
    # Longest interval between two looks at a tenant's pending flags by a process that keeps
    # appending to it; the heartbeat sweep looks on its own schedule.
    _ANCHOR_RECHECK_MAX_S = 30.0
    # Clock for the intervals above; tests replace it.
    _now_monotonic = staticmethod(time.monotonic)

    def _anchor_due(self, n_before: int, new_count: int) -> bool:
        """Did an append from n_before to new_count cross a multiple of k? Anchoring at the
        crossing keeps the gap between anchors at most k + B - 1."""
        k = max(1, int(settings.merkle_anchor_batch_k))
        return (new_count // k) > (n_before // k)

    def _anchor_recheck_s(self) -> float:
        max_age = float(settings.merkle_anchor_max_age_s or 0)
        t = anchor_timing(max_age)
        return min(self._ANCHOR_RECHECK_MAX_S, t["period_s"]) if t else self._ANCHOR_RECHECK_MAX_S

    async def _anchor_after_append(self, tenant_id: str, tree_id: str, n_before: int,
                                   new_count: int, replay: bool = False,
                                   raise_tamper: bool = False) -> None:
        """Write this tenant's pending anchors after a committed append: on every crossing of a
        multiple of k, on a redelivery (replay), on the first append to a tenant, and then at least
        every _anchor_recheck_s(). A failure leaves the pending flags for any process to retry.
        Never raises, except AnchorTamper with raise_tamper: only the tail's owner can repair it."""
        store = _get_anchor_store()
        if store is None:
            return
        pending = self._anchor_pending
        due = self._anchor_due(n_before, new_count)
        if not due and not replay:
            now = self._now_monotonic()
            last = self._anchor_last_try.get(tenant_id)
            interval = (self._ANCHOR_RETRY_INTERVAL_S if tenant_id in pending
                        else self._anchor_recheck_s())
            if last is not None and now - last < interval:
                return
        self._anchor_last_try[tenant_id] = self._now_monotonic()
        try:
            from database.graph_db import graph_db
            flushed = await self._flush_pending_anchors(store, graph_db, tenant_id, tree_id,
                                                        newest=new_count if due else None)
        except AnchorTamper:
            pending.add(tenant_id)
            if raise_tamper:
                raise
            flushed = False
        except Exception as e:
            logger.warning(f"Anchoring after append failed for {tenant_id}: {e}")
            flushed = False
        if flushed:
            pending.discard(tenant_id)
        else:
            pending.add(tenant_id)

    _SET_ANCHOR_TIP = """
    MATCH (tip:MerkleAnchorTip {tree_id: $tree_id, tenant_id: $tenant_id})
    SET tip.tip_n = $n, tip.tip_hash = $h, tip.tip_sig = $s
    """

    def _head_authentic(self, tenant_id: str, n, record_hash, sig) -> Optional[bool]:
        """Is (tenant, n, record_hash) a head the deployment key signed? None if no key is
        configured. Tip rows are in the database, which the adversary can write."""
        from crypto.signing import anchor_statement, get_public_key, verify
        pub = get_public_key(settings)
        if pub is None:
            return None
        if n is None or not record_hash:
            return False
        try:
            return verify(pub, sig, anchor_statement(tenant_id, int(n), record_hash))
        except Exception:
            return False

    def _alarm(self, kind: str, message: str) -> None:
        self.alarms[kind] = self.alarms.get(kind, 0) + 1
        logger.error(f"INTEGRITY ALARM [{kind}]: {message}")

    async def _anchor_serialized(self, store, graph_db, tenant_id: str, tree_id: str,
                                 n: int, root_hex: str, reached_at: Optional[float] = None) -> None:
        """Write one anchor, serialised per tenant by the MerkleAnchorTip row (apart from the tree
        row, so a store outage does not stall appends) and chained to the recorded tip. A newer
        record in the store is adopted; an anchor at or below the tip is skipped. reached_at is
        when the log reached n. Raises if the store write fails."""
        from crypto.anchor_store import GENESIS_PREV
        params = {"tree_id": tree_id, "tenant_id": tenant_id}
        _t = time.perf_counter if _STAGE_TIMING else None
        _t0 = _t() if _t else 0.0
        async with graph_db.driver.session() as session:
            tx = await begin_tx(session)
            try:
                await tx.run(
                    """
                    MERGE (tip:MerkleAnchorTip {tree_id: $tree_id, tenant_id: $tenant_id})
                    SET tip.locked_at = timestamp()
                    """,
                    params,
                )
                result = await tx.run(
                    """
                    MATCH (tip:MerkleAnchorTip {tree_id: $tree_id, tenant_id: $tenant_id})
                    RETURN tip.tip_n AS n, tip.tip_hash AS h, tip.tip_sig AS s
                    """,
                    params,
                )
                row = await result.single()
                _t1 = _t() if _t else 0.0
                tip_n = int(row["n"]) if row and row["n"] is not None else None
                tip_hash = row["h"] if row else None
                tip_sig = row["s"] if row else None
                repaired = False
                if tip_n is not None and self._head_authentic(tenant_id, tip_n, tip_hash, tip_sig) is False:
                    # Not a tip we signed: recover the head from the store.
                    self._alarm("tip", f"chain tip for {tenant_id} (n={tip_n}) failed authentication; "
                                       f"recovering the head from the anchor store")
                    tip_n = tip_hash = tip_sig = None
                    repaired = True
                _t2 = _t() if _t else 0.0
                newer = await asyncio.to_thread(
                    store.latest_after, tenant_id, -1 if tip_n is None else tip_n)
                _t3 = _t() if _t else 0.0
                if newer is not None and self._head_authentic(
                        tenant_id, newer.n, newer.record_hash, newer.sig) is False:
                    self._alarm("store", f"the anchor store presented an unauthenticated record for "
                                         f"{tenant_id} at n={newer.n}; passing over it")
                    floor = -1 if tip_n is None else tip_n
                    good = [r for r in await asyncio.to_thread(store.all, tenant_id)
                            if int(r.n) > floor and r.verify_self()
                            and self._head_authentic(tenant_id, r.n, r.record_hash, r.sig)]
                    newer = max(good, key=lambda r: int(r.n)) if good else None
                if newer is not None:
                    tip_n, tip_hash, tip_sig = int(newer.n), newer.record_hash, newer.sig
                if tip_n is not None and n <= tip_n:
                    if newer is not None or repaired:
                        await tx.run(self._SET_ANCHOR_TIP, dict(params, n=tip_n, h=tip_hash, s=tip_sig))
                        await tx.commit()
                    else:
                        await tx.rollback()
                    return
                if _acct_mode():
                    # The record returned may be another anchorer's that succeeded the same
                    # predecessor and covers n.
                    rec, segment = await self._anchor_v2(store, tx, tenant_id, tree_id, n, root_hex,
                                                         tip_n, tip_hash, newer, reached_at)
                    await tx.run(self._SET_ANCHOR_TIP,
                                 dict(params, n=int(rec.n), h=rec.record_hash, s=rec.sig))
                    await tx.commit()
                    self._notify_anchor(tenant_id, rec, segment)
                    return
                # Off the event loop: the backends are synchronous (boto3 PUT, write + fsync).
                rec = await asyncio.to_thread(
                    store.anchor, tenant_id, n, root_hex, None, tip_hash or GENESIS_PREV, None,
                    reached_at)
                _t5 = _t() if _t else 0.0
                await tx.run(self._SET_ANCHOR_TIP, dict(params, n=n, h=rec.record_hash, s=rec.sig))
                await tx.commit()
                if _t:
                    a = _AnchorStats
                    a.n += 1
                    a.lock += (_t1 - _t0) * 1000
                    a.auth += (_t2 - _t1) * 1000
                    a.latest += (_t3 - _t2) * 1000
                    a.write += (_t5 - _t3) * 1000
                    a.commit += (_t() - _t5) * 1000
                    if a.n % _TIMING_EVERY == 0:
                        total = a.lock + a.auth + a.latest + a.write + a.commit
                        logger.warning(
                            f"ANCHORSPLIT n={a.n} lock={a.lock / a.n:.0f} auth={a.auth / a.n:.0f} "
                            f"latest_after={a.latest / a.n:.0f} store_write={a.write / a.n:.0f} "
                            f"commit={a.commit / a.n:.0f} total={total / a.n:.0f} ms")
            except BaseException:
                try:
                    await tx.rollback()
                except Exception:
                    pass
                raise

    # Accounted ingestion.

    def add_anchor_listener(self, fn) -> None:
        """fn(tenant_id, AnchorRecord, segment dict) is called after every v2 anchor this process
        writes."""
        self._anchor_listeners.append(fn)

    def _notify_anchor(self, tenant_id: str, rec, segment: Optional[dict]) -> None:
        own = self._own_records.get(tenant_id)
        if own:
            pos = self._own_pos.setdefault(tenant_id, {})
            for s in [s for s in own if s < int(rec.n)]:
                del own[s]
                pos.pop(s, None)
        for fn in self._anchor_listeners:
            try:
                fn(tenant_id, rec, segment)
            except Exception as e:
                logger.warning(f"Anchor listener failed for {tenant_id}: {e}")

    def _remember_own(self, tenant_id: str, seq: int, h: str, pos=None, epoch=None) -> None:
        own = self._own_records.setdefault(tenant_id, {})
        positions = self._own_pos.setdefault(tenant_id, {})
        if epoch is not None and self._own_epoch.get(tenant_id) != int(epoch):
            own.clear()
            positions.clear()
            self._own_epoch[tenant_id] = int(epoch)
        own[int(seq)] = h
        if pos is not None:
            positions[int(seq)] = (str(pos["topic"]), int(pos["p"]), int(pos["o"]))

    def release_tenant(self, tenant_id: str) -> None:
        """The tenant's partition was revoked: forget this process's state for it. The pending
        flags in the database stay for the new owner."""
        self._own_records.pop(tenant_id, None)
        self._own_pos.pop(tenant_id, None)
        self._own_epoch.pop(tenant_id, None)
        self._replay_from.pop(tenant_id, None)
        self._tampered.discard(tenant_id)
        self._superseded.discard(tenant_id)
        self._anchor_pending.discard(tenant_id)

    def _own_current(self, tenant_id: str, epoch: int) -> Dict[int, str]:
        """The own records of tenant_id if they were appended under the tree's current epoch.
        Otherwise another writer reset the tail: they are forgotten and the tenant is queued for
        take_superseded."""
        own = self._own_records.get(tenant_id) or {}
        if own and self._own_epoch.get(tenant_id) not in (None, int(epoch)):
            logger.warning(f"Tail of {tenant_id} reset by another writer under epoch {epoch}; "
                           f"own unanchored records forgotten")
            self.release_tenant(tenant_id)
            self._superseded.add(tenant_id)
            return {}
        return own

    async def _store_record(self, store, tenant_id: str, n: int, record_hash: Optional[str]):
        """The anchor record at exactly n from the store, if it is ours and (when given) has this
        record hash; None otherwise."""
        from crypto.anchor_store import AnchorRecord, anchor_key
        raw = await asyncio.to_thread(store.get_object, anchor_key(tenant_id, n))
        if raw is None:
            return None
        try:
            rec = AnchorRecord.parse(raw)
        except Exception:
            return None
        if not store.acceptable(tenant_id, rec, n):
            return None
        if record_hash is not None and rec.record_hash != record_hash:
            return None
        return rec

    _ACCT_LEAVES = """
    // acct: leaves in range
    MATCH (x:MerkleNode {tree_id: $tree_id, tenant_id: $tenant_id, is_leaf: true})
    WHERE x.leaf_index >= $lo AND x.leaf_index < $hi
    RETURN x.leaf_index AS i, x.data AS data, x.hash AS hash
    ORDER BY x.leaf_index ASC
    """

    async def _prefix_peaks(self, tx, tree_id: str, tenant_id: str, prev) -> list:
        """MMR peaks of the anchored prefix [0, prev.n) when prev (a v1 record) does not carry
        them: rebuilt from the stored leaf hashes and accepted only if they give prev's root."""
        from crypto import records as R
        result = await tx.run(self._ACCT_LEAVES, {"tree_id": tree_id, "tenant_id": tenant_id,
                                                  "lo": 0, "hi": int(prev.n)})
        rows = await result.data()
        if [int(r["i"]) for r in rows] != list(range(int(prev.n))):
            raise AnchorTamper(tenant_id, f"the anchored prefix [0, {prev.n}) is incomplete in the database")
        peaks, root = R.mmr_extend([], [r["hash"] for r in rows])
        if root != prev.root:
            raise AnchorTamper(tenant_id, f"the stored prefix does not give the anchored root at n={prev.n}")
        return peaks

    # Attempts of _anchor_v2 while other anchorers keep extending the chain.
    _CHAIN_RETRIES = 8

    async def _anchor_v2(self, store, tx, tenant_id: str, tree_id: str, n: int, root_hex: str,
                         tip_n: Optional[int], tip_hash: Optional[str], newer, reached_at):
        """Write the v2 anchor record at n on top of the authenticated tip. Returns (record,
        segment dict or None): ours, or another anchorer's successor of the same predecessor that
        covers n. Raises AnchorTamper when the tail fails the check, AnchorDeferred when the
        records were appended by another process."""
        prev = None
        if tip_n is not None:
            if newer is not None and int(newer.n) == int(tip_n):
                prev = newer
            else:
                prev = await self._store_record(store, tenant_id, tip_n, tip_hash)
            if prev is None:
                # Not provable tampering: leave the anchor pending and retry.
                raise RuntimeError(f"predecessor anchor n={tip_n} of {tenant_id} not readable from the store")
        state = await self._read_acct_state(tx, tree_id, tenant_id)
        own = self._own_current(tenant_id, state["epoch"])
        for _ in range(self._CHAIN_RETRIES):
            rec, segment, mine = await self._anchor_v2_on(store, tx, tenant_id, tree_id, n, root_hex,
                                                          prev, reached_at, own)
            if mine or int(rec.n) >= int(n):
                return rec, segment
            # Another anchorer's record succeeded prev first and stops short of n: build on it.
            prev = rec
        raise RuntimeError(f"{tenant_id}: the chain kept moving while anchoring n={n}; retried later")

    async def _anchor_v2_on(self, store, tx, tenant_id: str, tree_id: str, n: int, root_hex: str,
                            prev, reached_at, own: Dict[int, str]):
        """One attempt of _anchor_v2 on top of prev. Returns (record, segment, mine): mine is False
        when prev's successor slot held another anchorer's record, which is returned instead."""
        from crypto import records as R
        from crypto.anchor_store import GENESIS_PREV
        frm = int(prev.n) if prev is not None else 0
        result = await tx.run(self._ACCT_LEAVES, {"tree_id": tree_id, "tenant_id": tenant_id,
                                                  "lo": frm, "hi": int(n)})
        rows = await result.data()
        if prev is None:
            prev_peaks = []
        elif prev.peaks is not None:
            prev_peaks = [list(p) for p in prev.peaks]
            if R.mmr_root_hex(prev_peaks) != prev.root:
                raise AnchorTamper(tenant_id, f"predecessor n={prev.n} carries peaks that do not give its root")
        else:
            prev_peaks = await self._prefix_peaks(tx, tree_id, tenant_id, prev)
        prev_hash = prev.record_hash if prev is not None else GENESIS_PREV

        # v1 leaves before the first v2 record (accounted mode switched on for an existing
        # tenant) are anchored first; the v2 segment starts after them.
        def _is_v2_row(r):
            try:
                return R.is_v2(json.loads(r["data"]) if isinstance(r["data"], str) else r["data"])
            except (TypeError, ValueError):
                return False
        flags = [_is_v2_row(r) for r in rows]
        if flags and not flags[0]:
            if prev is not None and prev.v == 2:
                raise AnchorTamper(tenant_id, f"a v1 leaf follows the v2 anchor at n={prev.n}")
            b = next((k for k, f in enumerate(flags) if f), len(flags))
            if any(not f for f in flags[b:]):
                raise AnchorTamper(tenant_id, "v1 and v2 leaves interleave in the tail")
            v1_rows = rows[:b]
            if [int(r["i"]) for r in v1_rows] != list(range(frm, frm + b)):
                raise AnchorTamper(tenant_id, "the v1 run of the tail is incomplete")
            prev_peaks, v1_root = R.mmr_extend(prev_peaks, [r["hash"] for r in v1_rows])
            if b == len(rows):
                if v1_root != root_hex:
                    raise AnchorTamper(tenant_id, "the v1 tail does not give the snapshot root")
            closer = await asyncio.to_thread(store.build_record, tenant_id, frm + b, v1_root,
                                             prev_hash, reached_at)
            got, got_seg, mine = await self._claim_successor(store, tenant_id, prev, closer, None)
            if not mine:
                return got, (json.loads(got_seg) if got_seg is not None else None), False
            if b == len(rows):
                return got, None, True
            prev, prev_hash, frm, rows = got, got.record_hash, frm + b, rows[b:]
        # Only the process that appended a record anchors it: its memory of what it appended is
        # the part of the tail the database cannot rewrite. Others leave the anchor pending.
        foreign = [frm + k for k in range(len(rows)) if frm + k not in own]
        if foreign and own:
            raise AnchorTamper(tenant_id, f"records {foreign[:5]} in the tail were not appended by its writer")
        if foreign:
            raise AnchorDeferred(f"{tenant_id}: records {foreign[0]}..{foreign[-1]} were not appended "
                                 f"by this process; left for their writer")
        chk = _check_v2_segment(tenant_id, frm, rows, prev, prev_peaks, root_hex, _system_tenant(),
                                own=own)
        if frm + len(rows) != int(n):
            raise AnchorTamper(tenant_id, f"the tail holds {len(rows)} records for [{frm}, {n})")
        rec = await asyncio.to_thread(
            store.build_record, tenant_id, int(n), chk["root"], prev_hash, reached_at,
            v=2, peaks=chk["peaks"], seg=chk["seg"], pos_last=chk["pos_last"], u=chk["u"],
            acct_from=chk["acct_from"], peaks_from=chk["peaks_from"])
        got, got_seg, mine = await self._claim_successor(store, tenant_id, prev, rec,
                                                         chk["segment_bytes"])
        if mine:
            return got, chk["segment"], True
        return got, (json.loads(got_seg) if got_seg is not None else None), False

    async def _claim_successor(self, store, tenant_id: str, prev, rec, segment_bytes: Optional[bytes]):
        """Claim prev's successor slot for rec, then write rec's segment and rec. Returns
        (record, segment bytes, mine): rec, or the record another anchorer claimed first. The slot
        is written once and holds the record and its segment, so whoever finds a claim completes
        it; the segment is written before the record."""
        from crypto import records as R
        from crypto.anchor_store import (GENESIS_PREV, WriteConflict, parse_slot, segment_key,
                                         slot_body, succ_key)
        prev_n = int(prev.n) if prev is not None else 0
        prev_hash = prev.record_hash if prev is not None else GENESIS_PREV
        key = succ_key(tenant_id, prev_n)
        mine = True
        try:
            await asyncio.to_thread(store.put_once, key, slot_body(rec, segment_bytes))
        except WriteConflict:
            mine = False
        if not mine:
            raw = await asyncio.to_thread(store.get_object, key)
            try:
                other, other_seg = parse_slot(raw)
            except (TypeError, ValueError, KeyError):
                other, other_seg = None, None
            ok = (other is not None and store.acceptable(tenant_id, other)
                  and other.prev_hash == prev_hash and int(other.n) > prev_n)
            if ok and other.seg is not None:
                ok = (other_seg is not None and R.sha256_hex(other_seg) == other.seg.get("sha256")
                      and int(other.seg.get("from", -1)) == prev_n
                      and int(other.seg.get("to", -1)) == int(other.n))
            if not ok:
                self._alarm("store", f"the successor slot of {tenant_id} at n={prev_n} holds an object "
                                     f"that is not a record extending it; the chain cannot grow there")
                raise RuntimeError(f"successor slot {key} is blocked")
            rec, segment_bytes = other, other_seg
        if segment_bytes is not None:
            try:
                await asyncio.to_thread(store.put_once, segment_key(tenant_id, int(rec.n)), segment_bytes)
            except WriteConflict:
                self._alarm("store", f"a segment that no successor claim names occupies n={rec.n} "
                                     f"of {tenant_id}")
                raise RuntimeError(f"segment at n={rec.n} of {tenant_id} is occupied")
        try:
            await asyncio.to_thread(store.put_record, rec)
        except WriteConflict:
            self._alarm("store", f"a record other than the claimed successor is stored at n={rec.n} "
                                 f"of {tenant_id}")
            raise RuntimeError(f"record at n={rec.n} of {tenant_id} is not the claimed successor")
        if not mine:
            logger.warning(f"Successor of n={prev_n} of {tenant_id} claimed by another anchorer "
                           f"(n={rec.n}); continuing from it")
        return rec, segment_bytes, mine

    async def check_own_tails(self, tenants=None) -> set:
        """Queue for reset (take_tampered) every tenant whose database tail is shorter than what
        this process appended under the current epoch; returns them. The read runs outside the
        tree lock, so a tenant whose own records change during the read is left to the next poll."""
        from database.graph_db import graph_db
        queued = set()
        for tenant_id, own in list(self._own_records.items()):
            if not own or (tenants is not None and tenant_id not in tenants):
                continue
            top, epoch_before = max(own), self._own_epoch.get(tenant_id)
            try:
                async with graph_db.driver.session() as session:
                    state = await self._read_acct_state(session, _tree_id(tenant_id), tenant_id)
            except Exception as e:
                logger.warning(f"Tail check of {tenant_id} failed: {type(e).__name__}: {e}")
                continue
            if self._own_records.get(tenant_id) is not own \
                    or self._own_epoch.get(tenant_id) != epoch_before:
                continue
            own = self._own_current(tenant_id, state["epoch"])
            if own and int(state["leaf_count"]) <= top:
                self._alarm("tail", f"tenant {tenant_id!r}: the tail holds {state['leaf_count']} "
                                    f"records, this writer appended up to seq {top}; its owner "
                                    f"resets it")
                self._tampered.add(tenant_id)
                queued.add(tenant_id)
        return queued

    async def anchor_own_tails(self) -> int:
        """Write the pending anchors of every tenant whose unanchored records this process appended,
        after check_own_tails. Runs on every heartbeat wake, lease or not: only a tail's writer
        anchors it. Returns the number of tenants flushed; never raises."""
        store = _get_anchor_store()
        if store is None:
            return 0
        from database.graph_db import graph_db
        try:
            short = await self.check_own_tails()
        except Exception as e:
            logger.warning(f"Tail check failed: {type(e).__name__}: {e}")
            short = set()
        done = 0
        for tenant_id, own in list(self._own_records.items()):
            if not own or tenant_id in short:
                continue
            try:
                if await self._flush_pending_anchors(store, graph_db, tenant_id, _tree_id(tenant_id)):
                    done += 1
            except AnchorTamper as e:
                self._tampered.add(tenant_id)
                logger.warning(f"Anchoring the own tail of {tenant_id} refused: {e}")
            except Exception as e:
                logger.warning(f"Anchoring the own tail of {tenant_id} failed: {e}")
        return done

    def _tampered_tenants(self) -> set:
        return self._tampered

    def take_tampered(self) -> set:
        """Tenants whose tail the anchorer refused outside add_records (anchor_own_tails): their
        writer must reset them. Clears the set."""
        out, self._tampered = set(self._tampered), set()
        return out

    def take_superseded(self) -> set:
        """Tenants in whose log another writer took a newer epoch while this process still had
        unanchored records there (_own_current). Clears the set."""
        out, self._superseded = set(self._superseded), set()
        return out

    async def _read_acct_state(self, tx, tree_id: str, tenant_id: str) -> Dict[str, Any]:
        state = await self._read_persistent_state(tx, tree_id, tenant_id)
        result = await tx.run(
            """
            // acct: state
            MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
            RETURN tree.writer_epoch AS epoch, tree.acct_last_json AS last
            """,
            {"tree_id": tree_id, "tenant_id": tenant_id},
        )
        row = await result.single()
        state["epoch"] = int(row["epoch"] or 0) if row else 0
        try:
            state["last"] = {str(k): int(v) for k, v in json.loads((row["last"] if row else None) or "{}").items()}
        except (TypeError, ValueError, AttributeError):
            state["last"] = {}
        return state

    async def current_epoch(self, tenant_id: str) -> int:
        """The tenant's writer epoch as the database holds it."""
        tree_id = await self.get_or_create_persistent_tree(tenant_id)
        from database.graph_db import graph_db
        async with graph_db.driver.session() as session:
            result = await session.run(
                """
                // acct: epoch
                MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
                RETURN tree.writer_epoch AS epoch
                """,
                {"tree_id": tree_id, "tenant_id": tenant_id},
            )
            row = await result.single()
        return int(row["epoch"] or 0) if row else 0

    async def _check_replayed(self, tenant_id: str, first: Dict[str, Any]) -> None:
        """After a tail reset deleted records this process had appended, the next append must
        start at or below the lowest deleted position, or the hole would be anchored. Raises
        PositionConflict (the consumer rewinds) unless the store already anchors past it."""
        mark = self._replay_from.get(tenant_id)
        if mark is None:
            return
        pos = first["pos"]
        if (str(pos["topic"]), int(pos["p"])) != mark[:2] or int(pos["o"]) <= mark[2]:
            self._replay_from.pop(tenant_id, None)
            return
        store = _get_anchor_store()
        latest = await self._latest_from_store(store, tenant_id) if store is not None else None
        pl = latest.pos_last if latest is not None else None
        if pl and (str(pl["topic"]), int(pl["p"])) == mark[:2] and int(pl["o"]) >= mark[2]:
            self._replay_from.pop(tenant_id, None)
            return
        self._alarm("tail", f"tenant {tenant_id!r}: records from {mark[0]}/{mark[1]}@{mark[2]} were "
                            f"deleted by the tail reset and not appended again; refusing to append "
                            f"from @{pos['o']} over them")
        from crypto import records as R
        raise PositionConflict(tenant_id, R.Position.from_json(pos), -1)

    # Fault injection for the failing-appends attack: a (:Fault {kind: 'poison'}) node names a
    # tenant and a count; appends of the first `count` event positions taken afterwards always
    # fail (not an outage). Only with FAULT_INJECTION=1 and outside production.

    @staticmethod
    def _faults_on() -> bool:
        return os.environ.get("FAULT_INJECTION", "") == "1" \
            and str(settings.environment).lower() != "production"

    async def _injected_poison(self, tenant_id: str, templates: List[Dict[str, Any]]) -> None:
        events = [t for t in templates if t.get("kind") == "event"]
        if not events:
            return
        from database.graph_db import graph_db
        async with graph_db.driver.session() as session:
            result = await session.run(
                """
                // fault: read
                MATCH (f:Fault {kind: 'poison', tenant_id: $tenant_id})
                RETURN f.count AS count, f.taken AS taken
                """, {"tenant_id": tenant_id})
            row = await result.single()
            if row is None:
                return
            count, taken = int(row["count"] or 0), list(row["taken"] or [])
            hit, grew = None, False
            for t in events:
                key = f"{t['pos']['topic']}/{int(t['pos']['p'])}/{int(t['pos']['o'])}"
                if key not in taken and len(taken) < count:
                    taken.append(key)
                    grew = True
                if key in taken and hit is None:
                    hit = key
            if grew:
                await session.run(
                    """
                    // fault: take
                    MATCH (f:Fault {kind: 'poison', tenant_id: $tenant_id})
                    SET f.taken = $taken
                    """, {"tenant_id": tenant_id, "taken": taken})
        if hit is not None:
            raise InjectedFault(f"injected poison: the database write of {tenant_id} at {hit} fails")

    async def add_records(self, tenant_id: str, templates: List[Dict[str, Any]],
                          writer_epoch: int) -> List[Tuple[int, str]]:
        """Append accounting records (crypto.records templates, without seq) in offset order, in
        one transaction under the tree lock. Returns [(seq, record_hash)] aligned with templates.
        Deduplication is by broker position: a template at a position the tail covers must find the
        identical record there, else PositionConflict (also raised for a tail shorter than what
        this writer appended, and by _check_replayed). A stale epoch raises FencedWriter. After the
        commit the due anchors are written; a failed check raises AnchorTamper."""
        from crypto import records as R
        if not templates:
            return []
        seen_tp: Dict[str, int] = {}
        for t in templates:
            if not R.is_v2(t) or "seq" in t or t.get("tenant_id") != tenant_id:
                raise ValueError("add_records takes v2 templates of this tenant, without seq")
            pos = R.Position.from_json(t["pos"])
            key = _tp_key(pos.topic, pos.p)
            if seen_tp and key not in seen_tp:
                raise ValueError("a tenant's records come from one partition")
            if key in seen_tp and pos.o <= seen_tp[key]:
                raise ValueError("templates must be in strictly increasing offset order")
            seen_tp[key] = pos.o
        if self._faults_on():
            await self._injected_poison(tenant_id, templates)
        tree_id = await self.get_or_create_persistent_tree(tenant_id)
        from database.graph_db import graph_db
        results: List[Optional[Tuple[int, str]]] = [None] * len(templates)
        _t = time.perf_counter()
        async with graph_db.driver.session() as session:
            tx = await begin_tx(session)
            settled = False
            try:
                await self._lock_tree_for_append(tx, tree_id, tenant_id)
                state = await self._read_acct_state(tx, tree_id, tenant_id)
                _t = _tadd("db_lock_read", _t)
                if state["epoch"] != int(writer_epoch):
                    # Checked first: a fenced writer must not reset a tail it no longer owns.
                    raise FencedWriter(f"{tenant_id}: writer epoch {writer_epoch}, tree at {state['epoch']}")
                if tenant_id in self._tampered:
                    self._tampered.discard(tenant_id)
                    raise AnchorTamper(tenant_id, "the anchorer refused this tail since the last append")
                own = self._own_current(tenant_id, state["epoch"])
                if own and max(own) >= state["leaf_count"]:
                    # Records were removed under this writer.
                    raise PositionConflict(tenant_id, None, max(own))
                await self._check_replayed(tenant_id, templates[0])
                last = dict(state["last"])
                old_idx, new_idx = [], []
                for k, t in enumerate(templates):
                    pos = t["pos"]
                    if int(pos["o"]) <= last.get(_tp_key(pos["topic"], pos["p"]), -1):
                        old_idx.append(k)
                    else:
                        new_idx.append(k)
                if old_idx:
                    result = await tx.run(
                        """
                        // acct: records at positions
                        UNWIND $positions AS q
                        MATCH (x:MerkleNode {tree_id: $tree_id, tenant_id: $tenant_id, is_leaf: true,
                                             acct_topic: q.topic, acct_p: q.p, acct_o: q.o})
                        RETURN x.leaf_index AS i, x.data AS data, q.topic AS topic, q.p AS p, q.o AS o
                        """,
                        {"tree_id": tree_id, "tenant_id": tenant_id,
                         "positions": [{"topic": templates[k]["pos"]["topic"],
                                        "p": int(templates[k]["pos"]["p"]),
                                        "o": _db_offset(templates[k]["pos"]["o"])} for k in old_idx]},
                    )
                    at: Dict[Tuple[str, int, int], List[Dict[str, Any]]] = {}
                    for r in await result.data():
                        at.setdefault((r["topic"], int(r["p"]), int(r["o"])), []).append(r)
                    for k in old_idx:
                        t = templates[k]
                        pos = R.Position.from_json(t["pos"])
                        found = at.get((pos.topic, pos.p, pos.o), [])
                        seq = int(found[0]["i"]) if len(found) == 1 and found[0].get("i") is not None else -1
                        try:
                            data = json.loads(found[0]["data"]) if seq >= 0 else None
                        except (TypeError, ValueError):
                            data = None
                        if data is None or data.get("seq") != seq or not R.same_template(data, t):
                            raise PositionConflict(tenant_id, pos, seq)
                        results[k] = (seq, R.record_hash(R.with_seq(t, seq)))
                    new_idx.sort()
                if not new_idx:
                    await tx.rollback()
                    settled = True
                else:
                    log = IncrementalMerkleLog()
                    log.peaks = list(state["peaks"])
                    n_before = state["leaf_count"]
                    rows = []
                    for j, k in enumerate(new_idx):
                        seq = n_before + j
                        rec = R.with_seq(templates[k], seq)
                        data = R.canon(rec)
                        h = log.append(data).hex()
                        pos = rec["pos"]
                        last[_tp_key(pos["topic"], pos["p"])] = int(pos["o"])
                        # event_id only on event records; the event-id index looks referents up by it.
                        ev = rec.get("event") if (rec.get("kind") == "event"
                                                  and isinstance(rec.get("event"), dict)) else {}
                        rows.append({"node_id": f"leaf_{h}", "hash": h, "data": data.decode(),
                                     "leaf_index": seq, "event_id": ev.get("event_id"),
                                     "topic": pos["topic"], "p": int(pos["p"]), "o": _db_offset(pos["o"])})
                        results[k] = (seq, h)
                    new_root = log.root()
                    new_count = n_before + len(rows)
                    new_version = state["version"] + 1
                    appended_at = datetime.utcnow()
                    await tx.run(
                        """
                        // acct: create records
                        UNWIND $rows AS r
                        CREATE (node:MerkleNode {
                            tree_id: $tree_id, node_id: r.node_id, hash: r.hash, depth: 0,
                            is_leaf: true, tenant_id: $tenant_id, data: r.data,
                            leaf_index: r.leaf_index, event_id: r.event_id,
                            acct_topic: r.topic, acct_p: r.p, acct_o: r.o, created_at: $created_at
                        })
                        """,
                        {"rows": rows, "tree_id": tree_id, "tenant_id": tenant_id,
                         "created_at": appended_at},
                    )
                    await self._write_persistent_state(tx, tree_id, tenant_id, list(log.peaks),
                                                       new_root.hex(), new_count, new_version)
                    await tx.run(
                        """
                        // acct: set last
                        MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
                        SET tree.acct_last_json = $last
                        """,
                        {"tree_id": tree_id, "tenant_id": tenant_id,
                         "last": json.dumps(last, sort_keys=True)},
                    )
                    await tx.run(
                        """
                        CREATE (snap:MerkleRootSnapshot {
                            tree_id: $tree_id,
                            tenant_id: $tenant_id,
                            version: $version,
                            root_hash: $root_hash,
                            leaf_count: $leaf_count,
                            timestamp: $timestamp,
                            anchor_pending: CASE WHEN $pending THEN true ELSE null END
                        })
                        """,
                        {"tree_id": tree_id, "tenant_id": tenant_id, "version": new_version,
                         "root_hash": new_root.hex(), "leaf_count": new_count,
                         "timestamp": appended_at, "pending": self._anchor_due(n_before, new_count)},
                    )
                    _t = _tadd("db_write", _t)
                    await tx.commit()
                    _t = _tadd("db_commit", _t)
                    settled = True
                    for j, k in enumerate(new_idx):
                        self._remember_own(tenant_id, n_before + j, results[k][1],
                                           templates[k]["pos"], state["epoch"])
            except BaseException:
                if not settled:
                    try:
                        await tx.rollback()
                    except Exception:
                        pass
                raise
        _t = time.perf_counter()
        if new_idx:
            await self._anchor_after_append(tenant_id, tree_id, n_before, new_count,
                                            raise_tamper=True)
        else:
            await self._anchor_after_append(tenant_id, tree_id, state["leaf_count"],
                                            state["leaf_count"], replay=True, raise_tamper=True)
        _tadd("anchor", _t)
        if _STAGE_TIMING:
            ACCT_TIMING["appends"] = ACCT_TIMING.get("appends", 0.0) + 1
        return results

    async def latest_anchor(self, tenant_id: str):
        """The tenant's latest authenticated anchor record, from the store. The database tip is
        only a hint where to start looking."""
        store = _get_anchor_store()
        if store is None:
            return None
        from database.graph_db import graph_db
        tree_id = _tree_id(tenant_id)
        tip_n = tip_hash = None
        try:
            async with graph_db.driver.session() as session:
                result = await session.run(
                    """
                    MATCH (tip:MerkleAnchorTip {tree_id: $tree_id, tenant_id: $tenant_id})
                    RETURN tip.tip_n AS n, tip.tip_hash AS h, tip.tip_sig AS s
                    """,
                    {"tree_id": tree_id, "tenant_id": tenant_id},
                )
                row = await result.single()
            if row and row["n"] is not None and self._head_authentic(
                    tenant_id, row["n"], row["h"], row["s"]) is not False:
                tip_n, tip_hash = int(row["n"]), row["h"]
        except Exception as e:
            logger.debug(f"Tip unreadable for {tenant_id} ({e}); asking the store from genesis")
        return await self._latest_from_store(store, tenant_id, tip_n, tip_hash)

    async def _latest_from_store(self, store, tenant_id: str, tip_n=None, tip_hash=None):
        newer = await asyncio.to_thread(store.latest_after, tenant_id, -1 if tip_n is None else tip_n)
        if newer is not None and self._head_authentic(tenant_id, newer.n, newer.record_hash,
                                                      newer.sig) is not False:
            return newer
        if tip_n is not None:
            rec = await self._store_record(store, tenant_id, tip_n, tip_hash)
            if rec is not None:
                return rec
            newer = await asyncio.to_thread(store.latest_after, tenant_id, -1)
            if newer is not None and self._head_authentic(tenant_id, newer.n, newer.record_hash,
                                                          newer.sig) is not False:
                return newer
        return None

    async def reset_tenant_tail(self, tenant_id: str) -> Tuple[int, int]:
        """Rebuild the tenant's database tail from the store. Returns (base_n, new_epoch).
        Under the tip and tree locks: delete the leaves and snapshots above the latest
        authenticated anchor, reset the tree state and tip to it, and raise the writer epoch, which
        fences other writers. The caller then replays the partition from its committed offset."""
        from crypto import records as R
        store = _get_anchor_store()
        tree_id = await self.get_or_create_persistent_tree(tenant_id)
        from database.graph_db import graph_db
        params = {"tree_id": tree_id, "tenant_id": tenant_id}
        async with graph_db.driver.session() as session:
            tx = await begin_tx(session)
            try:
                await tx.run(
                    """
                    MERGE (tip:MerkleAnchorTip {tree_id: $tree_id, tenant_id: $tenant_id})
                    SET tip.locked_at = timestamp()
                    """,
                    params,
                )
                await self._lock_tree_for_append(tx, tree_id, tenant_id)
                base = await self._latest_from_store(store, tenant_id) if store is not None else None
                state = await self._read_acct_state(tx, tree_id, tenant_id)
                if base is None:
                    base_n, peaks, root, last = 0, [], "", {}
                else:
                    base_n = int(base.n)
                    if base.peaks is not None:
                        peaks = [list(p) for p in base.peaks]
                    else:
                        peaks = await self._prefix_peaks(tx, tree_id, tenant_id, base)
                    root = base.root
                    pl = base.pos_last
                    last = {_tp_key(pl["topic"], pl["p"]): int(pl["o"])} if pl else {}
                # v1 leaves right after the base predate accounted mode and cannot be replayed:
                # they are kept, and only v2 records are reset.
                if base is None or base.v != 2:
                    result = await tx.run(self._ACCT_LEAVES, dict(params, lo=base_n,
                                                                  hi=int(state["leaf_count"])))
                    for r in await result.data():
                        try:
                            d = json.loads(r["data"]) if isinstance(r["data"], str) else r["data"]
                        except (TypeError, ValueError):
                            d = None
                        if int(r["i"]) != base_n or R.is_v2(d):
                            break
                        peaks, root = R.mmr_extend(peaks, [r["hash"]])
                        base_n += 1
                epoch = int(state["epoch"]) + 1
                await tx.run(
                    """
                    // acct: delete tail
                    MATCH (x:MerkleNode {tree_id: $tree_id, tenant_id: $tenant_id})
                    WHERE x.leaf_index >= $n
                    DETACH DELETE x
                    """,
                    dict(params, n=base_n),
                )
                await tx.run(
                    """
                    // acct: delete snapshots
                    MATCH (s:MerkleRootSnapshot {tree_id: $tree_id, tenant_id: $tenant_id})
                    WHERE s.leaf_count > $n
                    DETACH DELETE s
                    """,
                    dict(params, n=base_n),
                )
                await tx.run(
                    """
                    // acct: reset state
                    MATCH (tree:MerkleTree {tree_id: $tree_id, tenant_id: $tenant_id})
                    SET tree.peaks_json = $peaks_json, tree.root_hash = $root, tree.leaf_count = $n,
                        tree.version = tree.version + 1, tree.acct_last_json = $last,
                        tree.writer_epoch = $epoch, tree.updated_at = $now
                    """,
                    dict(params, peaks_json=json.dumps([{"h": h, "ht": int(ht)} for h, ht in peaks]),
                         root=root, n=base_n, last=json.dumps(last, sort_keys=True), epoch=epoch,
                         now=datetime.utcnow()),
                )
                if base is not None:
                    # The tip is the base record itself (base.n), not the count over a kept v1 run.
                    await tx.run(self._SET_ANCHOR_TIP,
                                 dict(params, n=int(base.n), h=base.record_hash, s=base.sig))
                await tx.commit()
            except BaseException:
                try:
                    await tx.rollback()
                except Exception:
                    pass
                raise
        # Own records above the base are deleted; the next append must start with them again
        # (_check_replayed).
        deleted = [p for s, p in self._own_pos.get(tenant_id, {}).items() if s >= base_n]
        if deleted:
            low = min(deleted, key=lambda q: q[2])
            old = self._replay_from.get(tenant_id)
            if old is None or old[:2] != low[:2] or low[2] < old[2]:
                self._replay_from[tenant_id] = low
        self._own_records.pop(tenant_id, None)
        self._own_pos.pop(tenant_id, None)
        self._own_epoch.pop(tenant_id, None)
        self._tampered.discard(tenant_id)
        logger.warning(f"Tail of {tenant_id} reset to the anchor at n={base_n}; writer epoch {epoch}")
        return base_n, epoch

    # Time-based anchoring.
    async def anchor_heartbeat_once(self) -> int:
        """Anchor every log whose first leaf after the chain tip was appended more than
        merkle_anchor_max_age_s ago (a missing leaf counts as old, an unauthenticated tip as
        genesis), and write every anchor any process left pending. Returns the logs flagged by age."""
        max_age = float(settings.merkle_anchor_max_age_s or 0)
        store = _get_anchor_store()
        if max_age <= 0 or store is None:
            return 0
        from database.graph_db import graph_db
        cutoff = datetime.utcnow() - timedelta(seconds=max_age)
        async with graph_db.driver.session() as session:
            result = await session.run(
                """
                // heartbeat: logs with a tail
                MATCH (tree:MerkleTree) WHERE tree.tree_id STARTS WITH 'global_persistent_'
                                          AND tree.leaf_count > 0
                OPTIONAL MATCH (tip:MerkleAnchorTip {tree_id: tree.tree_id, tenant_id: tree.tenant_id})
                RETURN tree.tenant_id AS tenant_id, tree.tree_id AS tree_id,
                       tree.leaf_count AS n, tip.tip_n AS tip_n, tip.tip_hash AS tip_hash,
                       tip.tip_sig AS tip_sig
                """,
            )
            cands = []
            for r in await result.data():
                tip_n = r.get("tip_n")
                if tip_n is not None and self._head_authentic(
                        r["tenant_id"], tip_n, r.get("tip_hash"), r.get("tip_sig")) is False:
                    self._alarm("tip", f"chain tip for {r['tenant_id']} (n={tip_n}) failed authentication; "
                                       f"the heartbeat treats the tail as unanchored")
                    tip_n = None
                first = int(tip_n or 0)
                if int(r.get("n") or 0) > first:
                    cands.append({"tenant_id": r["tenant_id"], "tree_id": r["tree_id"],
                                  "n": int(r["n"]), "first": first})
            rows = []
            if cands:
                result = await session.run(
                    """
                    // heartbeat: oldest unanchored leaf
                    UNWIND $rows AS r
                    OPTIONAL MATCH (leaf:MerkleNode {tree_id: r.tree_id, leaf_index: r.first})
                    WITH r, leaf
                    WHERE leaf IS NULL OR leaf.created_at < $cutoff
                    RETURN r.tenant_id AS tenant_id, r.tree_id AS tree_id, r.n AS n
                    """,
                    {"rows": cands, "cutoff": cutoff},
                )
                rows = [{"tenant_id": r["tenant_id"], "tree_id": r["tree_id"], "n": int(r["n"])}
                        for r in await result.data()]
            if rows:
                await session.run(
                    """
                    // heartbeat: flag
                    UNWIND $rows AS r
                    MATCH (snap:MerkleRootSnapshot {tree_id: r.tree_id, tenant_id: r.tenant_id,
                                                    leaf_count: r.n})
                    SET snap.anchor_pending = true
                    """,
                    {"rows": rows},
                )
            result = await session.run(
                """
                // heartbeat: pending anchors
                MATCH (snap:MerkleRootSnapshot) WHERE snap.anchor_pending = true
                RETURN DISTINCT snap.tenant_id AS tenant_id, snap.tree_id AS tree_id
                """,
            )
            waiting = await result.data()
        todo = {(r["tenant_id"], r["tree_id"]) for r in rows}
        todo |= {(r["tenant_id"], r["tree_id"]) for r in waiting}
        for tenant_id, tree_id in sorted(todo):
            try:
                if await self._flush_pending_anchors(store, graph_db, tenant_id, tree_id):
                    self._anchor_pending.discard(tenant_id)
            except Exception as e:
                logger.warning(f"Heartbeat anchor failed for {tenant_id}: {e}")
        return len(rows)

    # Sleep of the loop below; tests replace it.
    _sleep = staticmethod(asyncio.sleep)

    def _lease_holder(self) -> str:
        """This process's identity as a lease holder: stable for its life, unique across hosts."""
        if self._holder is None:
            import uuid
            self._holder = f"{os.getpid()}-{uuid.uuid4().hex[:12]}"
        return self._holder

    async def _take_lease(self, name: str, seconds: float) -> bool:
        """Take or renew the right to do a deployment-wide sweep for the next `seconds`, by the
        database's clock (the row is locked before it is read). If the database cannot answer this
        returns True: the sweep is idempotent."""
        from database.graph_db import graph_db
        me = self._lease_holder()
        ms = int(max(1.0, seconds) * 1000)
        try:
            async with graph_db.driver.session() as session:
                tx = await begin_tx(session)
                try:
                    await tx.run(
                        "MERGE (l:Lease {name: $name}) SET l.locked_at = timestamp()",
                        {"name": name})
                    result = await tx.run(
                        """
                        MATCH (l:Lease {name: $name})
                        RETURN l.holder AS holder, l.until AS until, timestamp() AS now
                        """,
                        {"name": name})
                    row = await result.single()
                    now = int(row["now"])
                    until = row["until"]
                    until = int(until) if until is not None else None
                    if until is not None and until - now > ms:
                        self._alarm("lease", f"lease {name} held until {until - now} ms from now, "
                                             f"longer than one lease ({ms} ms); treated as expired")
                        until = None
                    won = until is None or until <= now or row["holder"] == me
                    if won:
                        await tx.run(
                            "MATCH (l:Lease {name: $name}) SET l.holder = $holder, l.until = $until",
                            {"name": name, "holder": me, "until": now + ms})
                        await tx.commit()
                    else:
                        await tx.rollback()
                    return won
                except BaseException:
                    try:
                        await tx.rollback()
                    except Exception:
                        pass
                    raise
        except Exception as e:
            logger.debug(f"Lease {name} unavailable ({e}); proceeding without it")
            return True

    async def anchor_heartbeat_loop(self) -> None:
        """Every process wakes every period * U(0.8, 1.2); the one holding the lease sweeps."""
        import random
        while True:
            timing = anchor_timing(float(settings.merkle_anchor_max_age_s or 0))
            if timing is None:
                return
            await self._sleep(timing["period_s"] * random.uniform(*HEARTBEAT_JITTER))
            try:
                if await self._take_lease("anchor_heartbeat", timing["lease_s"]):
                    await self.anchor_heartbeat_once()
                if _acct_mode():
                    await self.anchor_own_tails()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Anchor heartbeat error: {e}")

    # The public log (Sigsum) client used by the period statements and the contract publisher.
    def _public_witness(self):
        if self._pw_loaded:
            return self._pw_client
        self._pw_loaded = True
        url = settings.merkle_public_witness_url
        seed = settings.merkle_public_witness_seed or settings.merkle_signing_seed
        if url and seed:
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                from crypto.public_witness import SigsumClient, load_policy
                log_key = settings.merkle_public_witness_log_key
                # Sigsum trust policy, a file path or inline. Without it receipts never verify.
                policy = load_policy(settings.merkle_public_witness_policy)
                self._pw_client = SigsumClient(
                    url, Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)),
                    log_public_key=bytes.fromhex(log_key) if log_key else None,
                    token=settings.merkle_public_witness_token,
                    policy=policy)
                if policy is None:
                    logger.error("Public witness: no witness policy configured "
                                 "(merkle_public_witness_policy); receipts will not verify")
                logger.info(f"Public witness: log {url}, key hash {self._pw_client.key_hash.hex()}")
            except Exception as e:
                logger.error(f"Public witness disabled: {e}")
        return self._pw_client

    async def _flush_pending_anchors(self, store, graph_db, tenant_id: str, tree_id: str,
                                     newest: Optional[int] = None) -> bool:
        """Write this tenant's pending anchors in leaf-count order; True if none remain. newest is
        the leaf count the caller just made due, if any; pending anchors below it are backfills."""
        try:
            async with graph_db.driver.session() as session:
                result = await session.run(
                    """
                    MATCH (snap:MerkleRootSnapshot {tree_id: $tree_id, tenant_id: $tenant_id})
                    WHERE snap.anchor_pending = true
                    RETURN snap.leaf_count AS n, snap.root_hash AS root, snap.timestamp AS at
                    ORDER BY n ASC
                    """,
                    {"tree_id": tree_id, "tenant_id": tenant_id},
                )
                rows = await result.data()
        except Exception as e:
            logger.warning(f"Could not read pending anchors for {tenant_id}: {e}")
            self._anchor_pending.add(tenant_id)
            return False
        for row in rows:
            n, root = int(row["n"]), row["root"]
            try:
                await self._anchor_serialized(store, graph_db, tenant_id, tree_id, n, root,
                                              reached_at=_unix_time(row.get("at")))
            except AnchorTamper as e:
                self._alarm("anchor-tamper", str(e))
                self._anchor_pending.add(tenant_id)
                raise
            except AnchorDeferred as e:
                logger.debug(f"Anchor at n={n} deferred: {e}")
                return False
            except Exception as e:
                logger.warning(f"Anchor backfill still failing at n={n} for {tenant_id}: {e}")
                self._anchor_pending.add(tenant_id)
                return False
            try:
                async with graph_db.driver.session() as session:
                    await session.run(
                        """
                        MATCH (snap:MerkleRootSnapshot {tree_id: $tree_id, tenant_id: $tenant_id, leaf_count: $n})
                        WHERE snap.anchor_pending = true
                        REMOVE snap.anchor_pending
                        """,
                        {"tree_id": tree_id, "tenant_id": tenant_id, "n": n},
                    )
            except Exception as e:
                logger.warning(f"Anchor at n={n} written but its pending flag was not cleared "
                               f"for {tenant_id}: {e}")
            if newest is None or n < newest:
                logger.warning(f"Backfilled anchor at n={n} for {tenant_id}")
        self._anchor_pending.discard(tenant_id)
        return True

    async def proof_bundle(self, tenant_id: str, event_id: str) -> Dict[str, Any]:
        """What a third party needs to check one event offline: the leaf, its inclusion proof
        against the first anchored root that covers it, and that signed anchor. status is "ok",
        "pending", "unknown" or "mismatch"; for an event id with several leaves, the lowest."""
        store = _get_anchor_store()
        if store is None:
            return {"status": "unavailable", "reason": "anchoring disabled"}
        from database.graph_db import graph_db
        from crypto.signing import get_public_key
        params = {"tree_id": _tree_id(tenant_id), "tenant_id": tenant_id}
        async with graph_db.driver.session() as session:
            result = await session.run(
                """
                MATCH (leaf:MerkleNode {tree_id: $tree_id, tenant_id: $tenant_id, is_leaf: true,
                                        event_id: $event_id})
                RETURN leaf.leaf_index AS i, leaf.data AS data, leaf.hash AS hash
                ORDER BY leaf.leaf_index ASC
                """,
                dict(params, event_id=event_id),
            )
            found = [r for r in await result.data() if r.get("i") is not None]
            if not found:
                return {"status": "unknown", "event_id": event_id}
            found.sort(key=lambda r: int(r["i"]))
            row = found[0]
            duplicates = [int(r["i"]) for r in found[1:]]
            i = int(row["i"])
            rec = await asyncio.to_thread(store.first_at_or_after, tenant_id, i + 1)
            if rec is None:
                out = {"status": "pending", "event_id": event_id, "leaf_index": i,
                       "reason": "no anchor covers this leaf yet"}
                if duplicates:
                    out["duplicate_leaf_indexes"] = duplicates
                return out
            result = await session.run(
                """
                MATCH (x:MerkleNode {tree_id: $tree_id, tenant_id: $tenant_id, is_leaf: true})
                WHERE x.leaf_index < $n
                RETURN x.hash AS hash
                ORDER BY x.leaf_index ASC
                """,
                dict(params, n=int(rec.n)),
            )
            hashes = [bytes.fromhex(r["hash"]) for r in await result.data()]
        if len(hashes) != int(rec.n):
            return {"status": "mismatch", "event_id": event_id,
                    "reason": f"{len(hashes)} stored leaves below the anchor at n={rec.n}"}
        log = IncrementalMerkleLog.from_leaf_hashes(hashes)
        proof = log.inclusion_proof(i)
        if log.root().hex() != rec.root:
            return {"status": "mismatch", "event_id": event_id,
                    "reason": f"stored leaves do not reproduce the anchored root at n={rec.n}"}
        pub = get_public_key(settings)
        bundle = {
            "v": 1, "tenant_id": tenant_id, "event_id": event_id,
            "leaf": {"index": i, "data": row["data"], "hash": row["hash"]},
            "mmr_size": int(rec.n),
            "proof": [[h.hex(), side] for h, side in proof],
            "anchor": rec.to_json(),
            "public_key": pub.hex() if pub else None,
        }
        if duplicates:
            bundle["duplicate_leaf_indexes"] = duplicates
        return {"status": "ok", "bundle": bundle}


merkle_tree_storage = MerkleTreeStorage()

