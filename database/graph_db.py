import asyncio
import json
import logging
import os
import time
from typing import List, Dict, Any, Optional, Tuple
from neo4j import AsyncGraphDatabase

from schemas import ProvenanceEvent
from config import settings
from crypto.merkle_tree_storage import merkle_tree_storage, begin_tx

logger = logging.getLogger(__name__)

_GRAPH_TIMING = os.getenv("STAGE_TIMING", "").strip().lower() in ("1", "true", "yes", "on")

_INT64 = (-(1 << 63), (1 << 63) - 1)

# Entity, Agent and IP nodes keep at most this many recent access timestamps, next to a counter
# of all accesses and the first-seen time.
RECENT_TIMESTAMPS = 20

def _property_value(value: Any) -> Any:
    """A metadata value as a Neo4j property: nested objects as JSON text, an integer outside int64
    as its decimal text, None as "". A sender's metadata never makes a graph write fail."""
    try:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value if _INT64[0] <= value <= _INT64[1] else str(value)
        if isinstance(value, float):
            return value
        if isinstance(value, (dict, list)):
            return json.dumps(value, default=str)
        if value is None:
            return ""
        return str(value)
    except Exception:
        return "error_converting"

def _stored_record(data: Any) -> Any:
    return json.loads(data) if isinstance(data, str) else data

def _flatten_metadata(metadata: Optional[Dict[str, Any]], prefix: str) -> Dict[str, Any]:
    """Metadata as flat properties named <prefix>_<key> (Neo4j has no nested maps)."""
    return {f"{prefix}_{key}": _property_value(value) for key, value in (metadata or {}).items()}

class _GraphStats:
    """STAGE_TIMING counters of the graph write path, per process."""
    n = 0
    nodes_ms = 0.0
    merkle_ms = 0.0
    tx_n = 0
    events = 0
    ent = 0.0
    agt = 0.0
    act = 0.0
    rel = 0.0
    cmt = 0.0

class _NodeWriteBatcher:
    """Group commit for the node writes: queued events share one transaction (graph_write_batch_g
    at most), so they pay one commit and do not contend for locks. submit() returns after the
    event's nodes are committed."""

    def __init__(self, db):
        self.db = db
        self.queue: List[Tuple[Any, Any]] = []
        self.running = False

    def _max_batch(self) -> int:
        return max(1, int(settings.graph_write_batch_g))

    async def submit(self, event) -> None:
        fut = asyncio.get_running_loop().create_future()
        self.queue.append((event, fut))       # no await before the flag
        if not self.running:
            self.running = True
            asyncio.create_task(self._drain())
        return await fut

    async def _drain(self):
        try:
            while self.queue:
                batch = self.queue[:self._max_batch()]
                del self.queue[:len(batch)]
                try:
                    # Per-event failures (an event_id collision) fail only their own event; the
                    # rest of the group has committed.
                    failed = await self.db._write_nodes_tx([e for e, _ in batch]) or {}
                    for i, (_, f) in enumerate(batch):
                        if f.done():
                            continue
                        if i in failed:
                            f.set_exception(failed[i])
                        else:
                            f.set_result(None)
                except Exception as e:
                    for _, f in batch:
                        if not f.done():
                            f.set_exception(e)
        finally:
            self.running = False
            if self.queue:
                self.running = True
                asyncio.create_task(self._drain())

class GraphDatabaseManager:

    def __init__(self):
        self.driver = None
        self._node_batcher = _NodeWriteBatcher(self)
        self._append_locks: Dict[str, asyncio.Lock] = {}

    async def initialize(self):
        try:
            self.driver = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                max_connection_lifetime=settings.neo4j_max_connection_lifetime,
                max_connection_pool_size=settings.neo4j_max_connection_pool_size,
                connection_acquisition_timeout=settings.neo4j_max_retry_time,
                database=settings.neo4j_database
            )

            await self.driver.verify_connectivity()
            await self._create_schema()

            logger.info("Graph database initialized")

        except Exception as e:
            logger.error(f"Failed to initialize graph database: {e}")
            raise

    async def close(self):
        if self.driver:
            await self.driver.close()

    async def _create_schema(self):
        """Create the constraints and indexes; every per-event MERGE and MATCH needs one. Raises when
        more than half of them fail."""
        try:
            async with self.driver.session() as session:
                constraints = [
                    "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (e:Entity) REQUIRE (e.id, e.tenant_id) IS UNIQUE",
                    "CREATE CONSTRAINT activity_id_unique IF NOT EXISTS FOR (a:Activity) REQUIRE a.id IS UNIQUE",
                    # Agent and IP nodes are MERGEd by concurrent writers.
                    "CREATE CONSTRAINT agent_id_tenant_unique IF NOT EXISTS FOR (a:Agent) REQUIRE (a.id, a.tenant_id) IS UNIQUE",
                    "CREATE CONSTRAINT ip_address_tenant_unique IF NOT EXISTS FOR (i:IP) REQUIRE (i.address, i.tenant_id) IS UNIQUE",
                    # One log per tenant, one leaf per (tree, node_id) and one anchor-chain tip per
                    # tenant, even when two consumers write at once.
                    "CREATE CONSTRAINT merkle_tree_unique IF NOT EXISTS FOR (t:MerkleTree) REQUIRE (t.tree_id, t.tenant_id) IS UNIQUE",
                    "CREATE CONSTRAINT merkle_node_unique IF NOT EXISTS FOR (n:MerkleNode) REQUIRE (n.tree_id, n.node_id) IS UNIQUE",
                    "CREATE CONSTRAINT merkle_anchor_tip_unique IF NOT EXISTS FOR (t:MerkleAnchorTip) REQUIRE (t.tree_id, t.tenant_id) IS UNIQUE",
                ]

                indices = [
                    "CREATE INDEX entity_tenant_idx IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id)",
                    "CREATE INDEX entity_type_idx IF NOT EXISTS FOR (e:Entity) ON (e.type)",
                    "CREATE INDEX entity_hash_idx IF NOT EXISTS FOR (e:Entity) ON (e.hash)",
                    "CREATE INDEX activity_timestamp_idx IF NOT EXISTS FOR (act:Activity) ON (act.timestamp)",
                    "CREATE INDEX activity_tenant_idx IF NOT EXISTS FOR (act:Activity) ON (act.tenant_id)",
                    "CREATE INDEX agent_ip_idx IF NOT EXISTS FOR (a:Agent) ON (a.ip)",
                ]

                # Per-event MATCH keys of the log append.
                hot_path_indices = [
                    "CREATE INDEX merkle_node_lookup_idx IF NOT EXISTS FOR (n:MerkleNode) ON (n.tree_id, n.node_id, n.tenant_id)",
                    "CREATE INDEX merkle_tree_lookup_idx IF NOT EXISTS FOR (t:MerkleTree) ON (t.tree_id, t.tenant_id)",
                    "CREATE INDEX merkle_tree_tenant_idx IF NOT EXISTS FOR (t:MerkleTree) ON (t.tenant_id)",
                ]

                composite_indices = [
                    "CREATE INDEX entity_tenant_type_composite IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.type)",
                    "CREATE INDEX activity_tenant_timestamp_composite IF NOT EXISTS FOR (act:Activity) ON (act.tenant_id, act.timestamp)",
                ]

                merkle_indices = [
                    "CREATE INDEX merkle_snapshot_tree_idx IF NOT EXISTS FOR (s:MerkleRootSnapshot) ON (s.tree_id)",
                    "CREATE INDEX merkle_snapshot_version_idx IF NOT EXISTS FOR (s:MerkleRootSnapshot) ON (s.version)",
                    "CREATE INDEX merkle_snapshot_timestamp_idx IF NOT EXISTS FOR (s:MerkleRootSnapshot) ON (s.timestamp)",
                    "CREATE INDEX merkle_leaf_order_idx IF NOT EXISTS FOR (n:MerkleNode) ON (n.tree_id, n.leaf_index)",
                    "CREATE INDEX merkle_snapshot_pending_idx IF NOT EXISTS FOR (s:MerkleRootSnapshot) ON (s.anchor_pending)",
                    # The heartbeat joins a tree to the snapshot at its current leaf count.
                    "CREATE INDEX merkle_snapshot_at_count_idx IF NOT EXISTS FOR (s:MerkleRootSnapshot) ON (s.tree_id, s.leaf_count)",
                    # One process per period does the deployment-wide sweeps (MerkleTreeStorage._take_lease).
                    "CREATE CONSTRAINT lease_unique IF NOT EXISTS FOR (l:Lease) REQUIRE l.name IS UNIQUE",
                    # Proof bundles and the writer's event-id lookups find a leaf by its event.
                    "CREATE INDEX merkle_leaf_event_idx IF NOT EXISTS FOR (n:MerkleNode) ON (n.tree_id, n.event_id)",
                    # Accounted ingestion looks a record up by its broker position.
                    "CREATE INDEX merkle_leaf_acct_pos_idx IF NOT EXISTS FOR (n:MerkleNode) ON (n.tree_id, n.acct_topic, n.acct_p, n.acct_o)",
                ]

                all_queries = (constraints + indices + hot_path_indices
                               + composite_indices + merkle_indices)

                success_count = 0
                failure_count = 0

                for query in all_queries:
                    try:
                        await session.run(query)
                        success_count += 1
                        logger.debug(f"Schema query executed: {query}")
                    except Exception as e:
                        error_msg = str(e).lower()
                        if "already exists" in error_msg or "equivalent" in error_msg:
                            logger.debug(f"Schema already exists: {query}")
                            success_count += 1
                        else:
                            failure_count += 1
                            logger.error(f"Schema query failed: {query}: {e}")

                logger.info(
                    f"Schema setup complete: {success_count} successful, "
                    f"{failure_count} failed, of {len(all_queries)}")

                if failure_count > len(all_queries) / 2:
                    raise Exception(f"Too many schema failures ({failure_count}/{len(all_queries)})")

        except Exception as e:
            logger.error(f"Schema creation failed: {e}")
            raise

    async def create_entity_node(self, entity: ProvenanceEvent, tenant_id: str, session, fetch: bool = True) -> str:
        query = """
        MERGE (e:Entity {id: $entity_id, tenant_id: $tenant_id})
        ON CREATE SET
            e.type = $entity_type,
            e.created_at = $timestamp,
            e.hash = $hash,
            e.size = $size,
            e.ip = $ip,
            e.access_count = 1,
            e.access_timestamps = [$timestamp]
        ON MATCH SET
            e.last_updated = $timestamp,
            e.access_count = coalesce(e.access_count, 1) + 1,
            e.access_timestamps = (coalesce(e.access_timestamps, []) + [$timestamp])[-$recent..],
            e.ip = $ip,
            e += $metadata
        RETURN e.id as entity_id
        """

        flattened_metadata = _flatten_metadata(entity.entity.metadata, "metadata")

        params = {
            "entity_id": entity.entity.id,
            "tenant_id": tenant_id,
            "entity_type": entity.entity.type,
            "timestamp": entity.timestamp,
            "hash": entity.entity.hash,
            "size": entity.entity.size,
            "ip": entity.entity.ip,
            "metadata": flattened_metadata,
            "recent": RECENT_TIMESTAMPS,
        }

        # fetch=False pipelines the statement; a failure is still reported at commit.
        result = await session.run(query, params)
        if not fetch:
            return None
        record = await result.single()
        return record["entity_id"] if record else None

    async def create_agent_node(self, event: ProvenanceEvent, tenant_id: str, session, fetch: bool = True) -> str:
        query = """
        MERGE (a:Agent {id: $agent_id, tenant_id: $tenant_id})
        ON CREATE SET
            a.type = $agent_type,
            a.created_at = $timestamp,
            a.ip = $ip,
            a.user_agent = $user_agent,
            a.activity_count = 1,
            a.activity_timestamps = [$timestamp]
        ON MATCH SET
            a.last_seen = $timestamp,
            a.activity_count = coalesce(a.activity_count, 1) + 1,
            a.activity_timestamps = (coalesce(a.activity_timestamps, []) + [$timestamp])[-$recent..],
            a += $metadata
        RETURN a.id as agent_id
        """

        flattened_metadata = _flatten_metadata(event.agent.metadata, "metadata")

        params = {
            "agent_id": event.agent.id,
            "tenant_id": tenant_id,
            "agent_type": event.agent.type,
            "timestamp": event.timestamp,
            "ip": event.agent.ip,
            "user_agent": event.agent.user_agent or 'unknown',
            "metadata": flattened_metadata,
            "recent": RECENT_TIMESTAMPS,
        }

        result = await session.run(query, params)
        if not fetch:
            return None
        record = await result.single()
        return record["agent_id"] if record else None

    async def create_activity_node(self, event: ProvenanceEvent, session, fetch: bool = True) -> str:
        query = """
        CREATE (act:Activity {
            id: $event_id,
            tenant_id: $tenant_id,
            timestamp: $timestamp,
            source: $source,
            event_type: $event_type,
            operation: $operation,
            resource: $resource,
            duration_ms: $duration_ms,
            status_code: $status_code,
            provenance_hash: $provenance_hash,
            chain_position: $chain_position,
            correlation_id: $correlation_id,
            parent_event_id: $parent_event_id
        })
        SET act += $activity_metadata
        RETURN act.id as activity_id
        """

        flattened_activity_metadata = _flatten_metadata(event.activity.metadata, "activity")

        params = {
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "timestamp": event.timestamp,
            "source": event.source.value,
            "event_type": event.event_type.value,
            "operation": event.activity.operation.value,
            "resource": event.activity.resource,
            "duration_ms": event.activity.duration_ms,
            "status_code": event.activity.status_code,
            "provenance_hash": event.provenance_hash,
            "chain_position": event.chain_position,
            "correlation_id": event.correlation_id,
            "parent_event_id": event.parent_event_id,
            "activity_metadata": flattened_activity_metadata
        }

        result = await session.run(query, params)
        if not fetch:
            return None
        record = await result.single()
        return record["activity_id"] if record else None

    async def create_relationships(self, event: ProvenanceEvent, session) -> None:
        main_query = """
        MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
        MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})
        MATCH (act:Activity {id: $event_id, tenant_id: $tenant_id})

        CREATE (a)-[:PERFORMED {
            timestamp: $timestamp,
            operation: $operation,
            event_id: $event_id,
            source: $source
        }]->(act)

        CREATE (act)-[:AFFECTED {
            timestamp: $timestamp,
            operation: $operation,
            event_type: $event_type,
            duration_ms: $duration_ms,
            status_code: $status_code
        }]->(e)

        CREATE (a)-[:ACTED_ON {
            timestamp: $timestamp,
            operation: $operation,
            event_type: $event_type,
            event_id: $event_id,
            source: $source
        }]->(e)
        """

        main_params = {
            "agent_id": event.agent.id,
            "entity_id": event.entity.id,
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "timestamp": event.timestamp,
            "operation": event.activity.operation.value,
            "event_type": event.event_type.value,
            "source": event.source.value,
            "duration_ms": event.activity.duration_ms,
            "status_code": event.activity.status_code
        }

        await session.run(main_query, main_params)

        specific_relationship_query = self._get_specific_relationship_query(event)
        if specific_relationship_query:
            await session.run(specific_relationship_query, main_params)

        if event.agent.ip:
            await self._create_ip_relationships(event, session)

    async def _create_ip_relationships(self, event: ProvenanceEvent, session):
        ip_address = event.agent.ip
        ip_query = """
        MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
        MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})

        MERGE (ip:IP {address: $ip_address, tenant_id: $tenant_id})
        ON CREATE SET
            ip.first_seen = $timestamp,
            ip.created_at = $timestamp,
            ip.is_internal = $is_internal,
            ip.access_timestamps = [$timestamp],
            ip.access_count = 1
        ON MATCH SET
            ip.last_seen = $timestamp,
            ip.access_count = coalesce(ip.access_count, 1) + 1,
            ip.access_timestamps = (coalesce(ip.access_timestamps, []) + [$timestamp])[-$recent..]

        MERGE (a)-[af:ACCESSED_FROM]->(ip)
        ON CREATE SET
            af.timestamp = $timestamp,
            af.operation = $operation,
            af.event_id = $event_id,
            af.user_agent = $user_agent
        ON MATCH SET
            af.last_timestamp = $timestamp

        MERGE (ip)-[acc:ACCESSED]->(e)
        ON CREATE SET
            acc.timestamp = $timestamp,
            acc.operation = $operation,
            acc.event_id = $event_id,
            acc.source = $source,
            acc.user_agent = $user_agent
        ON MATCH SET
            acc.last_timestamp = $timestamp,
            acc.access_count = coalesce(acc.access_count, 0) + 1
        """

        is_internal = ip_address.startswith(('192.168.', '10.', '172.16.', '127.'))

        ip_params = {
            "agent_id": event.agent.id,
            "entity_id": event.entity.id,
            "event_id": event.event_id,
            "tenant_id": event.tenant_id,
            "timestamp": event.timestamp,
            "operation": event.activity.operation.value,
            "ip_address": ip_address,
            "is_internal": is_internal,
            "user_agent": event.agent.user_agent or 'unknown',
            "source": event.source.value,
            "recent": RECENT_TIMESTAMPS,
        }

        await session.run(ip_query, ip_params)

    def _get_specific_relationship_query(self, event: ProvenanceEvent) -> Optional[str]:
        """The extra relationship (ACCESSED, MODIFIED, CREATED, DELETED) for the event's type and
        operation, or None."""
        operation = event.activity.operation
        event_type = event.event_type

        if event_type == "access" and operation in ["GET", "READ"]:
            return """
            MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
            MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})
            CREATE (a)-[:ACCESSED {
                timestamp: $timestamp,
                operation: $operation,
                event_id: $event_id,
                read_only: true
            }]->(e)
            """

        elif event_type == "modify" and operation in ["PUT", "POST", "PATCH"]:
            return """
            MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
            MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})
            CREATE (a)-[:MODIFIED {
                timestamp: $timestamp,
                operation: $operation,
                event_id: $event_id,
                modification_type: $operation
            }]->(e)
            """

        elif event_type == "create" and operation in ["POST", "PUT"]:
            return """
            MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
            MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})
            CREATE (a)-[:CREATED {
                timestamp: $timestamp,
                operation: $operation,
                event_id: $event_id,
                creator: $agent_id
            }]->(e)
            """

        elif event_type == "delete" and operation == "DELETE":
            return """
            MATCH (a:Agent {id: $agent_id, tenant_id: $tenant_id})
            MATCH (e:Entity {id: $entity_id, tenant_id: $tenant_id})
            CREATE (a)-[:DELETED {
                timestamp: $timestamp,
                operation: $operation,
                event_id: $event_id,
                deleted_by: $agent_id
            }]->(e)
            """

        return None

    async def process_provenance_event(self, event: ProvenanceEvent, accounted: bool = False) -> None:
        """Write one event's nodes and relationships in one transaction, then (plain pipeline) append
        it to the tenant's log.

        accounted: the graph write only; the consumer appends the log record. An Activity already
        stored under the id with other content has no record behind it: it is left alone and
        reported (INTEGRITY ALARM [graph-planted]).
        """
        _t0 = time.perf_counter() if _GRAPH_TIMING else 0.0
        # graph_write_enabled=false: the plain pipeline without the graph (the log append only).
        write_nodes = accounted or settings.graph_write_enabled
        try:
            if write_nodes and self._node_batcher is not None and self._node_batcher._max_batch() > 1:
                await self._node_batcher.submit(event)
            elif write_nodes:
                failed = await self._write_nodes_tx([event]) or {}
                if 0 in failed:
                    raise failed[0]
            _t1 = time.perf_counter() if _GRAPH_TIMING else 0.0
        except Exception as e:
            from database.activity_identity import EventIdCollision
            if accounted and isinstance(e, EventIdCollision):
                logger.error(f"INTEGRITY ALARM [graph-planted]: tenant {event.tenant_id!r} event "
                             f"{event.event_id!r}: an Activity with this id and other content is in "
                             f"the graph but not in the log; the event is recorded, the Activity is "
                             f"left for the evidence audit")
                return
            logger.error(f"Failed to write nodes for event {event.event_id}: {e}")
            raise

        if accounted:
            return
        try:
            if settings.merkle_tree_enabled:
                # The same leaf data the API signed in its acknowledgement (crypto/leaf_format.py).
                from crypto.leaf_format import leaf_event_data
                event_data = leaf_event_data(event)
                # A failed append fails the event, and the consumer redelivers it.
                await self._build_entity_merkle_tree_async(event.tenant_id, event_data)
            else:
                logger.debug(f"Merkle tree disabled: no log append for event {event.event_id}")

            if _GRAPH_TIMING:
                _GraphStats.n += 1
                _GraphStats.nodes_ms += (_t1 - _t0) * 1000.0
                _GraphStats.merkle_ms += (time.perf_counter() - _t1) * 1000.0
                if _GraphStats.n % 100 == 0:
                    n = _GraphStats.n
                    logger.warning("GRAPHSPLIT n=%d nodes_tx=%.0fms merkle_wait=%.0fms"
                                   % (n, _GraphStats.nodes_ms / n, _GraphStats.merkle_ms / n))

            logger.debug(f"Processed provenance activity: {event.event_id}")

        except Exception as e:
            logger.error(f"Failed to process provenance event {event.event_id}: {e}")
            raise

    async def _write_nodes_tx(self, events: List[ProvenanceEvent]) -> Dict[int, Exception]:
        """Entity, agent, activity and relationships for a group of events, in one transaction.

        Returns {index: exception} for the events that failed on their own (an event_id already
        recorded with different content); those are not written, the rest are. A failure of the
        transaction itself is raised.
        """
        if not events:
            return {}
        # Idempotent under redelivery: an Activity that exists with the same content is skipped (the
        # caller still runs the append); a known id with different content fails that event alone.
        from database.activity_identity import plan_group
        async with self.driver.session() as session:
            tx = await begin_tx(session)
            try:
                result = await tx.run(
                    "MATCH (act:Activity) WHERE act.id IN $ids "
                    "RETURN act.id AS id, act.tenant_id AS tenant_id, act.operation AS operation, "
                    "act.resource AS resource, toString(act.timestamp) AS timestamp",
                    {"ids": list({e.event_id for e in events})},
                )
                existing = {r["id"]: dict(r) for r in await result.data()}
                write, failed = plan_group(
                    [(e.event_id, e.tenant_id, e.activity.operation, e.activity.resource, e.timestamp)
                     for e in events],
                    existing)
                events = [events[i] for i in write]
                if not events:
                    await tx.rollback()
                    return failed
                grouped = len(events) > 1
                _a = time.perf_counter()
                for event in events:
                    await self.create_entity_node(event, event.tenant_id,
                                                  session=tx, fetch=not grouped)
                _b = time.perf_counter()
                for event in events:
                    await self.create_agent_node(event, event.tenant_id,
                                                 session=tx, fetch=not grouped)
                _c = time.perf_counter()
                for event in events:
                    await self.create_activity_node(event, session=tx,
                                                    fetch=not grouped)
                _d = time.perf_counter()
                for event in events:
                    await self.create_relationships(event, session=tx)
                _e = time.perf_counter()
                await tx.commit()
                if _GRAPH_TIMING:
                    k = len(events)
                    _GraphStats.tx_n += 1
                    _GraphStats.events += k
                    _GraphStats.ent += (_b - _a) * 1000
                    _GraphStats.agt += (_c - _b) * 1000
                    _GraphStats.act += (_d - _c) * 1000
                    _GraphStats.rel += (_e - _d) * 1000
                    _GraphStats.cmt += (time.perf_counter() - _e) * 1000
                    if _GraphStats.tx_n % 50 == 0:
                        m = _GraphStats.tx_n
                        logger.warning(
                            "NODESPLIT tx=%d avg_group=%.1f entity=%.0f agent=%.0f "
                            "activity=%.0f rels=%.0f commit=%.0f => %.1f ev/s/tx"
                            % (m, _GraphStats.events / m, _GraphStats.ent / m,
                               _GraphStats.agt / m, _GraphStats.act / m,
                               _GraphStats.rel / m, _GraphStats.cmt / m,
                               1000.0 * _GraphStats.events
                               / max(1e-9, _GraphStats.ent + _GraphStats.agt
                                     + _GraphStats.act + _GraphStats.rel
                                     + _GraphStats.cmt)))
                return failed
            except Exception:
                try:
                    await tx.rollback()
                except Exception:
                    pass
                raise

    async def find_event_records(self, tenant_id: str, event_id: str, limit: int = 16) -> List[Tuple[int, Dict[str, Any]]]:
        """Accounting records of the tenant's log stored under this event id, as (seq, record), in
        seq order, for decide.EventIdIndex (which does not trust the answer). Graph nodes are never
        consulted."""
        async with self.driver.session() as session:
            result = await session.run(
                "MATCH (n:MerkleNode {tree_id: $tree_id, event_id: $event_id}) "
                "WHERE n.leaf_index IS NOT NULL "
                "RETURN n.leaf_index AS seq, n.data AS data ORDER BY seq LIMIT $limit",
                {"tree_id": f"global_persistent_{tenant_id}", "event_id": event_id,
                 "limit": int(limit)})
            rows = await result.data()
        out: List[Tuple[int, Dict[str, Any]]] = []
        for r in rows:
            try:
                out.append((int(r["seq"]), _stored_record(r.get("data"))))
            except Exception:
                continue
        return out

    async def find_event_records_many(self, keys, limit: int = 16) -> Dict[Tuple[str, str], List[Tuple[int, Dict[str, Any]]]]:
        """find_event_records for many (tenant_id, event_id) keys in one query; a key with no
        record maps to []."""
        keys = list(dict.fromkeys((str(t), str(e)) for t, e in keys))
        out: Dict[Tuple[str, str], List[Tuple[int, Dict[str, Any]]]] = {k: [] for k in keys}
        if not keys:
            return out
        q = [{"tree_id": f"global_persistent_{t}", "tenant": t, "eid": e} for t, e in keys]
        async with self.driver.session() as session:
            result = await session.run(
                # The explicit predicates and the hint keep the planner on merkle_leaf_event_idx;
                # the map-pattern form under UNWIND is planned as a label scan.
                "UNWIND $q AS q "
                "MATCH (n:MerkleNode) USING INDEX n:MerkleNode(tree_id, event_id) "
                "WHERE n.tree_id = q.tree_id AND n.event_id = q.eid AND n.leaf_index IS NOT NULL "
                "RETURN q.tenant AS tenant, q.eid AS eid, n.leaf_index AS seq, n.data AS data "
                "ORDER BY tenant, eid, seq",
                {"q": q})
            rows = await result.data()
        for r in rows:
            lst = out.setdefault((r["tenant"], r["eid"]), [])
            if len(lst) >= int(limit):
                continue
            try:
                lst.append((int(r["seq"]), _stored_record(r.get("data"))))
            except Exception:
                continue
        return out

    async def _build_entity_merkle_tree_async(self, tenant_id: str, event_data: Dict[str, Any]):
        """Append the event to the tenant's log. With merkle_append_batch_b > 1 the storage's
        per-tenant batcher is the single writer, and holding the lock would make every batch one
        event, so it is taken only on the unbatched path."""
        if max(1, int(settings.merkle_append_batch_b)) > 1:
            return await self._build_entity_merkle_tree_locked(tenant_id, event_data)
        lock = self._append_locks.setdefault(tenant_id, asyncio.Lock())
        async with lock:
            return await self._build_entity_merkle_tree_locked(tenant_id, event_data)

    async def _build_entity_merkle_tree_locked(self, tenant_id: str, event_data: Dict[str, Any]):
        """Append one event to the tenant's log. Raises if the append did not happen."""
        success = await merkle_tree_storage.add_event_to_persistent_tree(tenant_id, event_data)
        if not success:
            raise RuntimeError(f"log append failed for tenant {tenant_id}")

    async def health_check(self) -> bool:
        try:
            async with self.driver.session() as session:
                result = await session.run("RETURN 1 as health")
                record = await result.single()
                return record is not None and record["health"] == 1
        except Exception as e:
            logger.error(f"Graph database health check failed: {e}")
            return False

graph_db = GraphDatabaseManager()
