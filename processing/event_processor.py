import asyncio
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaError
from aiokafka.structs import TopicPartition

from config import settings
from crypto import records as R
from crypto.anchor_store import segment_key
from crypto.merkle_tree_storage import ACCT_TIMING, AnchorTamper, FencedWriter, PositionConflict
from database.graph_db import graph_db
from processing import sources
from processing.custody import CoverageMismatch, CoverageTracker, plan_commits_caa, verify_redelivery
from processing.decide import (Decision, EventIdIndex, decide, decode_and_authenticate, gap_decision,
                               log_tenant, resolve_ref)
from processing.delivery import (plan_offsets, is_permanent_event_error, identity_key,
                                 should_dead_letter, outage_suspected, is_outage_error,
                                 decode_record, UndecodableRecord)
from processing.sources import SourceContractMismatch
from schemas import ProvenanceEvent

logger = logging.getLogger(__name__)

# STAGE_TIMING=1 logs per-stage wall times of the ingest path.
_STAGE_TIMING = os.getenv("STAGE_TIMING", "").strip().lower() in ("1", "true", "yes", "on")

# A failed stop-marker write is retried at a later stall of the same position, at most this often.
_STOP_RETRY_S = 10.0
# Timing alarms remembered per process, so each is logged once.
_TIME_ALARMS_KEPT = 100_000

@dataclass
class ProcessingMetrics:
    events_processed: int = 0
    events_failed: int = 0
    processing_time_ms: float = 0.0
    last_processed_timestamp: Optional[datetime] = None

class EventProcessor:
    """One Kafka consumer of the provenance topic."""

    # STAGE_TIMING counters, shared by every processor in the process.
    _inflight = 0
    _inflight_max = 0
    _stage_n = 0
    _stage_graph_ms = 0.0

    def __init__(self):
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.producer: Optional[AIOKafkaProducer] = None
        self.is_running = False
        self.metrics = ProcessingMetrics()
        self.batch_size = settings.max_events_per_batch
        self.kafka_available = False
        self._acct: Optional["_AcctState"] = None
        self._poll_s = self._pause_s = 0.0          # STAGE_TIMING: the last poll and pause

        # Recently processed event identities (bounded, oldest evicted first): Kafka redelivers
        # and collectors re-read overlapping windows.
        self._seen_keys: "OrderedDict[str, None]" = OrderedDict()
        self._seen_max = settings.processor_dedup_window
        self.metrics_duplicates = 0
        self.metrics_dead_lettered = 0
        self.metrics_graph_skipped = 0   # accounted events whose graph write failed, backend up
        self._redeliveries = {}   # (partition, offset) -> deliveries, for the poison guard

    async def initialize(self):
        self.kafka_available = False
        accounted = settings.acct_mode
        try:
            # max_poll_interval_ms bounds the processing of one batch (graph write, log append,
            # anchor); a short one makes the group rebalance in a loop. 'earliest': a partition
            # with no committed offset holds acknowledged events from its first record.
            self.consumer = AIOKafkaConsumer(
                *([] if accounted else [settings.kafka_provenance_topic]),
                bootstrap_servers=settings.kafka_bootstrap_servers,
                group_id=settings.kafka_consumer_group,
                auto_offset_reset='earliest',
                enable_auto_commit=False,
                consumer_timeout_ms=1000,
                max_poll_records=self.batch_size,
                session_timeout_ms=int(os.getenv("KAFKA_SESSION_TIMEOUT_MS", "45000")),
                heartbeat_interval_ms=int(os.getenv("KAFKA_HEARTBEAT_MS", "3000")),
                max_poll_interval_ms=int(os.getenv("KAFKA_MAX_POLL_INTERVAL_MS", "600000")),
            )
            if accounted:
                # A partition's new owner resets its tenants' tails from the store before
                # appending; the listener tells it which partitions are new.
                from aiokafka.abc import ConsumerRebalanceListener

                proc = self

                class _Listener(ConsumerRebalanceListener):
                    async def on_partitions_revoked(self, revoked):
                        proc._acct_partitions_revoked(revoked)

                    async def on_partitions_assigned(self, assigned):
                        proc._acct_partitions_changed(assigned)

                self.consumer.subscribe([settings.kafka_provenance_topic], listener=_Listener())

            # Producer for downstream events
            self.producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                compression_type="gzip",
                acks='all'
            )

            await self.consumer.start()
            await self.producer.start()
            if accounted:
                try:
                    await self._acct_check_source()
                except SourceContractMismatch:
                    raise
                except Exception as check_error:
                    # The check could not run; the running consumer repeats it every
                    # acct_partition_check_s.
                    logger.warning(f"Source check at start failed: {type(check_error).__name__}: "
                                   f"{check_error}")

            self.kafka_available = True
            logger.info("Event processor with Kafka initialized")

        except SourceContractMismatch:
            raise
        except Exception as kafka_error:
            if accounted:
                # Accounted mode has no file mode: an acknowledged event stays in the broker
                # until the store holds it.
                raise RuntimeError(f"accounted mode requires its broker (kafka): "
                                   f"{kafka_error}") from kafka_error
            logger.warning(f"Kafka not available: {kafka_error}")
            logger.info("Event processor will run in file-based mode")
            self.consumer = None
            self.producer = None
            self.kafka_available = False

        logger.info("Event processor initialized")

    async def close(self):
        self.is_running = False

        if self.consumer:
            await self.consumer.stop()

        if self.producer:
            await self.producer.stop()

        logger.info("Event processor closed")

    async def start_processing(self):
        self.is_running = True

        if self.kafka_available:
            logger.info("Starting event processing loop (Kafka mode)")
            await self._start_kafka_processing()
        else:
            logger.info("Starting event processing loop (file-based mode)")
            await self._start_file_processing()

    async def _start_kafka_processing(self):
        try:
            while self.is_running:
                try:
                    t_poll = time.perf_counter()
                    events_batch = await self._consume_events_batch()
                    self._poll_s = time.perf_counter() - t_poll

                    if events_batch:
                        await self._process_events_batch(events_batch)
                        if len(events_batch) >= self.batch_size:
                            self._pause_s = 0.0
                            continue    # a full poll: more is waiting
                        pause = float(settings.processor_partial_poll_pause_s)
                    else:
                        await self.acct_tick()
                        pause = 0.1

                    self._pause_s = pause
                    if pause > 0:
                        await asyncio.sleep(pause)

                except Exception as e:
                    logger.error(f"Error in Kafka processing loop: {e}")
                    await asyncio.sleep(5)

        except asyncio.CancelledError:
            logger.info("Kafka event processing cancelled")
        except Exception as e:
            logger.error(f"Fatal error in Kafka event processing: {e}")
            raise

    async def _start_file_processing(self):
        try:
            while self.is_running:
                try:
                    events_batch = await self._consume_file_events()

                    if events_batch:
                        await self._process_events_batch(events_batch)

                    await asyncio.sleep(1.0)

                except Exception as e:
                    logger.error(f"Error in file processing loop: {e}")
                    await asyncio.sleep(5)

        except asyncio.CancelledError:
            logger.info("File event processing cancelled")
        except Exception as e:
            logger.error(f"Fatal error in file event processing: {e}")
            raise

    async def _consume_events_batch(self) -> List[Dict[str, Any]]:
        try:
            events = []
            msg_pack = await self.consumer.getmany(timeout_ms=1000, max_records=self.batch_size)

            accounted = settings.acct_mode
            for messages in msg_pack.values():
                for message in messages:
                    item = {
                        'offset': message.offset,
                        'partition': message.partition,
                        'timestamp': message.timestamp,
                    }
                    if accounted:
                        # Accounted mode decides from the bytes as fetched (processing/decide.py).
                        item['topic'] = message.topic
                        item['raw'] = message.value
                        # 1 = LogAppendTime (the broker's clock), 0 = CreateTime (the producer's)
                        item['timestamp_type'] = message.timestamp_type
                        events.append(item)
                        continue
                    # An undecodable record is dead-lettered on its own, not with the whole poll.
                    try:
                        item['data'] = decode_record(message.value)
                    except UndecodableRecord as e:
                        item['data'] = None
                        item['decode_error'] = e
                        item['raw'] = message.value
                    events.append(item)

            return events

        except KafkaError as e:
            logger.error(f"Kafka consumer error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error consuming events: {e}")
            return []

    async def _consume_file_events(self) -> List[Dict[str, Any]]:
        """Events from retry_queue/event_*.json, for the file-based mode."""
        try:
            events = []
            retry_dir = "retry_queue"

            if not os.path.exists(retry_dir):
                return events

            files = os.listdir(retry_dir)[:self.batch_size]

            for filename in files:
                if filename.startswith('event_') and filename.endswith('.json'):
                    file_path = os.path.join(retry_dir, filename)
                    try:
                        with open(file_path, 'r') as f:
                            event_data = json.load(f)

                        events.append({
                            'data': event_data,
                            'offset': 0,
                            'partition': 0,
                            'timestamp': int(datetime.utcnow().timestamp() * 1000)
                        })

                        os.remove(file_path)

                    except Exception as e:
                        logger.error(f"Failed to process file {filename}: {e}")
                        os.makedirs("retry_queue/errors", exist_ok=True)
                        os.rename(file_path, f"retry_queue/errors/{filename}")

            if events:
                logger.debug(f"Consumed {len(events)} events from file queue")

            return events

        except Exception as e:
            logger.error(f"Error consuming file events: {e}")
            return []

    async def _process_events_batch(self, events_batch: List[Dict[str, Any]]):
        if settings.acct_mode and self.kafka_available:
            return await self._process_batch_accounted(events_batch)
        return await self._process_events_batch_v1(events_batch)

    async def _process_events_batch_v1(self, events_batch: List[Dict[str, Any]]):
        """Process a batch at least once: never commit past an event that was not processed.

        Failed events are retried in place. A partition is committed only up to its first event
        that still fails, and the consumer is rewound there; processing is idempotent. A malformed
        event, or one that failed more than processor_max_redeliveries times while the backend was
        up, is dead-lettered so that it cannot stall its partition.
        """
        if not events_batch:
            return

        start_time = datetime.utcnow()
        batch_size = len(events_batch)
        semaphore = asyncio.Semaphore(settings.processor_max_concurrent_events)

        async def process_with_semaphore(event_msg):
            async with semaphore:
                return await self._process_single_event(event_msg['data'])

        retries = max(0, int(settings.processor_event_retries))
        errors: Dict[int, BaseException] = {}
        dead: List[int] = []
        # Records that did not decode are dead-lettered and committed past.
        for i, msg in enumerate(events_batch):
            if msg.get('decode_error') is not None:
                errors[i] = msg['decode_error']
                dead.append(i)
        unprocessed = [i for i in range(batch_size) if i not in errors]

        def failed(i, result) -> bool:
            if not isinstance(result, BaseException):
                errors.pop(i, None)
                return False
            errors[i] = result
            if is_permanent_event_error(result):
                dead.append(i)
                return False
            return True
        try:
            unprocessed = await _retry_in_place(
                unprocessed, lambda i: process_with_semaphore(events_batch[i]), retries, failed)
        except Exception as e:
            logger.error(f"Critical failure processing batch of {batch_size} activities: {e}")
            unprocessed = [i for i in range(batch_size) if i not in dead]

        # Poison guard: a record delivered too many times is dead-lettered instead of blocking.
        # Deliveries count only while the backend is up, so an outage is waited out.
        max_redeliveries = max(1, int(settings.processor_max_redeliveries))
        backend_up = True
        if outage_suspected(batch_size, len(unprocessed), len(dead)):
            backend_up = await self._backend_healthy()
            if not backend_up:
                logger.warning(f"Backend unreachable: {len(unprocessed)} events left for redelivery, "
                               f"not counted against the poison guard")
        for i in list(unprocessed):
            key = (events_batch[i].get('partition'), events_batch[i].get('offset'))
            # A failure whose error says the backend was unreachable never counts, whatever the
            # health check says now.
            counts = backend_up and not is_outage_error(errors.get(i))
            if should_dead_letter(self._redeliveries, key, counts, max_redeliveries):
                unprocessed.remove(i)
                dead.append(i)
        for i in dead:
            self._dead_letter(events_batch[i], errors.get(i))

        successful = batch_size - len(unprocessed) - len(dead)
        self.metrics.events_processed += successful
        self.metrics.events_failed += len(unprocessed) + len(dead)

        if self.kafka_available and self.consumer:
            commits, seeks = plan_offsets(events_batch, unprocessed)
            topic = settings.kafka_provenance_topic
            if commits:
                try:
                    await self.consumer.commit(
                        {TopicPartition(topic, p): off for p, off in commits.items()})
                except Exception as commit_error:
                    # Not fatal: an uncommitted offset only means redelivery, which is idempotent.
                    logger.error(f"Failed to commit Kafka offsets: {commit_error}")
            for p, off in seeks.items():
                try:
                    self.consumer.seek(TopicPartition(topic, p), off)
                except Exception as seek_error:
                    # The partition was revoked by a rebalance. Its new owner resumes from the
                    # committed offset, which never passed this event.
                    logger.warning(f"Could not rewind partition {p} to offset {off}: {seek_error}")
            if commits:
                done = [k for k in self._redeliveries
                        if k[0] in commits and k[1] is not None and k[1] < commits[k[0]]]
                for k in done:
                    del self._redeliveries[k]
            if unprocessed:
                first = unprocessed[0]
                logger.warning(
                    f"{len(unprocessed)} of {batch_size} events not processed after {retries} "
                    f"retries; rewound partitions {sorted(seeks)} for redelivery. First error: "
                    f"{type(errors.get(first)).__name__}: {errors.get(first)}")
        elif unprocessed:
            await self._handle_failed_events([
                {'event': events_batch[i], 'error': str(errors.get(i)),
                 'error_type': type(errors.get(i)).__name__} for i in unprocessed])

        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        self.metrics.processing_time_ms = processing_time
        self.metrics.last_processed_timestamp = datetime.utcnow()
        if unprocessed or dead:
            logger.warning(f"Batch processed: {successful}/{batch_size} successful, "
                           f"{len(unprocessed)} left for redelivery, {len(dead)} dead-lettered, "
                           f"{processing_time:.2f}ms")
        else:
            logger.debug(f"Batch processed: {successful} successful, {processing_time:.2f}ms")

    async def _backend_healthy(self) -> bool:
        """The graph database answers and, in accounted mode, so does the write-once store."""
        try:
            if not await graph_db.health_check():
                return False
        except Exception:
            return False
        if settings.acct_mode:
            try:
                _, store, _ = self._acct_state().resolve()
                if store is not None:
                    await asyncio.to_thread(store.get_object, "health/probe")
            except Exception:
                return False
        return True

    def _dead_letter(self, event_msg: Dict[str, Any], error) -> None:
        """Count, log and append to retry_queue/dead_letter.jsonl an event that will not be
        processed. Nothing replays that file automatically."""
        self.metrics_dead_lettered += 1
        logger.error(f"Dead-lettering event at partition {event_msg.get('partition')} offset "
                     f"{event_msg.get('offset')}: {type(error).__name__ if error else ''}: {error}")
        try:
            os.makedirs("retry_queue", exist_ok=True)
            with open("retry_queue/dead_letter.jsonl", "a") as f:
                f.write(json.dumps({"event": event_msg, "error": str(error),
                                    "at": datetime.utcnow().isoformat()}, default=str) + "\n")
        except Exception as file_error:
            logger.error(f"Could not write dead letter: {file_error}")

    async def _handle_failed_events(self, failed_events: List[Dict[str, Any]]):
        """Write events that failed in file-based mode to the retry queue."""
        try:
            os.makedirs("retry_queue", exist_ok=True)

            for failed_event in failed_events:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
                filename = f"retry_queue/event_failed_{timestamp}.json"

                retry_data = {
                    'event': failed_event['event'],
                    'error': failed_event['error'],
                    'failed_at': datetime.utcnow().isoformat(),
                    'retry_count': 0,
                    'max_retries': 3
                }

                try:
                    with open(filename, 'w') as f:
                        json.dump(retry_data, f, indent=2)
                except Exception as file_error:
                    logger.error(f"Failed to save failed event to retry queue: {file_error}")

            logger.info(f"Saved {len(failed_events)} failed events to retry queue")

        except Exception as e:
            logger.error(f"Failed to handle failed events: {e}")

    @staticmethod
    def _identity_key(event_data: Dict[str, Any]) -> str:
        return identity_key(event_data)

    def _already_seen(self, event_data: Dict[str, Any]) -> bool:
        key = self._identity_key(event_data)
        if key in self._seen_keys:
            self._seen_keys.move_to_end(key)
            return True
        return False

    def _mark_seen(self, event_data: Dict[str, Any]) -> None:
        """Record an event as processed; called only after processing succeeded."""
        key = self._identity_key(event_data)
        self._seen_keys[key] = None
        self._seen_keys.move_to_end(key)
        while len(self._seen_keys) > self._seen_max:
            self._seen_keys.popitem(last=False)

    async def _process_single_event(self, event_data: Dict[str, Any]):
        try:
            # Redelivered records stop here, whichever path they came in by.
            if self._already_seen(event_data):
                self.metrics_duplicates += 1
                logger.debug(f"Duplicate event suppressed: {self._identity_key(event_data)}")
                return
            event = ProvenanceEvent(**event_data)
            if not settings.provenance_tracking_enabled:
                return
            if _STAGE_TIMING:
                await self._timed_graph_update(event)
            else:
                await self._handle_graph_update(event)
            logger.debug(f"Processed activity: {event.event_id}")
            self._mark_seen(event_data)
        except Exception as e:
            logger.error(f"Failed to process activity: {e}")
            raise

    async def _timed_graph_update(self, event: ProvenanceEvent) -> None:
        """_handle_graph_update under STAGE_TIMING: the mean graph time and the events in flight,
        logged every 50 events."""
        cls = EventProcessor
        cls._inflight += 1
        cls._inflight_max = max(cls._inflight_max, cls._inflight)
        t0 = time.time()
        try:
            await self._handle_graph_update(event)
        finally:
            cls._inflight -= 1
            cls._stage_n += 1
            cls._stage_graph_ms += (time.time() - t0) * 1000.0
            if cls._stage_n % 50 == 0:
                n = cls._stage_n
                logger.warning(f"STAGE n={n} inflight_now={cls._inflight} "
                               f"inflight_max={cls._inflight_max} graph={cls._stage_graph_ms / n:.0f}ms")

    async def _handle_graph_update(self, event: ProvenanceEvent, accounted: bool = False):
        try:
            await graph_db.process_provenance_event(event, accounted=accounted)

            await self._send_downstream_event('graph_updated', {
                'event_id': event.event_id,
                'tenant_id': event.tenant_id,
                'entity_id': event.entity.id,
                'timestamp': event.timestamp.isoformat()
            })

        except Exception as e:
            logger.error(f"Failed to update graph for event {event.event_id}: {e}")
            raise

    async def _send_downstream_event(self, event_type: str, data: Dict[str, Any]):
        if not self.producer:
            logger.debug("Skipping downstream event: no Kafka producer")
            return

        try:
            downstream_event = {
                'type': event_type,
                'data': data,
                'timestamp': datetime.utcnow().isoformat(),
                'processor': 'event_processor'
            }

            topic = f"{settings.kafka_provenance_topic}_downstream"
            key = data.get('tenant_id', '')
            if key:
                key = key.encode('utf-8')

            await self.producer.send(
                topic,
                value=downstream_event,
                key=key
            )

        except Exception as e:
            logger.error(f"Failed to send downstream event: {type(e).__name__}: {e}")

    # Accounted mode. Every fetched position ends in exactly one accounting record in its
    # tenant's log (processing/decide.py); appends go per tenant, in offset order, only for the
    # processed prefix of each partition; a partition's offset is committed only past positions
    # whose record the store is verified to hold (commit-after-anchor, processing/custody.py).
    # Nothing is dead-lettered: what keeps failing while the backend is up becomes an
    # UNCHECKABLE verdict, counted against the published budget.

    def _acct_state(self) -> "_AcctState":
        if self._acct is None:
            self._acct = _AcctState()
        return self._acct

    def _acct_partitions_changed(self, tps) -> None:
        """A rebalance assigned these partitions: their tenants' tails are reset from the store
        before the next append, and their coverage starts afresh from the committed offset.

        aiokafka calls the listener from its coordinator task, so this can run between any two
        awaits of _process_batch_accounted; that batch sees the generation change."""
        st = self._acct_state()
        st.source_checked_at = 0.0          # a rebalance may follow a partition-count change
        for tp in tps or ():
            st.forget_partition(_tp_key(tp))

    def _acct_partitions_revoked(self, tps) -> None:
        """Forget these partitions, drop them from commit planning (a commit naming a partition
        the consumer does not own fails for the whole call), and release their tenants' tails."""
        st = self._acct_state()
        storage = st.storage
        if storage is None:
            from crypto.merkle_tree_storage import merkle_tree_storage as storage
        release = getattr(storage, "release_tenant", None)
        for tp in tps or ():
            key = _tp_key(tp)
            tenants = [t for t, x in st.tenant_tp.items() if x == key]
            st.forget_partition(key)
            st.known_tps.discard(key)
            for tenant in tenants:
                st.tenant_tp.pop(tenant, None)
                if release is not None:
                    try:
                        release(tenant)
                    except Exception as e:
                        logger.warning(f"Releasing tenant {tenant!r} of revoked {key}: {type(e).__name__}: {e}")

    def _acct_owned(self) -> Optional[set]:
        """The partitions the consumer holds now, as (topic, p); None when the source cannot say."""
        try:
            return {_tp_key(tp) for tp in self.consumer.assignment()}
        except Exception:
            return None

    def _acct_flags(self) -> Tuple[bool, bool]:
        """(verdicts, commit-after-anchor). Switching either off is a baseline; production refuses
        both unless acct_ablation_ok is set."""
        verdicts_on = bool(settings.acct_verdicts)
        caa = bool(settings.acct_caa)
        if (verdicts_on and caa) or bool(settings.acct_ablation_ok):
            return verdicts_on, caa
        if str(settings.environment).strip().lower() == "production":
            st = self._acct_state()
            if not st.ablation_refused:
                st.ablation_refused = True
                logger.error("INTEGRITY ALARM [config]: acct_verdicts/acct_caa ablations are refused in "
                             "production (set acct_ablation_ok to run one); running with both on")
            return True, True
        return verdicts_on, caa

    async def _acct_check_source(self) -> None:
        """Check the topic, its partitions and its settings against the signed contract. Raises
        SourceContractMismatch; without a verified contract only warns (the API then acknowledges
        nothing)."""
        st = self._acct_state()
        _, store, pubkey = st.resolve()
        contract = sources.load_contract(store, pubkey, str(settings.acct_deployment_id),
                                         int(settings.acct_contract_version))
        st.source_checked_at = time.time()
        st.contract = contract
        topic = settings.kafka_provenance_topic
        if contract is None:
            logger.warning("No verified contract in the store: the source is not checked")
        else:
            await sources.verify_source(self.consumer, contract, topic, settings)
        # The tenant-to-partition map a validly tagged record is held to (decide.misrouted).
        st.route = sources.route_for(self.consumer, contract, topic, settings)

    async def _graph_accounted(self, event: ProvenanceEvent) -> None:
        """The graph and side effects of one event. The log append is not here: it is made per
        tenant in offset order by _process_batch_accounted."""
        await self._handle_graph_update(event, accounted=True)

    async def _process_batch_accounted(self, events_batch: List[Dict[str, Any]]):
        """One fetched batch, accounted. An exception rewinds every partition of the batch to its
        first offset (or lower), so the records are delivered again and not seen as a gap."""
        seek_to: Dict[Any, int] = {}
        try:
            await self._process_batch_accounted_inner(events_batch, seek_to)
        except BaseException:
            self._acct_rewind(events_batch, seek_to)
            raise

    def _acct_rewind(self, events_batch, seek_to: Dict[Any, int]) -> None:
        first: Dict[Any, int] = {}
        for msg in events_batch or []:
            try:
                tp = (msg.get('topic') or settings.kafka_provenance_topic, int(msg['partition']))
                first[tp] = min(first.get(tp, int(msg['offset'])), int(msg['offset']))
            except Exception:
                continue
        targets = {tp: min(x for x in (first.get(tp), seek_to.get(tp)) if x is not None)
                   for tp in set(first) | set(seek_to)}
        self._acct_seek(self._acct_state(), targets)
        logger.error(f"Accounted batch failed; rewound {targets} for redelivery")

    def _acct_seek(self, st: "_AcctState", targets: Dict[Any, int]) -> None:
        """Rewind each partition to its target; the next fetch there is expected at that offset."""
        for tp, off in targets.items():
            st.expected[tp] = off
            try:
                self.consumer.seek(TopicPartition(tp[0], tp[1]), off)
            except Exception as seek_error:
                logger.warning(f"Could not rewind {tp[0]}/{tp[1]} to offset {off}: {seek_error}")

    async def _acct_rewind_to_committed(self, seek_to: Dict[Any, int], tp) -> None:
        committed = await self._acct_committed(tp)
        seek_to[tp] = min(seek_to.get(tp, committed), committed)

    async def _process_batch_accounted_inner(self, events_batch: List[Dict[str, Any]],
                                             seek_to: Dict[Any, int]):
        st = self._acct_state()
        if st.halted:
            # The source no longer matches the contract: nothing is appended or committed, and
            # the period statements show the stall.
            logger.error(f"Accounted batch not processed: {st.halted}")
            return
        storage, store, pubkey = st.resolve()
        verdicts_on, caa = self._acct_flags()
        batch = _AcctBatch(st, storage, store, pubkey, verdicts_on, seek_to)
        st.index.clear_pending()
        start_time = datetime.utcnow()
        timer = _StepTimer(self._pause_s, self._poll_s)

        # 1. Positions, decoding, broker gaps.
        self._acct_read_positions(batch, events_batch)
        timer.mark("decode")
        # The event-id lookups of the decisions below, asked of the database in one query.
        await st.prefetch_index([(r.log, r.d.event["event_id"]) for r in batch.records()
                                 if r.dec is None and r.d is not None and r.d.sub_valid
                                 and isinstance(r.d.event, dict)
                                 and isinstance(r.d.event.get("event_id"), str)])
        timer.mark("prefetch")

        # 2. Decisions, per partition in offset order (partitions concurrently).
        try:
            await asyncio.gather(*(self._acct_decide_partition(batch, tp, recs)
                                   for tp, recs in batch.by_tp.items()))
        finally:
            st.prefetched = {}                    # the answers belong to this batch only
        timer.mark("decide")

        # 3. Graph writes for event decisions.
        await self._acct_write_graph(batch)
        timer.mark("graph")

        # 4. The processed prefix of each partition, appended per tenant in offset order.
        groups = _prefix_groups(batch.by_tp)
        await asyncio.gather(*(self._acct_append_group(batch, tenant, tp, recs)
                               for (tenant, tp), recs in groups.items()))
        timer.mark("append_anchor")

        # 5. Poison accounting, 6. coverage, then the commit.
        await self._acct_count_failures(batch)
        stale_tps = await self._acct_note_coverage(batch)
        timer.mark("poison_coverage")
        await self._acct_refresh_and_commit(st, store, pubkey, caa, batch.by_tp, seek_to, stale_tps)
        timer.mark("commit")

        # 7. Rewind every partition to its first position without a record.
        for tp in stale_tps:
            await self._acct_rewind_to_committed(seek_to, tp)
        for tp, recs in batch.by_tp.items():
            first = next((r.pos.o for r in recs
                          if r.status in ("failed", "stalled", "later") and r.i is not None), None)
            if first is not None:
                seek_to[tp] = min(seek_to.get(tp, first), first)
        for tp in batch.by_tp:
            nxt = seek_to.get(tp, batch.next_o.get(tp))
            if nxt is not None:
                st.expected[tp] = nxt
        self._acct_seek(st, seek_to)

        n_total = sum(1 for r in batch.records() if r.i is not None)
        n_done = sum(1 for r in batch.records()
                     if r.i is not None and r.status in ("appended", "verified"))
        timer.mark("rewind")
        timer.log(n_total, n_done)
        self.metrics.events_processed += n_done
        self.metrics.events_failed += n_total - n_done
        self.metrics.processing_time_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        self.metrics.last_processed_timestamp = datetime.utcnow()
        if n_done < n_total:
            logger.warning(f"Accounted batch: {n_done}/{n_total} records accounted, the rest left "
                           f"for redelivery from {dict(seek_to)}")

    def _acct_read_positions(self, batch: "_AcctBatch", events_batch) -> None:
        """Group the batch per partition in offset order, decode each record and insert a GAP
        verdict where the broker skipped offsets."""
        st = batch.st
        for i, msg in enumerate(events_batch or []):
            topic = msg.get('topic') or settings.kafka_provenance_topic
            tp = (topic, int(msg['partition']))
            pos = R.Position(topic, tp[1], int(msg['offset']), int(msg.get('timestamp') or 0))
            batch.by_tp.setdefault(tp, []).append(_AcctRec(i, tp, pos, raw=msg.get('raw'),
                                                           tstype=msg.get('timestamp_type')))
        for tp, recs in batch.by_tp.items():
            batch.gen0[tp] = st.gen.get(tp, 0)
            recs.sort(key=lambda r: r.pos.o)
            out: List[_AcctRec] = []
            expected = st.expected.get(tp)
            for r in recs:
                if expected is not None and r.pos.o > expected and batch.verdicts:
                    if st.gap_probe.get(tp) != (expected, r.pos.o):
                        # Read again from `expected` before recording a gap: records lost on this
                        # side come back on a second read; a real gap does not.
                        st.gap_probe[tp] = (expected, r.pos.o)
                        logger.warning(f"{tp[0]}/{tp[1]}: offset {r.pos.o} arrived after {expected - 1}; "
                                       f"reading again from {expected} before recording a gap")
                        batch.seek_to[tp] = expected
                        break
                    st.gap_probe.pop(tp, None)
                    logger.error(f"INTEGRITY ALARM [gap]: {tp[0]}/{tp[1]} offsets [{expected}, {r.pos.o}) "
                                 f"were never delivered")
                    gap = _AcctRec(None, tp, R.Position(tp[0], tp[1], expected, r.pos.bt_ms))
                    gap.dec = gap_decision(r.pos, expected, r.pos.o, system_tenant=st.sys_log(tp))
                    gap.log = gap.dec.tenant_id
                    out.append(gap)
                elif expected is not None and r.pos.o == expected and tp in st.gap_probe:
                    st.gap_probe.pop(tp, None)            # read again, the offset is there
                if expected is None or r.pos.o >= expected:
                    expected = r.pos.o + 1
                r.d = decode_and_authenticate(r.raw, batch.pubkey, st.contract_hash)
                r.log = st.log_of(r.d, tp)
                st.check_times(r)
                out.append(r)
            batch.by_tp[tp] = out
            batch.next_o[tp] = expected
            st.known_tps.add(tp)
            for r in out:
                gap = (r.dec.template["verdict"].get("gap") or {}) if r.i is None and r.dec else {}
                st.tracker.note_fetched(tp, r.pos.o, r.log, upto=gap.get("to"))

    async def _acct_decide_partition(self, batch: "_AcctBatch", tp, recs: List["_AcctRec"]) -> None:
        """Decide one partition's records in offset order. A record whose decision cannot be made
        stops the partition: later ones are beyond the prefix."""
        st, storage, store, pubkey = batch.st, batch.storage, batch.store, batch.pubkey
        latest: Dict[str, Any] = {}               # tenant log -> its latest anchor
        stopped = False
        for r in recs:
            if stopped or batch.stale(tp):
                r.status = "later"
                continue
            try:
                await st.ensure_epoch(r.log, tp, storage)
                if r.log not in latest:
                    latest[r.log] = await storage.latest_anchor(r.log)
                last = latest[r.log].pos_last if latest[r.log] else None
                anchored = bool(last) and (last.get("topic"), int(last.get("p", -1))) == tp \
                    and r.pos.o <= int(last["o"])
                if r.dec is None:
                    # An anchored position is decided afresh: a cached UNCHECKABLE never
                    # stands against what the store holds.
                    cached = None if anchored else st.unchk.get((tp, r.pos.o))
                    if anchored:
                        st.unchk.pop((tp, r.pos.o), None)
                    if cached is not None:
                        r.dec = cached
                    else:
                        r.dec = await decide(r.d, r.pos, st.index, False, system_tenant=st.sys_log(tp),
                                             verdicts=batch.verdicts, route=batch.route)
                    if r.dec.kind == "event":
                        r.dec.token = st.index.add_pending(r.log, r.d.event["event_id"],
                                                           r.d.content_hash, r.pos.o)
                if anchored:
                    # Already accounted in the store (redelivery after a crash or a
                    # rebalance): nothing to append, only to verify.
                    outcome = await verify_redelivery(store, pubkey, r.log, r.pos, r.dec.template)
                    if outcome == "mismatch" and r.dec.kind == "event":
                        adopted = await st.adopt_uncheckable(store, pubkey, r.log, r.pos, r.dec.template)
                        if adopted is not None:
                            r.dec = adopted
                            outcome = await verify_redelivery(store, pubkey, r.log, r.pos, r.dec.template)
                    if outcome == "covered":
                        r.status = "verified"
                        continue
                    if outcome != "beyond":
                        if (tp, r.pos.o) not in st.alarmed:
                            st.alarmed.add((tp, r.pos.o))
                            logger.error(f"INTEGRITY ALARM [anchored-mismatch]: tenant {r.log!r} "
                                         f"{tp[0]}/{tp[1]}@{r.pos.o}: the store holds {outcome} at this "
                                         f"position; the partition is not committed past it")
                        # API processes refuse the partition's tenants once this marker is in
                        # the store (processing/stops.py); written in the background.
                        st.mark_stop(store, tp, r.pos.o, r.log, outcome, st.epochs.get(r.log))
                        r.status = "stalled"
                        stopped = True
                        continue
                r.status = "verified" if r.dec.kind == "skip" else "decided"
                if r.dec.kind == "skip":
                    logger.error(f"Skipping {tp[0]}/{tp[1]}@{r.pos.o} with no record "
                                 f"({r.dec.vtype}): verdicts are off")
            except Exception as e:
                r.status, r.err = "failed", e
                stopped = True

    async def _acct_write_graph(self, batch: "_AcctBatch") -> None:
        """Graph writes for event decisions, retried in place. The graph is derived state: a write
        that fails because the backend is unreachable leaves the record for redelivery; any other
        failure, with the backend up, appends the event record without its Activity (the evidence
        audit reports it), so no sender value can block the partition."""
        if not settings.acct_graph_write:
            return                              # the log without the graph
        semaphore = asyncio.Semaphore(settings.processor_max_concurrent_events)
        todo = [r for r in batch.records() if r.status == "decided" and r.dec.kind == "event"]

        async def write(r):
            async with semaphore:
                return await self._graph_accounted(r.dec.graph_event)

        def failed(r, outcome) -> bool:
            r.err = outcome if isinstance(outcome, BaseException) else None
            return r.err is not None
        todo = await _retry_in_place(todo, write, max(0, int(settings.processor_event_retries)), failed)
        backend_up: Optional[bool] = None
        for r in todo:
            if not is_outage_error(r.err):
                if backend_up is None:
                    backend_up = await self._backend_healthy()
                if backend_up:
                    logger.error(f"INTEGRITY ALARM [graph]: {r.tp[0]}/{r.tp[1]}@{r.pos.o} event "
                                 f"{r.d.event.get('event_id')!r}: the graph write failed "
                                 f"({type(r.err).__name__}); the event is recorded in the log "
                                 f"without its Activity")
                    self.metrics_graph_skipped += 1
                    r.err = None
                    continue
            r.status = "failed"

    async def _acct_append_group(self, batch: "_AcctBatch", tenant: str, tp,
                                 recs: List["_AcctRec"]) -> None:
        """Append one tenant's decided records of one partition, in offset order."""
        st, storage, store = batch.st, batch.storage, batch.store
        tokens: Dict[int, Tuple[int, str]] = {}      # pending token -> (seq, record hash)
        chunk: List[_AcctRec] = []

        def appended(r, seq, rh) -> None:
            r.seq, r.rh, r.status = int(seq), str(rh), "appended"
            if r.dec.token is not None:
                tokens[r.dec.token] = (int(seq), str(rh))
            if r.dec.kind == "event":
                st.index.note(tenant, r.d.event["event_id"], int(seq), r.d.content_hash, str(rh),
                              r.pos.o)

        async def flush():
            if not chunk:
                return
            epoch = st.epochs.get(tenant)
            if batch.stale(tp) or epoch is None:
                raise _AcctStale()
            for r in chunk:
                if r.dec.blob is not None:
                    # The blob is in the write-once store before the verdict naming it is in
                    # the log, so a third party can always re-run the validator.
                    try:
                        await asyncio.to_thread(store.put_once,
                                                r.dec.template["verdict"]["raw"]["blob"], r.dec.blob)
                    except Exception as e:
                        raise _AcctRecordFailed(r, e) from e
            try:
                res = await storage.add_records(tenant, [r.dec.template for r in chunk], epoch)
                for r, (seq, rh) in zip(chunk, res):
                    appended(r, seq, rh)
            except (FencedWriter, PositionConflict, AnchorTamper):
                raise
            except Exception as e:
                if len(chunk) == 1:
                    raise _AcctRecordFailed(chunk[0], e) from e
                # Find the record the group fails on, one append at a time (appends are
                # idempotent by position), and charge the failure to that record alone.
                for r in chunk:
                    if r.status == "appended":
                        continue
                    try:
                        (seq, rh), = await storage.add_records(tenant, [r.dec.template], epoch)
                    except (FencedWriter, PositionConflict, AnchorTamper):
                        raise
                    except Exception as e1:
                        raise _AcctRecordFailed(r, e1) from e1
                    appended(r, seq, rh)
            chunk.clear()

        try:
            for idx, r in enumerate(recs):
                if r.dec.pending_ref is not None:
                    if r.dec.pending_ref not in tokens and any(
                            c.dec.token == r.dec.pending_ref for c in chunk):
                        await flush()
                    if r.dec.pending_ref not in tokens:
                        # Its referent was not appended in this delivery: decide it again on
                        # the next one, where the referent is found in the log.
                        for rest in recs[idx:]:
                            rest.status = "later"
                        break
                    resolve_ref(r.dec, *tokens[r.dec.pending_ref])
                chunk.append(r)
            await flush()
        except _AcctStale:
            # The partition was revoked or reassigned during the batch: its new generation
            # replays these records.
            _later_unless_appended(recs)
        except FencedWriter:
            # Another writer holds the tenant's epoch. If this process still owns the
            # partition, its next append resets the tail (ensure_epoch), deleting the tenant's
            # unanchored records; they are fetched again from the committed offset.
            st.epochs.pop(tenant, None)
            st.tracker.reset_tenant(tenant)
            _later_unless_appended(recs)
            await self._acct_rewind_to_committed(batch.seek_to, tp)
        except (PositionConflict, AnchorTamper) as e:
            logger.error(f"INTEGRITY ALARM [tail]: tenant {tenant!r}: {type(e).__name__}: {e}; "
                         f"resetting its tail from the store")
            _later_unless_appended(recs)
            await st.reset_tail(tenant, storage)
            await self._acct_rewind_to_committed(batch.seek_to, tp)
        except _AcctRecordFailed as failure:
            failure.rec.status, failure.rec.err = "failed", failure.err
            for r in recs:
                if r.status not in ("appended", "failed"):
                    r.status = "later"
        except Exception as e:
            # Not attributable to one record: the first record not appended carries it.
            charged = False
            for r in recs:
                if r.status == "appended":
                    continue
                if not charged:
                    r.status, r.err, charged = "failed", e, True
                else:
                    r.status = "later"

    async def _acct_count_failures(self, batch: "_AcctBatch") -> None:
        """Poison accounting: a delivery counts only while the backend (database and store) is up
        and the failure is not an outage. An exhausted position gets an UNCHECKABLE verdict at
        its next delivery."""
        st = batch.st
        failed = [r for r in batch.records()
                  if r.status == "failed" and r.err is not None and not batch.stale(r.tp)]
        backend_up = True
        if any(not is_outage_error(r.err) for r in failed):
            backend_up = await self._backend_healthy()
        max_redeliveries = max(1, int(settings.processor_max_redeliveries))
        now_ms = int(time.time() * 1000)
        for r in failed:
            key = (r.tp, r.pos.o)
            counts = backend_up and not is_outage_error(r.err)
            if counts:
                st.fail_meta.setdefault(key, (now_ms, type(r.err).__name__))
            if should_dead_letter(st.counts, key, counts, max_redeliveries) and r.d is not None:
                first_ms, err_name = st.fail_meta.get(key, (now_ms, type(r.err).__name__))
                try:
                    dec = await decide(r.d, r.pos, st.index, True, system_tenant=st.sys_log(r.tp),
                                       attempts=st.counts.get(key), first_fail_ms=first_ms,
                                       err=err_name, verdicts=batch.verdicts, route=batch.route)
                    if dec.vtype == "UNCHECKABLE":
                        st.unchk[key] = dec
                        logger.error(f"UNCHECKABLE(POISON) at {r.tp[0]}/{r.tp[1]}@{r.pos.o} after "
                                     f"{st.counts.get(key)} deliveries ({err_name}); counted against "
                                     f"the budget")
                except Exception:
                    pass

    async def _acct_note_coverage(self, batch: "_AcctBatch") -> set:
        """Tell the coverage tracker what the writer appended and what it verified. A partition
        whose generation changed records nothing; returns those partitions."""
        st = batch.st
        stale_tps = {tp for tp in batch.by_tp if batch.stale(tp)}
        for tp, recs in batch.by_tp.items():
            if tp in stale_tps:
                continue
            broken: set = set()
            for r in recs:
                if r.status == "appended":
                    if r.log in broken:
                        continue
                    try:
                        st.tracker.note_appended(r.tp, r.pos.o, r.log, r.seq, r.rh)
                    except CoverageMismatch as e:
                        # The tail lost a record under the writer: reset the tenant's tail and
                        # read the partition again from the committed offset.
                        logger.error(f"INTEGRITY ALARM [coverage]: tenant {r.log!r}: {e}; resetting "
                                     f"its tail, nothing is committed past it")
                        broken.add(r.log)
                        await st.reset_tail(r.log, batch.storage)
                        await self._acct_rewind_to_committed(batch.seek_to, tp)
                elif r.status == "verified":
                    st.tracker.note_verified(r.tp, r.pos.o)
        return stale_tps

    async def _acct_committed(self, tp) -> int:
        """The partition's committed offset (0 when none)."""
        try:
            c = await self.consumer.committed(TopicPartition(tp[0], tp[1]))
            return int(c) if c is not None else 0
        except Exception:
            return 0

    async def _acct_refresh_and_commit(self, st, store, pubkey, caa: bool, by_tp, seek_to,
                                       stale_tps=None) -> None:
        try:
            if st.mismatch is not None:
                e, st.mismatch = st.mismatch, None
                raise e
            await st.tracker.refresh(store, pubkey)
        except CoverageMismatch as e:
            logger.error(f"INTEGRITY ALARM [coverage]: tenant {e.tenant_id!r}: the store's record at seq "
                         f"{e.seq} is not the one this writer built; resetting its tail, nothing is "
                         f"committed past it")
            tp = st.tenant_tp.get(e.tenant_id)
            if e.tenant_id in st.epochs:
                storage, _, _ = st.resolve()
                await st.reset_tail(e.tenant_id, storage)
            if tp is not None:
                await self._acct_rewind_to_committed(seek_to, tp)
                return
        except Exception as e:
            logger.warning(f"Coverage refresh failed: {type(e).__name__}: {e}")
        # Only partitions this consumer holds now: a commit naming another member's partition is
        # refused for the whole call.
        owned = self._acct_owned()
        skip = set(stale_tps or ())

        def mine(tp) -> bool:
            return tp not in skip and (owned is None or tp in owned)
        if caa:
            commits = plan_commits_caa(st.tracker, [tp for tp in sorted(st.known_tps) if mine(tp)])
        else:
            # Commit-after-DB baseline: commit once the database append is done.
            commits = {}
            for tp, recs in (by_tp or {}).items():
                if not mine(tp):
                    continue
                done = None
                for r in recs:
                    if r.status in ("appended", "verified"):
                        done = r.pos.o + 1
                    else:
                        break
                if done is not None:
                    commits[tp] = done
        commits = {tp: off for tp, off in commits.items() if tp not in seek_to or off <= seek_to[tp]}
        if not commits:
            return
        try:
            await self.consumer.commit({TopicPartition(tp[0], tp[1]): off for tp, off in commits.items()})
        except Exception as commit_error:
            logger.error(f"Failed to commit Kafka offsets: {commit_error}; committing per partition")
            committed: Dict[Any, int] = {}
            for tp, off in commits.items():
                try:
                    await self.consumer.commit({TopicPartition(tp[0], tp[1]): off})
                    committed[tp] = off
                except Exception as one_error:
                    logger.error(f"Failed to commit {tp[0]}/{tp[1]}@{off}: {one_error}")
            commits = committed
        for tp, off in commits.items():
            st.tracker.forget_below(tp, off)
            for k in [k for k in st.counts if k[0] == tp and k[1] < off]:
                st.counts.pop(k, None)
                st.fail_meta.pop(k, None)
                st.unchk.pop(k, None)

    async def acct_tick(self) -> None:
        """Between batches: poll the store for coverage and commit what it now covers (anchors
        also land on the heartbeat, with no new record fetched)."""
        if not (settings.acct_mode and self.kafka_available and self.consumer):
            return
        st = self._acct_state()
        now = time.time()
        if now - st.last_tick < float(settings.acct_coverage_poll_s):
            return
        st.last_tick = now
        if st.halted is None and hasattr(self.consumer, "partitions_for_topic") and \
                now - st.source_checked_at >= float(settings.acct_partition_check_s):
            try:
                await self._acct_check_source()
            except SourceContractMismatch as e:
                # E.g. partitions added: tenants may now land on other partitions, and appending
                # would split their logs.
                st.halted = f"the source no longer matches the contract: {e}"
                logger.error(f"INTEGRITY ALARM [partitions]: {st.halted}; processing stops")
                return
            except Exception as e:
                logger.warning(f"Source check failed: {type(e).__name__}: {e}")
        if st.halted:
            return
        storage, store, pubkey = st.resolve()
        seek_to: Dict[Any, int] = {}
        # A quiet tenant whose tail the database shortened makes no append that add_records could
        # refuse, so this process's tails are checked here and a short one is queued for reset.
        check = getattr(storage, "check_own_tails", None)
        if check is not None:
            try:
                await check()
            except Exception as e:
                logger.warning(f"Tail check failed: {type(e).__name__}: {e}")
        take_tampered = getattr(storage, "take_tampered", None)
        take_superseded = getattr(storage, "take_superseded", None)
        owned = self._acct_owned()
        queued = [(t, "tampered") for t in (take_tampered() if take_tampered is not None else ())]
        # Another writer took the epoch of a log in which this process still had unanchored
        # records and its reset deleted them; a quiet log would otherwise never be anchored.
        queued += [(t, "superseded") for t in (take_superseded() if take_superseded is not None else ())]
        for tenant, why in queued:
            tp = st.tenant_tp.get(tenant)
            if tenant not in st.epochs or tp is None or (owned is not None and tp not in owned):
                # Not a tail this process writes (its partition moved in a rebalance): a reset
                # from here would fence the tenant's current writer and delete its tail.
                logger.warning(f"Tenant {tenant!r} ({why}) is on a partition this process does not own; "
                               f"not resetting it")
                continue
            # Reset as for AnchorTamper and replay from the committed offset.
            reason = ("anchorer refused its tail" if why == "tampered"
                      else "another writer took its epoch under our unanchored records")
            logger.error(f"INTEGRITY ALARM [tail]: tenant {tenant!r}: {reason}; resetting")
            await st.reset_tail(tenant, storage)
            await self._acct_rewind_to_committed(seek_to, tp)
        await self._acct_refresh_and_commit(st, store, pubkey, self._acct_flags()[1], None, seek_to)
        self._acct_seek(st, seek_to)

    async def get_processing_metrics(self) -> Dict[str, Any]:
        return {
            'events_processed': self.metrics.events_processed,
            'events_failed': self.metrics.events_failed,
            'processing_time_ms': self.metrics.processing_time_ms,
            'last_processed': self.metrics.last_processed_timestamp.isoformat() if self.metrics.last_processed_timestamp else None,
            'is_running': self.is_running,
            'success_rate': self.metrics.events_processed / max(1, self.metrics.events_processed + self.metrics.events_failed)
        }

async def _retry_in_place(items: list, run, retries: int, failed) -> list:
    """Run run(x) for every item, then again, with backoff, for the items whose outcome (a result or
    an exception) failed(x, outcome) keeps, at most `retries` more times. Returns the items kept."""
    for attempt in range(retries + 1):
        if not items:
            break
        if attempt:
            await asyncio.sleep(min(5.0, 0.5 * (2 ** (attempt - 1))))
        results = await asyncio.gather(*(run(x) for x in items), return_exceptions=True)
        items = [x for x, res in zip(items, results) if failed(x, res)]
    return items

def _tp_key(tp) -> Tuple[str, int]:
    """(topic, partition) of an aiokafka TopicPartition (a named tuple) or a plain pair."""
    return (str(tp[0]), int(tp[1]))

def _prefix_groups(by_tp) -> Dict[Tuple[str, Any], List["_AcctRec"]]:
    """The decided records of each partition's processed prefix, by (tenant log, partition): the
    prefix ends at the first record that failed, stalled or is left for later."""
    groups: Dict[Tuple[str, Any], List[_AcctRec]] = {}
    for tp, recs in by_tp.items():
        cut = False
        for r in recs:
            if cut:
                if r.status in ("decided", "verified"):
                    r.status = "later"
                continue
            if r.status in ("failed", "stalled", "later"):
                cut = True
                continue
            if r.status == "decided":
                groups.setdefault((r.log, tp), []).append(r)
    return groups

def _later_unless_appended(recs) -> None:
    for r in recs:
        if r.status != "appended":
            r.status = "later"

class _AcctStale(Exception):
    """The batch's partition changed generation (a rebalance) before its group was appended."""

class _AcctRecordFailed(Exception):
    """An append failure attributed to one record of a group."""

    def __init__(self, rec, err: BaseException):
        super().__init__(f"{type(err).__name__}: {err}")
        self.rec, self.err = rec, err

class _AcctRec:
    """One fetched position (or a GAP) in an accounted batch. status: decided (to append),
    appended, verified (already accounted, or skipped with verdicts off), failed (retried at the
    next delivery and counted), stalled (the store contradicts it), later (beyond the processed
    prefix, redelivered without counting)."""
    __slots__ = ("i", "tp", "pos", "raw", "d", "dec", "log", "status", "err", "seq", "rh", "tstype")

    def __init__(self, i, tp, pos, raw=None, tstype=None):
        self.i, self.tp, self.pos, self.raw, self.tstype = i, tp, pos, raw, tstype
        self.d = self.dec = self.log = self.err = self.seq = self.rh = None
        self.status = "new"

class _AcctBatch:
    """What the steps of one accounted batch share: the records per partition, the backends and
    the partitions to rewind."""

    def __init__(self, st: "_AcctState", storage, store, pubkey, verdicts: bool,
                 seek_to: Dict[Any, int]):
        self.st, self.storage, self.store, self.pubkey = st, storage, store, pubkey
        self.verdicts = verdicts
        self.route = st.route
        self.seek_to = seek_to
        self.by_tp: Dict[Any, List[_AcctRec]] = {}
        self.next_o: Dict[Any, Optional[int]] = {}    # partition -> offset expected after the batch
        # Each partition's generation when the batch started. A rebalance during the batch
        # changes it; the batch then records and commits nothing on that partition.
        self.gen0: Dict[Any, int] = {}

    def stale(self, tp) -> bool:
        return self.st.gen.get(tp, 0) != self.gen0.get(tp, 0)

    def records(self):
        return (r for recs in self.by_tp.values() for r in recs)

class _StepTimer:
    """STAGE_TIMING: wall time per step of an accounted batch (and the poll and pause before it),
    logged as one ACCTSPLIT line."""

    def __init__(self, pause_s: float, poll_s: float):
        self.steps: Dict[str, float] = {"pause": pause_s, "poll": poll_s} if _STAGE_TIMING else {}
        self.last = time.perf_counter()

    def mark(self, step: str) -> None:
        if _STAGE_TIMING:
            now = time.perf_counter()
            self.steps[step] = self.steps.get(step, 0.0) + (now - self.last)
            self.last = now

    def log(self, n_total: int, n_done: int) -> None:
        if not _STAGE_TIMING:
            return
        # add_records' busy time inside append_anchor, summed over its concurrent calls.
        sums = dict(ACCT_TIMING)
        ACCT_TIMING.clear()
        appends = int(sums.pop("appends", 0))
        steps = " ".join(f"{k}={v * 1000:.1f}" for k, v in self.steps.items())
        busy = " ".join(f"sum_{k}={v * 1000:.1f}" for k, v in sums.items())
        logger.info(f"ACCTSPLIT n={n_total} done={n_done} {steps} "
                    f"total={sum(self.steps.values()) * 1000:.1f} appends={appends} {busy}")

class _AcctState:
    """The accounted consumer's memory. Safety does not depend on it: after a crash the next
    owner resets the tails from the store and replays from the committed offset."""

    def __init__(self, storage=None, store=None, pubkey: Optional[bytes] = None, graph=None,
                 contract_hash: Optional[str] = None):
        self.storage, self.store, self.pubkey, self.graph = storage, store, pubkey, graph
        self.contract_hash = contract_hash
        self.index = EventIdIndex(lookup=self._lookup)
        self.tracker = CoverageTracker(dense=True)
        self.epochs: Dict[str, int] = {}          # tenant log -> writer epoch from our reset
        self.tenant_tp: Dict[str, Any] = {}       # tenant log -> its partition
        self.expected: Dict[Any, int] = {}        # partition -> next offset, for GAP detection
        self.counts: Dict[Any, int] = {}          # (partition, offset) -> counted deliveries
        self.fail_meta: Dict[Any, Tuple[int, str]] = {}
        self.unchk: Dict[Any, Any] = {}           # (partition, offset) -> UNCHECKABLE decision
        self.alarmed: set = set()
        self.known_tps: set = set()
        self.last_tick = 0.0
        self.mismatch = None                      # a CoverageMismatch from an own anchor
        self._listening = None
        self.halted: Optional[str] = None          # why the source no longer matches the contract
        self.source_checked_at = 0.0               # last source check (time.time())
        self.gen: Dict[Any, int] = {}              # partition -> assignment generation
        self.gap_probe: Dict[Any, Tuple[int, int]] = {}   # partition -> (expected, o) read once
        self.route: Optional[dict] = None          # the source's partitioner (acct-route/1)
        self.ablation_refused = False
        self.contract: Optional[dict] = None       # the verified contract body, once checked
        self.last_bt: Dict[Any, Tuple[int, int]] = {}     # partition -> (offset, append time) seen last
        self.time_alarms: Dict[str, int] = {"late": 0, "backwards": 0}
        self._time_alarmed: set = set()
        self.stop_tasks: Dict[Any, Any] = {}      # (partition, offset) -> marker write task
        self.stops_marked: set = set()            # (partition, offset) whose marker is stored
        self.stop_tried: Dict[Any, float] = {}    # (partition, offset) -> last write started
        self.prefetched: Dict[Any, Any] = {}      # (log, event id) -> this batch's DB answer

    def mark_stop(self, store, tp, o: int, tenant: str, reason: str, epoch: Optional[int]) -> None:
        """Write the stop marker of (tp, o) in the background (processing/stops.py)."""
        key = (tp, int(o))
        if key in self.stops_marked:
            return
        task = self.stop_tasks.get(key)
        if task is not None and not task.done():
            return
        now = time.monotonic()
        if now - self.stop_tried.get(key, float("-inf")) < _STOP_RETRY_S:
            return
        self.stop_tried[key] = now
        from processing.stops import write_stop

        async def write() -> None:
            if await write_stop(store, tp[0], tp[1], o, tenant, reason, epoch):
                self.stops_marked.add(key)
        self.stop_tasks[key] = asyncio.get_running_loop().create_task(write())

    def delta_ms(self) -> int:
        body = self.contract or {}
        body = body.get("body", body) if isinstance(body, dict) else {}
        return int(body.get("delta_s") or settings.acct_delta_s) * 1000

    def check_times(self, r: "_AcctRec") -> None:
        """Alarm on the timing the statement maker's HEAD rule relies on: an append time more than
        the broker's skew below an earlier offset's, or a tagged record appended more than the
        contract's delta after its tag's time. A CreateTime stamp is the producer's clock and is
        not checked."""
        if r.i is None or r.tstype == 0 or not r.pos.bt_ms:
            return
        tp, o, bt = r.tp, int(r.pos.o), int(r.pos.bt_ms)
        prev = self.last_bt.get(tp)
        eps_b = int(settings.acct_broker_skew_ms)
        if prev is not None and o > prev[0] and bt < prev[1] - eps_b:
            self._time_alarm("backwards", tp, o,
                             f"{tp[0]}/{tp[1]}@{o}: LogAppendTime {bt} is {prev[1] - bt} ms before that of "
                             f"offset {prev[0]}, beyond the broker's skew of {eps_b} ms; HEAD statements "
                             f"no longer bound this partition's overdue records")
        if prev is None or o > prev[0]:
            self.last_bt[tp] = (o, bt)
        sub = r.d.sub if (r.d is not None and r.d.sub_valid) else None
        at = sub.get("at_ms") if isinstance(sub, dict) else None
        if isinstance(at, int) and not isinstance(at, bool) and bt - at > self.delta_ms():
            self._time_alarm("late", tp, o,
                             f"{tp[0]}/{tp[1]}@{o}: appended {bt - at} ms after its tag's time, beyond "
                             f"the contract's delta of {self.delta_ms()} ms; HEAD statements do not "
                             f"cover it before its deadline")

    def _time_alarm(self, kind: str, tp, o: int, message: str) -> None:
        key = (kind, tp, o)
        if key in self._time_alarmed:
            return
        if len(self._time_alarmed) > _TIME_ALARMS_KEPT:
            self._time_alarmed.clear()
        self._time_alarmed.add(key)
        self.time_alarms[kind] = self.time_alarms.get(kind, 0) + 1
        logger.error(f"INTEGRITY ALARM [timing]: {message}")

    async def _lookup(self, tenant_id: str, event_id: str):
        # The batch's prefetched answer when there is one (prefetch_index), else one query.
        hit = self.prefetched.get((tenant_id, event_id))
        if hit is not None:
            return hit
        return await self._graph().find_event_records(tenant_id, event_id)

    def _graph(self):
        return self.graph if self.graph is not None else graph_db

    async def prefetch_index(self, keys) -> None:
        """Ask the database once for the event-id lookups a batch will make. Records appended
        during the batch are found through EventIdIndex.note() and the pending records, so no
        decision changes. Without the batched query, or when it fails, lookups go per record."""
        self.prefetched = {}
        many = getattr(self._graph(), "find_event_records_many", None)
        if many is None or not keys:
            return
        try:
            self.prefetched = await many(keys)
        except Exception as e:
            logger.warning(f"batched event-id lookup failed, looking up per record: "
                           f"{type(e).__name__}: {e}")
            self.prefetched = {}

    def resolve(self):
        storage = self.storage
        if storage is None:
            from crypto.merkle_tree_storage import merkle_tree_storage
            storage = merkle_tree_storage
        store = self.store
        if store is None:
            from crypto.merkle_tree_storage import _get_anchor_store
            store = _get_anchor_store()
        pubkey = self.pubkey
        if pubkey is None:
            from crypto.signing import get_public_key
            pubkey = get_public_key()
        if self._listening is not storage and hasattr(storage, "add_anchor_listener"):
            # Coverage from this process's own anchors, with no store read.
            storage.add_anchor_listener(self._on_anchor)
            self._listening = storage
        return storage, store, pubkey

    def _on_anchor(self, tenant_id, rec, segment) -> None:
        try:
            self.tracker.note_anchor(tenant_id, rec, segment)
        except Exception as e:           # CoverageMismatch: handled after the appends
            self.mismatch = e

    async def adopt_uncheckable(self, store, pubkey, tenant_id: str, pos, template: dict):
        """The anchored verdict at pos as a Decision when it is the UNCHECKABLE(POISON) verdict an
        honest writer builds from this event template (equal on every field except seq, attempts,
        first_fail_ms and err), else None.

        UNCHECKABLE depends on how often an earlier process saw the record fail, so a new owner
        rebuilds an event template instead; it adopts the anchored verdict rather than stalling."""
        def find():
            for a in store.all(tenant_id):
                seg = a.seg
                if not seg or not (int(seg["o_first"]) <= int(pos.o) <= int(seg["o_last"])):
                    continue
                if not a.verify_self() or (pubkey is not None and not a.verify_sig(pubkey)):
                    continue
                raw = store.get_object(segment_key(tenant_id, a.n))
                if raw is None or R.sha256_hex(raw) != seg.get("sha256"):
                    continue
                for rec in json.loads(raw).get("records", []):
                    at = rec.get("pos") or {}
                    if (at.get("topic"), at.get("p"), at.get("o")) == (pos.topic, pos.p, pos.o):
                        return rec
            return None
        rec = await asyncio.to_thread(find)
        if not rec:
            return None
        # A planted UNCHECKABLE that differs anywhere else (code, raw reference, ref) is not adopted.
        honest = R.verdict_template(template.get("tenant_id"), R.Position.from_json(template["pos"]),
                                    template.get("sub"), template.get("event"), "UNCHECKABLE",
                                    code="POISON")
        found = R.without_seq(rec)
        v = dict(found.get("verdict") or {})
        for k in ("attempts", "first_fail_ms", "err"):
            v[k] = None
        if dict(found, verdict=v) != honest:
            return None
        logger.warning(f"Adopting the anchored UNCHECKABLE verdict at {pos.topic}/{pos.p}@{pos.o} "
                       f"of tenant {tenant_id!r}")
        return Decision("verdict", tenant_id, R.without_seq(rec), None, None)

    @staticmethod
    def sys_log(tp) -> str:
        """The system log of a partition, one per partition so that each log has a single writer:
        <acct_system_tenant>-<p> for the deployment's topic, and
        <acct_system_tenant>-<8 hex of SHA-256(topic)>-<p> for any other topic."""
        base = settings.acct_system_tenant
        topic = str(tp[0]) if tp[0] is not None else None
        if topic is None or topic == str(settings.kafka_provenance_topic):
            return f"{base}-{int(tp[1])}"
        return f"{base}-{hashlib.sha256(topic.encode('utf-8')).hexdigest()[:8]}-{int(tp[1])}"

    def log_of(self, d, tp) -> str:
        """The log a decoded record's accounting record goes to (decide.log_tenant)."""
        return log_tenant(d, self.sys_log(tp), int(tp[1]), self.route)

    async def ensure_epoch(self, tenant_id: str, tp, storage) -> None:
        """Before this process first appends to a tenant log after (re)acquiring its partition,
        it resets the tail from the store and takes a new writer epoch."""
        if tenant_id in self.epochs:
            return
        base_n, epoch = await storage.reset_tenant_tail(tenant_id)
        self.index.forget_from(tenant_id, int(base_n))
        self.tracker.reset_tenant(tenant_id)
        self.epochs[tenant_id] = int(epoch)
        self.tenant_tp[tenant_id] = tp

    async def reset_tail(self, tenant_id: str, storage) -> None:
        """Reset one tenant's tail from the store. Only that tenant's coverage entries go back to
        FETCHED; they block the commit until the caller's rewind has accounted them again."""
        try:
            base_n, epoch = await storage.reset_tenant_tail(tenant_id)
            self.index.forget_from(tenant_id, int(base_n))
            self.tracker.reset_tenant(tenant_id)
            self.epochs[tenant_id] = int(epoch)
        except Exception as e:
            logger.error(f"Tail reset of tenant {tenant_id!r} failed: {type(e).__name__}: {e}")
            self.tracker.reset_tenant(tenant_id)
            self.epochs.pop(tenant_id, None)
        tp = self.tenant_tp.get(tenant_id)
        if tp is not None:
            self.expected.pop(tp, None)

    def forget_partition(self, tp) -> None:
        """A rebalance assigned or revoked tp: drop its coverage and floor; the next fetch starts
        at the group's committed offset."""
        self.gen[tp] = self.gen.get(tp, 0) + 1
        self.tracker.revoked(tp)
        self.expected.pop(tp, None)
        self.gap_probe.pop(tp, None)
        for t in [t for t, x in self.tenant_tp.items() if x == tp]:
            self.epochs.pop(t, None)
        for d in (self.counts, self.fail_meta, self.unchk):
            for k in [k for k in d if k[0] == tp]:
                d.pop(k, None)

class StreamProcessor:
    """Runs several EventProcessors in one process."""

    def __init__(self):
        self.processors: List[EventProcessor] = []
        self.is_running = False

    async def initialize(self, num_processors: int = 3):
        try:
            for _ in range(num_processors):
                processor = EventProcessor()
                await processor.initialize()
                self.processors.append(processor)

            logger.info(f"Stream processor initialized with {num_processors} processors")

        except Exception as e:
            logger.error(f"Failed to initialize stream processor: {e}")
            raise

    async def start(self):
        self.is_running = True

        tasks = [asyncio.create_task(processor.start_processing()) for processor in self.processors]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Stream processor cancelled")
        except Exception as e:
            logger.error(f"Stream processor error: {e}")
            raise

    async def stop(self):
        self.is_running = False

        for processor in self.processors:
            await processor.close()

        logger.info("Stream processor stopped")

stream_processor = StreamProcessor()
