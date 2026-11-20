from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SourceContractMismatch(RuntimeError):
    """The source is not the one the contract describes."""

    def __init__(self, problems: List[str]):
        super().__init__("; ".join(problems))
        self.problems = list(problems)


def load_contract(store, pubkey: Optional[bytes], dep: str, ver: int) -> Optional[dict]:
    """The contract body in force, if the store holds one that verifies under pubkey."""
    from crypto.records import NS_STMT, canon
    from crypto.signing import verify
    if store is None or pubkey is None:
        return None
    raw = store.get_object(f"contract/{dep}/{int(ver):06d}.json")
    if raw is None:
        return None
    try:
        stmt = json.loads(raw)
        body = stmt["body"]
        if verify(pubkey, stmt.get("sig"), NS_STMT + canon(body)):
            return body
    except (ValueError, KeyError, TypeError):
        pass
    logger.error("INTEGRITY ALARM [contract]: the stored contract does not verify under the deployment key")
    return None


# The send bound: how long after a tag's time the broker can still append the tagged record.
# Accounted mode runs the producer without idempotence (with it, a batch never expires), so a
# record the API gave up on is sent or abandoned within late_append_ms().

def delivery_timeout_ms() -> int:
    """How long the API waits, from the tag's time, for the broker's acknowledgement of a send."""
    return int(os.getenv("KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS", "30000"))


def kafka_producer_timing() -> dict:
    """The accounted-mode Kafka producer's timing options (api/main.py passes them to aiokafka)."""
    return {"request_timeout_ms": int(os.getenv("KAFKA_PRODUCER_REQUEST_TIMEOUT_MS", "10000")),
            "retry_backoff_ms": int(os.getenv("KAFKA_PRODUCER_RETRY_BACKOFF_MS", "100")),
            # With the batch size below, a deep send queue drains in large requests.
            "linger_ms": int(os.getenv("KAFKA_PRODUCER_LINGER_MS", "5"))}


def kafka_producer_batch_bytes() -> int:
    """The accounted-mode producer's batch size per partition (aiokafka max_batch_size). The 16 KB
    default holds about 20 records, too few for a deep send queue; 256 KB stays below the broker's
    default max.message.bytes (1 MB)."""
    return int(os.getenv("KAFKA_PRODUCER_MAX_BATCH_BYTES", "262144"))


def late_append_ms() -> int:
    """How late after the tag's time the broker can receive a record the API gave up on, for the
    non-idempotent producer: 2 * request_timeout_ms + retry_backoff_ms + linger_ms."""
    t = kafka_producer_timing()
    return 2 * t["request_timeout_ms"] + t["retry_backoff_ms"] + t["linger_ms"]


def send_bound_ms() -> int:
    """The send bound: the larger of the API's delivery timeout and the late-append bound."""
    return max(delivery_timeout_ms(), late_append_ms())


# The topic settings custody depends on: time retention of at least the contract's retention_s, no
# size-based retention, no compaction (it breaks the dense offsets the audits read), and
# LogAppendTime (the statement maker reads the broker's time, never the producer's).
KAFKA_TOPIC_KEYS = ("retention.ms", "retention.bytes", "cleanup.policy", "message.timestamp.type")


async def read_kafka_topic_config(bootstrap, topic: str, timeout_s: float = 10.0) -> dict:
    """{name: value} of KAFKA_TOPIC_KEYS for the topic, read with an admin client (DescribeConfigs).
    Raises when the cluster cannot be asked."""
    from aiokafka.admin import AIOKafkaAdminClient
    from aiokafka.admin.config_resource import ConfigResource, ConfigResourceType
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap, request_timeout_ms=int(timeout_s * 1000))
    await asyncio.wait_for(admin.start(), timeout_s)
    try:
        resp = await asyncio.wait_for(admin.describe_configs(
            [ConfigResource(ConfigResourceType.TOPIC, topic)]), timeout_s)
    finally:
        await admin.close()
    out = {}
    for r in resp:
        for res in getattr(r, "resources", ()):
            if res[0]:                                  # error_code
                raise RuntimeError(f"DescribeConfigs {topic}: error {res[0]} {res[1]}")
            for entry in res[4]:
                if entry[0] in KAFKA_TOPIC_KEYS:
                    out[str(entry[0])] = None if entry[1] is None else str(entry[1])
    return out


async def kafka_topic_config(client, settings, topic: str) -> Optional[dict]:
    """The topic settings of KAFKA_TOPIC_KEYS as `client` can read them: its own
    topic_config(topic), an admin read for aiokafka's producer and consumer, else None."""
    own = getattr(client, "topic_config", None)
    if callable(own):
        return await own(topic)
    from aiokafka.consumer import AIOKafkaConsumer
    from aiokafka.producer import AIOKafkaProducer
    if not isinstance(client, (AIOKafkaProducer, AIOKafkaConsumer)):
        return None
    return await read_kafka_topic_config(settings.kafka_bootstrap_servers, topic)


def topic_config_problems(contract: dict, config: dict) -> List[str]:
    """What a Kafka topic's settings void of the contract's custody promise."""
    body = contract.get("body", contract) if isinstance(contract, dict) else {}
    problems: List[str] = []

    def num(key):
        try:
            return int(config.get(key))
        except (TypeError, ValueError):
            return None
    want = body.get("retention_s")
    ms = num("retention.ms")
    if want is not None and (ms is None or (ms >= 0 and ms < int(want) * 1000)):
        problems.append(f"P15: the topic keeps records {config.get('retention.ms')} ms (retention.ms), "
                        f"the contract promises {int(want)} s")
    by = num("retention.bytes")
    if by is None or by >= 0:
        problems.append(f"P15: retention.bytes is {config.get('retention.bytes')}: size-based retention "
                        f"deletes records before the contract's retention")
    if "compact" in str(config.get("cleanup.policy") or "delete"):
        problems.append(f"A4: cleanup.policy is {config.get('cleanup.policy')!r}: compaction deletes "
                        f"records by key before their retention")
    if str(config.get("message.timestamp.type") or "") != "LogAppendTime":
        problems.append(f"A4: message.timestamp.type is {config.get('message.timestamp.type')!r}, not "
                        f"LogAppendTime: append times would be the producer's")
    return problems


def check_source_against_contract(contract: dict, *, topic: str,
                                  open_partitions: Optional[Iterable[int]],
                                  topic_config: Optional[dict] = None) -> Tuple[List[str], List[str]]:
    """(problems, warnings). Problems void a guarantee and stop the consumer; warnings name a
    check that could not be made. topic_config: a Kafka topic's settings (kafka_topic_config),
    checked by topic_config_problems."""
    body = contract.get("body", contract) if isinstance(contract, dict) else {}
    broker = body.get("broker") or {}
    problems: List[str] = []
    warnings: List[str] = []
    ckind = str(broker.get("kind", "kafka"))
    if ckind != "kafka":
        problems.append(f"the contract's broker is {ckind!r}, the source is 'kafka'")
    if broker.get("topic") is not None and str(broker["topic"]) != str(topic):
        problems.append(f"the contract's topic is {broker['topic']!r}, the source reads {topic!r}")
    if "partitions" not in broker:
        warnings.append("the contract does not freeze a partition count: partitions unchecked")
    elif open_partitions is None:
        warnings.append("the source's partitions could not be read: partitions unchecked")
    else:
        want = set(range(int(broker["partitions"])))
        have = {int(p) for p in open_partitions}
        if have != want:
            problems.append(f"P3: the contract freezes partitions {sorted(want)[:8]}.. ({len(want)}); the "
                            f"source has {sorted(have)[:8]}.. ({len(have)}), so tenants may now map to "
                            f"other partitions")
    if topic_config is not None:
        problems.extend(topic_config_problems(body, topic_config))
    return problems, warnings


def route_for(consumer, contract: Optional[dict], topic: str, settings=None) -> Optional[dict]:
    """The partitioner (crypto/validate_record.partition_of) that puts a tenant's records on their
    partition, for decide.misrouted; None when it cannot be known. The contract's
    broker.partitioner, else acct_partitioner, else "murmur2" (aiokafka's default), over the
    contract's partition count, else the topic's current one."""
    body = (contract or {}).get("body", contract or {}) if isinstance(contract, dict) else {}
    broker = body.get("broker") or {}
    if str(broker.get("kind", "kafka")) != "kafka":
        return None
    fn = broker.get("partitioner") or (settings.acct_partitioner if settings else None) or "murmur2"
    if fn not in ("murmur2", "crc32"):
        return None
    n = broker.get("partitions")
    if n is None:
        try:
            parts = consumer.partitions_for_topic(topic)
            n = len(parts) if parts else None
        except Exception:
            n = None
    return {"fn": str(fn), "n": int(n)} if n else None


async def verify_source(consumer, contract: dict, topic: str, settings=None) -> List[str]:
    """Run check_source_against_contract on a live consumer. Raises SourceContractMismatch; returns
    the warnings. With settings, the topic's settings are read (kafka_topic_config) and checked
    too."""
    parts = None
    try:
        # Fresh metadata first, to notice partitions added since the last check.
        await consumer.topics()
        parts = consumer.partitions_for_topic(topic)
    except Exception as e:
        logger.warning(f"partitions of {topic} not readable: {type(e).__name__}: {e}")
    config, config_warning = None, None
    if settings is not None:
        try:
            config = await kafka_topic_config(consumer, settings, topic)
            if config is None:
                config_warning = f"the settings of topic {topic} cannot be read here: retention unchecked"
        except Exception as e:
            config_warning = (f"the settings of topic {topic} are not readable ({type(e).__name__}: {e}): "
                              f"retention unchecked")
    problems, warnings = check_source_against_contract(contract, topic=topic, open_partitions=parts,
                                                       topic_config=config)
    if config_warning:
        warnings.append(config_warning)
    for w in warnings:
        logger.warning(w)
    if problems:
        for p in problems:
            logger.error(f"INTEGRITY ALARM [partitions]: {p}")
        raise SourceContractMismatch(problems)
    return warnings


__all__ = ["SourceContractMismatch", "load_contract", "check_source_against_contract", "verify_source",
           "route_for", "KAFKA_TOPIC_KEYS", "read_kafka_topic_config", "kafka_topic_config",
           "topic_config_problems", "delivery_timeout_ms", "kafka_producer_timing",
           "late_append_ms", "send_bound_ms"]
