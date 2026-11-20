from __future__ import annotations

from typing import Dict, Optional, Tuple


def partition_for(key: bytes, n_partitions: int) -> int:
    """The partition Kafka's default partitioner picks for a key: murmur2, positive, modulo."""
    from aiokafka.partitioner import murmur2
    if n_partitions <= 0:
        return 0
    return (murmur2(key) & 0x7FFFFFFF) % n_partitions


def admit(lag_by_partition: Optional[Dict[int, int]], n_partitions: int, key: bytes,
          partition_cap: int, total_cap: int) -> Tuple[bool, Optional[str]]:
    """(admitted, reason). Unknown lag admits: a monitoring failure must not become an outage."""
    if not lag_by_partition:
        return True, None
    p = partition_for(key, n_partitions or (max(lag_by_partition) + 1))
    mine = int(lag_by_partition.get(p, 0))
    if partition_cap and mine > partition_cap:
        return False, f"partition {p} lag {mine} exceeds limit {partition_cap}"
    total = sum(int(v) for v in lag_by_partition.values())
    if total_cap and total > total_cap:
        return False, f"consumer lag {total} exceeds limit {total_cap}"
    return True, None
