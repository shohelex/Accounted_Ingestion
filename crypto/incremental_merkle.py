from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable


LEAF_DOMAIN = b"\x00"
INTERNAL_DOMAIN = b"\x01"


def _hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + data).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(INTERNAL_DOMAIN + left + right).digest()


def canonicalize(payload: object) -> bytes:
    """Stable byte encoding for arbitrary JSON-serializable payloads."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


@dataclass
class _Peak:
    """One mountain in the MMR: a perfect binary subtree of given height."""
    hash: bytes
    height: int  # 0 = single leaf, h = perfect tree with 2^h leaves


@dataclass
class IncrementalMerkleLog:
    """``leaves``: leaf hashes in append order. ``peaks``: one per set bit of the size, largest
    first; the root bags them."""

    leaves: list[bytes] = field(default_factory=list)
    peaks: list[_Peak] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.leaves)

    @classmethod
    def from_leaf_hashes(cls, hashes: Iterable[bytes]) -> "IncrementalMerkleLog":
        """Rebuild the log from stored leaf hashes (not payloads)."""
        log = cls()
        for leaf_hash in hashes:
            log._push(leaf_hash)
        return log

    def _push(self, leaf_hash: bytes) -> None:
        self.leaves.append(leaf_hash)
        # Merge peaks of equal height, as in binary carry.
        carry = _Peak(hash=leaf_hash, height=0)
        while self.peaks and self.peaks[-1].height == carry.height:
            top = self.peaks.pop()
            carry = _Peak(hash=_hash_internal(top.hash, carry.hash), height=carry.height + 1)
        self.peaks.append(carry)

    def append(self, data: bytes | object) -> bytes:
        """Append one event; return the new leaf hash."""
        leaf_hash = _hash_leaf(data if isinstance(data, bytes) else canonicalize(data))
        self._push(leaf_hash)
        return leaf_hash

    def extend(self, payloads: Iterable[bytes | object]) -> None:
        for p in payloads:
            self.append(p)

    def root(self) -> bytes:
        """Bag the peaks right to left: root = H(p0, H(p1, ... p[k-1])). For a power-of-two size
        this is the perfect-tree root."""
        if not self.peaks:
            return b""
        if len(self.peaks) == 1:
            return self.peaks[0].hash
        acc = self.peaks[-1].hash
        for p in reversed(self.peaks[:-1]):
            acc = _hash_internal(p.hash, acc)
        return acc

    def root_hex(self) -> str:
        return self.root().hex()

    def inclusion_proof(self, index: int) -> list[tuple[bytes, str]]:
        """O(log n) inclusion proof for the leaf at ``index``: (sibling_hash, side) pairs, side
        being "left" or "right" of the running hash. Verifies against ``root()``."""
        if not 0 <= index < self.size:
            raise IndexError(f"index {index} out of range [0, {self.size})")

        proof: list[tuple[bytes, str]] = []

        # Path inside the peak that holds the leaf.
        sizes = [1 << p.height for p in self.peaks]
        offset = 0
        peak_idx = 0
        for i, sz in enumerate(sizes):
            if index < offset + sz:
                peak_idx = i
                break
            offset += sz
        local_idx = index - offset
        peak_height = self.peaks[peak_idx].height
        leaves_in_peak = self.leaves[offset:offset + (1 << peak_height)]
        proof.extend(_perfect_subtree_proof(leaves_in_peak, local_idx))

        # Then the bag fold: the smaller peaks to the right, folded into one hash, and then each
        # larger peak to the left, nearest first.
        right_peaks = self.peaks[peak_idx + 1:]
        left_peaks = self.peaks[:peak_idx]

        if right_peaks:
            composite = right_peaks[-1].hash
            for p in reversed(right_peaks[:-1]):
                composite = _hash_internal(p.hash, composite)
            proof.append((composite, "right"))

        for p in reversed(left_peaks):
            proof.append((p.hash, "left"))

        return proof


def verify_inclusion(leaf_hash: bytes, proof: list[tuple[bytes, str]],
                     expected_root: bytes) -> bool:
    """Verify an inclusion proof from ``IncrementalMerkleLog``. ``leaf_hash`` is the leaf hash
    that ``append`` returned, not the payload."""
    running = leaf_hash
    for sibling, side in proof:
        if side == "right":
            running = _hash_internal(running, sibling)
        elif side == "left":
            running = _hash_internal(sibling, running)
        else:
            raise ValueError(f"invalid side: {side!r}")
    return running == expected_root


def _perfect_subtree_proof(leaves: list[bytes], index: int) -> list[tuple[bytes, str]]:
    """Inclusion proof for a leaf inside a perfect subtree, level by level."""
    proof: list[tuple[bytes, str]] = []
    level_hashes = list(leaves)
    idx = index
    while len(level_hashes) > 1:
        sibling_idx = idx ^ 1
        sibling = level_hashes[sibling_idx]
        side = "right" if (idx & 1) == 0 else "left"
        proof.append((sibling, side))
        next_level = []
        for i in range(0, len(level_hashes), 2):
            next_level.append(_hash_internal(level_hashes[i], level_hashes[i + 1]))
        level_hashes = next_level
        idx //= 2
    return proof


__all__ = [
    "IncrementalMerkleLog",
    "verify_inclusion",
    "canonicalize",
]
