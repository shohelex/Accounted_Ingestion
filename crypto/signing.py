from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ANCHOR_NS = b"acct/anchor/v1\x00"
ACK_NS = b"acct/ack/v1\x00"


def anchor_statement(tenant_id: str, n: int, record_hash_hex: str) -> bytes:
    """What an anchor signature covers: the tenant, the leaf count and the record hash (which
    commits to every other field of the record)."""
    return ANCHOR_NS + str(tenant_id).encode() + b"\x00" + str(int(n)).encode() + b"\x00" \
        + bytes.fromhex(record_hash_hex)


def ack_statement(tenant_id: str, event_id: str, leaf_hash_hex: str, accepted_at: str) -> bytes:
    """What a signed acknowledgement covers: this event, with this leaf hash, was accepted for this
    tenant at this time."""
    return ACK_NS + str(tenant_id).encode() + b"\x00" + str(event_id).encode() + b"\x00" \
        + bytes.fromhex(leaf_hash_hex) + b"\x00" + str(accepted_at).encode()


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.public_key_raw: bytes = private_key.public_key().public_bytes_raw()

    @staticmethod
    def from_seed_hex(seed_hex: str) -> "Signer":
        return Signer(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)))

    @staticmethod
    def generate() -> "Signer":
        return Signer(Ed25519PrivateKey.generate())

    @property
    def public_key_hex(self) -> str:
        return self.public_key_raw.hex()

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._key

    def sign(self, data: bytes) -> str:
        return self._key.sign(data).hex()


def verify(public_key_raw: bytes, sig_hex: Optional[str], data: bytes) -> bool:
    if not sig_hex:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


_signers: dict = {}


def get_signer(settings=None) -> Optional[Signer]:
    """The deployment's signer, or None when no seed is configured (records stay unsigned)."""
    if settings is None:
        from config import settings as _s
        settings = _s
    seed = settings.merkle_signing_seed
    if not seed:
        return None
    if seed not in _signers:
        _signers[seed] = Signer.from_seed_hex(seed)
    return _signers[seed]


def get_public_key(settings=None) -> Optional[bytes]:
    """The key signatures are checked against: the configured public key, else the signer's."""
    if settings is None:
        from config import settings as _s
        settings = _s
    pub = settings.merkle_signing_public_key
    if pub:
        return bytes.fromhex(pub)
    signer = get_signer(settings)
    return signer.public_key_raw if signer else None


__all__ = ["Signer", "verify", "anchor_statement", "ack_statement", "get_signer", "get_public_key",
           "ANCHOR_NS", "ACK_NS"]
