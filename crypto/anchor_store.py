from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from urllib.parse import unquote

logger = logging.getLogger(__name__)

GENESIS_PREV = "0" * 64

# Characters a tenant id keeps as-is in a file name or object key; everything else becomes %XX of
# its UTF-8 bytes, so the encoding is injective and no tenant's key prefix is another's.
_TENANT_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

# Tenant ids records are written for (same rule as api/ingest_rules.valid_tenant_id).
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def valid_tenant_id(tenant_id) -> bool:
    return isinstance(tenant_id, str) and _TENANT_ID.match(tenant_id) is not None


def encode_tenant(tenant_id: str) -> str:
    out = []
    for ch in str(tenant_id):
        if ch in _TENANT_SAFE:
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def decode_tenant(name: str) -> str:
    return unquote(name, encoding="utf-8", errors="strict")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


# Fields of a v2 anchor record (accounted ingestion). Each enters the record hash only when not None.
V2_FIELDS = ("v", "peaks", "seg", "pos_last", "u", "acct_from", "peaks_from")


class WriteConflict(Exception):
    """put_once found a different object already stored under the key."""

    def __init__(self, key: str):
        super().__init__(f"a different object is already stored under {key!r}")
        self.key = key


def _record_hash(tenant_id: str, n: int, root: str, ts: float,
                 prev_hash: str, witnesses=None, reached_at=None, v2: Optional[dict] = None) -> str:
    body = {"tenant_id": tenant_id, "n": n, "root": root,
            "ts": ts, "prev_hash": prev_hash}
    if witnesses:
        body["witnesses"] = [[str(t), int(n_), str(h)] for t, n_, h in witnesses]
    if reached_at is not None:
        body["reached_at"] = reached_at
    for k in V2_FIELDS:
        if v2 and v2.get(k) is not None:
            body[k] = v2[k]
    return hashlib.sha256(_canon(body)).hexdigest()


@dataclass(frozen=True)
class AnchorRecord:
    tenant_id: str
    n: int              # leaf count committed by this anchor
    root: str           # MMR root hash (hex) at leaf count n
    ts: float           # unix time the record was written
    prev_hash: str      # record_hash of the previous anchor for this tenant
    record_hash: str    # sha256 over the other fields except sig
    # [tenant_id, n, record_hash] of other tenants' heads; in the record hash when present.
    witnesses: Optional[List[List]] = None
    # Ed25519 signature by the deployment key over (tenant, n, record_hash).
    sig: Optional[str] = None
    # Unix time the tenant's log reached n leaves.
    reached_at: Optional[float] = None
    # v2 (accounted ingestion): v = 2; peaks: MMR peaks at n, [[hex, height], ...]; seg: the
    # segment [from, to) covered, {"from", "to", "sha256", "o_first", "o_last"}; pos_last:
    # {topic, p, o} of the last record; u: cumulative UNCHECKABLE verdicts; acct_from: seq of the
    # first v2 record (first v2 anchor only).
    v: Optional[int] = None
    peaks: Optional[List[List]] = None
    seg: Optional[dict] = None
    pos_last: Optional[dict] = None
    u: Optional[int] = None
    acct_from: Optional[int] = None
    # MMR peaks at seg.from, on the first v2 record when its predecessor (v1) carries no peaks.
    peaks_from: Optional[List[List]] = None

    @staticmethod
    def create(tenant_id: str, n: int, root: str, ts: float,
               prev_hash: str, witnesses=None, signer=None, reached_at=None,
               *, v=None, peaks=None, seg=None, pos_last=None, u=None,
               acct_from=None, peaks_from=None) -> "AnchorRecord":
        if not valid_tenant_id(tenant_id):
            raise ValueError(f"refusing to anchor for tenant id {tenant_id!r}: not [A-Za-z0-9][A-Za-z0-9_-]{{0,63}}")
        w = [[str(t), int(n_), str(h)] for t, n_, h in witnesses] if witnesses else None
        ra = float(reached_at) if reached_at is not None else None
        v2 = {"v": None if v is None else int(v),
              "peaks": None if peaks is None else [[str(h), int(ht)] for h, ht in peaks],
              "seg": None if seg is None else dict(seg),
              "pos_last": None if pos_last is None else dict(pos_last),
              "u": None if u is None else int(u),
              "acct_from": None if acct_from is None else int(acct_from),
              "peaks_from": None if peaks_from is None else [[str(h), int(ht)] for h, ht in peaks_from]}
        rh = _record_hash(tenant_id, n, root, ts, prev_hash, w, ra, v2)
        sig = None
        if signer is not None:
            from crypto.signing import anchor_statement
            sig = signer.sign(anchor_statement(tenant_id, n, rh))
        return AnchorRecord(tenant_id, n, root, ts, prev_hash, rh, w, sig, ra, **v2)

    def v2_fields(self) -> dict:
        return {k: getattr(self, k) for k in V2_FIELDS}

    def verify_self(self) -> bool:
        return self.record_hash == _record_hash(
            self.tenant_id, self.n, self.root, self.ts, self.prev_hash, self.witnesses,
            self.reached_at, self.v2_fields())

    def to_json(self) -> dict:
        """The stored form: every field except v2 fields that are None."""
        d = asdict(self)
        for k in V2_FIELDS:
            if d.get(k) is None:
                d.pop(k, None)
        return d

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_json(), separators=(",", ":")).encode()

    def verify_sig(self, public_key_raw: bytes) -> bool:
        from crypto.signing import anchor_statement, verify
        return verify(public_key_raw, self.sig, anchor_statement(self.tenant_id, self.n, self.record_hash))

    @staticmethod
    def parse(raw) -> "AnchorRecord":
        """A record from its stored JSON. Unknown fields raise TypeError."""
        d = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else dict(raw)
        return AnchorRecord(**d)


# Object keys of accounted ingestion. Every object is written once.
_KEY_PART = re.compile(r"^[A-Za-z0-9%_.\-]+$")


def anchor_key(tenant_id: str, n: int) -> str:
    return f"anchors/{encode_tenant(tenant_id)}/{int(n):020d}.json"


def segment_key(tenant_id: str, n: int) -> str:
    return f"segments/{encode_tenant(tenant_id)}/{int(n):020d}.json"


def blob_key(sha256_hex: str) -> str:
    return f"blobs/{sha256_hex}.bin"


def succ_key(tenant_id: str, prev_n: int) -> str:
    """The successor slot of the record at leaf count prev_n (0 for genesis): written once, by the
    anchorer that extends that record, before the record it names."""
    return f"succ/{encode_tenant(tenant_id)}/{int(prev_n):020d}.json"


def slot_body(rec: "AnchorRecord", segment_bytes: Optional[bytes]) -> bytes:
    """A successor slot: the signed record and, for a v2 record, its segment, so whoever finds the
    claim can complete it."""
    return json.dumps({"v": 1, "record": rec.to_json(),
                       "segment": None if segment_bytes is None else segment_bytes.decode("ascii")},
                      sort_keys=True, separators=(",", ":")).encode()


def parse_slot(raw: bytes) -> "tuple[AnchorRecord, Optional[bytes]]":
    """(record, segment bytes or None) from a slot's bytes. Raises ValueError/TypeError on bytes
    that are not a slot."""
    d = json.loads(raw)
    if not isinstance(d, dict) or d.get("v") != 1 or not isinstance(d.get("record"), dict):
        raise ValueError("not a successor slot")
    seg = d.get("segment")
    return AnchorRecord.parse(d["record"]), (seg.encode("ascii") if isinstance(seg, str) else None)


def same_record(existing: Optional[bytes], rec: "AnchorRecord") -> bool:
    """Is the stored object `existing` the record rec? Compared as records: a record read back from
    a successor slot can have its nested keys in another order."""
    if existing is None:
        return False
    if existing == rec.to_bytes():
        return True
    try:
        return AnchorRecord.parse(existing) == rec
    except Exception:
        return False


def check_object_key(key: str) -> str:
    """A relative key of safe characters with no empty, '.' or '..' part."""
    parts = str(key).split("/")
    if not key or any(p in ("", ".", "..") or not _KEY_PART.match(p) for p in parts):
        raise ValueError(f"not a valid object key: {key!r}")
    return key


def _anchor_key_n(key: str):
    """(encoded tenant, n) when key names an anchor record, else None."""
    parts = key.split("/")
    if len(parts) == 3 and parts[0] == "anchors" and len(parts[2]) == 25 \
            and parts[2].endswith(".json") and parts[2][:20].isdigit():
        return parts[1], int(parts[2][:20])
    return None


class AnchorStore:
    """Abstract append-only anchor store: per-tenant anchor chains and write-once objects
    (segments, blobs, statements, contracts). Anchor records are also readable under anchor_key."""

    # The deployment's signer (crypto.signing.Signer); records are signed when it is set.
    signer = None
    # The key a record must verify under to be adopted as a chain head; None falls back to the
    # signer's public key, and with neither only the record hash is checked.
    verify_key: Optional[bytes] = None
    # Records skipped with an INTEGRITY ALARM.
    rejected_records = 0

    def anchor(self, tenant_id: str, n: int, root: str,
               ts: Optional[float] = None, prev_hash: Optional[str] = None,
               witnesses=None, reached_at: Optional[float] = None,
               *, v=None, peaks=None, seg=None, pos_last=None, u=None,
               acct_from=None, peaks_from=None) -> AnchorRecord:
        """Append an anchor. prev_hash chains it explicitly; None uses this process's cache, which
        is only correct for a sole writer. A v2 record (v set) is written once: a second record at
        the same n raises WriteConflict."""
        raise NotImplementedError

    def _new_record(self, tenant_id, n, root, ts, prev_hash, witnesses, reached_at,
                    **v2) -> AnchorRecord:
        """The signed record anchor() writes."""
        ts = time.time() if ts is None else ts
        prev = prev_hash if prev_hash is not None else self._prev_hash(tenant_id)
        return AnchorRecord.create(tenant_id, n, root, ts, prev, witnesses, self.signer, reached_at,
                                   **v2)

    def build_record(self, tenant_id: str, n: int, root: str, prev_hash: str,
                     reached_at: Optional[float] = None, ts: Optional[float] = None,
                     **v2) -> AnchorRecord:
        """A signed record, not yet written (put_record writes it)."""
        return AnchorRecord.create(tenant_id, n, root, time.time() if ts is None else ts, prev_hash,
                                   None, self.signer, reached_at, **v2)

    def put_record(self, rec: AnchorRecord) -> AnchorRecord:
        """Write a built record under anchor_key(t, n), once. An identical record already there is
        fine; a different one raises WriteConflict."""
        raise NotImplementedError

    def records_after(self, tenant_id: str, n: int) -> List[AnchorRecord]:
        """The records with leaf count above n, in n order, unverified."""
        return sorted((r for r in self.all(tenant_id) if int(r.n) > int(n)), key=lambda r: int(r.n))

    # Write-once objects.

    def _obj_create(self, key: str, data: bytes) -> Optional[bytes]:
        """Create the object if the key is free and return None; otherwise return the bytes of the
        object stored under the key first (and write nothing)."""
        raise NotImplementedError

    def _obj_get(self, key: str) -> Optional[bytes]:
        raise NotImplementedError

    def _obj_list(self, prefix: str) -> List[str]:
        raise NotImplementedError

    def put_once(self, key: str, data: bytes) -> bool:
        """Write data under key if no object is there. True: written. False: an identical object
        already exists (the write is idempotent). WriteConflict: a different object exists."""
        check_object_key(key)
        if _anchor_key_n(key) is not None:
            raise ValueError("anchor records are written by anchor(), not put_once")
        data = bytes(data)
        existing = self._obj_create(key, data)
        if existing is None:
            return True
        if existing == data:
            return False
        raise WriteConflict(key)

    def get_object(self, key: str) -> Optional[bytes]:
        """The bytes written first under key, or None."""
        check_object_key(key)
        return self._obj_get(key)

    def list_keys(self, prefix: str) -> List[str]:
        """Keys starting with prefix, sorted."""
        return sorted(k for k in self._obj_list(prefix) if k.startswith(prefix))

    def segment(self, tenant_id: str, n: int) -> Optional[dict]:
        """The segment stored for the anchor at n, parsed. Its hash is not checked here."""
        raw = self.get_object(segment_key(tenant_id, n))
        if raw is None:
            return None
        try:
            d = json.loads(raw)
        except ValueError:
            return None
        return d if isinstance(d, dict) else None

    def _anchor_object(self, key: str) -> Optional[bytes]:
        """The bytes of the record at an anchor key, from the tenant's chain, for backends that keep
        anchors outside the object namespace."""
        tn = _anchor_key_n(key)
        if tn is None:
            return None
        try:
            tenant_id = decode_tenant(tn[0])
        except Exception:
            return None
        rec = self._exact(tenant_id, tn[1])
        return rec.to_bytes() if rec is not None else None

    # Records the store holds that are not ours.
    def _key_for_checks(self) -> Optional[bytes]:
        if self.verify_key is not None:
            return self.verify_key
        return self.signer.public_key_raw if self.signer is not None else None

    def acceptable(self, tenant_id: str, rec: Optional[AnchorRecord], n: Optional[int] = None) -> bool:
        """Could the deployment have written this record here? Tenant and leaf count match, its
        hash verifies and, with a key, so does its signature."""
        if rec is None or rec.tenant_id != tenant_id or (n is not None and int(rec.n) != int(n)):
            return False
        try:
            if not rec.verify_self():
                return False
        except Exception:
            return False
        key = self._key_for_checks()
        return key is None or rec.verify_sig(key)

    def _reject(self, tenant_id: str, where: str, why: str) -> None:
        self.rejected_records += 1
        logger.error(f"INTEGRITY ALARM [store]: {where} for tenant {tenant_id!r} ignored: {why}")

    def tenants(self) -> List[str]:
        """Every tenant with at least one anchor in the store."""
        raise NotImplementedError

    def latest(self, tenant_id: str) -> Optional[AnchorRecord]:
        raise NotImplementedError

    def all(self, tenant_id: str) -> List[AnchorRecord]:
        raise NotImplementedError

    def latest_after(self, tenant_id: str, n: int) -> Optional[AnchorRecord]:
        """The highest acceptable anchor with leaf count greater than n, or None. Records that are
        not acceptable are skipped with an alarm."""
        newer = sorted((r for r in self.all(tenant_id) if r.n > n), key=lambda r: -r.n)
        for r in newer:
            if self.acceptable(tenant_id, r):
                return r
            self._reject(tenant_id, f"record at n={r.n}", "fails its hash or signature")
        return None

    def first_at_or_after(self, tenant_id: str, n: int) -> Optional[AnchorRecord]:
        """The lowest acceptable anchor with leaf count at least n: the first that covers leaf n - 1."""
        later = sorted((r for r in self.all(tenant_id) if r.n >= n), key=lambda r: r.n)
        for r in later:
            if self.acceptable(tenant_id, r):
                return r
            self._reject(tenant_id, f"record at n={r.n}", "fails its hash or signature")
        return None

    def verify_chain(self, tenant_id: str, public_key: Optional[bytes] = None) -> bool:
        """Verify the per-tenant hash chain end to end; with a public key, every signature too."""
        prev = GENESIS_PREV
        for rec in self.all(tenant_id):
            if not rec.verify_self() or rec.prev_hash != prev:
                return False
            if public_key is not None and not rec.verify_sig(public_key):
                return False
            prev = rec.record_hash
        return True

    def _exact(self, tenant_id: str, n: int) -> Optional[AnchorRecord]:
        for rec in self.all(tenant_id):
            if rec.n == n:
                return rec
        return None

    def _prev_hash(self, tenant_id: str) -> str:
        """Record hash of the previous anchor, cached from this process's own writes so that an
        anchor does not re-read the history. Correct only for a sole writer; the ingest path
        passes prev_hash from the chain tip in the database instead."""
        cached = self._last_record_hash.get(tenant_id)
        if cached is not None:
            return cached
        last = self.latest(tenant_id)
        return last.record_hash if last else GENESIS_PREV

    def _remember(self, tenant_id: str, rec: "AnchorRecord") -> "AnchorRecord":
        self._last_record_hash[tenant_id] = rec.record_hash
        return rec

    @property
    def _last_record_hash(self) -> dict:
        cache = getattr(self, "_lrh_cache", None)
        if cache is None:
            cache = {}
            self._lrh_cache = cache
        return cache


class InMemoryAnchorStore(AnchorStore):
    """Non-persistent backend, for tests."""

    def __init__(self):
        self._by_tenant: dict[str, List[AnchorRecord]] = {}
        self._objects: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def anchor(self, tenant_id, n, root, ts=None, prev_hash=None, witnesses=None, reached_at=None,
               **v2):
        rec = self._new_record(tenant_id, n, root, ts, prev_hash, witnesses, reached_at, **v2)
        with self._lock:
            if rec.v is not None and self._exact(tenant_id, n) is not None:
                raise WriteConflict(anchor_key(tenant_id, n))
            self._by_tenant.setdefault(tenant_id, []).append(rec)
        return self._remember(tenant_id, rec)

    def put_record(self, rec):
        with self._lock:
            have = self._exact(rec.tenant_id, int(rec.n))
            if have is not None:
                if have != rec:
                    raise WriteConflict(anchor_key(rec.tenant_id, rec.n))
                return have
            recs = self._by_tenant.setdefault(rec.tenant_id, [])
            recs.append(rec)
            recs.sort(key=lambda r: int(r.n))
        return self._remember(rec.tenant_id, rec)

    def _obj_create(self, key, data):
        with self._lock:
            if key in self._objects:
                return self._objects[key]
            self._objects[key] = data
            return None

    def _obj_get(self, key):
        if _anchor_key_n(key) is not None:
            return self._anchor_object(key)
        return self._objects.get(key)

    def _obj_list(self, prefix):
        keys = [k for k in self._objects if k.startswith(prefix)]
        if "anchors/".startswith(prefix) or prefix.startswith("anchors/"):
            for t, recs in self._by_tenant.items():
                keys.extend(k for k in {anchor_key(t, r.n) for r in recs} if k.startswith(prefix))
        return keys

    def tenants(self):
        return list(self._by_tenant)

    def latest(self, tenant_id):
        recs = self._by_tenant.get(tenant_id)
        return recs[-1] if recs else None

    def all(self, tenant_id):
        return list(self._by_tenant.get(tenant_id, []))


class LocalWORMAnchorStore(AnchorStore):
    """Append-only, hash-chained JSONL anchor store on the local filesystem: one file per tenant,
    <dir>/anchor_<tenant>.jsonl, each record appended and fsync'd. Write-once objects live under
    <dir>/objects/."""

    def __init__(self, directory: str, fsync: bool = True):
        self.dir = directory
        self.fsync = fsync
        os.makedirs(self.dir, exist_ok=True)
        self._cache: dict[str, List[AnchorRecord]] = {}

    def _path(self, tenant_id: str) -> str:
        return os.path.join(self.dir, f"anchor_{encode_tenant(tenant_id)}.jsonl")

    def _load(self, tenant_id: str) -> List[AnchorRecord]:
        # Reads the file every time; other processes append to it.
        recs: List[AnchorRecord] = []
        path = self._path(tenant_id)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            recs.append(AnchorRecord.parse(line))
                        except Exception as e:
                            self._reject(tenant_id, "an unparsable line", str(e)[:100])
        # A write-once record is created as an object first and appended to the chain file second;
        # after a crash between the two, the object is the record at n.
        orphans = self._orphan_records(tenant_id, {int(r.n) for r in recs})
        if orphans:
            recs = sorted(recs + orphans, key=lambda r: int(r.n))
        self._cache[tenant_id] = recs
        return recs

    def _anchor_object_ns(self, tenant_id: str) -> List[int]:
        d = os.path.join(self.dir, "objects", "anchors", encode_tenant(tenant_id))
        try:
            names = os.listdir(d)
        except OSError:
            return []
        return sorted(int(x[:20]) for x in names
                      if len(x) == 25 and x.endswith(".json") and x[:20].isdigit())

    def _orphan_records(self, tenant_id: str, have: set) -> List[AnchorRecord]:
        out = []
        for n in self._anchor_object_ns(tenant_id):
            if n in have:
                continue
            try:
                with open(self._obj_path(anchor_key(tenant_id, n)), "rb") as f:
                    rec = AnchorRecord.parse(f.read())
            except Exception as e:
                self._reject(tenant_id, f"anchor object at n={n}", str(e)[:100])
                continue
            if rec.tenant_id == tenant_id and int(rec.n) == n:
                out.append(rec)
        return out

    def tenants(self):
        out = []
        for name in sorted(os.listdir(self.dir)):
            if name.startswith("anchor_") and name.endswith(".jsonl"):
                out.append(decode_tenant(name[len("anchor_"):-len(".jsonl")]))
        # a tenant whose only record is an object without its chain line (see _load)
        objs = os.path.join(self.dir, "objects", "anchors")
        if os.path.isdir(objs):
            for name in sorted(os.listdir(objs)):
                try:
                    t = decode_tenant(name)
                except Exception:
                    continue
                if t not in out and self._anchor_object_ns(t):
                    out.append(t)
        return out

    def _obj_path(self, key: str) -> str:
        return os.path.join(self.dir, "objects", *key.split("/"))

    def _obj_create(self, key, data):
        path = self._obj_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            # Written to a temporary name and then linked: exactly one writer creates the file, and
            # a reader never sees a partly written object.
            tmp = f"{path}.{os.getpid()}.{time.time_ns()}.tmp"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                if self.fsync:
                    os.fsync(f.fileno())
            try:
                os.link(tmp, path)
            finally:
                os.unlink(tmp)
            return None
        except FileExistsError:
            with open(path, "rb") as f:
                return f.read()

    def _obj_get(self, key):
        path = self._obj_path(key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        if _anchor_key_n(key) is not None:
            return self._anchor_object(key)
        return None

    def _obj_list(self, prefix):
        root = os.path.join(self.dir, "objects")
        out = []
        for dirpath, _, files in os.walk(root):
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
            for name in files:
                if name.endswith(".tmp"):
                    continue
                key = name if rel == "." else f"{rel}/{name}"
                if key.startswith(prefix):
                    out.append(key)
        if "anchors/".startswith(prefix) or prefix.startswith("anchors/"):
            for t in self.tenants():
                out.extend(k for k in (anchor_key(t, r.n) for r in self._load(t)) if k.startswith(prefix))
        return sorted(set(out))

    def anchor(self, tenant_id, n, root, ts=None, prev_hash=None, witnesses=None, reached_at=None,
               **v2):
        rec = self._new_record(tenant_id, n, root, ts, prev_hash, witnesses, reached_at, **v2)
        if rec.v is not None:
            return self.put_record(rec)
        self._append_line(tenant_id, rec)
        return self._remember(tenant_id, rec)

    def put_record(self, rec):
        # The object is created first, then the chain line. If the object exists, its creator may
        # have died before appending: the line is completed here.
        key = anchor_key(rec.tenant_id, rec.n)
        existing = self._obj_create(key, rec.to_bytes())
        if existing is not None:
            self._complete_line(rec.tenant_id, int(rec.n), existing)
            if not same_record(existing, rec):
                raise WriteConflict(key)
            return self._remember(rec.tenant_id, rec)
        self._append_line(rec.tenant_id, rec)
        return self._remember(rec.tenant_id, rec)

    def _complete_line(self, tenant_id: str, n: int, raw: bytes) -> None:
        try:
            have = AnchorRecord.parse(raw)
        except Exception:
            return
        if have.tenant_id != tenant_id or int(have.n) != n:
            return
        path = self._path(tenant_id)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        if line.strip() and int(json.loads(line)["n"]) == n:
                            return
                    except (ValueError, KeyError, TypeError):
                        continue
        self._append_line(tenant_id, have)

    def _append_line(self, tenant_id: str, rec: AnchorRecord) -> None:
        with open(self._path(tenant_id), "a", encoding="utf-8") as f:
            f.write(rec.to_bytes().decode() + "\n")
            f.flush()
            if self.fsync:
                os.fsync(f.fileno())

    def latest(self, tenant_id):
        recs = self._load(tenant_id)
        return recs[-1] if recs else None

    def all(self, tenant_id):
        return list(self._load(tenant_id))

    def latest_after(self, tenant_id, n):
        """Reads only the file's last line (the highest anchor); falls back to the full read when
        that line is not acceptable or a newer record object exists."""
        try:
            rec = self._last_record(tenant_id)
        except Exception:
            rec = None
        else:
            objs = self._anchor_object_ns(tenant_id)
            if objs and (rec is None or objs[-1] > int(rec.n)):
                return super().latest_after(tenant_id, n)
            if rec is None:
                return None
            if self.acceptable(tenant_id, rec):
                return rec if rec.n > n else None
        return super().latest_after(tenant_id, n)

    def _last_record(self, tenant_id) -> Optional[AnchorRecord]:
        path = self._path(tenant_id)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, 65536)          # records are a few hundred bytes
            f.seek(size - block)
            tail = f.read(block)
        # Every record ends with a newline, so the last element is complete.
        lines = [ln for ln in tail.split(b"\n") if ln.strip()]
        return AnchorRecord.parse(lines[-1]) if lines else None


class S3ObjectLockAnchorStore(AnchorStore):
    """One immutable S3 object per anchor under Object Lock (WORM) retention. Needs boto3 and a
    bucket with Object Lock enabled; endpoint_url allows S3-compatible stores such as MinIO.

    Object key: ``anchors/<encode_tenant(tenant)>/<n:020d>.json``.
    """

    def __init__(self, bucket: str, prefix: str = "anchors",
                 retention_days: int = 3650, mode: str = "COMPLIANCE",
                 region: Optional[str] = None, endpoint_url: Optional[str] = None):
        import boto3
        self.bucket = bucket
        self.prefix = prefix
        self.retention_days = retention_days
        self.mode = mode
        # Short timeouts and few retries: anchoring is in the append path, and a failed anchor
        # stays pending and is retried later.
        from botocore.config import Config
        self._s3 = boto3.client(
            "s3", region_name=region, endpoint_url=endpoint_url,
            config=Config(
                max_pool_connections=int(os.environ.get("ANCHOR_S3_MAX_POOL", "128")),
                connect_timeout=float(os.environ.get("ANCHOR_S3_CONNECT_TIMEOUT_S", "2")),
                read_timeout=float(os.environ.get("ANCHOR_S3_READ_TIMEOUT_S", "10")),
                retries={"max_attempts": int(os.environ.get("ANCHOR_S3_MAX_ATTEMPTS", "2")),
                         "mode": "standard"}))

    def _key(self, tenant_id: str, n: int) -> str:
        return f"{self._tenant_prefix(tenant_id)}{n:020d}.json"

    def _tenant_prefix(self, tenant_id: str) -> str:
        return f"{self.prefix}/{encode_tenant(tenant_id)}/"

    def _n_of_key(self, tenant_id: str, key: str) -> Optional[int]:
        """The leaf count a key names, or None if it is not a key this store writes."""
        prefix = self._tenant_prefix(tenant_id)
        rest = key[len(prefix):] if key.startswith(prefix) else ""
        if len(rest) != 25 or not rest.endswith(".json") or not rest[:20].isdigit():
            return None
        return int(rest[:20])

    def tenants(self):
        out = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=f"{self.prefix}/", Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                out.append(decode_tenant(cp["Prefix"][len(self.prefix) + 1:].rstrip("/")))
        return out

    def anchor(self, tenant_id, n, root, ts=None, prev_hash=None, witnesses=None, reached_at=None,
               **v2):
        rec = self._new_record(tenant_id, n, root, ts, prev_hash, witnesses, reached_at, **v2)
        if rec.v is not None:
            return self.put_record(rec)
        self._put_locked(self._key(tenant_id, n), rec.to_bytes(), if_absent=False)
        return self._remember(tenant_id, rec)

    def put_record(self, rec):
        # Written once. A conflicting earlier record at this n wins, whoever wrote it.
        existing = self._put_locked(self._key(rec.tenant_id, rec.n), rec.to_bytes(), if_absent=True)
        if existing is not None and not same_record(existing, rec):
            raise WriteConflict(anchor_key(rec.tenant_id, rec.n))
        return self._remember(rec.tenant_id, rec)

    def records_after(self, tenant_id, n):
        """Lists only the keys after n's and reads only their retained versions."""
        marker = self._key(tenant_id, n) if n is not None and n >= 0 else ""
        out = []
        for key, versions in self._versions_after(tenant_id, marker):
            rec = self._retained_record(key, versions, tenant_id, require_acceptable=False)
            if rec is not None:
                out.append(rec)
        return sorted(out, key=lambda r: int(r.n))

    # A failed retention read or GET of one version means "not the committed version", unless the
    # store did not answer (5xx, throttling, timeout, lost connection): that is raised, so an outage
    # is never read as an absent record.
    _OUTAGE_CODES = frozenset({"SlowDown", "ServiceUnavailable", "InternalError", "RequestTimeout",
                               "Throttling", "ThrottlingException", "RequestLimitExceeded",
                               "XMinioServerNotInitialized", "503", "500", "429"})
    _OUTAGE_CLASSES = frozenset({"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
                                 "ConnectionClosedError", "ProxyConnectionError", "SSLError",
                                 "HTTPClientError", "ProtocolError", "NewConnectionError"})

    @classmethod
    def _store_outage(cls, e: BaseException) -> bool:
        if isinstance(e, (ConnectionError, TimeoutError)):
            return True
        if type(e).__name__ in cls._OUTAGE_CLASSES:
            return True
        resp = getattr(e, "response", None)
        if isinstance(resp, dict):
            code = str((resp.get("Error") or {}).get("Code", ""))
            status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
            if code in cls._OUTAGE_CODES:
                return True
            if isinstance(status, int) and (status >= 500 or status == 429):
                return True
        return False

    # Skip the version listing after a successful conditional PUT (see _put_locked).
    trust_conditional_put = os.environ.get("ANCHOR_S3_TRUST_CONDITIONAL_PUT", "").strip().lower() \
        in ("1", "true", "yes")

    def _put_locked(self, full_key: str, data: bytes, if_absent: bool) -> Optional[bytes]:
        """PUT under Object Lock retention. With if_absent the PUT is conditional (If-None-Match)
        and returns None when this PUT created the object, else the bytes retained first.
        If-None-Match tests only the current version and a delete marker can hide a retained one,
        so a created object is confirmed by a version listing, unless trust_conditional_put is set
        (safe only when the bucket policy denies versionless DeleteObject on these keys)."""
        retain_until = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        kwargs = dict(Bucket=self.bucket, Key=full_key, Body=data, ObjectLockMode=self.mode,
                      ObjectLockRetainUntilDate=retain_until,
                      ContentType="application/json" if full_key.endswith(".json")
                      else "application/octet-stream")
        if not if_absent:
            self._s3.put_object(**kwargs)
            return None
        created, resp = True, None
        try:
            resp = self._s3.put_object(IfNoneMatch="*", **kwargs)
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if code not in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
                raise
            created = False
        if created:
            if self.trust_conditional_put:
                return None
            vid = resp.get("VersionId") if isinstance(resp, dict) else None
            if vid and self._only_version(full_key, vid):
                return None
        first = self._retained_bytes(full_key)
        if first is None and not created:
            # An unretained object blocks the key: report it as a conflict.
            first = self._s3.get_object(Bucket=self.bucket, Key=full_key)["Body"].read()
        if created and (first is None or first == data):
            return None
        return first if first is not None else data

    def _only_version(self, full_key: str, version_id: str) -> bool:
        """Is version_id the key's only version, with no delete marker? One listing page."""
        versions, markers = [], []
        for page in self._s3.get_paginator("list_object_versions").paginate(
                Bucket=self.bucket, Prefix=full_key):
            versions.extend(v for v in page.get("Versions", []) if v["Key"] == full_key)
            markers.extend(m for m in page.get("DeleteMarkers", []) if m.get("Key") == full_key)
        return not markers and [v.get("VersionId") for v in versions] == [version_id]

    def _retained_bytes(self, full_key: str) -> Optional[bytes]:
        """The oldest version of an object that carries a retention lock."""
        versions = []
        for page in self._s3.get_paginator("list_object_versions").paginate(
                Bucket=self.bucket, Prefix=full_key):
            versions.extend(v for v in page.get("Versions", []) if v["Key"] == full_key)
        for ver in sorted(versions, key=lambda v: v["LastModified"]):
            try:
                self._s3.get_object_retention(Bucket=self.bucket, Key=full_key,
                                              VersionId=ver["VersionId"])
            except Exception as e:
                if self._store_outage(e):
                    raise
                continue
            return self._s3.get_object(Bucket=self.bucket, Key=full_key,
                                       VersionId=ver["VersionId"])["Body"].read()
        return None

    def _full_key(self, key: str) -> str:
        """Object keys live beside the anchor prefix: prefix "anchors" puts segments/... at the
        bucket root, prefix "x/anchors" puts them under x/. Anchor keys map onto the prefix."""
        if key.startswith("anchors/"):
            return f"{self.prefix}/{key[len('anchors/'):]}"
        root = self.prefix.rsplit("/", 1)[0] + "/" if "/" in self.prefix else ""
        return root + key

    def _obj_create(self, key, data):
        return self._put_locked(self._full_key(key), data, if_absent=True)

    def _obj_get(self, key):
        return self._retained_bytes(self._full_key(key))

    def _rel_key(self, full_key: str) -> str:
        if full_key.startswith(self.prefix + "/"):
            return "anchors/" + full_key[len(self.prefix) + 1:]
        root = self.prefix.rsplit("/", 1)[0] + "/" if "/" in self.prefix else ""
        return full_key[len(root):] if full_key.startswith(root) else full_key

    def _obj_list(self, prefix):
        # A listed key may hold only an unretained object, which get_object does not return.
        full = self._full_key(prefix) if prefix else (
            self.prefix.rsplit("/", 1)[0] + "/" if "/" in self.prefix else "")
        out = set()
        for page in self._s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=full):
            for obj in page.get("Contents", []):
                out.add(self._rel_key(obj["Key"]))
        return list(out)

    def all(self, tenant_id):
        """The retained version of every anchor, not the current one: Object Lock protects a
        version, not a key. A locked record with a bad hash or signature is returned, so the audit
        reports it; objects the deployment cannot have written are skipped and counted."""
        recs: List[AnchorRecord] = []
        by_key: dict = {}
        paginator = self._s3.get_paginator("list_object_versions")
        for page in paginator.paginate(
                Bucket=self.bucket, Prefix=self._tenant_prefix(tenant_id)):
            for ver in page.get("Versions", []):
                by_key.setdefault(ver["Key"], []).append(ver)

        for key, versions in by_key.items():
            rec = self._retained_record(key, versions, tenant_id, require_acceptable=False)
            if rec is not None:
                recs.append(rec)
        recs.sort(key=lambda r: r.n)
        return recs

    def _retained_record(self, key, versions, tenant_id: str,
                         require_acceptable: bool = True) -> Optional[AnchorRecord]:
        """The committed anchor under a key: the oldest locked version whose body is a record for
        this tenant and n (and, with require_acceptable, verifies). A planted earlier version does
        not shadow the honest one. None, with an alarm, when no version qualifies."""
        n_key = self._n_of_key(tenant_id, key)
        if n_key is None:
            self._reject(tenant_id, f"object {key}", "not a key this store writes")
            return None
        fallback = None
        for ver in sorted(versions, key=lambda v: v["LastModified"]):
            try:
                self._s3.get_object_retention(
                    Bucket=self.bucket, Key=key, VersionId=ver["VersionId"])
                body = self._s3.get_object(
                    Bucket=self.bucket, Key=key, VersionId=ver["VersionId"])["Body"].read()
            except Exception as e:
                if self._store_outage(e):
                    raise
                continue
            try:
                rec = AnchorRecord.parse(body)
            except Exception:
                continue
            if rec.tenant_id != tenant_id or int(rec.n) != n_key:
                continue
            if self.acceptable(tenant_id, rec, n_key):
                return rec
            if fallback is None:
                fallback = rec
        if fallback is not None and not require_acceptable:
            return fallback
        self._reject(tenant_id, f"object {key}",
                     "no retained version is a valid record for this key" if fallback is not None
                     else "no retained version holds a record for this key")
        return None

    def _versions_after(self, tenant_id, marker):
        """(key, versions) for every key after marker, in key order."""
        kwargs = {"Bucket": self.bucket, "Prefix": self._tenant_prefix(tenant_id)}
        if marker:
            kwargs["KeyMarker"] = marker
        cur, vers = None, []
        for page in self._s3.get_paginator("list_object_versions").paginate(**kwargs):
            for ver in page.get("Versions", []):
                if ver["Key"] <= marker:
                    continue
                if ver["Key"] != cur:
                    if cur is not None:
                        yield cur, vers
                    cur, vers = ver["Key"], []
                vers.append(ver)
        if cur is not None:
            yield cur, vers

    def first_at_or_after(self, tenant_id, n):
        """Lowest acceptable anchor at or above n, listing only keys after (n - 1)'s."""
        marker = self._key(tenant_id, n - 1) if n >= 1 else ""
        for key, versions in self._versions_after(tenant_id, marker):
            rec = self._retained_record(key, versions, tenant_id)
            if rec is not None:
                return rec
        return None

    def latest_after(self, tenant_id, n):
        """Highest acceptable anchor above n, listing only keys after n's (zero-padded, so key
        order is n order). Keys that are not our records are skipped with an alarm."""
        marker = self._key(tenant_id, n) if n is not None and n >= 0 else ""
        keys = list(self._versions_after(tenant_id, marker))
        for key, versions in reversed(keys):
            rec = self._retained_record(key, versions, tenant_id)
            if rec is not None:
                return rec
        return None

    def latest(self, tenant_id):
        recs = self.all(tenant_id)
        return recs[-1] if recs else None


def get_anchor_store(settings=None) -> Optional[AnchorStore]:
    """The store the settings describe, or None if anchoring is disabled."""
    if settings is None:
        from config import settings
    if not settings.merkle_anchor_enabled:
        return None
    if settings.merkle_anchor_backend == "s3":
        store = S3ObjectLockAnchorStore(
            bucket=settings.merkle_anchor_s3_bucket,
            prefix=settings.merkle_anchor_s3_prefix,
            retention_days=settings.merkle_anchor_retention_days,
            region=settings.aws_region,
            endpoint_url=settings.merkle_anchor_s3_endpoint_url,
        )
    else:
        store = LocalWORMAnchorStore(settings.merkle_anchor_dir)
    from crypto.signing import get_public_key, get_signer
    store.signer = get_signer(settings)
    store.verify_key = get_public_key(settings)
    return store


__all__ = [
    "AnchorRecord", "AnchorStore", "InMemoryAnchorStore",
    "LocalWORMAnchorStore", "S3ObjectLockAnchorStore", "get_anchor_store",
    "encode_tenant", "decode_tenant", "valid_tenant_id",
    "WriteConflict", "anchor_key", "segment_key", "blob_key", "check_object_key", "V2_FIELDS",
]
