from __future__ import annotations

import ipaddress
import math
import re
import weakref
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

# A tenant id is a Kafka key, part of event and tree ids, and a path component and key prefix in
# the anchor stores, so '/' and '.' are not allowed.
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def valid_tenant_id(tenant_id: Any) -> bool:
    return isinstance(tenant_id, str) and _TENANT_ID.match(tenant_id) is not None


def unstorable_string(value: Any, path: str = "$") -> Optional[str]:
    """The path of the first string (key or value) that cannot be encoded as UTF-8, or None.
    JSON may carry a lone surrogate ("\\ud800"), which the Neo4j driver cannot encode."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return path
        return None
    if isinstance(value, Mapping):
        for k, v in value.items():
            bad = unstorable_string(k, f"{path}.<key>") if isinstance(k, str) else None
            if bad is None:
                bad = unstorable_string(v, f"{path}.{k!s}" if _printable(k) else f"{path}.<key>")
            if bad is not None:
                return bad
        return None
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            bad = unstorable_string(v, f"{path}[{i}]")
            if bad is not None:
                return bad
    return None


def _printable(k: Any) -> bool:
    try:
        str(k).encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


INT64_MIN, INT64_MAX = -(1 << 63), (1 << 63) - 1


def unrepresentable_value(value: Any, max_depth: int = 64) -> Optional[str]:
    """Why a decoded event cannot be recorded as it is, or None: a NaN or infinite number, an
    integer outside int64, or nesting deeper than max_depth (counted as the record validator
    counts it: the object is level 1)."""
    stack = [(value, "$", 1)]
    while stack:
        v, path, d = stack.pop()
        if d > max_depth:
            return f"nesting deeper than {max_depth} levels at {path}"
        if isinstance(v, bool) or v is None or isinstance(v, str):
            continue
        if isinstance(v, int):
            if not INT64_MIN <= v <= INT64_MAX:
                return f"integer outside the 64-bit range at {path}"
        elif isinstance(v, float):
            if not math.isfinite(v):
                return f"non-finite number at {path}"
        elif isinstance(v, Mapping):
            stack.extend((c, f"{path}.{k!s}" if _printable(k) else f"{path}.<key>", d + 1)
                         for k, c in v.items())
        elif isinstance(v, (list, tuple)):
            stack.extend((c, f"{path}[{i}]", d + 1) for i, c in enumerate(v))
    return None


def tenant_admission(tenant: str, partition_lag: int, partition_cap: int,
                     recent: Mapping[str, int], soft_fraction: float = 0.5,
                     share_slack: float = 0.25) -> Tuple[bool, Optional[str]]:
    """(admitted, why not). Above soft_fraction of the cap, a tenant whose share of the partition's
    recent admissions exceeds (1 + share_slack) / k of the k active tenants is refused, so a flood
    stalls at the soft level and the rest of the cap stays with its co-tenants."""
    if partition_cap <= 0 or partition_lag <= soft_fraction * partition_cap:
        return True, None
    active = {t: int(n) for t, n in recent.items() if int(n) > 0}
    total = sum(active.values())
    if total <= 0 or len(active) <= 1:
        return True, None
    share = active.get(tenant, 0) / total
    fair = 1.0 / len(active)
    if share > fair * (1.0 + share_slack):
        return False, (f"tenant {tenant!r} has {share:.0%} of its partition's recent admissions, over "
                       f"its fair share {fair:.0%}, and the partition's lag {partition_lag} is over "
                       f"{int(soft_fraction * partition_cap)}")
    return True, None


class AdmissionWindow:
    """Per-partition, per-tenant admission counts over the last window_s seconds, in one-second
    buckets (the `recent` of tenant_admission)."""

    def __init__(self, window_s: float = 10.0):
        self.window_s = float(window_s)
        self._b: Dict[int, Dict[int, Dict[str, int]]] = {}      # partition -> second -> tenant -> n

    def _trim(self, p: int, now: float) -> Dict[int, Dict[str, int]]:
        lo = int(now - self.window_s)
        buckets = self._b.setdefault(int(p), {})
        for s in [s for s in buckets if s <= lo]:
            del buckets[s]
        return buckets

    def note(self, p: int, tenant: str, now: float) -> None:
        b = self._trim(p, now).setdefault(int(now), {})
        b[tenant] = b.get(tenant, 0) + 1

    def recent(self, p: int, now: float) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for b in self._trim(p, now).values():
            for t, n in b.items():
                out[t] = out.get(t, 0) + n
        return out


class OffsetReuseGuard:
    """Closes a partition, until reopen() or a restart, on which the broker returns a position twice
    or one more than `keep` below its highest (it lost acknowledged records). Per producer object."""

    def __init__(self, keep: int = 1 << 16):
        self.keep = int(keep)
        self._owner: Any = None
        self._seen: Dict[Any, Set[int]] = {}
        self._max: Dict[Any, int] = {}
        self._closed: Dict[Any, str] = {}

    def _bind(self, producer: Any) -> None:
        owner = self._owner() if self._owner is not None else None
        if owner is not producer:
            self._owner = weakref.ref(producer)
            self._seen.clear()
            self._max.clear()
            self._closed.clear()

    def closed(self, producer: Any, tp: Any) -> Optional[str]:
        self._bind(producer)
        return self._closed.get(tp)

    def observe(self, producer: Any, tp: Any, offset: int) -> Optional[str]:
        """None if offset is new on tp; otherwise why tp is closed (it is closed from now on)."""
        self._bind(producer)
        if tp in self._closed:
            return self._closed[tp]
        o = int(offset)
        seen = self._seen.setdefault(tp, set())
        top = self._max.get(tp, -1)
        if o in seen or o < top - self.keep:
            why = (f"the broker returned offset {o} on {tp} again (highest returned so far {top}): "
                   f"its log went backwards and reuses positions already acknowledged")
            self._closed[tp] = why
            return why
        seen.add(o)
        if o > top:
            self._max[tp] = top = o
        if len(seen) > 2 * self.keep:
            floor = top - self.keep
            self._seen[tp] = {x for x in seen if x >= floor}
        return None

    def reopen(self, tp: Any = None) -> None:
        """An operator's decision: accept on tp (every partition if None) again."""
        for d in (self._closed, self._seen, self._max):
            if tp is None:
                d.clear()
            else:
                d.pop(tp, None)


def credential_sources(user: Mapping[str, Any], default: Iterable[str]) -> Set[str]:
    """The record sources a credential may submit: its API key's `sources`, else the default."""
    declared = user.get("sources")
    if declared is None:
        declared = default
    if isinstance(declared, str):
        declared = declared.split(",")
    return {str(s).strip().lower() for s in (declared or []) if str(s).strip()}


def source_allowed(source: str, user: Mapping[str, Any], default: Iterable[str]) -> bool:
    """May this credential submit a record of this source?"""
    return str(source).lower() in credential_sources(user, default)


def _networks(trusted: Iterable[str]) -> List[Any]:
    out = []
    for t in trusted or []:
        try:
            out.append(ipaddress.ip_network(str(t).strip(), strict=False))
        except ValueError:
            continue
    return out


def _in(addr: str, nets: List[Any]) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return any(ip in n for n in nets)


def client_ip(peer: Optional[str], headers: Mapping[str, str], trusted_proxies: Iterable[str]) -> str:
    """The address that sent the request.

    X-Forwarded-For and X-Real-IP are believed only when the socket peer is a trusted proxy. Then
    X-Forwarded-For is read from the right: the first address that is not a trusted proxy is the
    client; everything to its left was written by the client and is ignored.
    """
    peer = (peer or "").strip()
    nets = _networks(trusted_proxies)
    if not peer or not nets or not _in(peer, nets):
        return peer or "unknown"
    forwarded = headers.get("x-forwarded-for") or ""
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _in(hop, nets):
            return hop
    if hops:
        return hops[0]
    real_ip = (headers.get("x-real-ip") or "").strip()
    return real_ip or peer
