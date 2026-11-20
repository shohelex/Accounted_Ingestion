from __future__ import annotations

import asyncio
import random
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Deque, Dict, Optional

import httpx


class IngestClient:
    def __init__(self, base_url: str, api_key: str, tenant_id: Optional[str] = None,
                 public_key_hex: Optional[str] = None, spool_max: int = 10_000,
                 max_attempts: int = 8, backoff_s: float = 0.5, backoff_max_s: float = 30.0,
                 timeout_s: float = 15.0, transport=None, retry_after_max_s: float = 120.0,
                 require_v2: Optional[bool] = None,
                 contract: Optional[Dict[str, Any]] = None, contract_hash: Optional[str] = None):
        self.url = base_url.rstrip("/") + "/api/v1/provenance/events"
        self.headers = {"x-api-key": api_key}
        if tenant_id:
            self.headers["x-tenant-id"] = tenant_id
        # Without a configured tenant, the first valid receipt fixes the tenant later ones must name.
        self.tenant_id = tenant_id
        self.public_key_hex = public_key_hex
        self.spool_max, self.max_attempts = int(spool_max), int(max_attempts)
        self.backoff_s, self.backoff_max_s = float(backoff_s), float(backoff_max_s)
        self.retry_after_max_s = max(float(retry_after_max_s), 0.0)
        self._http = httpx.AsyncClient(timeout=timeout_s, transport=transport)
        self._spool: Deque[Dict[str, Any]] = deque()
        self._task: Optional[asyncio.Task] = None
        self._resending: Optional[Dict[str, Any]] = None
        self._first_sends = 0                                # submit() calls waiting on their first send
        self.receipts: Dict[str, Any] = {}
        # The contract receipts v2 must name; a signed statement is checked under the pinned key.
        if contract is not None:
            from crypto.records import NS_STMT, canon, contract_hash as _contract_hash
            body = contract.get("body") if isinstance(contract, dict) else None
            if not isinstance(body, dict) or body.get("kind") != "contract":
                raise ValueError("contract: a signed CONTRACT statement {'body', 'sig'}")
            if public_key_hex:
                from crypto.signing import verify
                if not verify(bytes.fromhex(public_key_hex), contract.get("sig"), NS_STMT + canon(body)):
                    raise ValueError("contract: the signature does not verify under the pinned key")
            h = _contract_hash(body)
            if contract_hash is not None and contract_hash != h:
                raise ValueError("contract and contract_hash disagree")
            contract_hash = h
        self.contract_hash = contract_hash
        # require_v2: an acknowledgement without a valid receipt v2 does not count. It is the
        # default when the contract is known; a receipt for another contract could not be filed.
        self.require_v2 = bool(require_v2) if require_v2 is not None else contract_hash is not None
        self.receipts_v2: Dict[str, Any] = {}
        self.stats = {"offered": 0, "acknowledged": 0, "acknowledged_first_try": 0, "refused": 0,
                      "resent": 0, "gave_up": 0, "spool_dropped": 0, "bad_receipt": 0, "spool_peak": 0,
                      "receipt_unbound": 0, "unsent_at_close": 0}

    async def submit(self, event: Dict[str, Any]) -> bool:
        """Send one event. True if acknowledged now or spooled for resending; False if the spool
        was full and the event was dropped (counted in stats['spool_dropped'])."""
        body = dict(event)
        body.setdefault("event_id", "ic_" + uuid.uuid4().hex[:20])
        body.setdefault("timestamp", datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
        self.stats["offered"] += 1
        self._first_sends += 1
        try:
            ok, hint = await self._send(body, first=True)
        finally:
            self._first_sends -= 1
        if ok:
            return True
        if self.max_attempts <= 1:
            self.stats["gave_up"] += 1
            return False
        return self._spool_put({"body": body, "attempts": 1, "due": time.monotonic() + self._delay(1, hint)})

    def outstanding(self) -> int:
        """Events not yet acknowledged and not given up: spooled, being resent, or on their first send."""
        return len(self._spool) + (1 if self._resending is not None else 0) + self._first_sends

    async def drain(self, timeout_s: float = 60.0) -> int:
        """Wait until nothing is outstanding or the timeout passes; returns what still is."""
        end = time.monotonic() + timeout_s
        while self.outstanding() and time.monotonic() < end:
            await asyncio.sleep(0.05)
        return self.outstanding()

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        # The resender puts back an event it was sending when cancelled, so it is counted here.
        self.stats["unsent_at_close"] = len(self._spool) + self._first_sends
        await self._http.aclose()

    def _spool_put(self, item) -> bool:
        held = len(self._spool) + (1 if self._resending is not None else 0)   # the event being resent holds its slot
        if held >= self.spool_max:
            self.stats["spool_dropped"] += 1
            return False
        self._spool.append(item)
        self.stats["spool_peak"] = max(self.stats["spool_peak"], held + 1)
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._resender())
        return True

    def _delay(self, attempts: int, hint: Optional[float]) -> float:
        delay = min(self.backoff_max_s, self.backoff_s * (2 ** (attempts - 1))) * random.uniform(0.8, 1.2)
        if hint:
            # Jitter only upwards from the hint: the server said not before then.
            wait = min(float(hint), self.retry_after_max_s)
            delay = max(delay, wait * random.uniform(1.0, 1.1))
        return delay

    @staticmethod
    def _retry_after(value: Optional[str]) -> Optional[float]:
        """Retry-After as seconds: delta-seconds or an HTTP date (RFC 9110, 10.2.3)."""
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            pass
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())

    async def _send(self, body, first=False):
        """(acknowledged, Retry-After seconds or None)."""
        retry_after = None
        try:
            r = await self._http.post(self.url, json=body, headers=self.headers)
            code = r.status_code
            retry_after = r.headers.get("Retry-After")
        except Exception:
            code, r = 0, None
        if 200 <= code < 300:
            receipt, payload = None, None
            try:
                payload = r.json()
                receipt = payload.get("receipt") if isinstance(payload, dict) else None
            except Exception:
                receipt = None
            if not self._receipt_ok(receipt, body):
                self.stats["bad_receipt"] += 1
                return False, None
            receipt_v2 = payload.get("receipt_v2") if isinstance(payload, dict) else None
            if receipt_v2 is not None or self.require_v2:
                if not self._receipt_v2_ok(receipt_v2, body):
                    self.stats["bad_receipt"] += 1
                    return False, None
                self.receipts_v2[body["event_id"]] = receipt_v2
            self.receipts[body["event_id"]] = receipt
            self.stats["acknowledged"] += 1
            if first:
                self.stats["acknowledged_first_try"] += 1
            return True, None
        self.stats["refused"] += 1
        return False, self._retry_after(retry_after)

    def _receipt_ok(self, receipt, body) -> bool:
        """Is this receipt about this event? Without a pinned key an absent receipt is accepted; a
        receipt that is present is always checked against what was sent."""
        if receipt is None and not self.public_key_hex:
            return True
        if not isinstance(receipt, dict):
            return False
        try:
            tenant, eid = str(receipt["tenant_id"]), str(receipt["event_id"])
            leaf_hash, at = str(receipt["leaf_hash"]), str(receipt["accepted_at"])
            if self.tenant_id is not None and tenant != self.tenant_id:
                return False
            from crypto.leaf_format import flat_event_leaf_data, leaf_hash_hex
            expected = flat_event_leaf_data(body, tenant)
            if expected is None:
                self.stats["receipt_unbound"] += 1            # the route minted the id: nothing to bind to
            elif eid != expected["event_id"] or leaf_hash != leaf_hash_hex(expected):
                return False
            if self.public_key_hex:
                from crypto.signing import ack_statement, verify
                if not verify(bytes.fromhex(self.public_key_hex), receipt.get("sig"),
                              ack_statement(tenant, eid, leaf_hash, at)):
                    return False
        except Exception:                                    # missing fields, bad hex, wrong types
            return False
        if self.tenant_id is None:
            self.tenant_id = tenant
        return True

    def _receipt_v2_ok(self, receipt, body) -> bool:
        """The v1 checks plus a broker position and submission id under the signature. The
        receipt's own key is never trusted; the signature is checked under the pinned key."""
        if not isinstance(receipt, dict):
            return False
        try:
            tenant, eid, leaf_hash = str(receipt["tenant_id"]), str(receipt["event_id"]), str(receipt["leaf_hash"])
            pos = receipt["pos"]
            if int(receipt.get("v", 0)) != 2 or not isinstance(pos, dict) \
                    or not isinstance(pos.get("p"), int) or not isinstance(pos.get("o"), int):
                return False
            if self.tenant_id is not None and tenant != self.tenant_id:
                return False
            if self.contract_hash is not None and receipt.get("contract") != self.contract_hash:
                return False
            from crypto.leaf_format import flat_event_leaf_data, leaf_hash_hex
            expected = flat_event_leaf_data(body, tenant)
            if expected is not None and (eid != expected["event_id"] or leaf_hash != leaf_hash_hex(expected)):
                return False
            if self.public_key_hex:
                from crypto.records import NS_ACK2, ack2_body, signed
                from crypto.signing import verify
                if not verify(bytes.fromhex(self.public_key_hex), receipt.get("sig"), signed(
                        NS_ACK2, ack2_body(tenant, eid, leaf_hash, receipt["sub"], receipt["at_ms"],
                                           pos["topic"], pos["p"], pos["o"], receipt["contract"]))):
                    return False
        except Exception:                                    # missing fields, bad hex, wrong types
            return False
        return True

    async def _resender(self) -> None:
        while self._spool:
            item = self._spool[0]
            wait = item["due"] - time.monotonic()
            if wait > 0:
                await asyncio.sleep(min(wait, 0.2))
                continue
            self._spool.popleft()
            self.stats["resent"] += 1
            self._resending = item
            done = False
            try:
                ok, hint = await self._send(item["body"])
                done = True
            finally:
                self._resending = None
                if not done:                                 # cancelled mid-send: keep it, it is unsent
                    self._spool.appendleft(item)
            if ok:
                continue
            item["attempts"] += 1                            # max_attempts counts every send, the first included
            if item["attempts"] >= self.max_attempts:
                self.stats["gave_up"] += 1
                continue
            item["due"] = time.monotonic() + self._delay(item["attempts"], hint)
            self._spool.append(item)
