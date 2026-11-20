from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from api.dependencies import get_tenant_id
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


def _store():
    from crypto.anchor_store import get_anchor_store
    return get_anchor_store(settings)


@router.get("/period/{j}")
async def get_period_opening(j: int, tenant_id: str = Depends(get_tenant_id)):
    if not settings.acct_mode:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="accounted mode is off")
    if j < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="period must be non-negative")
    store = _store()
    if store is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="anchor store disabled")
    from crypto.period_statements import opening_key, receipt_key
    key = opening_key(settings.acct_deployment_id, j, tenant_id)
    try:
        raw = await asyncio.to_thread(store.get_object, key)
        receipt = None
        if raw is not None:
            receipt = await asyncio.to_thread(store.get_object, receipt_key(settings.acct_deployment_id, j))
    except Exception as e:
        logger.warning(f"Opening {key} unreadable: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="anchor store unavailable")
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="no opening for this tenant in this period")
    opening = json.loads(raw)
    if opening.get("tenant_id") != tenant_id or opening.get("j") != j:
        logger.error(f"INTEGRITY ALARM [period]: object {key} holds another opening")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="stored opening is inconsistent")
    return {"j": j, "opening": opening, "receipt": json.loads(receipt) if receipt is not None else None}
