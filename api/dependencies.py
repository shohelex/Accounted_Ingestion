import hashlib
import logging
from typing import Dict, Any
from fastapi import HTTPException, status, Depends, Request

from config import settings
from database.user_db import user_db
from api.ingest_rules import client_ip, valid_tenant_id

logger = logging.getLogger(__name__)


def key_id(api_key: str) -> str:
    """A short hash naming an API key in logs, records and rate-limit buckets."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


async def get_current_user(request: Request) -> Dict[str, Any]:
    """The caller's identity from its API key (x-api-key)."""
    api_key = request.headers.get("x-api-key")
    if api_key:
        return await _validate_api_key(api_key)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required"
    )


async def _validate_api_key(api_key: str) -> Dict[str, Any]:
    if len(api_key) < 32:
        logger.warning("Invalid API key format")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format"
        )

    try:
        user = await user_db.get_user_by_api_key(api_key)
        if user and user.is_active:
            logger.debug(f"API key authentication successful for user {user.user_id}")
            record = await user_db.get_api_key_record(api_key)

            return {
                "user_id": user.user_id,
                "tenant_id": user.tenant_id,
                "role": user.role,
                # The key, not the user, is the credential bound to record sources.
                "sources": record.sources if record else None,
            }
        logger.warning(f"API key authentication failed (key {key_id(api_key)})")
    except Exception as e:
        logger.error(f"API key validation error: {e}")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired API key"
    )


def get_tenant_id(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> str:
    """The request's tenant, refused (400) unless it is a valid tenant id that is not reserved."""
    tenant_id = _resolve_tenant_id(request, current_user)
    if not valid_tenant_id(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tenant id: 1-64 characters of A-Z, a-z, 0-9, '_' or '-', "
                   "starting with a letter or digit"
        )
    # The system logs (<system>-<p>) hold the UNAUTH verdicts; no caller may use them as its tenant.
    system = settings.acct_system_tenant
    if tenant_id == system or tenant_id.startswith(system + "-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This tenant id is reserved"
        )
    return tenant_id


def _resolve_tenant_id(request: Request, current_user: Dict[str, Any]) -> str:
    """The x-tenant-id header, else the caller's tenant, else the default tenant."""
    tenant_id = request.headers.get("x-tenant-id")
    if tenant_id:
        if not _user_has_tenant_access(current_user, tenant_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to specified tenant"
            )
        return tenant_id

    user_tenant = current_user.get("tenant_id")
    if user_tenant:
        return user_tenant
    return settings.default_tenant_id


def _user_has_tenant_access(user: Dict[str, Any], tenant_id: str) -> bool:
    """Admins may act for any tenant, other users only for their own."""
    user_role = user.get("role", "")
    user_tenant = user.get("tenant_id", "")
    user_id = user.get("user_id", "unknown")

    if user_role == "admin":
        if user_tenant != tenant_id:
            logger.debug(f"Admin user {user_id} accessing cross-tenant data: {user_tenant} -> {tenant_id}")
        return True

    if user_tenant != tenant_id:
        logger.warning(f"User {user_id} attempted unauthorized tenant access: {user_tenant} -> {tenant_id}")
        return False
    return True


def request_client_ip(request: Request) -> str:
    """The sender's address; X-Forwarded-For is believed only from settings.trusted_proxies."""
    peer = request.client.host if request.client else None
    return client_ip(peer, request.headers, settings.trusted_proxies)
