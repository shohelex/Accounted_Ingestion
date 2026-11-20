import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

from collectors.base_collector import BaseProvenanceCollector, ProvenanceEventBuffer
from schemas import SourceType, EventType, EntityType, AgentType, OperationType


logger = logging.getLogger(__name__)

_SENSITIVE_HEADERS = ('authorization', 'cookie', 'x-api-key')


def _known_user(user_id: Optional[str]) -> Optional[str]:
    # The middleware reports a request without credentials as "anonymous"; such a request is
    # keyed on its client address.
    return None if not user_id or user_id == "anonymous" else user_id


@dataclass
class APIRequest:
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, str]
    user_id: Optional[str]
    tenant_id: str
    timestamp: datetime
    request_id: str
    source_ip: str
    user_agent: str
    body_size: int = 0


@dataclass
class APIResponse:
    status_code: int
    headers: Dict[str, str]
    body_size: int
    duration_ms: int
    timestamp: datetime


class APIGatewayCollector(BaseProvenanceCollector):
    """Collector called by the API middleware."""

    def __init__(self, ingest_client=None):
        super().__init__(SourceType.API, ingest_client=ingest_client)
        self.event_buffer = ProvenanceEventBuffer(max_size=200, max_age_seconds=30)
        self.pending_requests: Dict[str, APIRequest] = {}

    async def log_request(self, request: APIRequest) -> None:
        try:
            self.pending_requests[request.request_id] = request

            event = self.create_event(
                event_type=EventType.ACCESS,
                entity_data={
                    "type": EntityType.ENDPOINT,
                    "id": f"{request.method}:{request.path}",
                    "metadata": {
                        "method": request.method,
                        "path": request.path,
                        "query_params": request.query_params
                    }
                },
                agent_data={
                    "type": AgentType.USER if _known_user(request.user_id) else AgentType.SERVICE,
                    "id": _known_user(request.user_id) or f"anonymous_{request.source_ip}",
                    "ip": request.source_ip,
                    "user_agent": request.user_agent,
                    "metadata": {
                        "authenticated": _known_user(request.user_id) is not None,
                        "request_headers": self._filter_sensitive_headers(request.headers)
                    }
                },
                activity_data={
                    "operation": OperationType(request.method),
                    "resource": request.path,
                    "metadata": {
                        "request_size": request.body_size,
                        "request_type": "api_request",
                    }
                },
                tenant_id=request.tenant_id,
                timestamp=request.timestamp,
                # Derived from the request id, so a resend is the same event.
                event_id=f"api_{request.request_id}_q",
            )

            await self.event_buffer.add_event(event, self)

        except Exception as e:
            logger.error(f"Failed to log API request: {e}")

    async def log_response(self, request_id: str, response: APIResponse) -> None:
        try:
            request = self.pending_requests.pop(request_id, None)
            if not request:
                logger.warning(f"No matching request found for response {request_id}")
                return

            if response.status_code < 400 and request.method in ('POST', 'PUT', 'PATCH'):
                event_type = EventType.MODIFY
            else:
                event_type = EventType.ACCESS

            event = self.create_event(
                event_type=event_type,
                entity_data={
                    "type": EntityType.ENDPOINT,
                    "id": f"{request.method}:{request.path}",
                    "metadata": {
                        "method": request.method,
                        "path": request.path,
                        "response_status": response.status_code,
                        "success": response.status_code < 400
                    }
                },
                agent_data={
                    "type": AgentType.USER if _known_user(request.user_id) else AgentType.SERVICE,
                    "id": _known_user(request.user_id) or f"anonymous_{request.source_ip}",
                    "ip": request.source_ip,
                    "user_agent": request.user_agent,
                    "metadata": {
                        "authenticated": _known_user(request.user_id) is not None,
                        "response_headers": self._filter_sensitive_headers(response.headers)
                    }
                },
                activity_data={
                    "operation": OperationType(request.method),
                    "resource": request.path,
                    "duration_ms": response.duration_ms,
                    "status_code": response.status_code,
                    "metadata": {
                        "request_size": request.body_size,
                        "response_size": response.body_size,
                        "request_type": "api_response",
                        "response_timestamp": response.timestamp.isoformat(),
                    }
                },
                tenant_id=request.tenant_id,
                timestamp=request.timestamp,
                event_id=f"api_{request_id}_r",
            )

            await self.event_buffer.add_event(event, self)

        except Exception as e:
            logger.error(f"Failed to log API response: {e}")

    @staticmethod
    def _filter_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
        return {k: "[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else v for k, v in headers.items()}


def _ingest_client_from_env():
    """An ingest client when ACCT_INGEST_URL and ACCT_INGEST_API_KEY are set; without one, events go
    to Kafka directly, outside the acknowledgement contract."""
    url, key = os.getenv("ACCT_INGEST_URL"), os.getenv("ACCT_INGEST_API_KEY")
    if not (url and key):
        return None
    from collectors.ingest_client import IngestClient
    return IngestClient(url, key, tenant_id=os.getenv("ACCT_INGEST_TENANT") or None,
                        public_key_hex=os.getenv("ACCT_INGEST_PUBLIC_KEY") or None)


def create_api_collector() -> APIGatewayCollector:
    return APIGatewayCollector(ingest_client=_ingest_client_from_env())
