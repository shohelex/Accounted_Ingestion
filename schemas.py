from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator


class SourceType(str, Enum):
    CDN = "cdn"
    STORAGE = "storage"
    API = "api"
    VM = "vm"
    CACHE = "cache"
    DATABASE = "database"


class EventType(str, Enum):
    ACCESS = "access"
    MODIFY = "modify"
    CREATE = "create"
    DELETE = "delete"
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    EXECUTE = "execute"


class EntityType(str, Enum):
    FILE = "file"
    ENDPOINT = "endpoint"
    USER = "user"
    VM = "vm"
    BUCKET = "bucket"
    CACHE_ENTRY = "cache_entry"
    DATABASE_TABLE = "database_table"
    API_KEY = "api_key"


class AgentType(str, Enum):
    USER = "user"
    SERVICE = "service"
    CDN_NODE = "cdn_node"
    VM = "vm"
    API_GATEWAY = "api_gateway"
    CACHE_SERVER = "cache_server"


class OperationType(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    CACHE = "CACHE"
    EXECUTE = "EXECUTE"


class ProvenanceEntity(BaseModel):
    type: EntityType
    id: str
    hash: Optional[str] = None
    size: Optional[int] = None
    ip: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceAgent(BaseModel):
    type: AgentType
    id: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceActivity(BaseModel):
    operation: OperationType
    resource: str
    duration_ms: Optional[int] = None
    status_code: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str
    source: SourceType
    event_type: EventType

    entity: ProvenanceEntity
    agent: ProvenanceAgent
    activity: ProvenanceActivity

    # Optional fields of the record format; the ingest API does not set them.
    provenance_hash: Optional[str] = None
    chain_position: Optional[int] = None
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None

    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v


class UserRole(str, Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class User(BaseModel):
    user_id: str
    tenant_id: str
    role: UserRole
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class APIKey(BaseModel):
    key_id: str
    user_id: str
    tenant_id: str
    name: str
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    hashed_key: str                 # SHA-256 of the key; the key itself is not stored
    last_used: Optional[datetime] = None
    # Record sources this key may submit; None = settings.ingest_default_sources.
    sources: Optional[List[str]] = None


class HealthCheck(BaseModel):
    status: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    components: Dict[str, str] = Field(default_factory=dict)
