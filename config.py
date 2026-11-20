from typing import List, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application
    app_name: str = "Accounted Ingestion API"
    version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    # False: the application runs without the request-path provenance capture.
    provenance_middleware_enabled: bool = True
    rate_limit_requests_per_minute: int = 1000

    # Neo4j
    neo4j_uri: str = "neo4j://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "research"
    neo4j_database: Optional[str] = "neo4j"
    neo4j_max_retry_time: int = 30
    neo4j_max_connection_lifetime: int = 3600
    # Size against processor_max_concurrent_events: each event opens several sessions.
    neo4j_max_connection_pool_size: int = 200
    # Longest life of a writer transaction (0 = no bound); releases the locks of a writer that died.
    neo4j_tx_timeout_s: float = 60.0

    # Redis
    redis_url: str = "redis://localhost:6379"
    redis_db: int = 0

    # Kafka
    kafka_bootstrap_servers: List[str] = ["localhost:9092"]
    kafka_provenance_topic: str = "provenance-events"
    kafka_consumer_group: str = "provenance-processor"

    # Integrity log
    merkle_tree_enabled: bool = True
    # Consumer-side switch: false skips the graph and the log; the request path still runs.
    provenance_tracking_enabled: bool = True

    # Anchoring
    merkle_anchor_enabled: bool = True        # export each log root to the anchor store
    merkle_anchor_backend: str = "local"      # "local" (WORM directory) or "s3" (Object Lock)
    merkle_anchor_batch_k: int = 1            # anchor every k leaves
    # Deployment signing key: 32-byte hex Ed25519 seed. Unset: unsigned records (development only).
    merkle_signing_seed: Optional[str] = None
    merkle_signing_public_key: Optional[str] = None
    # The heartbeat anchors a non-empty tail whose newest root is older than this. 0 = events only.
    merkle_anchor_max_age_s: float = 30.0
    # Sigsum log for the period statements. None = off (the judge reads silence).
    merkle_public_witness_url: Optional[str] = None
    merkle_public_witness_seed: Optional[str] = None      # 32-byte hex Ed25519 seed
    merkle_public_witness_log_key: Optional[str] = None   # hex Ed25519 key of the log
    merkle_public_witness_token: Optional[str] = None     # "domain hexsig" for rate-limited logs
    # Sigsum policy (path or text); without it no public receipt counts as verified.
    merkle_public_witness_policy: Optional[str] = None
    # Directory for statement receipts the store refused. Empty: kept in memory only.
    period_spool_dir: str = ""
    # Leaves per log append transaction; up to B-1 accepted events wait to be chained.
    merkle_append_batch_b: int = 1
    # Events whose graph writes share one transaction.
    graph_write_batch_g: int = 1
    merkle_anchor_dir: str = "./anchor_store"
    merkle_anchor_s3_bucket: Optional[str] = None
    merkle_anchor_s3_prefix: str = "anchors"
    merkle_anchor_s3_endpoint_url: Optional[str] = None   # S3-compatible endpoint; None = AWS
    merkle_anchor_retention_days: int = 3650

    # Accounted ingestion. Off: the plain pipeline.
    acct_mode: bool = False
    acct_caa: bool = True           # commit a broker offset only after store-verified coverage
    acct_verdicts: bool = True      # every skip becomes a verdict record at the skipped position
    acct_periods: bool = True       # per-period public statements
    # A backup statement maker in the API, one per host (file lock).
    acct_api_maker: bool = True
    acct_deployment_id: str = "acct"
    # Reserved tenant whose logs hold the records that authenticate no tenant (UNAUTH).
    acct_system_tenant: str = "acct-system"
    # 32-byte hex key for the salted aggregate. Unset: derived from merkle_signing_seed.
    acct_salt_seed: Optional[str] = None
    # Contract parameters (integer seconds or milliseconds).
    acct_theta_s: int = 300             # accounted within theta of the tag time unless excused
    acct_delta_s: int = 45              # send timeout plus clock skews
    acct_period_s: int = 360            # Sigsum allows 288 leaves per day per domain
    acct_t0_ms: int = 0
    acct_delta_pub_s: int = 80          # end of period to public inclusion
    acct_stall_budget: int = 20         # charged stall periods per tenant per window
    acct_stall_window_periods: int = 7200
    acct_unchk_budget: int = 10         # UNCHECKABLE verdicts per tenant per window
    acct_agg_cap: int = 1024            # aggregate tree size; hides the tenant count up to it
    acct_coverage_poll_s: float = 5.0
    acct_audit_interval_s: int = 86400
    acct_contract_version: int = 1
    # The consumer refuses acct_caa or acct_verdicts off unless this is set.
    acct_ablation_ok: bool = False
    # How often the topic's partitions and retention are checked against the contract.
    acct_partition_check_s: float = 60.0
    # Kafka key partitioner in the contract: "murmur2" (Java client, aiokafka) or "crc32" (librdkafka).
    acct_partitioner: str = "murmur2"
    acct_clock_skew_ms: int = 1000
    # How far the broker's LogAppendTime may go backwards within a partition.
    acct_broker_skew_ms: int = 1000
    # A stalled partition charges only the tenants whose overdue records are unanchored.
    acct_tenant_stall: bool = True
    # Baseline: acknowledge only once a write-once anchor covers the submission.
    acct_ack_after_anchor: bool = False
    # The v1 receipt next to receipt_v2 (the judge reads only receipt_v2).
    acct_v1_receipt: bool = True
    # False: the accounted writer does not write the graph.
    acct_graph_write: bool = True
    # False: the plain pipeline appends to the log and anchors but writes no graph.
    graph_write_enabled: bool = True
    acct_ack_anchor_timeout_s: float = 30.0
    acct_ack_anchor_poll_s: float = 0.05

    default_tenant_id: str = "research_tenant"

    # Processing
    max_events_per_batch: int = 100
    # Pause after a poll that returned fewer than max_events_per_batch records.
    processor_partial_poll_pause_s: float = 0.1
    processor_max_concurrent_events: int = 8
    # In-place retries of a failing event, and deliveries before a record is dead-lettered.
    processor_event_retries: int = 3
    processor_max_redeliveries: int = 100
    # Event ids remembered for deduplication.
    processor_dedup_window: int = 200000

    # Admission: above these lags the API refuses (503). 0 = off.
    ingest_max_consumer_lag: int = 10000
    ingest_max_partition_lag: int = 1000
    # Events one API process holds until the broker answers; more are refused. 0 = no cap.
    ingest_max_inflight_per_process: int = 1000
    # Events per POST /events/batch.
    ingest_max_batch: int = 500
    ingest_lag_probe_interval_s: float = 2.0
    # A failed lag probe's last answer is reused this long; then admission refuses (fail closed).
    ingest_lag_stale_s: float = 10.0
    ingest_admission_fail_closed: bool = True
    # Close a partition on which the broker reuses offsets.
    ingest_offset_reuse_guard: bool = True
    # Refuse tenants whose partition the consumers stopped (stop markers in the anchor store).
    ingest_stop_markers: bool = True
    # Per-tenant share of a partition's admissions above soft_fraction of its cap.
    ingest_tenant_isolation: bool = True
    ingest_tenant_soft_fraction: float = 0.5
    ingest_tenant_share_slack: float = 0.25
    ingest_tenant_window_s: float = 10.0

    # Record sources a credential that declares none may submit.
    ingest_default_sources: List[str] = ["api", "cdn", "storage", "vm", "cache", "database"]

    # Proxies whose X-Forwarded-For / X-Real-IP are believed (IPs or CIDRs, JSON list).
    trusted_proxies: List[str] = []

    # Region of the S3 anchor store; None: the AWS SDK's default (AWS_DEFAULT_REGION).
    aws_region: Optional[str] = None

    def validate_production_settings(self):
        if str(self.environment).lower() == "production":
            if self.neo4j_password in ("password", "research"):
                raise ValueError(
                    "NEO4J_PASSWORD must be changed from default for production"
                )
            if not self.merkle_signing_seed:
                raise ValueError(
                    "MERKLE_SIGNING_SEED must be set for production: without it acknowledgements "
                    "and anchor records are unsigned"
                )

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
