from __future__ import annotations

import json
import os

DATABASE = "acct_ledger"
TABLE = "dbo.events"
# SQL Server takes at most 2,100 parameters per statement and 1,000 rows per VALUES list.
MAX_ROWS_PER_INSERT = 1000
QUERY_TIMEOUT_S = 30

# pymssql 2.4.1 deadlocks the process on a connection whose session the server killed; 2.4.0
# raises error 20047 at once. Pinned in docker-compose.sqlledger.yml.
BROKEN_PYMSSQL = "2.4.1"


def settings(addr: str | None = None, user: str | None = None, password: str | None = None,
             database: str | None = None) -> dict:
    """host, port, user, password, database: arguments first, then the environment, then defaults.
    The password has no default: it comes from the argument or MSSQL_PASSWORD."""
    a = addr or os.environ.get("MSSQL_ADDR", "localhost:1433")
    host, _, port = a.rpartition(":") if ":" in a else (a, "", "1433")
    return {"host": host or "localhost", "port": int(port or 1433),
            "user": user or os.environ.get("MSSQL_USER", "sa"),
            "password": password if password is not None else os.environ.get("MSSQL_PASSWORD"),
            "database": database or os.environ.get("MSSQL_DATABASE", DATABASE)}


def watchdog(fn, seconds: float, what: str):
    """fn() in a daemon thread: its result or its exception, or TimeoutError after `seconds` with the
    thread abandoned (the caller then reconnects). A driver hang cannot stop a run silently."""
    import threading
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as e:          # re-raised in the caller
            box["error"] = e
    t = threading.Thread(target=run, daemon=True, name=what)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError(f"{what}: no answer in {seconds:.0f} s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def connect(s: dict, database: str | None = None, autocommit: bool = False, timeout: int = 30,
            query_timeout: int = QUERY_TIMEOUT_S):
    """A pymssql connection; `database` overrides s["database"] ("master" for CREATE and RESTORE).
    query_timeout 0 (no limit) is only for BACKUP and RESTORE."""
    if not s.get("password"):
        raise RuntimeError("No SQL Server password: set MSSQL_PASSWORD or pass --password")
    import pymssql
    if getattr(pymssql, "__version__", "") == BROKEN_PYMSSQL:
        raise RuntimeError(f"pymssql {BROKEN_PYMSSQL} deadlocks on a killed session; install pymssql==2.4.0")
    return pymssql.connect(server=s["host"], port=s["port"], user=s["user"], password=s["password"],
                           database=database or s["database"], autocommit=autocommit,
                           login_timeout=timeout, timeout=query_timeout)


def insert_statement(n_rows: int) -> str:
    """One multi-row INSERT for n rows of (event_id, leaf); pymssql's %s placeholders."""
    if not 1 <= n_rows <= MAX_ROWS_PER_INSERT:
        raise ValueError(f"1..{MAX_ROWS_PER_INSERT} rows per INSERT, not {n_rows}")
    return f"INSERT INTO {TABLE} (event_id, leaf) VALUES " + ",".join(["(%s,%s)"] * n_rows)


def insert_params(kv: dict) -> tuple:
    """(k1, v1, k2, v2, ...) with keys as str and values as bytearray: pymssql sends a bytes value that
    looks like text as a varchar literal, which SQL Server does not convert to VARBINARY (error 257)."""
    out = []
    for k, v in kv.items():
        out.append(k.decode() if isinstance(k, (bytes, bytearray)) else str(k))
        out.append(bytearray(v))
    return tuple(out)


def setup_statements(database: str) -> list:
    """(database, statement) pairs, run in order with autocommit. Idempotent."""
    db = database.replace("]", "]]")
    return [
        ("master", f"IF DB_ID(N'{database}') IS NULL CREATE DATABASE [{db}]"),
        # sp_verify_database_ledger refuses to run without it (ledger-database-verification docs).
        ("master", f"ALTER DATABASE [{db}] SET ALLOW_SNAPSHOT_ISOLATION ON"),
        (database, "IF OBJECT_ID(N'dbo.events', N'U') IS NULL "
                   "CREATE TABLE dbo.events (event_id NVARCHAR(200) NOT NULL, leaf VARBINARY(MAX) NOT NULL) "
                   "WITH (LEDGER = ON (APPEND_ONLY = ON))"),
    ]


# Every stored row with the ledger block its inserting transaction belongs to. The two GENERATED
# ALWAYS columns of an append-only ledger table exist whether or not the CREATE TABLE names them.
ROWS_WITH_BLOCKS = (
    "SELECT e.event_id, t.block_id, t.commit_time "
    "FROM dbo.events AS e JOIN sys.database_ledger_transactions AS t "
    "ON t.transaction_id = e.ledger_start_transaction_id")

GENERATE_DIGEST = "EXEC sys.sp_generate_database_ledger_digest"
VERIFY_WITH_DIGESTS = "EXEC sys.sp_verify_database_ledger %s"


def parse_digest(value) -> dict:
    """The JSON document sp_generate_database_ledger_digest returns (column latest_digest)."""
    d = json.loads(value) if isinstance(value, (str, bytes, bytearray)) else dict(value)
    if "block_id" not in d or "hash" not in d:
        raise ValueError(f"not a ledger digest: {str(value)[:200]}")
    d["block_id"] = int(d["block_id"])
    return d


def digests_for_verification(lines: list) -> tuple[list, dict]:
    """The distinct digests to pass to sp_verify_database_ledger, and every block id logged with two
    hashes (a fork: the database was rolled back). Both hashes are kept, so a fork fails verification."""
    seen, out, hashes = set(), [], {}
    for rec in lines:
        if not rec.get("ok") or rec.get("system") != "sqlledger":
            continue
        d = rec.get("digest") or {}
        if "block_id" not in d or "hash" not in d:
            continue
        key = (int(d["block_id"]), str(d["hash"]).upper())
        hashes.setdefault(key[0], set()).add(key[1])
        if key not in seen:
            seen.add(key)
            out.append(d)
    forks = {b: sorted(h) for b, h in hashes.items() if len(h) > 1}
    out.sort(key=lambda d: int(d["block_id"]))
    return out, forks

