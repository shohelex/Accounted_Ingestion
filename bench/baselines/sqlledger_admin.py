from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sqlledger_common as sc      # noqa: E402

BACKUP_FILE = "/var/opt/mssql/data/ledger_rollback.bak"
OFFLINE_TRIES = 15
RESTORE_WATCHDOG_S = 300.0


def _q(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def _lit(s: str) -> str:
    return "N'" + s.replace("'", "''") + "'"


def setup(s, connect=sc.connect) -> str:
    for db, stmt in sc.setup_statements(s["database"]):
        conn = connect(s, database=db, autocommit=True)
        try:
            conn.cursor().execute(stmt)
        finally:
            conn.close()
    return f"ledger table ready: {s['database']}.{sc.TABLE} (append-only ledger, snapshot isolation allowed)"


def scalar(s, sql, database=None, connect=sc.connect, params=None):
    conn = connect(s, database=database, autocommit=True)
    try:
        cur = conn.cursor()
        if params is None:
            cur.execute(sql)
        else:
            cur.execute(sql, params)
        return cur.fetchone()
    finally:
        conn.close()


def rows(s, connect=sc.connect) -> int:
    return int(scalar(s, f"SELECT COUNT_BIG(*) FROM {sc.TABLE}", connect=connect)[0])


# The rollback check counts rows committed before the restore began, before and after it: a count of the
# whole table would race the sinks' new writes. commit_time is the ledger's own clock.
ROWS_AND_LAST_COMMIT = (
    f"SELECT COUNT_BIG(*), CONVERT(VARCHAR(33), MAX(t.commit_time), 126) FROM {sc.TABLE} AS e "
    "JOIN sys.database_ledger_transactions AS t ON t.transaction_id = e.ledger_start_transaction_id")
ROWS_COMMITTED_BY = (
    f"SELECT COUNT_BIG(*) FROM {sc.TABLE} AS e "
    "JOIN sys.database_ledger_transactions AS t ON t.transaction_id = e.ledger_start_transaction_id "
    "WHERE t.commit_time <= CONVERT(DATETIME2(7), %s, 126)")


def rows_and_last_commit(s, connect=sc.connect) -> tuple[int, str | None]:
    r = scalar(s, ROWS_AND_LAST_COMMIT, connect=connect)
    return int(r[0]), (str(r[1]) if r[1] is not None else None)


def rows_committed_by(s, cut: str | None, connect=sc.connect) -> int:
    if cut is None:
        return 0
    return int(scalar(s, ROWS_COMMITTED_BY, connect=connect, params=(cut,))[0])


def backup_statement(database: str, path: str) -> str:
    return f"BACKUP DATABASE {_q(database)} TO DISK = {_lit(path)} WITH COPY_ONLY, INIT, FORMAT"


def restore_statements(database: str, path: str) -> list:
    # OFFLINE, not SINGLE_USER: a reconnecting sink would take the single session first.
    return [f"ALTER DATABASE {_q(database)} SET OFFLINE WITH ROLLBACK IMMEDIATE",
            f"RESTORE DATABASE {_q(database)} FROM DISK = {_lit(path)} WITH REPLACE",
            f"ALTER DATABASE {_q(database)} SET ONLINE"]


def offline_restore_online(s, path, connect=sc.connect):
    """The three restore statements. SET OFFLINE is retried on a fresh connection: a reconnecting sink's
    lock (error 5061) or a connect timeout can fail it, and repeating it is harmless."""
    offline, restore_stmt, online = restore_statements(s["database"], path)
    for attempt in range(1, OFFLINE_TRIES + 1):
        try:
            run_master(s, [offline], connect)
            break
        except Exception:
            if attempt == OFFLINE_TRIES:
                raise
            time.sleep(1.0)
    run_master(s, [restore_stmt, online], connect)


def run_master(s, statements, connect=sc.connect):
    conn = connect(s, database="master", autocommit=True, timeout=60, query_timeout=0)   # BACKUP/RESTORE may run long
    try:
        cur = conn.cursor()
        for stmt in statements:
            cur.execute(stmt)
            try:
                while cur.nextset():
                    pass
            except Exception:
                pass
    finally:
        conn.close()


def backup(s, path=BACKUP_FILE, connect=sc.connect) -> str:
    t0 = time.time()
    n = rows(s, connect)
    run_master(s, [backup_statement(s["database"], path)], connect)
    return f"backup t={t0:.3f} done={time.time():.3f} rows={n} file={path}"


def db_state(s, connect=sc.connect) -> str:
    return str(scalar(s, f"SELECT state_desc FROM sys.databases WHERE name = {_lit(s['database'])}",
                      database="master", connect=connect)[0])


def restore(s, path=BACKUP_FILE, connect=sc.connect, watchdog_s: float = RESTORE_WATCHDOG_S) -> str:
    """Offline, restore, online, under a wall-clock watchdog; when it fires, an ONLINE database is a
    completed restore. rows_before: rows committed when the restore began; rows_after: how many of
    those remain; rows_now: the whole table."""
    before, cut = rows_and_last_commit(s, connect)
    t0 = time.time()
    try:
        sc.watchdog(lambda: offline_restore_online(s, path, connect), watchdog_s, "restore")
    except TimeoutError:
        if db_state(s, connect) != "ONLINE":
            run_master(s, [restore_statements(s["database"], path)[-1]], connect)
            raise
    except Exception:
        run_master(s, [restore_statements(s["database"], path)[-1]], connect)   # never leave it offline
        raise
    after = rows_committed_by(s, cut, connect)
    done = time.time()
    return (f"restore t={t0:.3f} done={done:.3f} rows_before={before} rows_after={after} "
            f"rows_now={rows(s, connect)} cut={cut}")


def verify_now(s, digest_lines, connect=sc.connect) -> str:
    """The tenant checking the database against the digests it holds, now; on failure the server's
    reason names the block whose hash no longer matches."""
    import sqlledger_verify as sv
    digests, _forks = sc.digests_for_verification(digest_lines)
    t0 = time.time()
    conn = connect(s, autocommit=True)
    try:
        v = sv.run_verification(conn, digests)
    finally:
        conn.close()
    err = " ".join(str(v.get("verify_error") or "").split()).replace('"', "'")
    return (f"verify t={t0:.3f} done={time.time():.3f} ledger_verified={v['ledger_verified']} "
            f"digests={len(digests)} error={err[:300]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", required=True, help="SQL Server host:port")
    ap.add_argument("--user")
    ap.add_argument("--password", help="default: MSSQL_PASSWORD")
    ap.add_argument("--database")
    ap.add_argument("command", choices=("setup", "version", "rows", "backup", "restore", "verify"))
    ap.add_argument("--file", default=BACKUP_FILE, help="backup file on the server")
    ap.add_argument("--digests", help="verify: the tenant's digest log (<label>.digests.jsonl)")
    a = ap.parse_args()
    s = sc.settings(a.addr, a.user, a.password, a.database)
    if a.command == "setup":
        print(setup(s))
    elif a.command == "version":
        v = scalar(s, "SELECT @@VERSION, CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128))", database="master")
        # The settings the comparison depends on: commit durability, recovery model, snapshot isolation.
        d = scalar(s, "SELECT delayed_durability_desc, recovery_model_desc, snapshot_isolation_state_desc "
                      f"FROM sys.databases WHERE name = {_lit(s['database'])}",
                   database="master") or ("?", "?", "?")
        print(" ".join(str(v[0]).split()) + f" | edition: {v[1]} | delayed_durability: {d[0]} | "
              f"recovery_model: {d[1]} | snapshot_isolation: {d[2]}")
    elif a.command == "rows":
        print(rows(s))
    elif a.command == "backup":
        print(backup(s, a.file))
    elif a.command == "verify":
        from ledger_digest import load
        print(verify_now(s, load(Path(a.digests))))
    else:
        print(restore(s, a.file))


if __name__ == "__main__":
    main()
