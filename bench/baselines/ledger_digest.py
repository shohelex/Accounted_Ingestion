from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sqlledger_common as sc      # noqa: E402


class SqlLedgerDigests:
    system = "sqlledger"

    def __init__(self, addr, user=None, password=None, database=None, connect=None):
        self.s = sc.settings(addr, user, password, database)
        self._connect = connect or (lambda: sc.connect(self.s, autocommit=True, timeout=10))
        self.conn = None

    def take(self) -> tuple[int, dict]:
        # Under a wall-clock watchdog: the driver can hang on a session the server killed.
        def once():
            conn = self.conn
            if conn is None:
                conn = self.conn = self._connect()
            cur = conn.cursor()
            cur.execute(sc.GENERATE_DIGEST)
            return cur.fetchone()
        try:
            row = sc.watchdog(once, float(os.environ.get("SQLLEDGER_WATCHDOG_S", "60")), "digest")
            d = sc.parse_digest(row[0])
            return d["block_id"], d
        except Exception:
            self.conn = None            # an abandoned call keeps its own connection; never reuse it
            raise

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self.conn = None


class ImmudbDigests:
    system = "immudb"

    def __init__(self, addr, user="immudb", password="immudb", database="defaultdb", client=None):
        self.addr, self.user, self.password, self.database = addr, user, password, database
        self.client = client

    def take(self) -> tuple[int, dict]:
        if self.client is None:
            from immudb import ImmudbClient
            c = ImmudbClient(self.addr)
            c.login(self.user, self.password)
            c.useDatabase(self.database.encode())
            self.client = c
        try:
            st = self.client.currentState()
        except Exception:
            self.client = None
            raise
        h = st.txHash
        d = {"db": _text(st.db), "txId": int(st.txId),
             "txHash": h.hex() if isinstance(h, (bytes, bytearray)) else str(h),
             "signature": _text(st.signature) if st.signature else None}
        return d["txId"], d

    def close(self):
        self.client = None


def _text(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex() if any(b > 127 or b < 32 for b in v) else v.decode()
    return str(v) if v is not None else None


def take_one(src, clock=time.time) -> dict:
    t0 = clock()
    try:
        cov, d = src.take()
        return {"system": src.system, "t_before": round(t0, 4), "t_after": round(clock(), 4), "ok": True,
                "coverage": cov, "digest": d}
    except Exception as e:
        return {"system": src.system, "t_before": round(t0, 4), "t_after": round(clock(), 4), "ok": False,
                "error": str(e)[:300]}


def append(out: Path, rec: dict) -> None:
    with open(out, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def run(src, out: Path, period: float, stop, max_n: int | None = None, clock=time.time, sleep=time.sleep) -> int:
    """Take a digest every `period` s on a fixed schedule (a slow call does not shift the next one)."""
    n, nxt = 0, clock()
    while not stop():
        rec = take_one(src, clock)
        append(out, rec)
        n += 1
        if max_n is not None and n >= max_n:
            break
        nxt += period
        while not stop() and clock() < nxt:
            sleep(min(0.2, max(0.0, nxt - clock())))
        if clock() - nxt > period:          # fell behind by more than a period (store hung): skip ahead
            nxt = clock()
    return n


def load(path: Path) -> list:
    if not path or not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass            # a line cut by a kill: ignore it
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", choices=("sqlledger", "immudb"), required=True)
    ap.add_argument("--addr", required=True, help="host:port of the store")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--database")
    ap.add_argument("--period", type=float, default=30.0, help="seconds between digests")
    ap.add_argument("--out", type=Path, required=True, help="digest log, JSON lines (appended)")
    ap.add_argument("--once", action="store_true", help="one digest now")
    a = ap.parse_args()
    if a.system == "sqlledger":
        src = SqlLedgerDigests(a.addr, a.user, a.password, a.database)
    else:
        src = ImmudbDigests(a.addr, a.user or "immudb", a.password or "immudb", a.database or "defaultdb")
    stopped = {"v": False}

    def _stop(*_):
        stopped["v"] = True
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass
    a.out.parent.mkdir(parents=True, exist_ok=True)
    n = run(src, a.out, a.period, lambda: stopped["v"], max_n=1 if a.once else None)
    src.close()
    if a.once:
        rec = load(a.out)[-1]
        print(f"digest ok={rec['ok']} coverage={rec.get('coverage')} {rec.get('error', '')}".rstrip())
    else:
        print(f"digests taken: {n}")


if __name__ == "__main__":
    main()
