import re
import sys
from pathlib import Path


def observations(text, first_field):
    return [m.group(0) for m in re.finditer(rf"^    \[{first_field}.*?\],?$", text, flags=re.M)]


def write_control(d, src, text, cfg, name, rows):
    body = ",\n".join(r.rstrip(",") for r in rows)
    text = re.sub(r"Trace == <<\n.*?\n>>", lambda _: "Trace == <<\n" + body + "\n>>", text, flags=re.S)
    (d / f"{name}.tla").write_text(text.replace(src, name), encoding="utf-8", newline="\n")
    (d / f"{name}.cfg").write_text(cfg, encoding="utf-8", newline="\n")
    print("wrote", name)


def ingest_controls(d):
    src = "Trace_adversary_tenant_b"
    text = (d / f"{src}.tla").read_text(encoding="utf-8")
    cfg = (d / f"{src}.cfg").read_text(encoding="utf-8")
    rows = observations(text, "treeCount")
    assert len(rows) >= 3, "unexpected trace shape"

    # The heartbeat clears a quiet tenant's pending flag and leaves its forged tip in place.
    last = rows[-1]
    assert "tipSigned |-> TRUE" in last and "pending |-> {}" in last, last
    write_control(d, src, text, cfg, "Control_unrepaired_tip",
                  rows[:-1] + [last.replace("tipSigned |-> TRUE", "tipSigned |-> FALSE")])

    # The append that reaches k = 5 does not flag its snapshot pending in the same transaction.
    i = next(k for k, r in enumerate(rows) if "treeCount |-> 5" in r and "pending |-> {5}" in r)
    write_control(d, src, text, cfg, "Control_unflagged_cross",
                  rows[:i] + [rows[i].replace("pending |-> {5}", "pending |-> {}")] + rows[i + 1:])


def acct_controls(d):
    src = "Trace_acct_crash_acme"
    text = (d / f"{src}.tla").read_text(encoding="utf-8")
    cfg = (d / f"{src}.cfg").read_text(encoding="utf-8")
    rows = observations(text, "log")
    assert len(rows) >= 5, "unexpected trace shape"

    # A commit past a position the store does not hold: from the first observation with the fourth
    # record in the database and three anchored, the committed offset is 4 instead of 3.
    i = next(k for k, r in enumerate(rows)
             if "[pos |-> 4" in r.split("anchored")[0] and "committed |-> 3]" in r
             and "[pos |-> 4" not in r.split("anchored")[1])
    write_control(d, src, text, cfg, "Control_acct_uncovered_commit",
                  rows[:i] + [r.replace("committed |-> 3]", "committed |-> 4]") for r in rows[i:]])

    # A DUP verdict whose referent does not exist: the DUP at offset 2 points at seq 9.
    dup = '[pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 1,'
    assert any(dup in r for r in rows), "the trace has no DUP verdict"
    write_control(d, src, text, cfg, "Control_acct_dangling_ref",
                  [r.replace(dup, '[pos |-> 2, kind |-> "DUP", sub |-> 2, ref |-> 9,') for r in rows])


if __name__ == "__main__":
    trace_dir = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent / "traces")
    ingest_controls(trace_dir)
    acct_controls(trace_dir)
