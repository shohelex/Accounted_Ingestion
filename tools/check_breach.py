#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import string
import sys
import time
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import acct_common as AC  # noqa: E402
import judge_time  # noqa: E402
from check_verdict import check_verdict  # noqa: E402

# Digits of the period, contract version and anchor numbers in store keys.
J_DIGITS, VER_DIGITS, N_DIGITS = 12, 6, 20
_TENANT_SAFE = frozenset(string.ascii_letters + string.digits + "_-")


def _complaint_fields(complaint: dict) -> Optional[dict]:
    if "receipt" in complaint:
        r = complaint["receipt"]
        return {"tenant_id": r.get("tenant_id"), "event_id": r.get("event_id"),
                "leaf_hash": r.get("leaf_hash"), "sub": r.get("sub"), "contract": r.get("contract"),
                "pos": r.get("pos"), "form": "receipt"}
    if "sub_record" in complaint:
        s = complaint["sub_record"]
        a = s.get("acct") or {}
        return {"tenant_id": s.get("tenant_id"), "event_id": s.get("event_id"),
                "leaf_hash": a.get("leaf_hash"), "sub": a.get("sub"), "contract": a.get("contract"),
                "pos": None, "form": "sub"}
    return None


def complaint_signature_ok(complaint: dict, key_hex: str) -> bool:
    try:
        if "receipt" in complaint:
            return AC.verify_receipt_v2(complaint["receipt"], key_hex)
        s = complaint["sub_record"]
        return AC.verify_sub_tag(s["tenant_id"], s["event_id"], s["acct"], key_hex)
    except (KeyError, TypeError):
        return False


# a defense from a store mirror

def _encode_tenant(t: str) -> str:
    return "".join(ch if ch in _TENANT_SAFE else "".join(f"%{b:02X}" for b in ch.encode()) for ch in t)


class Mirror:
    """Read-only view of a mirror directory: anchor_<tenant>.jsonl chains and objects/<key>."""

    def __init__(self, directory: str):
        self.dir = directory

    def get(self, key: str) -> Optional[bytes]:
        parts = key.split("/")
        if any(p in ("", ".", "..") for p in parts):
            return None
        path = os.path.join(self.dir, "objects", *parts)
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def list(self, prefix: str) -> List[str]:
        root = os.path.join(self.dir, "objects")
        out = []
        for dirpath, _, files in os.walk(root):
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
            for name in files:
                key = name if rel == "." else f"{rel}/{name}"
                if key.startswith(prefix) and not name.endswith(".tmp"):
                    out.append(key)
        return sorted(out)

    def anchors(self, tenant: str, key_hex: str) -> List[dict]:
        recs: Dict[int, dict] = {}
        path = os.path.join(self.dir, f"anchor_{_encode_tenant(tenant)}.jsonl")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        a = json.loads(line)
                    except ValueError:
                        continue
                    if a.get("tenant_id") == tenant and AC.verify_anchor(a, key_hex):
                        recs.setdefault(int(a["n"]), a)
        for k in self.list(f"anchors/{_encode_tenant(tenant)}/"):
            try:
                a = json.loads(self.get(k))
            except (TypeError, ValueError):
                continue
            if a.get("tenant_id") == tenant and AC.verify_anchor(a, key_hex):
                recs.setdefault(int(a["n"]), a)
        return [recs[n] for n in sorted(recs)]


def _unchk_evidence(chain: List[dict], segments: Dict[str, dict], seq: int, cb: dict) -> dict:
    """For an UNCHECKABLE verdict at seq: the anchors from the last one before its budget window
    through the one covering it, with their segments, so the judge can count the window's verdicts."""
    cover_i = next((k for k, a in enumerate(chain) if isinstance(a.get("seg"), dict)
                    and int(a["seg"].get("from", 0)) <= seq < int(a["seg"].get("to", 0))), None)
    if cover_i is None:
        return {}
    cover = chain[cover_i]
    start = float(cover["ts"]) * 1000 - int(cb["window_periods"]) * int(cb["period_s"]) * 1000
    first = 0
    for k in range(cover_i, -1, -1):
        if float(chain[k]["ts"]) * 1000 < start:
            first = k
            break
    part = chain[first:cover_i + 1]
    return {"anchors": part, "segment": segments.get(str(int(cover["n"]))),
            "segments": {str(int(a["n"])): segments[str(int(a["n"]))] for a in part
                         if str(int(a["n"])) in segments}}


def mirror_defense(mirror: Mirror, complaint: dict, contract_body: dict, key_hex: str) -> dict:
    """The defense an honest respondent builds from the store (crypto/audit_period.build_defense):
    statement bodies, contracts, receipt tree heads, the tenant's openings and anchors, and the
    complaint's records from the v2 segments with an MMR proof against every opened head."""
    c = _complaint_fields(complaint)
    dep = contract_body["dep"]
    d: Dict[str, Any] = {"bodies": {}, "openings": {}, "anchors": [], "records": [], "blobs": {},
                         "unchk": {}, "segments": {}, "heads": [], "contracts": []}

    def add_body(j: str, st) -> None:
        cur = d["bodies"].get(j)
        items = cur if isinstance(cur, list) else [cur] if cur is not None else []
        if st not in items:
            items.append(st)
        d["bodies"][j] = items[0] if len(items) == 1 else items

    def load(k: str):
        try:
            return json.loads(mirror.get(k))
        except (TypeError, ValueError):
            return None
    for k in mirror.list(f"periods/{dep}/"):
        rest = k[len(f"periods/{dep}/"):]
        if "/" in rest or not rest[:J_DIGITS].isdigit() or rest[J_DIGITS:J_DIGITS + 1] != ".":
            if c is not None and rest[:J_DIGITS].isdigit() \
                    and rest.endswith(f".open/{_encode_tenant(c['tenant_id'])}.json"):
                op = load(k)
                if op is not None:
                    d["openings"][str(int(rest[:J_DIGITS]))] = op
            continue
        j, tail = str(int(rest[:J_DIGITS])), rest[J_DIGITS:]
        if tail in (".json", ".outage.json"):
            st = load(k)
            if st is not None:
                add_body(j, st)
        elif tail == ".receipt.json":
            r = load(k)
            if isinstance(r, dict) and isinstance(r.get("tree_head"), dict):
                d["heads"].append(r["tree_head"])
    for k in mirror.list(f"contract/{dep}/"):
        rest = k[len(f"contract/{dep}/"):]
        if "/" in rest or not rest[:VER_DIGITS].isdigit():
            continue
        if rest[VER_DIGITS:] == ".json":
            st = load(k)
            if st is not None:
                d["contracts"].append(st)
        elif rest[VER_DIGITS:] == ".receipt.json":
            r = load(k)
            if isinstance(r, dict) and isinstance(r.get("tree_head"), dict):
                d["heads"].append(r["tree_head"])
    if c is None:
        return d
    t = c["tenant_id"]
    chain = mirror.anchors(t, key_hex)
    d["anchors"] = chain
    records: Dict[int, dict] = {}
    for a in chain:
        if a.get("v") != 2 or not a.get("seg"):
            continue
        raw = mirror.get(f"segments/{_encode_tenant(t)}/{int(a['n']):0{N_DIGITS}d}.json")
        ok, _, recs = AC.check_segment(a, raw, None) if raw is not None else (False, "", [])
        if ok:
            d["segments"][str(int(a["n"]))] = json.loads(raw)
            for r in recs:
                records[int(r["seq"])] = r

    def mine(r):
        if r.get("tenant_id") != t:
            return False
        if c["form"] == "receipt":
            p = r.get("pos") or {}
            q = c["pos"] or {}
            return (p.get("topic"), p.get("p"), p.get("o")) == (q.get("topic"), q.get("p"), q.get("o"))
        return (r.get("sub") or {}).get("sub") == c["sub"]
    for s in sorted(k for k, r in records.items() if mine(r)):
        need = {s}
        v = records[s].get("verdict") or {}
        if isinstance(v.get("ref"), int):
            need.add(int(v["ref"]))
        raw_ref = v.get("raw") or {}
        if raw_ref.get("blob"):
            b = mirror.get(raw_ref["blob"])
            if b is not None:
                d["blobs"][raw_ref.get("sha256")] = base64.b64encode(b).decode()
        if v.get("type") == "UNCHECKABLE":
            d["unchk"][str(s)] = _unchk_evidence(chain, d["segments"], s, contract_body)
        for op in d["openings"].values():
            n = int(op["n"])
            if any(x not in records for x in range(n)):
                continue
            hashes = [AC.record_hash(records[x]) for x in range(n)]
            for i in sorted(need):
                if i < n:
                    d["records"].append({"n": n, "index": i, "record": records[i],
                                         "proof": AC.mmr_proof(hashes, i)})
    return d


# the check

def check(claim: dict, key_hex: str, now_ms: int, contract: Optional[dict] = None,
          view: Optional[dict] = None, policy_text: Optional[str] = None,
          store_dir: Optional[str] = None) -> dict:
    def reject(kind, detail):
        return {"verdict": "REJECT", "kind": kind, "detail": detail, "evidence": []}
    contract = contract or claim.get("contract")
    if not isinstance(contract, dict) or not isinstance(contract.get("body"), dict):
        return reject("contract", "no contract in the claim and none given")
    body = contract["body"]
    if not AC.same_key(body.get("pk"), key_hex):
        return reject("key", "the contract does not name the pinned key")
    if not AC.verify_statement(contract, key_hex) or body.get("kind") != "contract":
        return reject("contract", "the contract's signature does not verify under the pinned key")
    complaint = claim.get("complaint") or {}
    fields = _complaint_fields(complaint)
    if fields is None:
        return reject("complaint", "neither a receipt nor a tagged broker record")
    if not complaint_signature_ok(complaint, key_hex):
        return reject("signature", "the complaint is not signed by the deployment key")
    if fields["contract"] != AC.contract_hash(body):
        return reject("contract", "the complaint names another contract")
    view = dict(view if view is not None else (claim.get("public") or {}))
    if policy_text is not None and not view.get("policy"):
        view["policy"] = policy_text
    bodies = view.get("bodies")
    defense = claim.get("defense")
    if store_dir:
        built = mirror_defense(Mirror(store_dir), complaint, body, key_hex)
        defense = dict(built, **(defense or {}))
        if not bodies:
            bodies = built["bodies"]
    return judge_time.judge(complaint, contract, view, bodies, defense, int(now_ms), check_verdict)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("claim", help="claim bundle (JSON)")
    ap.add_argument("--key", required=True, help="deployment public key (hex), from a channel you trust")
    ap.add_argument("--contract", help="signed contract statement (JSON), if not in the claim")
    ap.add_argument("--pl-view", help="public-log view (JSON), if not in the claim")
    ap.add_argument("--policy", help="Sigsum trust policy file, if the view does not carry it")
    ap.add_argument("--store-dir", help="mirror of the write-once store, to build the defense from")
    ap.add_argument("--now-ms", type=int, default=None, help="evaluation time (default: now)")
    a = ap.parse_args()
    claim = json.loads(_read(a.claim))
    contract = json.loads(_read(a.contract)) if a.contract else None
    view = json.loads(_read(a.pl_view)) if a.pl_view else None
    policy = _read(a.policy) if a.policy else None
    if policy is not None:
        judge_time.parse_policy(policy)                   # refuse an unparsable policy early
    now = a.now_ms if a.now_ms is not None else int(time.time() * 1000)
    res = check(claim, a.key, now, contract, view, policy, a.store_dir)
    print(json.dumps(res, indent=2, sort_keys=True, default=str))
    v = res.get("verdict")
    return 0 if v in ("MET", "EXCUSED", "PENDING") else 1 if v == "VIOLATED" else 2


if __name__ == "__main__":
    sys.exit(main())
