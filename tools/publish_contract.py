#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse_offsets(values: List[str], topic: str) -> Dict[str, int]:
    """{"topic/p": o} from "topic/p=o" (or "p=o") arguments."""
    out: Dict[str, int] = {}
    for v in values:
        k, sep, o = v.partition("=")
        if not sep or not o.strip().isdigit():
            raise ValueError(f"--first-acct-offset {v!r}: expected TOPIC/P=OFFSET")
        k = k.strip()
        if "/" not in k:
            k = f"{topic}/{k}"
        out[k] = int(o)
    return out


async def read_offsets(settings, topic: str, which: str) -> Dict[str, int]:
    """Each partition's committed offset (or high watermark) now, from the broker."""
    from crypto.period_statements import read_broker_status
    status = await read_broker_status(topic, settings.kafka_consumer_group)
    return {tp: int(v[0] if which == "committed" else v[1]) for tp, v in status.items()}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--partitions", type=int, required=True, help="partition count of the topic (frozen)")
    ap.add_argument("--effective-j", type=int, default=None, help="first period under this contract")
    ap.add_argument("--retention-s", type=int, default=7 * 86400, help="broker retention, seconds")
    ap.add_argument("--first-acct-offset", action="append", default=None,
                    help="committed (default), end, none, or TOPIC/P=OFFSET (repeat per partition)")
    ap.add_argument("--dry-run", action="store_true", help="print the signed contract; store and post nothing")
    ap.add_argument("--out", default=None, help="also write the signed contract to this file")
    args = ap.parse_args(argv)

    from config import settings
    from crypto.anchor_store import WriteConflict, get_anchor_store
    from crypto.period_statements import (contract_from_settings, contract_hash, contract_key,
                                          contract_receipt_key, p10_problems, sign_statement,
                                          theta_max_s)
    from crypto.records import canon, stmt_message
    from crypto.signing import get_signer
    from processing.sources import send_bound_ms

    signer = get_signer(settings)
    if signer is None:
        print("MERKLE_SIGNING_SEED is not set", file=sys.stderr)
        return 1
    topic = settings.kafka_provenance_topic
    fao = args.first_acct_offset or ["committed"]
    first: Optional[Dict[str, int]] = None
    if fao in (["committed"], ["end"]):
        try:
            first = asyncio.run(read_offsets(settings, topic, fao[0]))
        except Exception as e:
            print(f"cannot read the broker: {type(e).__name__}: {e}; pass --first-acct-offset "
                  f"TOPIC/P=O values or 'none'", file=sys.stderr)
            return 1
    elif fao != ["none"]:
        try:
            first = parse_offsets(fao, topic)
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
    try:
        body = contract_from_settings(settings, args.partitions, args.effective_j,
                                      first_acct_offset=first)
    except ValueError as e:
        print(f"invalid contract: {e}", file=sys.stderr)
        return 1
    body["retention_s"] = int(args.retention_s)
    if body["retention_s"] < theta_max_s(body) + int(settings.acct_audit_interval_s):
        print(f"retention {body['retention_s']} s is below the longest time to a verdict plus the "
              f"audit interval ({theta_max_s(body) + int(settings.acct_audit_interval_s)} s)", file=sys.stderr)
        return 1
    # The API refuses to acknowledge under a contract whose delta does not cover its send bound.
    timing = p10_problems(body, send_bound_ms(),
                          int(settings.acct_broker_skew_ms), int(settings.acct_clock_skew_ms))
    if timing:
        print(f"{timing[0]}; raise ACCT_DELTA_S or lower KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS / "
              f"KAFKA_PRODUCER_REQUEST_TIMEOUT_MS", file=sys.stderr)
        return 1
    if not body["witness_policy_sha256"] or not body["sigsum_key_hash"]:
        print("warning: no witness policy or public-log key configured; the judge cannot use this "
              "contract's public log", file=sys.stderr)
    stmt = sign_statement(signer, body)
    out = {"contract": stmt, "hash": contract_hash(body), "message": stmt_message(body).hex(),
           "theta_max_s": theta_max_s(body)}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(stmt, f, indent=2, sort_keys=True)
    if args.dry_run:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    store = get_anchor_store(settings)
    if store is None:
        print("anchoring is disabled; the contract must be stored", file=sys.stderr)
        return 1
    key = contract_key(body["dep"], body["ver"])
    try:
        written = store.put_once(key, canon(stmt))
    except WriteConflict:
        print(f"a different contract is already stored under {key}; raise ACCT_CONTRACT_VERSION",
              file=sys.stderr)
        return 1
    out["stored"] = key if written else f"{key} (already stored)"
    from crypto.merkle_tree_storage import merkle_tree_storage
    client = merkle_tree_storage._public_witness()
    if client is None:
        out["public"] = "no public log configured: contract not posted"
    else:
        receipt = client.receipt_if_included(stmt_message(body)) or client.witness(stmt_message(body))
        try:
            store.put_once(contract_receipt_key(body["dep"], body["ver"]), receipt.to_json().encode())
        except WriteConflict:
            pass
        out["public"] = {"leaf_index": receipt.leaf_index, "tree_size": receipt.tree_head.size}
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
