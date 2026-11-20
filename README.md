# Accounted Ingestion

Source code and data for the paper "Verifiable Ingestion of Acknowledged Provenance Events on Managed Cloud Services"
by Md Shohel Khan, Rubaiyat Sha Fardin Siam and Muhammad Abdullah Adnan.

Archived on Zenodo: https://doi.org/10.5281/zenodo.24404927

The API acknowledges an event when Kafka has it and returns a signed receipt with the broker
position. Writers append the event to the tenant's log (MMR), anchor the log in write-once storage,
and only then commit the Kafka offset. If a writer skips a record it stores a verdict instead, which
anyone can check. A statement maker posts a HEAD or STALL statement to Sigsum every period. The
replay auditor finds unaccounted records and files complaints, and the judge decides them offline.

```
api/          ingest API (FastAPI)
processing/   writers (run_consumer.py), statement maker (run_maker.py)
crypto/       tenant logs, anchor store, signed records, period statements, audits, Sigsum client
database/     Neo4j graph, API keys, rate limiting
collectors/   request-path collector
tools/        judge, replay auditor, checkers, contract publisher
bench/        load generator, end-of-run audit, immudb and SQL Server ledger baselines
tla/          TLA+ models and TLC configs
results/      raw output of the runs in the paper
deploy/       Dockerfile, docker-compose.yml, Sigsum test policy
```

## Setup

You need Docker (Compose v2) and Python 3.12.

```sh
pip install -r requirements.txt
pip install -r bench/requirements.txt
```

The second file is only needed for the load generator and the baselines.

Copy `deploy/.env.example` to `deploy/.env` and fill in the secrets and keys. Then:

```sh
cd deploy
docker compose up -d --build api
docker compose exec api python tools/publish_contract.py --partitions 8 --first-acct-offset end
docker compose up -d
```

The first command starts Kafka, Neo4j, MinIO, Redis and the API. The contract has to be published
before the writers and the statement maker start; the last command starts them.

Everything runs on one host. MinIO is the S3 store with Object Lock. The API does not acknowledge
anything before the contract is published. `--partitions` has to be the same as `PARTITIONS` in
`.env`.

Ports: API 8000, Kafka 29092, Neo4j 7687, MinIO 9000 (all on localhost).

## Sending events

From `deploy/`, with the values of `.env` exported in the shell:

```sh
python ../bench/loadgen.py --base-url http://localhost:8000 --api-key $BOOTSTRAP_API_KEY \
    --kafka localhost:29092 --neo4j-uri neo4j://localhost:7687 --neo4j-password $NEO4J_PASSWORD \
    --rate 1000 --duration-s 120 --tenants 64 \
    --receipts-sample 64 --receipts-sample-out receipts.json --out run.json
```

`run.json` has the acknowledged rate, latencies, consumer lag and delivery to the graph.

Two endpoints are useful for a tenant:

- `GET /api/v1/accounted/period/{j}` gives the tenant's opening of period `j`
- `GET /api/v1/provenance/proof/{event_id}` gives the proof bundle of an event

## Audit after a run

```sh
docker compose cp receipts.json api:/tmp/receipts.json
docker compose exec api python bench/audit.py audit --receipts /tmp/receipts.json
```

It runs the replay audit and the accounting audit, checks the period statements, and runs the judge
on the sampled receipts and on the complaints of the replay. It also counts the stored objects (we
used this for the cost numbers).

## Tools for a third party

Run these from the repository root. `judge_time.py`, `check_breach.py`, `check_verdict.py` and
`verify_bundle.py` only need the files in `tools/` and the `cryptography` package.
`replay_audit.py` and `publish_contract.py` import the rest of the repository.

Replay the broker against the store:

```sh
python tools/replay_audit.py --contract contract.json --key <public key> --state audit_state.json \
    --out audit_out/ --bootstrap localhost:29092 --topic provenance-events \
    --s3-bucket anchors --s3-endpoint http://localhost:9000
```

It writes `report.json` and one claim file per unaccounted record. `contract.json` comes from
`publish_contract.py --out`. The MinIO credentials are read from `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`.

Decide a claim:

```sh
python tools/check_breach.py claim.json --key <public key> --pl-view view.json --store-dir store/
```

The exit code is 0 for MET, EXCUSED or PENDING, 1 for VIOLATED and 2 for REJECT. `--pl-view` is the
view of the public log; it is not needed if the claim file already has one. `--store-dir` is a copy
of the anchor store. The defense is built from it, and without a defense the judge cannot answer MET.

Check a verdict record, or verify a proof bundle:

```sh
python tools/check_verdict.py verdict.json --prefix records.json --blobs blobs.json --key <public key>
python tools/verify_bundle.py bundle.json --key <public key>
```

## Baselines

The three pipeline baselines of the paper are settings in `.env`:

| Baseline | Setting |
|---|---|
| Commit-after-DB | `ACCT_CAA=false` and `ACCT_ABLATION_OK=true` |
| Ack-after-anchor | `ACCT_ACK_AFTER_ANCHOR=true` |
| No accounting | `ACCT_MODE=false` |

immudb and SQL Server ledger are in `bench/baselines/`. The comment at the top of each compose file
shows how to start it next to the pipeline.

## TLA+

You need Java 11 or newer. The script downloads `tla2tools.jar` (v1.7.4) on the first run.

```sh
bash tla/run_tlc.sh
bash tla/run_tlc.sh accounted
bash tla/run_tlc.sh NoCAA
bash tla/run_traces.sh
```

Without an argument `run_tlc.sh` checks all 68 configurations. It also takes a module name (ingest,
accounted, logs, chain, period or maker) or the name of one configuration. `run_traces.sh` checks
the traces recorded from the storage code, and four altered traces that must be rejected.

The five models of the paper:

- `Accounted`: one tenant's log with its writers, outages, and an attacker on the sender and the database
- `AccountedLogs`: two logs on one partition
- `AccountedChain`: anchoring when the lock is broken
- `Period`: the statements and the judge
- `MakerTiming`: statement makers with skewed clocks

`Ingest` is the plain pipeline the others are built on. The traces are checked against `Ingest` and
`Accounted`.

Every `.cfg` file says which module it is for and what TLC should report: `EXPECT: OK`, or
`EXPECT: FAIL` with the property that must be violated. Most of the FAIL configurations switch off
one rule of the design.

## Results

`results/` has the raw output of the runs in the paper. In the folder names `c3` is Accounted, `c2`
is Commit-after-DB, `aaa` is Ack-after-anchor and `c0` is No accounting. `r1`, `r2`, `r3` are
repeats of the same run.

| Folder | Runs | In the paper |
|---|---|---|
| `throughput/` | offered rates from 500 to 15,000 events/s, the graph alone, immudb and the SQL ledger | Figure 3, Tables 5 and 6 |
| `faults/` | process and network faults, store outages, and the control run without a fault | Table 4 |
| `attacks/` | erased tails, forged records, failing appends | Table 4 |
| `powercuts/` | power cut to the database host or a broker host, at 7,000 events/s (`aaa` at 1,000) | Table 4, Section 6.3, Table 6 |
| `rollback/` | SQL ledger rolled back to a backup, before and after the next digest | Section 6.6 |
| `tenants/` | 8, 64 and 512 tenants at 310 events/s | Section 6.5 |
| `default_period/` | 30 minutes with the default period (360 s) and deadline (300 s) | Section 7 |
| `isolation/` | one tenant floods a shared partition with 33 (`lo`) or 133 (`hi`) events/s, isolation rule off (`iso0`) and on (`iso1`) | Appendix F |

The throughput runs are from the five cloud servers (64 vCPUs, NVMe disks). Everything else is
from the five VMs. In `throughput/` the number in a folder name is the offered rate in events/s,
and `graph` is the graph alone.

In `faults/` and `attacks/` there is one folder per run, named after the system and the fault.
A `powercuts/` or `tenants/` folder holds all repeats of one setting, so the files there start
with the run name (for example `T5b_r2.audit.json`).

The files of a run:

- `<run>.json`: result of the load generator (acknowledged and refused events, latencies)
- `<run>.audit.json`: the audit after the run (replay audit, complaints, period statements, the
  judge's answers for the 64 sampled receipts)
- `<run>.costs.json`: CPU time and storage per event
- `<run>.exposure.json`: time from acknowledgement to anchor
- `<run>.recovery.json`: when the fault started and ended, and what was refused during it
- `<run>.verify.json` (baselines): which acknowledged events were still in the database
- `config.json`: the settings of the run

The other files are snapshots of the containers' CPU and memory (`res_*.txt`), the contract, and
the sampled receipts. Container logs are not included because of their size.

`tenants/c3/T8_r1` acknowledged less than half of the offered events and is marked `INVALID`. We
did not use it.

## License

The code is under the MIT License, see `LICENSE`. The data in `results/` is under the
Creative Commons Attribution 4.0 International License (CC BY 4.0), see `LICENSE-DATA`.
