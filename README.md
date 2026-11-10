# AI-Driven Quantum-Safe Cryptography Assessment Assistant

This repository is being implemented as a capstone MVP with separate React, Express, FastAPI, PostgreSQL, Redis, and Celery services.

## Start locally

1. Install Docker Desktop with Compose.
2. Copy `.env.example` to `.env`; set non-default JWT/analyzer secrets and keep `DATABASE_URL` credentials consistent with the PostgreSQL variables.
3. Run `python scripts/prepare_datasets.py` to generate the processed JSONL catalogs (add `--import-cvefixes` only if the local SQLite copy is missing).
4. Run `docker compose up --build`.
5. Open the UI at http://localhost:5173; the client API is at http://localhost:8000/api. Both published ports bind to localhost.

The scanner never executes uploaded repository code. Uploads are size-limited and extracted into a private shared volume. Do not expose the development secrets or database/Redis ports to a public network.

## Data preparation

See [`datasets/README.md`](datasets/README.md). Run `python scripts/prepare_datasets.py` to generate attributed JSONL lookup files. Add `--import-cvefixes` to build the local SQLite copy from the original compressed SQL dump.

## Verify the local analyzer

On Windows, create `.venv`, install `analyzer/requirements.txt`, then run `.venv\Scripts\python -m unittest discover -s tests -v`. Docker and Node are not required for these unit/contract checks; they are required to run the full dashboard stack.

## Current MVP limits

The first scanner release focuses on Python and known cryptographic APIs. CVE/KEV correlation is conservative and only supported when explicit evidence is available; a CWE match alone is not a CVE match. The bundled PQC benchmark data covers signatures and platform-specific timing/key sizes, not KEM or per-operation memory. Migration complexity predictions remain manual review until enough curated labels exist.
