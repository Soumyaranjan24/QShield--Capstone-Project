# Implementation status

This status is tied to the capstone roadmap. A service scaffold or passing unit test does not count as full end-to-end acceptance.

| Phase | Status | Implemented / remaining |
|---|---|---|
| 0 · Dataset preparation | Complete locally | Canonical `datasets/` path; checksummed source manifest; CWE, KEV, signature/classical benchmark JSONL; full CVEfixes v1.0.0 SQLite conversion and 273-row cryptographic-CWE patch subset; custom annotation guide/template. |
| 1 · Architecture and technical plan | Documented | Existing architecture, methodology, service split, and assessment workflow documents define the intended system. |
| 2 · Environment | Scaffolded, not run | Compose, PostgreSQL schema, Redis, analyzer, worker, gateway, and frontend definitions exist. Full Compose startup still needs Docker. |
| 3 · Auth and repository handling | Implemented, not end-to-end verified | Express registration/login, Argon2id/JWT, owned projects, ZIP upload checks, analyzer dispatch, and assessment polling are present. Requires Compose for integration verification. |
| 4 · Discovery | Python MVP | Python AST scanning, weak primitive rules, evidence redaction, and safe extraction are implemented. Other languages, dependency manifests, and TLS configuration are not yet supported. |
| 5 · CBOM and CWE | MVP implemented | CWE data is ingested; explicit weak-primitive mappings and CycloneDX-shaped JSON/CSV exports are present. Validate output against the official CycloneDX schema before relying on conformance claims. |
| 6 · Vulnerability intelligence | Data ingested; matching intentionally conservative | KEV and CVEfixes crypto subset are stored with provenance. The scanner does not yet identify product/version pairs, so results state that no correlation was established. |
| 7 · Risk and CARS | Provisional MVP | Weighted factor breakdown and five dimensions are returned. Several factors use declared defaults because repository evidence cannot establish business context. |
| 8 · PQC and benchmarks | Partial | Purpose-based FIPS recommendations and signature timing/size data are shown. KEM metrics and per-operation memory are unavailable. |
| 9 · ML, roadmap, validation | Pipeline scaffolded | Annotation rubric, rules baseline, repository-group split, metrics, manual-review fallback, roadmap generation, and before/after API are present. No classifier is trained because the annotation template has no labels. |
| 10 · Dashboard and reports | Implemented, not browser verified | React workflow, findings, risk/CARS, recommendations, benchmark sample, migration comparison, JSON/PDF report, and CBOM export are present. Needs Node/Docker to build and exercise. |
| 11 · Evaluation and demo | Partially verified | Twelve local Python unit/contract tests cover analyzer behavior and config parsing. Python compilation also passes. Full API/database/queue/browser E2E and measured scanner/ML evaluation remain to be run. |

## Current verification environment

Python analyzer dependencies are installed in the ignored local `.venv`. This workspace did not provide Docker, Node/npm, or Git, so Compose startup, gateway execution, frontend build, browser flows, and repository status checks could not be run here.
