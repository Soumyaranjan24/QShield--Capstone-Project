#!/usr/bin/env python3
"""Prepare local, attributed lookup files from the project source datasets.

This script uses only the Python standard library. It never edits downloaded
source files. CVEfixes' SQL dump is streamed into SQLite to avoid loading the
multi-gigabyte decompressed SQL text into memory.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "datasets"
PROCESSED = DATA / "processed"
CRYPTO_CWES = {310, 326, 327, 328, 330, 780}


def retrieved_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rows(path: Path) -> Iterator[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        yield from csv.DictReader(stream)


def write_jsonl(path: Path, records: Iterator[dict]) -> int:
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
    return count


def prepare_cwe() -> int:
    source = DATA / "cwe" / "extracted" / "1000.csv"
    target = PROCESSED / "cwe_view_1000.jsonl"

    def records() -> Iterator[dict]:
        for raw in rows(source):
            cwe_id = raw.get("CWE-ID", "").strip()
            if not cwe_id.isdigit() or cwe_id == "1000":
                continue
            yield {
                "cwe_id": int(cwe_id),
                "name": raw.get("Name", "").strip(),
                "abstraction": raw.get("Weakness Abstraction", "").strip(),
                "status": raw.get("Status", "").strip(),
                "description": raw.get("Description", "").strip(),
                "extended_description": raw.get("Extended Description", "").strip(),
                "potential_mitigations": raw.get("Potential Mitigations", "").strip(),
                "source_view": 1000,
                "source_file": "MITRE CWE View 1000 CSV",
            }

    return write_jsonl(target, records())


def prepare_kev() -> int:
    source = DATA / "known_exploited_vulnerabilities.csv"
    target = PROCESSED / "cisa_kev.jsonl"

    def records() -> Iterator[dict]:
        for raw in rows(source):
            if raw.get("cveID", "").strip():
                yield {key: value.strip() for key, value in raw.items() if key}

    return write_jsonl(target, records())


def parse_benchmark(path: Path) -> Iterator[dict]:
    metadata: dict[str, str] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line or not line.startswith("#"):
                stream.seek(position)
                break
            key, _, value = line[1:].partition(":")
            if key.strip():
                metadata[key.strip()] = value.strip()
        for record in csv.DictReader(stream):
            yield {
                **record,
                "source_file": path.name,
                "metadata": metadata,
                "metric_scope": "signature operation timing; system memory metadata is not per-operation memory",
            }


def prepare_benchmarks() -> int:
    source_dir = DATA / "pqc_benchmarks" / "extracted" / "pqc-sig-bench-c-main" / "results"
    target = PROCESSED / "pqc_signature_benchmarks.jsonl"

    def records() -> Iterator[dict]:
        paths = list(source_dir.glob("*_liboqs.csv")) + list(source_dir.glob("*_traditional.csv"))
        for path in sorted(paths):
            yield from parse_benchmark(path)

    return write_jsonl(target, records())


def prepare_benchmark_sizes() -> int:
    source = DATA / "pqc_benchmarks" / "extracted" / "pqc-sig-bench-c-main" / "results" / "key_sig_sizes.csv"
    target = PROCESSED / "pqc_signature_sizes.jsonl"

    def records() -> Iterator[dict]:
        for raw in rows(source):
            yield {**raw, "source_file": source.name, "source_version": "pqc-sig-bench-c snapshot"}

    return write_jsonl(target, records())


def statements(stream: Iterator[str]) -> Iterator[str]:
    buffer = ""
    for line in stream:
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                yield statement
            buffer = ""
    if buffer.strip():
        raise ValueError("CVEfixes SQL dump ends with an incomplete statement")


def import_cvefixes(force: bool = False) -> Path:
    source = DATA / "cvefixes" / "extracted" / "CVEfixes_v1.0.0" / "Data" / "CVEfixes-2021-06-09.sql.gz"
    target = PROCESSED / "cvefixes_v1.0.0.sqlite3"
    if target.exists() and not force:
        return target
    if target.exists():
        target.unlink()

    connection = sqlite3.connect(target)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    count = 0
    with gzip.open(source, "rt", encoding="utf-8", errors="strict") as stream:
        for statement in statements(stream):
            connection.execute(statement)
            count += 1
            if count % 5000 == 0:
                connection.commit()
                print(f"CVEfixes SQL statements imported: {count:,}", file=sys.stderr)
    connection.commit()
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.close()
    return target


def export_crypto_subset(database: Path) -> int:
    """Export patch-level examples linked to the project's target crypto CWEs."""
    target = PROCESSED / "cvefixes_crypto_subset.jsonl"
    placeholders = ",".join("?" for _ in CRYPTO_CWES)
    query = f"""SELECT cc.cve_id, cc.cwe_id, fx.hash AS commit_hash, fx.repo_url,
        fc.filename, fc.programming_language, fc.diff, fc.code_before, fc.code_after
        FROM cwe_classification cc
        JOIN fixes fx ON fx.cve_id=cc.cve_id
        LEFT JOIN file_change fc ON fc.hash=fx.hash
        WHERE CAST(REPLACE(UPPER(cc.cwe_id),'CWE-','') AS INTEGER) IN ({placeholders})
        ORDER BY cc.cve_id, fc.filename"""
    count = 0
    with sqlite3.connect(database) as connection, target.open("w", encoding="utf-8", newline="\n") as output:
        connection.row_factory = sqlite3.Row
        for row in connection.execute(query, tuple(sorted(CRYPTO_CWES))):
            output.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
            count += 1
    return count


def build_manifest(counts: dict[str, int], cve_db: Path | None) -> None:
    entries = [
        {
            "name": "MITRE CWE View 1000",
            "source": "https://cwe.mitre.org/data/definitions/1000.html",
            "source_version": "CWE 5.0 View 1000 CSV; pinned by SHA-256",
            "license_or_terms": "MITRE CWE terms; retain attribution",
            "source_file": "datasets/cwe/extracted/1000.csv",
            "retrieved_at": retrieved_at(DATA / "cwe" / "cwe_view_1000.csv.zip"),
            "output_file": "datasets/processed/cwe_view_1000.jsonl",
            "records": counts.get("cwe", 0),
            "sha256": sha256(DATA / "cwe" / "extracted" / "1000.csv"),
            "note": "CWE-1000 is a view, not a weakness ID for vulnerability mapping.",
        },
        {
            "name": "CISA Known Exploited Vulnerabilities",
            "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source_version": datetime.fromtimestamp((DATA / "known_exploited_vulnerabilities.csv").stat().st_mtime, timezone.utc).isoformat(),
            "license_or_terms": "U.S. government work; verify source terms",
            "source_file": "datasets/known_exploited_vulnerabilities.csv",
            "retrieved_at": retrieved_at(DATA / "known_exploited_vulnerabilities.csv"),
            "output_file": "datasets/processed/cisa_kev.jsonl",
            "records": counts.get("kev", 0),
            "sha256": sha256(DATA / "known_exploited_vulnerabilities.csv"),
        },
        {
            "name": "CVEfixes v1.0.0",
            "source": "https://zenodo.org/records/4476564",
            "source_version": "v1.0.0; CVEs through 2021-06-09",
            "license_or_terms": "See included LICENSE.txt and dataset record",
            "source_file": "datasets/cvefixes/CVEfixes_v1.0.0.zip",
            "retrieved_at": retrieved_at(DATA / "cvefixes" / "CVEfixes_v1.0.0.zip"),
            "output_file": str(cve_db.relative_to(ROOT)).replace("\\", "/") if cve_db else None,
            "sha256": sha256(DATA / "cvefixes" / "CVEfixes_v1.0.0.zip"),
            "note": "Historical vulnerability/fix examples; not migration-complexity labels.",
        },
        {
            "name": "CVEfixes cryptographic-CWE patch subset",
            "source": "CVEfixes v1.0.0; CWEs 310, 326, 327, 328, 330, 780",
            "source_version": "Derived from CVEfixes v1.0.0; query in scripts/prepare_datasets.py",
            "license_or_terms": "CC BY 4.0; retain original attribution",
            "source_file": "datasets/processed/cvefixes_v1.0.0.sqlite3",
            "retrieved_at": retrieved_at(DATA / "cvefixes" / "CVEfixes_v1.0.0.zip"),
            "output_file": "datasets/processed/cvefixes_crypto_subset.jsonl" if cve_db else None,
            "records": counts.get("cvefixes_crypto_subset", 0),
            "sha256": sha256(PROCESSED / "cvefixes_crypto_subset.jsonl") if cve_db else None,
            "note": "Patch-level historical examples; never used as migration-complexity labels.",
        },
        {
            "name": "PQC and classical signature benchmark data",
            "source": "https://github.com/cryptohslu/pqc-sig-bench-c",
            "source_version": "Downloaded repository snapshot; result CSV metadata records run/library/platform",
            "license_or_terms": "Repository code is MIT; verify benchmark data terms with authors before redistribution",
            "source_file": "datasets/pqc_benchmarks/extracted/pqc-sig-bench-c-main/results",
            "retrieved_at": retrieved_at(DATA / "pqc_benchmarks" / "pqc-sig-bench-c-main.zip"),
            "output_file": "datasets/processed/pqc_signature_benchmarks.jsonl",
            "records": counts.get("benchmarks", 0),
            "sha256": sha256(DATA / "pqc_benchmarks" / "pqc-sig-bench-c-main.zip"),
            "note": "Signature timings and sizes; no KEM benchmark or per-operation memory metric.",
        },
        {
            "name": "PQC signature key and signature sizes",
            "source": "https://github.com/cryptohslu/pqc-sig-bench-c",
            "source_version": "Downloaded repository snapshot",
            "license_or_terms": "See repository LICENSE and citation file",
            "source_file": "datasets/pqc_benchmarks/extracted/pqc-sig-bench-c-main/results/key_sig_sizes.csv",
            "retrieved_at": retrieved_at(DATA / "pqc_benchmarks" / "pqc-sig-bench-c-main.zip"),
            "output_file": "datasets/processed/pqc_signature_sizes.jsonl",
            "records": counts.get("benchmark_sizes", 0),
            "sha256": sha256(DATA / "pqc_benchmarks" / "pqc-sig-bench-c-main.zip"),
        },
        {
            "name": "Custom migration-complexity annotations",
            "source": "Project-curated; no public source dataset",
            "source_version": "Template schema v1",
            "license_or_terms": "Project must define permitted use for contributed annotations",
            "source_file": "datasets/custom_annotated/migration_complexity_annotations.csv",
            "retrieved_at": retrieved_at(DATA / "custom_annotated" / "migration_complexity_annotations.csv"),
            "output_file": None,
            "records": 0,
            "note": "Template only; populate with reviewed examples and provenance.",
        },
    ]
    manifest = {
        "schema_version": 1,
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "datasets": entries,
    }
    (PROCESSED / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--import-cvefixes", action="store_true", help="stream the full CVEfixes SQL dump into SQLite")
    parser.add_argument("--force-cvefixes", action="store_true", help="replace an existing generated CVEfixes SQLite database")
    args = parser.parse_args()

    PROCESSED.mkdir(parents=True, exist_ok=True)
    counts = {
        "cwe": prepare_cwe(),
        "kev": prepare_kev(),
        "benchmarks": prepare_benchmarks(),
        "benchmark_sizes": prepare_benchmark_sizes(),
    }
    cve_db = import_cvefixes(force=args.force_cvefixes) if args.import_cvefixes else None
    if cve_db is None:
        existing = PROCESSED / "cvefixes_v1.0.0.sqlite3"
        cve_db = existing if existing.exists() else None
    if cve_db:
        counts["cvefixes_crypto_subset"] = export_crypto_subset(cve_db)
    build_manifest(counts, cve_db)
    print(json.dumps({"outputs": str(PROCESSED), "records": counts, "cvefixes_database": str(cve_db) if cve_db else None}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
