from __future__ import annotations

import json
import hashlib
from pathlib import Path

from psycopg2.extras import Json, execute_values

from app.core.config import DATASETS_DIR
from app.core.db import connection


def jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def load_reference_data() -> dict[str, int]:
    processed = DATASETS_DIR / "processed"
    counts = {"cwe": 0, "kev": 0, "cvefixes_crypto_examples": 0, "benchmarks": 0}
    with connection() as conn:
        with conn.cursor() as cur:
            values = [(r["cwe_id"], r["name"] or "Unknown", r.get("abstraction"), r.get("status"), r.get("description"), r.get("extended_description"), r.get("potential_mitigations"), "CWE View 1000 CSV") for r in jsonl(processed / "cwe_view_1000.jsonl") or []]
            if values:
                execute_values(cur, """INSERT INTO cwe_records(cwe_id,name,abstraction,status,description,extended_description,potential_mitigations,source_version) VALUES %s
                ON CONFLICT(cwe_id) DO UPDATE SET name=EXCLUDED.name,abstraction=EXCLUDED.abstraction,status=EXCLUDED.status,description=EXCLUDED.description,extended_description=EXCLUDED.extended_description,potential_mitigations=EXCLUDED.potential_mitigations,source_version=EXCLUDED.source_version""", values)
            counts["cwe"] = len(values)

            values = [(r.get("cveID"), r.get("vendorProject"), r.get("product"), r.get("vulnerabilityName"), r.get("dateAdded") or None, r.get("requiredAction"), Json([v.strip() for v in (r.get("cwes") or "").split(",") if v.strip()]), "CISA KEV local snapshot") for r in jsonl(processed / "cisa_kev.jsonl") or [] if r.get("cveID")]
            if values:
                execute_values(cur, """INSERT INTO kev_records(cve_id,vendor_project,product,vulnerability_name,date_added,required_action,cwes,source_version) VALUES %s
                ON CONFLICT(cve_id) DO UPDATE SET vendor_project=EXCLUDED.vendor_project,product=EXCLUDED.product,vulnerability_name=EXCLUDED.vulnerability_name,date_added=EXCLUDED.date_added,required_action=EXCLUDED.required_action,cwes=EXCLUDED.cwes,source_version=EXCLUDED.source_version""", values)
            counts["kev"] = len(values)

            values = []
            for r in jsonl(processed / "pqc_signature_benchmarks.jsonl") or []:
                try:
                    ms = float(r["ms_per_op"])
                    ops = float(r["ops_per_sec"])
                    iterations = int(r["iterations"])
                except (KeyError, TypeError, ValueError):
                    continue
                values.append((r.get("algorithm", "unknown"), r.get("operation", "unknown"), ms, ops, iterations, Json(r.get("metadata", {})), r.get("source_file", "unknown"), "pqc-sig-bench-c snapshot"))
            if values:
                execute_values(cur, """INSERT INTO benchmark_results(algorithm,operation,ms_per_op,ops_per_sec,iterations,platform_metadata,source_file,source_version) VALUES %s
                ON CONFLICT(source_file,algorithm,operation) DO UPDATE SET ms_per_op=EXCLUDED.ms_per_op,ops_per_sec=EXCLUDED.ops_per_sec,iterations=EXCLUDED.iterations,platform_metadata=EXCLUDED.platform_metadata,source_version=EXCLUDED.source_version""", values)
            counts["benchmarks"] = len(values)

            values = []
            for r in jsonl(processed / "pqc_signature_sizes.jsonl") or []:
                try:
                    public_key = int(r["public_key_bytes"])
                    secret_key = int(r["secret_key_bytes"])
                    signature = int(r["signature_bytes"])
                except (KeyError, TypeError, ValueError):
                    continue
                values.append((r.get("algorithm", "unknown"), "sizes", None, None, None, public_key, secret_key, signature, Json({"nist_level": r.get("nist_level")}), r.get("source_file", "key_sig_sizes.csv"), "pqc-sig-bench-c snapshot"))
            if values:
                execute_values(cur, """INSERT INTO benchmark_results(algorithm,operation,ms_per_op,ops_per_sec,iterations,public_key_bytes,secret_key_bytes,signature_bytes,platform_metadata,source_file,source_version) VALUES %s
                ON CONFLICT(source_file,algorithm,operation) DO UPDATE SET public_key_bytes=EXCLUDED.public_key_bytes,secret_key_bytes=EXCLUDED.secret_key_bytes,signature_bytes=EXCLUDED.signature_bytes,platform_metadata=EXCLUDED.platform_metadata,source_version=EXCLUDED.source_version""", values)
            counts["benchmark_sizes"] = len(values)

            values = []
            for r in jsonl(processed / "cvefixes_crypto_subset.jsonl") or []:
                key = "|".join(str(r.get(k) or "") for k in ("cve_id", "cwe_id", "commit_hash", "filename"))
                source_key = hashlib.sha256(key.encode("utf-8")).hexdigest()
                values.append((source_key, r.get("cve_id"), str(r.get("cwe_id")), r.get("commit_hash"), r.get("repo_url"), r.get("filename"), r.get("programming_language"), Json(r), "CVEfixes v1.0.0"))
            if values:
                execute_values(cur, """INSERT INTO cvefixes_crypto_examples(source_key,cve_id,cwe_id,commit_hash,repository_url,filename,programming_language,patch_json,source_version) VALUES %s ON CONFLICT(source_key) DO NOTHING""", values, page_size=250)
            counts["cvefixes_crypto_examples"] = len(values)
    return counts
