from __future__ import annotations

import json
from pathlib import Path

from app.core.config import DATASETS_DIR, MODEL_ARTIFACTS_DIR
from app.services.discovery import discover
from app.services.ml import predict
from app.services.safe_extract import extract_archive

RISK_WEIGHTS = {"quantum_exposure": 0.30, "sensitivity": 0.25, "system_exposure": 0.20, "data_lifetime": 0.15, "business_criticality": 0.10}


def recommend(algorithm: str, operation: str) -> dict:
    if operation in {"signature", "public_key_signature"}:
        target = "ML-DSA (FIPS 204); consider SLH-DSA (FIPS 205) where hash-based signatures fit requirements"
    elif operation == "key_agreement":
        target = "ML-KEM (FIPS 203), with a standards-compatible hybrid transition where required"
    elif algorithm in {"RSA", "ECDH", "ECDSA"}:
        target = "Review cryptographic purpose before selecting ML-KEM or a PQ signature standard"
    else:
        target = "Review key size, mode, implementation, and use; PQC replacement may not apply"
    return {"source_algorithm": algorithm, "operation": operation, "recommendation": target, "basis": "Purpose-based mapping; validate protocol and implementation constraints."}


def benchmark_context(findings: list[dict]) -> dict:
    relevant = {f["algorithm"].upper() for f in findings}
    pqc_names = {"ML-DSA", "SLH-DSA", "FALCON", "FN-DSA"}
    timing_path = DATASETS_DIR / "processed" / "pqc_signature_benchmarks.jsonl"
    size_path = DATASETS_DIR / "processed" / "pqc_signature_sizes.jsonl"
    timings, sizes = [], []
    if timing_path.exists():
        with timing_path.open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                algorithm = record.get("algorithm", "")
                if any(name in algorithm.upper() for name in relevant) or any(name in algorithm.upper() for name in pqc_names):
                    timings.append(record)
    if size_path.exists():
        with size_path.open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                algorithm = record.get("algorithm", "")
                if any(name in algorithm.upper() for name in relevant) or any(name in algorithm.upper() for name in pqc_names):
                    sizes.append(record)
    return {"signature_timings": timings[:100], "key_signature_sizes": sizes[:100], "source": "cryptohslu/pqc-sig-bench-c", "limitations": "Platform-specific signature measurements; system memory is host metadata, not per-operation RAM. No KEM metrics."}


def migration_tasks(findings: list[dict]) -> list[dict]:
    unique = {(f["algorithm"], f["operation"], f["file_path"]) for f in findings}
    tasks = []
    for algorithm, operation, file_path in sorted(unique):
        tasks.append({"priority": "review", "algorithm": algorithm, "operation": operation, "file_path": file_path, "steps": ["Confirm the cryptographic purpose and protocol dependencies.", "Introduce an abstraction or provider boundary and add compatibility tests.", "Pilot a standards-based or hybrid replacement where applicable.", "Validate interoperability and compare the before/after assessment.", "Retire the classical path only after rollout and policy review."], "estimated_complexity": "manual_review"})
    return tasks


def score_risk(findings: list[dict]) -> dict:
    algorithms = {f["algorithm"] for f in findings}
    quantum = 100 if algorithms & {"RSA", "ECDH", "ECDSA", "Ed25519", "Ed448", "X25519", "X448", "DH"} else 35 if algorithms & {"AES", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "ChaCha20", "DES", "3DES", "Blowfish"} else 0
    factors = {"quantum_exposure": quantum, "sensitivity": 70 if findings else 0, "system_exposure": 50 if findings else 0, "data_lifetime": 65 if findings else 0, "business_criticality": 50 if findings else 0}
    score = round(sum(factors[key] * weight for key, weight in RISK_WEIGHTS.items()), 2)
    category = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
    return {"score": score, "category": category, "factors": factors, "weights": RISK_WEIGHTS, "assumptions": "Sensitivity, exposure, lifetime, and business criticality use provisional defaults pending user-specific inputs."}


def score_cars(findings: list[dict], files_scanned: int) -> dict:
    dimensions = {
        "inventory_completeness": {"score": min(100, files_scanned * 10), "evidence": f"Scanned {files_scanned} Python source files."},
        "algorithm_compliance": {"score": max(0, 100 - 20 * sum(bool(f["cwe_ids"]) for f in findings)), "evidence": "Provisional penalty for algorithms flagged by explicit weak-primitive rules."},
        "architectural_decoupling": {"score": 50, "evidence": "Not inferable from cryptographic call sites alone."},
        "toolchain_readiness": {"score": 50, "evidence": "No CI/toolchain migration evidence collected yet."},
        "governance_alignment": {"score": 0, "evidence": "No governance evidence supplied; score is unknown represented as zero."},
    }
    return {"score": round(sum(item["score"] for item in dimensions.values()) / len(dimensions), 2), "dimensions": dimensions, "provisional": True}


def analyze(archive: Path, work_dir: Path, progress=None) -> dict:
    extracted = work_dir / "source"
    if progress:
        progress("EXTRACTION")
    files = extract_archive(archive, extracted)
    if progress:
        progress("DISCOVERY")
    findings, source_count = discover(extracted)
    if progress:
        progress("CBOM")
    cbom = [{"bom-ref": f"crypto-{i}", "type": "cryptographic-asset", "name": f["algorithm"], "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": _primitive(f["algorithm"]), "parameterSetIdentifier": f["algorithm"]}}, "evidence": {"occurrences": [{"location": f["file_path"], "line": f["line_start"]}]}} for i, f in enumerate(findings, 1)]
    if progress:
        progress("RISK")
    risk = score_risk(findings)
    cars = score_cars(findings, source_count)
    model_features = {
        "crypto_component": ",".join(sorted({f["operation"] for f in findings})) or "none",
        "algorithm_or_library": ",".join(sorted({f["algorithm"] for f in findings})) or "none",
        "example_path": ".py",
    }
    model = predict(model_features, MODEL_ARTIFACTS_DIR)
    if progress:
        progress("RECOMMENDATIONS")
    recommendations = [recommend(f["algorithm"], f["operation"]) for f in findings]
    return {
        "schema_version": "1.0",
        "files_scanned": source_count,
        "archive_entries_extracted": len(files),
        "findings": findings,
        "cbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": cbom},
        "risk": risk,
        "cars": cars,
        "recommendations": recommendations,
        "ml": {**model, "target": "migration_complexity", "input_features": model_features},
        "vulnerability_correlation": {"status": "not_correlated", "reason": "No exact product/version/CVE evidence was established by this code scan."},
        "benchmarks": benchmark_context(findings),
        "migration_roadmap": migration_tasks(findings),
        "benchmark_scope": "Signature measurements are platform-specific; KEM and per-operation memory comparisons are unavailable.",
    }


def _primitive(algorithm: str) -> str:
    if algorithm in {"MD5", "SHA-1"}:
        return "hash"
    if algorithm in {"AES", "DES", "3DES", "Blowfish"}:
        return "block-cipher"
    if algorithm == "ChaCha20":
        return "stream-cipher"
    if algorithm in {"ML-DSA", "SLH-DSA", "Falcon/FN-DSA", "Ed25519", "Ed448", "ECDSA"}:
        return "signature"
    if algorithm in {"RSA", "ECDH", "X25519", "X448", "DH", "ML-KEM"}:
        return "pke"
    return "unknown"
