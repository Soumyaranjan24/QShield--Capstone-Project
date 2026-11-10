"""Synthetic after-state for scanner comparison only; no cryptographic operations are performed."""

import hashlib


def modern_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pqc_algorithm_labels():
    # Names are labels only; no algorithm implementation or key operation is included.
    ml_kem_768 = "ML-KEM-768"
    ml_dsa_65 = "ML-DSA-65"
    return ml_kem_768, ml_dsa_65
