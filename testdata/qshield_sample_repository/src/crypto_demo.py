"""Synthetic cryptography examples for static-scanner testing. No function is called."""

import hashlib


def legacy_md5_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def legacy_sha1_digest(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def rsa_fixture_identifier():
    # Identifier cue only; no key is generated.
    rsa = "RSA"
    return rsa


def x25519_fixture_identifier():
    # Identifier cue only; no key agreement is performed.
    x25519 = "X25519"
    return x25519


def pqc_algorithm_labels():
    # Labels only; no cryptographic operation is performed.
    ml_kem_768 = "ML-KEM-768"
    ml_dsa_65 = "ML-DSA-65"
    return ml_kem_768, ml_dsa_65
