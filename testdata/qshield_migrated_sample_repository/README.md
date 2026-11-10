# QShield synthetic migrated-state fixture

This is a synthetic after-state for testing QShield's before/after assessment comparison. It is not a working cryptographic migration and contains algorithm labels only; do not use it in an application.

Expected comparison behavior: legacy MD5, SHA-1, RSA, and X25519 cues from the baseline sample disappear. ML-KEM and ML-DSA identifiers remain visible. SHA-256 appears as a modern hash example. QShield only compares scan findings; it does not edit either archive.
