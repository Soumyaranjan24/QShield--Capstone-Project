# QShield synthetic scan fixture

This tiny repository is synthetic and intended only to exercise the QShield upload and Python pattern scanner. It is not production code, and QShield does not execute the functions.

Expected scanner cues in `src/crypto_demo.py`: MD5 and SHA-1 hash calls, RSA and X25519 identifiers, and ML-KEM/ML-DSA identifiers. The scanner may emit nearby identifier findings; review the evidence and line numbers rather than expecting an exact total.
