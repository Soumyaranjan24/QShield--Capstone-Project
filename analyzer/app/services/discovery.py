from __future__ import annotations

import ast
import re
from pathlib import Path


CRYPTO_CALLS = {
    "md5": ("MD5", "hash", "CWE-328", 0.92),
    "sha1": ("SHA-1", "hash", "CWE-328", 0.84),
    "sha256": ("SHA-256", "hash", None, 0.92),
    "sha384": ("SHA-384", "hash", None, 0.92),
    "sha512": ("SHA-512", "hash", None, 0.92),
    "sha3": ("SHA-3", "hash", None, 0.9),
    "pbkdf2": ("PBKDF2", "key_derivation", None, 0.88),
    "scrypt": ("scrypt", "key_derivation", None, 0.9),
    "argon2": ("Argon2", "password_hash", None, 0.9),
    "des": ("DES", "encryption", "CWE-327", 0.93),
    "3des": ("3DES", "encryption", "CWE-327", 0.85),
    "blowfish": ("Blowfish", "encryption", "CWE-327", 0.82),
    "rsa": ("RSA", "public_key", None, 0.78),
    "ecdh": ("ECDH", "key_agreement", None, 0.82),
    "ecds": ("ECDSA", "signature", None, 0.82),
    "ed25519": ("Ed25519", "signature", None, 0.92),
    "ed448": ("Ed448", "signature", None, 0.92),
    "x25519": ("X25519", "key_agreement", None, 0.92),
    "x448": ("X448", "key_agreement", None, 0.92),
    "dh": ("DH", "key_agreement", None, 0.75),
    "ml_kem": ("ML-KEM", "key_agreement", None, 0.95),
    "mlkem": ("ML-KEM", "key_agreement", None, 0.92),
    "kyber": ("ML-KEM", "key_agreement", None, 0.9),
    "ml_dsa": ("ML-DSA", "signature", None, 0.95),
    "mldsa": ("ML-DSA", "signature", None, 0.92),
    "dilithium": ("ML-DSA", "signature", None, 0.9),
    "slh_dsa": ("SLH-DSA", "signature", None, 0.95),
    "slhdsa": ("SLH-DSA", "signature", None, 0.92),
    "sphincs": ("SLH-DSA", "signature", None, 0.9),
    "falcon": ("Falcon/FN-DSA", "signature", None, 0.9),
    "aes": ("AES", "encryption", None, 0.88),
    "chacha20": ("ChaCha20", "encryption", None, 0.9),
}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}
SECRET = re.compile(r"(?i)(password|secret|token|credential|private[_ -]?key|api[_ -]?key)\s*[:=]\s*[^,;\s]+")
PREFIX_ALGORITHMS = {"aes", "md5", "sha1", "sha256", "sha384", "sha512", "sha3", "des", "3des", "chacha20", "blowfish", "ed25519", "ed448", "x25519", "x448", "kyber", "dilithium", "sphincs", "falcon", "mlkem", "mldsa", "slhdsa"}


def _matches_algorithm_name(name: str, key: str) -> bool:
    return name == key or name.startswith(key + "_") or (key in PREFIX_ALGORITHMS and name.startswith(key))


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    return ""


class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str, source_lines: list[str]):
        self.path = relative_path
        self.lines = source_lines
        self.findings: list[dict] = []
        self.seen: set[tuple[int, str]] = set()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        match = next(((key, value) for key, value in CRYPTO_CALLS.items() if _matches_algorithm_name(name, key)), None)
        if match:
            key, (algorithm, operation, cwe, confidence) = match
            self._record(node, algorithm, operation, cwe, confidence, f"AST call `{name}`")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        name = node.id.lower()
        key = next((candidate for candidate in sorted(CRYPTO_CALLS, key=len, reverse=True) if _matches_algorithm_name(name, candidate)), None)
        if key:
            algorithm, operation, cwe, confidence = CRYPTO_CALLS[key]
            self._record(node, algorithm, operation, cwe, min(confidence, 0.68), f"AST identifier `{node.id}`")

    def _record(self, node: ast.AST, algorithm: str, operation: str, cwe: str | None, confidence: float, detector: str) -> None:
        line = getattr(node, "lineno", 1)
        key = (line, algorithm)
        if key in self.seen:
            return
        self.seen.add(key)
        evidence = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        hint = evidence.casefold()
        if re.search(r"\b(sign|verify)\s*\(", hint):
            operation = "signature"
        elif re.search(r"\b(exchange|derive_shared_secret)\s*\(", hint):
            operation = "key_agreement"
        elif re.search(r"\b(encrypt|decrypt)\s*\(", hint):
            operation = "encryption"
        elif "generate_private_key" in hint or "generate_key" in hint:
            operation = "key_generation"
        if "BEGIN" in evidence.upper() and "PRIVATE KEY" in evidence.upper():
            evidence = "[PRIVATE KEY MATERIAL REDACTED]"
        else:
            evidence = SECRET.sub(r"\1=[REDACTED]", evidence)[:500]
        self.findings.append({
            "file_path": self.path,
            "line_start": line,
            "line_end": getattr(node, "end_lineno", line),
            "algorithm": algorithm,
            "operation": operation,
            "purpose": {"public_key": "key_establishment_or_signature", "key_agreement": "key_establishment", "signature": "digital_signature", "hash": "integrity_or_password_hashing", "encryption": "data_encryption"}.get(operation, "unknown"),
            "library": None,
            "key_size_bits": None,
            "detector": detector,
            "confidence": confidence,
            "evidence": evidence,
            "cwe_ids": [cwe] if cwe else [],
            "quantum_threat_type": "Shor-potential" if algorithm in {"RSA", "ECDH", "ECDSA", "Ed25519", "Ed448", "X25519", "X448", "DH"} else "Grover-security-margin" if algorithm in {"AES", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "ChaCha20", "DES", "3DES", "Blowfish"} else None,
        })


def discover(root: Path) -> tuple[list[dict], int]:
    results: list[dict] = []
    scanned = 0
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        lines = content.splitlines()
        try:
            tree = ast.parse(content, filename=str(path))
        except SyntaxError:
            continue
        visitor = CryptoVisitor(path.relative_to(root).as_posix(), lines)
        visitor.visit(tree)
        results.extend(visitor.findings)
    return results, scanned
