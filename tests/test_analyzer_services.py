import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from app.services.assessment import analyze, recommend, score_cars, score_risk
from app.services.discovery import CryptoVisitor
from app.services.ml import rule_baseline
from app.services.safe_extract import UnsafeArchive, extract_archive


class DiscoveryTests(unittest.TestCase):
    def test_ast_finds_weak_hash_and_redacts_token(self):
        source = 'token = "do-not-store"; digest = hashlib.md5(payload).hexdigest()\n'
        tree_source = __import__("ast").parse(source)
        visitor = CryptoVisitor("app.py", source.splitlines())
        visitor.visit(tree_source)
        self.assertEqual(len(visitor.findings), 1)
        self.assertEqual(visitor.findings[0]["algorithm"], "MD5")
        self.assertIn("REDACTED", visitor.findings[0]["evidence"])
        self.assertNotIn("do-not-store", visitor.findings[0]["evidence"])
        self.assertEqual(visitor.findings[0]["cwe_ids"], ["CWE-328"])

    def test_key_generation_does_not_claim_a_pq_signature_replacement(self):
        source = "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        visitor = CryptoVisitor("app.py", source.splitlines())
        visitor.visit(__import__("ast").parse(source))
        self.assertEqual(visitor.findings[0]["operation"], "key_generation")
        self.assertIn("Review", recommend("RSA", "key_generation")["recommendation"])

    def test_pqc_parameterized_identifiers_are_discovered(self):
        source = "ml_kem_768 = provider.load_ml_kem_768()\nml_dsa_65 = provider.load_ml_dsa_65()\n"
        visitor = CryptoVisitor("pqc.py", source.splitlines())
        visitor.visit(__import__("ast").parse(source))
        self.assertEqual({finding["algorithm"] for finding in visitor.findings}, {"ML-KEM", "ML-DSA"})


class SafeExtractTests(unittest.TestCase):
    def test_extracts_normal_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "ok.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("src/app.py", "import hashlib\n")
            extracted = extract_archive(archive, root / "out")
            self.assertEqual(len(extracted), 1)
            self.assertEqual(extracted[0].read_text(), "import hashlib\n")

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../escape.py", "unsafe")
            with self.assertRaises(UnsafeArchive):
                extract_archive(archive, root / "out")
            self.assertFalse((root / "escape.py").exists())

    def test_rejects_extreme_compression_ratio(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "bomb.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("large.py", "0" * 30_000)
            with self.assertRaises(UnsafeArchive):
                extract_archive(archive, root / "out")


class ScoringTests(unittest.TestCase):
    def test_risk_is_repeatable_and_explained(self):
        finding = {"algorithm": "RSA", "cwe_ids": []}
        result = score_risk([finding])
        self.assertEqual(result["score"], 72.25)
        self.assertEqual(sum(result["weights"].values()), 1.0)
        self.assertEqual(set(result["factors"]), set(result["weights"]))

    def test_cars_has_five_evidenced_dimensions(self):
        result = score_cars([], 3)
        self.assertEqual(len(result["dimensions"]), 5)
        self.assertTrue(all("evidence" in value for value in result["dimensions"].values()))
        self.assertTrue(result["provisional"])

    def test_complete_analysis_returns_evidence_cbom_and_manual_ml_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("service.py", 'import hashlib\ndigest = hashlib.md5(b"sample").hexdigest()\n')
            result = analyze(archive, root / "work")
            self.assertEqual(result["findings"][0]["algorithm"], "MD5")
            self.assertEqual(result["findings"][0]["cwe_ids"], ["CWE-328"])
            self.assertEqual(result["cbom"]["specVersion"], "1.6")
            self.assertEqual(result["ml"]["status"], "manual_review")
            self.assertEqual(result["vulnerability_correlation"]["status"], "not_correlated")

    def test_rules_baseline_explains_obvious_complexity_cues(self):
        self.assertEqual(rule_baseline({"evidence": "single call site behind isolated wrapper"}), "Low")
        self.assertEqual(rule_baseline({"notes": "protocol change requires certificate lifecycle coordination"}), "High")
        self.assertEqual(rule_baseline({}), "Medium")


if __name__ == "__main__":
    unittest.main()
