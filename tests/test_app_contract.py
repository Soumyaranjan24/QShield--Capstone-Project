import sys
import unittest
from pathlib import Path
import json
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from app.main import app


class AnalyzerApiContractTests(unittest.TestCase):
    def test_internal_health_scan_and_pdf_routes_are_registered(self):
        routes = {(route.path, tuple(sorted(route.methods or []))) for route in app.routes}
        self.assertTrue(any(path == "/healthz" and "GET" in methods for path, methods in routes))
        self.assertTrue(any(path == "/api/analyzer/scan" and "POST" in methods for path, methods in routes))
        self.assertTrue(any(path == "/api/reports/{assessment_id}/pdf" and "GET" in methods for path, methods in routes))

    def test_compose_and_package_manifests_parse_with_required_services(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        self.assertEqual(set(compose["services"]), {"postgres", "redis", "analyzer", "worker", "backend", "frontend"})
        for path in (ROOT / "backend" / "package.json", ROOT / "frontend" / "package.json"):
            json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
