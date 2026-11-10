import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://pqc_app:local-dev-only-change-me@localhost:5432/pqc_assistant")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(PROJECT_ROOT / "uploads"))).resolve()
DATASETS_DIR = Path(os.getenv("DATASETS_DIR", str(PROJECT_ROOT / "datasets"))).resolve()
MODEL_ARTIFACTS_DIR = Path(os.getenv("MODEL_ARTIFACTS_DIR", str(PROJECT_ROOT / "model_artifacts"))).resolve()
ANALYZER_SHARED_TOKEN = os.getenv("ANALYZER_SHARED_TOKEN", "local-analyzer-token-change-me")
MAX_FILES = int(os.getenv("MAX_EXTRACTED_FILES", "20000"))
MAX_UNPACKED_BYTES = int(os.getenv("MAX_UNPACKED_BYTES", str(1_000_000_000)))
MAX_MEMBER_BYTES = int(os.getenv("MAX_MEMBER_BYTES", str(100_000_000)))
