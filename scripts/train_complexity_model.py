from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))
from app.services.ml import train

root = Path(__file__).resolve().parents[1]
print(train(root / "datasets" / "custom_annotated" / "migration_complexity_annotations.csv", root / "model_artifacts"))
