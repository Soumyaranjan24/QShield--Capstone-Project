"""Migration-complexity experiment; refuses to train on inadequate labels."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

LABELS = {"Low", "Medium", "High"}
MIN_EXAMPLES = 30
MIN_GROUPS_PER_CLASS = 2


def load_annotations(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    return [row for row in rows if row.get("migration_complexity") in LABELS and row.get("repository_url") and row.get("algorithm_or_library")]


def rule_baseline(row: dict[str, str]) -> str:
    context = " ".join(row.get(key, "") for key in ("crypto_component", "algorithm_or_library", "example_path", "evidence", "notes")).casefold()
    if any(term in context for term in ("multiple service", "protocol change", "certificate lifecycle", "wire format", "hardware", "firmware", "interoperability break")):
        return "High"
    if any(term in context for term in ("isolated wrapper", "provider interface", "single call site", "drop-in adapter")):
        return "Low"
    return "Medium"


def train(path: Path, artifacts: Path) -> dict:
    try:
        import joblib
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report, confusion_matrix
        from sklearn.model_selection import GroupShuffleSplit
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError as exc:
        raise RuntimeError("Install analyzer requirements to train the optional classifier") from exc

    rows = load_annotations(path)
    counts = Counter(row["migration_complexity"] for row in rows)
    groups_per_label = {label: len({r["repository_url"] for r in rows if r["migration_complexity"] == label}) for label in LABELS}
    if len(rows) < MIN_EXAMPLES or len(counts) != 3 or min(groups_per_label.values(), default=0) < MIN_GROUPS_PER_CLASS:
        raise ValueError(f"Insufficient reviewed labels: need at least {MIN_EXAMPLES} examples across all three classes and {MIN_GROUPS_PER_CLASS} repositories per class; found {len(rows)} examples and {groups_per_label}")

    features = [{"crypto_component": r["crypto_component"], "algorithm_or_library": r["algorithm_or_library"], "example_path": Path(r["example_path"]).suffix.lower()} for r in rows]
    labels = [r["migration_complexity"] for r in rows]
    groups = [r["repository_url"] for r in rows]
    split = next(((train_idx, test_idx) for train_idx, test_idx in GroupShuffleSplit(n_splits=100, test_size=0.25, random_state=42).split(features, labels, groups)
                  if {labels[i] for i in train_idx} == LABELS and {labels[i] for i in test_idx} == LABELS), None)
    if split is None:
        raise ValueError("Grouped split did not place all three labels in both partitions; add more repositories per class")
    train_idx, test_idx = split
    categorical = ["crypto_component", "algorithm_or_library", "example_path"]
    model = Pipeline([
        ("features", ColumnTransformer([("categorical", OneHotEncoder(handle_unknown="ignore"), categorical)])),
        ("classifier", RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample", random_state=42)),
    ])
    model.fit([features[i] for i in train_idx], [labels[i] for i in train_idx])
    predictions = model.predict([features[i] for i in test_idx])
    baseline_predictions = [rule_baseline(rows[i]) for i in test_idx]
    metrics = {
        "model_version": "migration-complexity-v1",
        "target": "migration_complexity",
        "split": "GroupShuffleSplit by repository_url; random_state=42",
        "class_counts": dict(counts),
        "groups_per_class": groups_per_label,
        "classification_report": classification_report([labels[i] for i in test_idx], predictions, labels=sorted(LABELS), output_dict=True, zero_division=0),
        "rules_baseline_report": classification_report([labels[i] for i in test_idx], baseline_predictions, labels=sorted(LABELS), output_dict=True, zero_division=0),
        "confusion_matrix_labels": sorted(LABELS),
        "confusion_matrix": confusion_matrix([labels[i] for i in test_idx], predictions, labels=sorted(LABELS)).tolist(),
        "rules_baseline_confusion_matrix": confusion_matrix([labels[i] for i in test_idx], baseline_predictions, labels=sorted(LABELS)).tolist(),
        "training_rows": len(train_idx),
        "test_rows": len(test_idx),
    }
    artifacts.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, artifacts / "migration_complexity_v1.joblib")
    (artifacts / "migration_complexity_v1.metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics


def predict(features: dict, artifacts: Path) -> dict:
    model_file = artifacts / "migration_complexity_v1.joblib"
    if not model_file.exists():
        return {"status": "manual_review", "model_version": None, "prediction": None, "confidence": None, "reason": "No trained model; collect and review repository annotations first."}
    try:
        import joblib
        model = joblib.load(model_file)
        probabilities = model.predict_proba([features])[0]
        index = int(probabilities.argmax())
        confidence = float(probabilities[index])
        if confidence < 0.55:
            return {"status": "manual_review", "model_version": "migration-complexity-v1", "prediction": None, "confidence": confidence, "reason": "Model confidence is below the review threshold."}
        return {"status": "decision_support", "model_version": "migration-complexity-v1", "prediction": str(model.classes_[index]), "confidence": round(confidence, 4), "reason": "Review the prediction with repository and dependency evidence."}
    except Exception:
        return {"status": "manual_review", "model_version": None, "prediction": None, "confidence": None, "reason": "Model artifact could not be loaded safely."}
