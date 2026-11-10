# Model artifacts

The migration-complexity classifier is intentionally absent until reviewed labels are available. Add annotations to `datasets/custom_annotated/migration_complexity_annotations.csv`, then run `python scripts/train_complexity_model.py` after installing analyzer dependencies. The trainer requires at least 30 labeled examples across all three classes and at least two distinct repositories per class. It keeps repositories grouped across train/test, and writes a model plus metrics here. Predictions are decision support; missing or low-confidence models return manual review.
