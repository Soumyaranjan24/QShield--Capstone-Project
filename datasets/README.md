# Project datasets

Canonical project dataset path: `datasets/`.

| Dataset | Local path | Source / status |
|---|---|---|
| MITRE CWE View 1000 | `cwe/cwe_view_1000.csv.zip`, extracted to `cwe/extracted/1000.csv` | Official CSV archive: https://cwe.mitre.org/data/definitions/1000.html. Retain MITRE attribution and terms. CWE-1000 is a view identifier, not a vulnerability mapping value; map findings to individual CWE IDs. |
| CVEfixes v1.0.0 | `cvefixes/CVEfixes_v1.0.0.zip` and `cvefixes/extracted/CVEfixes_v1.0.0/` | Official Zenodo record: https://zenodo.org/records/4476564. Archive MD5 verified: `729aa041a4f8c466cf90de9c7d14fe41`. SQL is distributed compressed as `.sql.gz`; see the included `INSTALL.md` for conversion instructions. |
| PQC signature benchmarks | `pqc_benchmarks/pqc-sig-bench-c-main.zip` and `pqc_benchmarks/extracted/pqc-sig-bench-c-main/` | Source repository: https://github.com/cryptohslu/pqc-sig-bench-c. Includes PQC and classical platform-specific timing CSVs and `results/key_sig_sizes.csv`. Cite hardware and methodology from its README. Repository code is MIT; confirm data redistribution terms with the authors before republishing results. |
| CISA KEV | `known_exploited_vulnerabilities.csv` | Project's downloaded CISA snapshot. Official catalog/download: https://www.cisa.gov/known-exploited-vulnerabilities-catalog. Snapshot retrieval timestamp and SHA-256 are in `processed/manifest.json`. |
| Custom annotated repository data | `custom_annotated/migration_complexity_annotations.csv` | Project-created template only; no labels included. See `custom_annotated/ANNOTATION_GUIDE.md` for Low/Medium/High criteria and provenance requirements. |

The PQC measurements are platform- and implementation-specific. The Kaggle source name mentioned in the project architecture could not be verified, so the included benchmark data is the available reproducible repository source. Do not combine these sources into one undifferentiated training table. Run `python scripts/prepare_datasets.py` to create derived JSONL files and `processed/manifest.json`; run with `--import-cvefixes` to stream the original CVEfixes SQL dump into SQLite.
