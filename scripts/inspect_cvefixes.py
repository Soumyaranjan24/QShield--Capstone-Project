"""Print CVEfixes table/column and row counts for reproducibility notes."""
import sqlite3
from pathlib import Path

db = Path(__file__).resolve().parents[1] / "datasets" / "processed" / "cvefixes_v1.0.0.sqlite3"
with sqlite3.connect(db) as connection:
    for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{name}")')]
        count = connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        print(f"{name}: {count:,} rows; columns={columns}")
