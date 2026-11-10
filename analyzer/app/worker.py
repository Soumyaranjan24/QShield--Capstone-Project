from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from celery import Celery
from psycopg2.extras import Json

from app.core.config import REDIS_URL, UPLOAD_DIR
from app.core.db import connection
from app.services.assessment import analyze

celery_app = Celery("pqc_analyzer", broker=REDIS_URL, backend=REDIS_URL)


@celery_app.task(name="analyze_assessment")
def analyze_assessment(assessment_id: str) -> dict:
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT a.id, r.stored_name FROM assessments a JOIN repositories r ON r.id=a.repository_id WHERE a.id=%s""", (assessment_id,))
            record = cur.fetchone()
            if not record:
                raise ValueError("Assessment or repository not found")
            cur.execute("UPDATE assessments SET status='SCANNING', stage='EXTRACTION', started_at=NOW() WHERE id=%s", (assessment_id,))

    archive = (UPLOAD_DIR / record["stored_name"]).resolve()
    if not archive.is_relative_to(UPLOAD_DIR.resolve()) or not archive.is_file():
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE assessments SET status='FAILED',stage='FAILED',error_message='Stored archive is unavailable',completed_at=NOW() WHERE id=%s", (assessment_id,))
        raise ValueError("Stored archive is unavailable")
    work_dir = Path(tempfile.mkdtemp(prefix=f"assessment-{assessment_id}-"))
    try:
        def progress(stage: str) -> None:
            with connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE assessments SET stage=%s WHERE id=%s", (stage, assessment_id))

        result = analyze(archive, work_dir, progress=progress)
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM cryptographic_findings WHERE assessment_id=%s", (assessment_id,))
                for item in result["findings"]:
                    cur.execute("""INSERT INTO cryptographic_findings
                    (assessment_id,file_path,line_start,line_end,detected_algorithm,operation_type,purpose,library_name,key_size_bits,detection_method,confidence,evidence,cwe_ids)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (assessment_id,item["file_path"],item["line_start"],item["line_end"],item["algorithm"],item["operation"],item["purpose"],item["library"],item["key_size_bits"],item["detector"],item["confidence"],Json({"snippet":item["evidence"]}),Json(item["cwe_ids"])))
                cur.execute("""UPDATE assessments SET status='COMPLETED',stage='COMPLETED',files_scanned=%s,findings_count=%s,
                overall_risk_score=%s,cars_score=%s,result_json=%s,completed_at=NOW() WHERE id=%s""",
                (result["files_scanned"],len(result["findings"]),result["risk"]["score"],result["cars"]["score"],Json(result),assessment_id))
        return {"assessment_id": assessment_id, "status": "COMPLETED", "findings_count": len(result["findings"])}
    except Exception as exc:
        with connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE assessments SET status='FAILED',stage='FAILED',error_message=%s,completed_at=NOW() WHERE id=%s", (str(exc)[:1000], assessment_id))
        raise
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
