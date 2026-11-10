from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from io import BytesIO
import unicodedata
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.core.config import ANALYZER_SHARED_TOKEN
from app.core.db import connection
from app.worker import analyze_assessment
from app.services.reference_data import load_reference_data

app = FastAPI(title="PQC Assessment Analyzer", version="0.1.0")


@app.on_event("startup")
def startup_reference_data():
    load_reference_data()


class ScanRequest(BaseModel):
    assessment_id: str


@app.get("/healthz")
def health():
    return {"status": "ok", "service": "analyzer"}


@app.post("/api/analyzer/scan", status_code=202)
def enqueue_scan(request: ScanRequest, authorization: str | None = Header(default=None)):
    if authorization != f"Bearer {ANALYZER_SHARED_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized service request")
    task = analyze_assessment.delay(request.assessment_id)
    return {"assessment_id": request.assessment_id, "status": "QUEUED", "task_id": task.id}


@app.get("/api/reports/{assessment_id}/pdf")
def report_pdf(assessment_id: str, authorization: str | None = Header(default=None)):
    if authorization != f"Bearer {ANALYZER_SHARED_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized service request")
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT scan_label,status,files_scanned,findings_count,overall_risk_score,cars_score,result_json FROM assessments WHERE id=%s AND status='COMPLETED'", (assessment_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Completed assessment not found")
    data = BytesIO()
    pdf = canvas.Canvas(data, pagesize=letter)
    _, height = letter
    y = height - 48
    lines = [
        "Quantum-Safe Cryptography Assessment",
        f"Assessment: {row['scan_label']}",
        f"Status: {row['status']}",
        f"Python files scanned: {row['files_scanned']}",
        f"Cryptographic findings: {row['findings_count']}",
        f"Risk score: {row['overall_risk_score']}",
        f"CARS score (provisional): {row['cars_score']}",
        "",
        "Weighted risk factors:",
        *[f"{name}: {value}" for name, value in (row["result_json"] or {}).get("risk", {}).get("factors", {}).items()],
        "",
        "Findings (evidence snippets are secret-redacted):",
    ]
    for finding in (row["result_json"] or {}).get("findings", []):
        lines.append(f"{finding['algorithm']} / {finding['operation']} — {finding['file_path']}:{finding['line_start']}")
        lines.append(f"  {finding['evidence'][:140]}")
    lines.extend(["", "Recommendations:"])
    for recommendation in (row["result_json"] or {}).get("recommendations", []):
        lines.append(f"{recommendation['source_algorithm']} / {recommendation['operation']}: {recommendation['recommendation']}")
    lines.append("Vulnerability correlation is not asserted without exact supporting evidence.")
    for line in lines:
        if y < 48:
            pdf.showPage()
            y = height - 48
        safe_line = unicodedata.normalize("NFKD", line).encode("latin-1", "replace").decode("latin-1")
        pdf.drawString(42, y, safe_line[:110])
        y -= 16
    pdf.save()
    return Response(data.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="assessment-{assessment_id}.pdf"'})
