"""FastAPI application: REST API for log analysis.

Endpoints:
    GET  /            - HTML dashboard
    GET  /health      - Health check
    GET  /samples     - List available log scenarios
    GET  /samples/{name} - Get a specific scenario's log text
    POST /analyze     - Parse and analyze log text/file
    POST /report      - Generate downloadable analysis report
"""

import io
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from app.parser import parse_text
from app.analyzers import AnomalyDetector, PerformanceAnalyzer, SecurityAuditor
from app.reporters import (
    generate_anomalies_csv,
    generate_performance_csv,
    generate_security_csv,
    generate_full_report,
)
from app.samples import SAMPLES

app = FastAPI(title="LogAnalyzer", version="1.0.0")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"


@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(_TEMPLATE_PATH.read_text(encoding="utf-8"))


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/samples")
async def list_samples():
    return [
        {"key": k, "label": v[0]}
        for k, v in SAMPLES.items()
    ]


@app.get("/samples/{name}")
async def get_sample(name: str):
    if name not in SAMPLES:
        return {"error": f"Sample '{name}' not found. Available: {list(SAMPLES.keys())}"}
    log_text = SAMPLES[name][1]()
    return {"label": SAMPLES[name][0], "log_text": log_text}


@app.post("/analyze")
async def analyze(file: UploadFile = File(None), log_text: Optional[str] = Form(None)):
    content = ""

    if file and file.filename:
        content = (await file.read()).decode("utf-8", errors="replace")
    elif log_text:
        content = log_text

    if not content.strip():
        return {
            "error": "No log data provided. Upload a file or paste log content.",
            "entries": [],
            "anomalies": [],
            "performance": [],
            "security": [],
            "total_entries": 0,
        }

    entries = parse_text(content)

    anomaly_detector = AnomalyDetector(error_threshold=3)
    anomalies = anomaly_detector.analyze(entries)

    performance_analyzer = PerformanceAnalyzer()
    performance = performance_analyzer.analyze(entries)

    security_auditor = SecurityAuditor()
    security_alerts = security_auditor.audit(entries)

    return {
        "entries": [
            {
                "remote_addr": e.remote_addr,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "method": e.method,
                "path": e.path,
                "status": e.status,
                "body_bytes_sent": e.body_bytes_sent,
                "request_time": e.request_time,
                "http_referer": e.http_referer,
                "http_user_agent": e.http_user_agent,
            }
            for e in entries
        ],
        "anomalies": [
            {
                "ip": a.ip,
                "total_errors": a.total_errors,
                "client_errors": a.client_errors,
                "server_errors": a.server_errors,
                "total_requests": a.total_requests,
                "error_rate": a.error_rate,
            }
            for a in anomalies
        ],
        "performance": [
            {
                "endpoint": p.endpoint,
                "request_count": p.request_count,
                "avg_response_time": p.avg_response_time,
                "min_response_time": p.min_response_time,
                "max_response_time": p.max_response_time,
            }
            for p in performance
        ],
        "security": [
            {
                "path": s.path,
                "method": s.method,
                "ip": s.ip,
                "pattern_type": s.pattern_type,
                "matched_content": s.matched_content,
            }
            for s in security_alerts
        ],
        "total_entries": len(entries),
    }


@app.post("/report")
async def download_report(log_text: str = Form(None), file: UploadFile = File(None)):
    content = ""

    if file and file.filename:
        content = (await file.read()).decode("utf-8", errors="replace")
    elif log_text:
        content = log_text

    if not content.strip():
        return {"error": "No log data provided"}

    entries = parse_text(content)

    anomaly_detector = AnomalyDetector(error_threshold=3)
    anomalies = anomaly_detector.analyze(entries)

    performance_analyzer = PerformanceAnalyzer()
    performance = performance_analyzer.analyze(entries)

    security_auditor = SecurityAuditor()
    security_alerts = security_auditor.audit(entries)

    report = generate_full_report(anomalies, performance, security_alerts, len(entries))

    return StreamingResponse(
        io.BytesIO(report.encode("utf-8")),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=log_analysis_report.txt"},
    )
