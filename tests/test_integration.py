import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.main import app

client = TestClient(app)

SAMPLE_LOG = """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.120
192.168.1.2 - - [10/Oct/2023:13:55:38 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.115
192.168.1.2 - - [10/Oct/2023:13:55:39 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.130
192.168.1.2 - - [10/Oct/2023:13:55:40 -0300] "POST /login HTTP/1.1" 500 50 "-" "curl/7.68" 1.500
"""


class TestHomeEndpoint:
    def test_home_returns_html(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "LogAnalyzer" in response.text

    def test_health_endpoint_returns_ok(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"


class TestAnalyzeEndpoint:
    def test_analyze_with_text_form_field(self):
        response = client.post("/analyze", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5
        assert len(data["anomalies"]) >= 0
        assert data["entries"][0]["remote_addr"] == "192.168.1.1"

    def test_analyze_with_no_data_returns_error(self):
        response = client.post("/analyze", data={"log_text": ""})
        assert response.status_code == 200
        data = response.json()
        assert "error" in data

    def test_analyze_detects_anomalies(self):
        response = client.post("/analyze", data={"log_text": SAMPLE_LOG})
        data = response.json()
        anomalies = [a for a in data["anomalies"] if a["ip"] == "192.168.1.2"]
        assert len(anomalies) == 1
        assert anomalies[0]["total_errors"] >= 4

    def test_analyze_with_sql_injection_log(self):
        sql_log = '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api/users?id=1 OR 1=1-- HTTP/1.1" 200 432 "-" "sqlmap"'
        response = client.post("/analyze", data={"log_text": sql_log})
        data = response.json()
        assert len(data["security"]) >= 1
        assert any(s["pattern_type"] == "SQL Injection" for s in data["security"])

    def test_analyze_with_xss_log(self):
        xss_log = '192.168.1.6 - - [10/Oct/2023:13:55:44 -0300] "GET /profile?user=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "Mozilla"'
        response = client.post("/analyze", data={"log_text": xss_log})
        data = response.json()
        assert len(data["security"]) >= 1
        assert any(s["pattern_type"] == "XSS" for s in data["security"])

    def test_analyze_with_path_traversal_log(self):
        traversal_log = '192.168.1.7 - - [10/Oct/2023:13:55:45 -0300] "GET /../../etc/passwd HTTP/1.1" 403 50 "-" "curl"'
        response = client.post("/analyze", data={"log_text": traversal_log})
        data = response.json()
        assert len(data["security"]) >= 1
        assert any(s["pattern_type"] == "Path Traversal" for s in data["security"])

    def test_analyze_performance_data(self):
        perf_log = '10.0.0.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 100 "-" "test" 2.5'
        response = client.post("/analyze", data={"log_text": perf_log})
        data = response.json()
        assert len(data["performance"]) == 1
        assert data["performance"][0]["avg_response_time"] == 2.5


class TestReportEndpoint:
    def test_report_returns_full_analysis(self):
        response = client.post("/report", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        content = response.text
        assert "TRAFFIC ANOMALIES" in content
        assert "PERFORMANCE ANALYSIS" in content
        assert "SECURITY AUDIT" in content

    def test_report_with_no_data_returns_error(self):
        response = client.post("/report", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()


class TestFileUpload:
    def test_analyze_with_file_upload(self):
        response = client.post(
            "/analyze",
            files={"file": ("test.log", SAMPLE_LOG.encode(), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5

    def test_report_with_file_upload(self):
        response = client.post(
            "/report",
            files={"file": ("test.log", SAMPLE_LOG.encode(), "text/plain")},
        )
        assert response.status_code == 200
        assert "TRAFFIC ANOMALIES" in response.text
