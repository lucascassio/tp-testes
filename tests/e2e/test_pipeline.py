"""End-to-end tests — real uvicorn server, real HTTP via httpx."""
import pytest
import httpx

pytestmark = pytest.mark.e2e

SAMPLE_LOG = """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.120
192.168.1.2 - - [10/Oct/2023:13:55:38 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.115
192.168.1.2 - - [10/Oct/2023:13:55:39 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.130
192.168.1.2 - - [10/Oct/2023:13:55:40 -0300] "POST /login HTTP/1.1" 500 50 "-" "curl/7.68" 1.500
"""


class TestHealthEndpoint:
    def test_health_returns_ok(self, live_server):
        response = httpx.get(f"{live_server}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_home_returns_html(self, live_server):
        response = httpx.get(f"{live_server}/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "LogAnalyzer" in response.text


class TestSamplesEndpoint:
    def test_list_samples(self, live_server):
        response = httpx.get(f"{live_server}/samples")
        assert response.status_code == 200
        samples = response.json()
        assert isinstance(samples, list)
        assert len(samples) == 7
        keys = {s["key"] for s in samples}
        assert "full-attack" in keys

    def test_get_sample_by_key(self, live_server):
        response = httpx.get(f"{live_server}/samples/sqli")
        assert response.status_code == 200
        data = response.json()
        assert "UNION" in data["log_text"]
        assert "label" in data

    def test_get_unknown_sample(self, live_server):
        response = httpx.get(f"{live_server}/samples/nonexistent")
        assert response.status_code == 200
        assert "error" in response.json()


class TestAnalyzeEndpoint:
    def test_analyze_form_data(self, live_server):
        response = httpx.post(f"{live_server}/analyze", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5
        assert len(data["entries"]) == 5

    def test_analyze_detects_anomalies(self, live_server):
        response = httpx.post(f"{live_server}/analyze", data={"log_text": SAMPLE_LOG})
        data = response.json()
        anomalies = [a for a in data["anomalies"] if a["ip"] == "192.168.1.2"]
        assert len(anomalies) == 1

    def test_analyze_detects_security_issues(self, live_server):
        sql_log = '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api?id=1 OR 1=1 HTTP/1.1" 200 432 "-" "sqlmap"'
        response = httpx.post(f"{live_server}/analyze", data={"log_text": sql_log})
        data = response.json()
        assert len(data["security"]) >= 1
        pattern_types = {s["pattern_type"] for s in data["security"]}
        assert "SQL Injection" in pattern_types

    def test_analyze_with_no_data(self, live_server):
        response = httpx.post(f"{live_server}/analyze", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()

    def test_analyze_file_upload(self, live_server):
        files = {"file": ("access.log", SAMPLE_LOG.encode(), "text/plain")}
        response = httpx.post(f"{live_server}/analyze", files=files)
        assert response.status_code == 200
        assert response.json()["total_entries"] == 5

    @pytest.mark.parametrize("log_line,expected_type", [
        (
            '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api?id=1 OR 1=1 HTTP/1.1" 200 432 "-" "sqlmap"',
            "SQL Injection",
        ),
        (
            '192.168.1.6 - - [10/Oct/2023:13:55:44 -0300] "GET /?q=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "x"',
            "XSS",
        ),
        (
            '192.168.1.7 - - [10/Oct/2023:13:55:45 -0300] "GET /../../etc/passwd HTTP/1.1" 403 50 "-" "c"',
            "Path Traversal",
        ),
    ])
    def test_analyze_security_patterns(self, live_server, log_line, expected_type):
        response = httpx.post(f"{live_server}/analyze", data={"log_text": log_line})
        data = response.json()
        assert any(s["pattern_type"] == expected_type for s in data["security"])


class TestReportEndpoint:
    def test_report_text_response(self, live_server):
        response = httpx.post(f"{live_server}/report", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        assert "TRAFFIC ANOMALIES" in response.text
        assert "PERFORMANCE ANALYSIS" in response.text
        assert "SECURITY AUDIT" in response.text

    def test_report_empty_data(self, live_server):
        response = httpx.post(f"{live_server}/report", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()
