import pytest

pytestmark = pytest.mark.integration


class TestHomeEndpoint:
    def test_home_returns_html(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "LogAnalyzer" in response.text

    def test_health_endpoint_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"


class TestAnalyzeEndpoint:
    def test_analyze_with_text_form_field(self, client, sample_multiline_log):
        response = client.post("/analyze", data={"log_text": sample_multiline_log})
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5
        assert data["entries"][0]["remote_addr"] == "192.168.1.1"

    def test_analyze_with_no_data_returns_error(self, client):
        response = client.post("/analyze", data={"log_text": ""})
        assert response.status_code == 200
        data = response.json()
        assert "error" in data
        assert data["total_entries"] == 0

    def test_analyze_detects_anomalies(self, client, sample_multiline_log):
        response = client.post("/analyze", data={"log_text": sample_multiline_log})
        data = response.json()
        anomalies = [a for a in data["anomalies"] if a["ip"] == "192.168.1.2"]
        assert len(anomalies) == 1
        assert anomalies[0]["total_errors"] == 4

    @pytest.mark.parametrize("log_line,pattern_type", [
        (
            '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api/users?id=1 OR 1=1-- HTTP/1.1" 200 432 "-" "sqlmap"',
            "SQL Injection",
        ),
        (
            '192.168.1.6 - - [10/Oct/2023:13:55:44 -0300] "GET /profile?user=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "Mozilla"',
            "XSS",
        ),
        (
            '192.168.1.7 - - [10/Oct/2023:13:55:45 -0300] "GET /../../etc/passwd HTTP/1.1" 403 50 "-" "curl"',
            "Path Traversal",
        ),
    ])
    def test_analyze_detects_security_issues(self, client, log_line, pattern_type):
        response = client.post("/analyze", data={"log_text": log_line})
        data = response.json()
        assert any(s["pattern_type"] == pattern_type for s in data["security"])

    def test_analyze_performance_data(self, client):
        perf_log = '10.0.0.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 100 "-" "test" 2.5'
        response = client.post("/analyze", data={"log_text": perf_log})
        data = response.json()
        assert len(data["performance"]) == 1
        assert data["performance"][0]["avg_response_time"] == 2.5


class TestReportEndpoint:
    def test_report_returns_full_analysis(self, client, sample_multiline_log):
        response = client.post("/report", data={"log_text": sample_multiline_log})
        assert response.status_code == 200
        assert "TRAFFIC ANOMALIES" in response.text
        assert "PERFORMANCE ANALYSIS" in response.text
        assert "SECURITY AUDIT" in response.text

    def test_report_with_no_data_returns_error(self, client):
        response = client.post("/report", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()


class TestFileUpload:
    def test_analyze_with_file_upload(self, client, sample_multiline_log):
        response = client.post(
            "/analyze",
            files={"file": ("test.log", sample_multiline_log.encode(), "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5

    def test_report_with_file_upload(self, client, sample_multiline_log):
        response = client.post(
            "/report",
            files={"file": ("test.log", sample_multiline_log.encode(), "text/plain")},
        )
        assert response.status_code == 200
        assert "TRAFFIC ANOMALIES" in response.text


class TestSamplesEndpoint:
    def test_list_samples_returns_scenarios(self, client):
        response = client.get("/samples")
        assert response.status_code == 200
        samples = response.json()
        assert isinstance(samples, list)
        assert len(samples) > 0
        assert all("key" in s and "label" in s for s in samples)
        keys = {s["key"] for s in samples}
        assert "normal" in keys
        assert "full-attack" in keys

    def test_get_sample_returns_log_text(self, client):
        response = client.get("/samples/sqli")
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "SQL Injection Attacks"
        assert "UNION" in data["log_text"]
        assert "45.33.32.156" in data["log_text"]

    def test_get_unknown_sample_returns_error(self, client):
        response = client.get("/samples/doesnotexist")
        assert response.status_code == 200
        assert "error" in response.json()

    def test_sample_endpoints_content_type_is_json(self, client):
        response = client.get("/samples/normal")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]


class TestTemplateAndStatic:
    def test_template_file_exists(self):
        from pathlib import Path
        template = Path(__file__).parent.parent.parent / "app" / "templates" / "index.html"
        assert template.exists(), f"Template not found at {template}"
        content = template.read_text(encoding="utf-8")
        assert len(content) > 0
        assert "<html" in content.lower()

    def test_home_response_has_correct_content_type(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_upload_directory_is_created(self):
        from pathlib import Path
        upload_dir = Path(__file__).parent.parent.parent / "uploads"
        assert upload_dir.exists()
        assert upload_dir.is_dir()
