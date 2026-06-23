"""End-to-end tests — real uvicorn server, real HTTP via httpx.

Cada teste levanta um servidor uvicorn em porta aleatória (fixture live_server),
faz requisições HTTP reais com httpx, e verifica a resposta JSON/HTML.
Sem mocks, sem TestClient — é o sistema rodando de verdade.
"""
import pytest
import httpx

pytestmark = pytest.mark.e2e

# Log de exemplo com 5 linhas: 1 normal + 4 erros do mesmo IP (192.168.1.2)
# O IP 192.168.1.2 tem 3x 401 + 1x 500 = 4 erros → deve ser detectado como anomalia
SAMPLE_LOG = """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.120
192.168.1.2 - - [10/Oct/2023:13:55:38 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.115
192.168.1.2 - - [10/Oct/2023:13:55:39 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.130
192.168.1.2 - - [10/Oct/2023:13:55:40 -0300] "POST /login HTTP/1.1" 500 50 "-" "curl/7.68" 1.500
"""


class TestHealthEndpoint:
    """Verifica que o servidor está vivo e respondendo."""

    def test_health_returns_ok(self, live_server):
        # GET http://127.0.0.1:54832/health → confere status e versão
        response = httpx.get(f"{live_server}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_home_returns_html(self, live_server):
        # GET http://127.0.0.1:54832/ → confere que é HTML com "LogAnalyzer"
        response = httpx.get(f"{live_server}/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "LogAnalyzer" in response.text


class TestSamplesEndpoint:
    """Verifica o endpoint de cenários de demonstração."""

    def test_list_samples(self, live_server):
        # GET /samples → confere que devolve lista com chave "full-attack"
        response = httpx.get(f"{live_server}/samples")
        assert response.status_code == 200
        samples = response.json()
        assert isinstance(samples, list)
        assert len(samples) > 0
        keys = {s["key"] for s in samples}
        assert "full-attack" in keys

    def test_get_sample_by_key(self, live_server):
        # GET /samples/sqli → confere que o log gerado contém "UNION"
        response = httpx.get(f"{live_server}/samples/sqli")
        assert response.status_code == 200
        data = response.json()
        assert "UNION" in data["log_text"]
        assert "label" in data

    def test_get_unknown_sample(self, live_server):
        # GET /samples/chave-que-nao-existe → confere que volta erro
        response = httpx.get(f"{live_server}/samples/nonexistent")
        assert response.status_code == 200
        assert "error" in response.json()


class TestAnalyzeEndpoint:
    """Verifica o endpoint principal de análise de logs."""

    def test_analyze_form_data(self, live_server):
        # POST /analyze com 5 linhas de log → confere que parseou todas
        response = httpx.post(f"{live_server}/analyze", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == 5
        assert len(data["entries"]) == 5

    def test_analyze_detects_anomalies(self, live_server):
        # POST /analyze com SAMPLE_LOG → IP 192.168.1.2 tem 4 erros, deve ser flagado
        response = httpx.post(f"{live_server}/analyze", data={"log_text": SAMPLE_LOG})
        data = response.json()
        anomalies = [a for a in data["anomalies"] if a["ip"] == "192.168.1.2"]
        assert len(anomalies) == 1

    def test_analyze_detects_security_issues(self, live_server):
        # POST /analyze com log contendo SQL Injection na URL
        sql_log = '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api?id=1 OR 1=1 HTTP/1.1" 200 432 "-" "sqlmap"'
        response = httpx.post(f"{live_server}/analyze", data={"log_text": sql_log})
        data = response.json()
        assert len(data["security"]) == 1, f"Expected 1 security alert, got {len(data['security'])}"
        assert "SQL Injection" in {s["pattern_type"] for s in data["security"]}

    def test_analyze_with_no_data(self, live_server):
        # POST /analyze sem dados → confere que devolve erro
        response = httpx.post(f"{live_server}/analyze", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()

    def test_analyze_file_upload(self, live_server):
        # POST /analyze com upload de arquivo (simula arrastar .log no navegador)
        files = {"file": ("access.log", SAMPLE_LOG.encode(), "text/plain")}
        response = httpx.post(f"{live_server}/analyze", files=files)
        assert response.status_code == 200
        assert response.json()["total_entries"] == 5

    @pytest.mark.parametrize("log_line,expected_type", [
        (
            # Log com ?id=1 OR 1=1 → SQL Injection
            '192.168.1.5 - - [10/Oct/2023:13:55:43 -0300] "GET /api?id=1 OR 1=1 HTTP/1.1" 200 432 "-" "sqlmap"',
            "SQL Injection",
        ),
        (
            # Log com <script>alert(1)</script> → XSS
            '192.168.1.6 - - [10/Oct/2023:13:55:44 -0300] "GET /?q=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "x"',
            "XSS",
        ),
        (
            # Log com /../../etc/passwd → Path Traversal
            '192.168.1.7 - - [10/Oct/2023:13:55:45 -0300] "GET /../../etc/passwd HTTP/1.1" 403 50 "-" "c"',
            "Path Traversal",
        ),
    ])
    def test_analyze_security_patterns(self, live_server, log_line, expected_type):
        # Roda 3x: manda log com ataque → confere que o alerta do tipo certo veio
        response = httpx.post(f"{live_server}/analyze", data={"log_text": log_line})
        data = response.json()
        assert any(s["pattern_type"] == expected_type for s in data["security"])


class TestReportEndpoint:
    """Verifica o endpoint de download de relatório."""

    def test_report_text_response(self, live_server):
        # POST /report com SAMPLE_LOG → confere que tem as 3 seções do relatório
        response = httpx.post(f"{live_server}/report", data={"log_text": SAMPLE_LOG})
        assert response.status_code == 200
        assert "TRAFFIC ANOMALIES" in response.text
        assert "PERFORMANCE ANALYSIS" in response.text
        assert "SECURITY AUDIT" in response.text

    def test_report_empty_data(self, live_server):
        # POST /report vazio → confere que devolve erro
        response = httpx.post(f"{live_server}/report", data={"log_text": ""})
        assert response.status_code == 200
        assert "error" in response.json()
