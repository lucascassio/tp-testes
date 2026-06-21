import pytest

pytestmark = pytest.mark.unit


SQLI_PATHS = [
    ("/products?id=1 UNION SELECT * FROM users", "192.168.1.1"),
    ("/login?user=admin' OR '1'='1", "192.168.1.1"),
    ("/search?q=test; DROP TABLE users;--", "10.0.0.5"),
]

XSS_PATHS = [
    "/profile?name=<script>alert(1)</script>",
    "/redirect?url=javascript:alert(document.cookie)",
]

TRAVERSAL_PATHS = [
    "/download?file=../../etc/passwd",
    "/download?file=%2e%2e%2fetc%2fpasswd",
]

CLEAN_PATHS = [
    "/api/users",
    "/products/42",
    "/search?q=hello+world",
]


class TestSecurityAuditor:
    @pytest.mark.parametrize("path,ip", SQLI_PATHS)
    def test_detect_sql_injection(self, make_entry, security_auditor, path, ip):
        entry = make_entry(path=path, ip=ip)
        alerts = security_auditor.audit([entry])

        assert len(alerts) == 1, f"Expected 1 alert, got {len(alerts)}"
        assert alerts[0].pattern_type == "SQL Injection", f"Expected SQL Injection, got {alerts[0].pattern_type}"
        assert alerts[0].ip == ip

    @pytest.mark.parametrize("path", XSS_PATHS)
    def test_detect_xss(self, make_entry, security_auditor, path):
        entry = make_entry(path=path)
        alerts = security_auditor.audit([entry])

        assert len(alerts) == 1, f"Expected 1 XSS alert, got {len(alerts)}"
        assert alerts[0].pattern_type == "XSS"

    @pytest.mark.parametrize("path", TRAVERSAL_PATHS)
    def test_detect_path_traversal(self, make_entry, security_auditor, path):
        entry = make_entry(path=path)
        alerts = security_auditor.audit([entry])

        assert len(alerts) == 1, f"Expected 1 traversal alert, got {len(alerts)}"
        assert alerts[0].pattern_type == "Path Traversal"

    @pytest.mark.parametrize("path", CLEAN_PATHS)
    def test_no_alert_on_clean_url(self, make_entry, security_auditor, path):
        entry = make_entry(path=path)
        alerts = security_auditor.audit([entry])

        assert alerts == [], f"Unexpected alerts on clean path {path}: {alerts}"

    def test_multiple_security_issues_in_one_log(self, make_entry, security_auditor):
        entry = make_entry(path="/search?q=1 UNION SELECT * FROM users<script>alert(1)</script>")
        alerts = security_auditor.audit([entry])

        assert len(alerts) == 2, f"Expected 2 alerts, got {len(alerts)}"
        pattern_types = {a.pattern_type for a in alerts}
        assert pattern_types >= {"SQL Injection", "XSS"}, f"Missing expected pattern types: {pattern_types}"

    def test_empty_entries_returns_empty_list(self, security_auditor):
        assert security_auditor.audit([]) == []

    def test_alert_includes_matched_content(self, make_entry, security_auditor):
        entry = make_entry(path="/api?id=1 OR 1=1")
        alerts = security_auditor.audit([entry])

        assert len(alerts) == 1, f"Expected 1 alert, got {len(alerts)}"
        assert alerts[0].matched_content == "OR 1=1", f"Expected 'OR 1=1', got {alerts[0].matched_content!r}"
