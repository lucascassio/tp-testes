import pytest
from datetime import datetime

from app.models import LogEntry
from app.analyzers import SecurityAuditor, SecurityAlert


def _make_entry(path="/", method="GET", ip="192.168.1.1"):
    return LogEntry(
        remote_addr=ip,
        remote_user="-",
        timestamp=datetime(2023, 10, 10, 13, 0),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=200,
        body_bytes_sent=100,
        http_referer="-",
        http_user_agent="test",
        request_time=0.1,
        raw_line="",
    )


class TestSecurityAuditor:
    def test_detect_sql_injection_union_select(self):
        entry = _make_entry(path="/products?id=1 UNION SELECT * FROM users")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "SQL Injection"
        assert alerts[0].ip == "192.168.1.1"

    def test_detect_sql_injection_or_condition(self):
        entry = _make_entry(path="/login?user=admin' OR '1'='1")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) >= 1
        assert any(a.pattern_type == "SQL Injection" for a in alerts)

    def test_detect_sql_injection_drop_table(self):
        entry = _make_entry(path="/search?q=test; DROP TABLE users;--")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) >= 1
        assert any(a.pattern_type == "SQL Injection" for a in alerts)

    def test_detect_xss_script_tag(self):
        entry = _make_entry(path="/profile?name=<script>alert(1)</script>")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "XSS"

    def test_detect_xss_javascript_protocol(self):
        entry = _make_entry(path="/redirect?url=javascript:alert(document.cookie)")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) >= 1
        assert any(a.pattern_type == "XSS" for a in alerts)

    def test_detect_path_traversal_dot_dot_slash(self):
        entry = _make_entry(path="/download?file=../../etc/passwd")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "Path Traversal"

    def test_detect_path_traversal_encoded(self):
        entry = _make_entry(path="/download?file=%2e%2e%2fetc%2fpasswd")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "Path Traversal"

    def test_no_alert_on_clean_urls(self):
        entries = [
            _make_entry(path="/api/users"),
            _make_entry(path="/products/42"),
            _make_entry(path="/search?q=hello+world"),
        ]
        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)
        assert alerts == []

    def test_multiple_security_issues_in_one_log(self):
        entry = _make_entry(path="/search?q=1 UNION SELECT * FROM users<script>alert(1)</script>")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        pattern_types = {a.pattern_type for a in alerts}
        assert "SQL Injection" in pattern_types
        assert "XSS" in pattern_types

    def test_empty_entries_returns_empty_list(self):
        auditor = SecurityAuditor()
        assert auditor.audit([]) == []

    def test_alert_includes_matched_content(self):
        entry = _make_entry(path="/api?id=1 OR 1=1")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) >= 1
        assert "OR" in alerts[0].matched_content
