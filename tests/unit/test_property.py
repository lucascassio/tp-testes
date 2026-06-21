"""Property-based tests using Hypothesis — fuzz testing with generated inputs."""
from datetime import datetime

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from app.models import LogEntry
from app.parser import parse_line, parse_text
from app.analyzers import SecurityAuditor

pytestmark = pytest.mark.unit


ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    *[st.integers(min_value=0, max_value=255)] * 4,
)

http_method = st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])

# Numeric path segments guarantee no SQLi/XSS/traversal keywords
safe_path = st.builds(
    lambda *parts: "/" + "/".join(str(p) for p in parts),
    st.lists(st.integers(min_value=0, max_value=99999), min_size=0, max_size=3),
)

status_code = st.sampled_from([200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503])

request_time = st.one_of(
    st.floats(min_value=0.0, max_value=60.0, allow_nan=False, allow_infinity=False).map(lambda f: f"{f:.3f}"),
    st.just("0.045"),
)

clean_line = st.builds(
    lambda ip, method, path, status, rt: (
        f'{ip} - - [10/Oct/2023:13:55:36 -0300] '
        f'"{method} {path} HTTP/1.1" {status} 100 "-" "test-agent" {rt}'
    ),
    ip=ipv4,
    method=http_method,
    path=safe_path,
    status=status_code,
    rt=request_time,
)


class TestParserProperties:
    @given(clean_line)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_valid_log_line_always_parses(self, line):
        entry = parse_line(line)
        assert entry is not None, f"Failed to parse: {line!r}"
        assert entry.status == int(line.split('"')[2].strip().split()[0])
        assert entry.request_time >= 0.0

    @given(clean_line, clean_line, clean_line)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_parse_text_returns_all_valid_lines(self, line1, line2, line3):
        text = f"{line1}\n{line2}\n{line3}\n"
        entries = parse_text(text)
        assert len(entries) == 3


class TestSecurityAuditorProperties:
    @staticmethod
    def _make_entry(ip="192.168.1.1", method="GET", path="/"):
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

    @given(safe_path)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_clean_paths_never_trigger_alerts(self, path):
        if not path.strip() or not path.startswith("/"):
            return
        entry = self._make_entry(path=path)
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert alerts == [], f"False positive on clean path: {path!r}"

    @given(http_method, ipv4)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_known_sqli_payload_always_detected(self, method, ip):
        entry = self._make_entry(ip=ip, method=method, path="/products?id=1 UNION SELECT * FROM users")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "SQL Injection"
        assert alerts[0].ip == ip

    @given(http_method, ipv4)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_known_xss_payload_always_detected(self, method, ip):
        entry = self._make_entry(ip=ip, method=method, path="/profile?name=<script>alert(1)</script>")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "XSS"

    @given(http_method, ipv4)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_known_traversal_payload_always_detected(self, method, ip):
        entry = self._make_entry(ip=ip, method=method, path="/download?file=../../etc/passwd")
        auditor = SecurityAuditor()
        alerts = auditor.audit([entry])
        assert len(alerts) == 1
        assert alerts[0].pattern_type == "Path Traversal"

    @given(safe_path, http_method, ipv4)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_auditor_never_crashes_on_any_path(self, path, method, ip):
        if not path:
            return
        entry = self._make_entry(ip=ip, method=method, path=path)
        auditor = SecurityAuditor()
        result = auditor.audit([entry])
        assert isinstance(result, list)
