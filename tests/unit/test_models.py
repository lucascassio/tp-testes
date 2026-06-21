"""Unit tests for LogEntry model properties and computed attributes."""
import pytest
from datetime import datetime

from app.models import LogEntry

pytestmark = pytest.mark.unit


class TestLogEntryProperties:
    def test_endpoint_combines_method_and_path(self):
        entry = LogEntry(
            remote_addr="1.2.3.4", remote_user="-",
            timestamp=datetime(2024, 1, 1, 12, 0),
            method="POST", path="/api/data", protocol="HTTP/1.1",
            status=201, body_bytes_sent=50,
            http_referer="-", http_user_agent="test",
        )
        assert entry.endpoint == "POST /api/data"

    @pytest.mark.parametrize("status,is_client,is_server,is_error", [
        (200, False, False, False),
        (201, False, False, False),
        (301, False, False, False),
        (400, True, False, True),
        (401, True, False, True),
        (403, True, False, True),
        (404, True, False, True),
        (429, True, False, True),
        (500, False, True, True),
        (502, False, True, True),
        (503, False, True, True),
    ])
    def test_http_status_classification(self, status, is_client, is_server, is_error):
        entry = LogEntry(
            remote_addr="1.2.3.4", remote_user="-",
            timestamp=datetime(2024, 1, 1, 12, 0),
            method="GET", path="/", protocol="HTTP/1.1",
            status=status, body_bytes_sent=0,
            http_referer="-", http_user_agent="test",
        )
        assert entry.is_client_error == is_client, f"Status {status}: expected is_client_error={is_client}"
        assert entry.is_server_error == is_server, f"Status {status}: expected is_server_error={is_server}"
        assert entry.is_error == is_error, f"Status {status}: expected is_error={is_error}"

    def test_default_request_time_is_zero(self):
        entry = LogEntry(
            remote_addr="1.2.3.4", remote_user="-",
            timestamp=datetime(2024, 1, 1, 12, 0),
            method="GET", path="/", protocol="HTTP/1.1",
            status=200, body_bytes_sent=0,
            http_referer="-", http_user_agent="test",
        )
        assert entry.request_time == 0.0

    def test_default_raw_line_is_empty(self):
        entry = LogEntry(
            remote_addr="1.2.3.4", remote_user="-",
            timestamp=datetime(2024, 1, 1, 12, 0),
            method="GET", path="/", protocol="HTTP/1.1",
            status=200, body_bytes_sent=0,
            http_referer="-", http_user_agent="test",
        )
        assert entry.raw_line == ""

    def test_repr_excludes_raw_line(self):
        entry = LogEntry(
            remote_addr="1.2.3.4", remote_user="-",
            timestamp=datetime(2024, 1, 1, 12, 0),
            method="GET", path="/test", protocol="HTTP/1.1",
            status=200, body_bytes_sent=100,
            http_referer="-", http_user_agent="test",
            request_time=0.05, raw_line="very long raw line" * 10,
        )
        r = repr(entry)
        assert "very long raw line" not in r
        assert "method='GET'" in r
        assert "path='/test'" in r
        assert "status=200" in r
