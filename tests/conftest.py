import pytest
from datetime import datetime

from app.models import LogEntry
from app.analyzers import AnomalyResult, PerformanceResult, SecurityAlert


@pytest.fixture
def make_entry():
    def _make(
        ip="192.168.1.1",
        status=200,
        method="GET",
        path="/",
        request_time=0.1,
        user_agent="test",
        referer="-",
    ):
        return LogEntry(
            remote_addr=ip,
            remote_user="-",
            timestamp=datetime(2023, 10, 10, 13, 0),
            method=method,
            path=path,
            protocol="HTTP/1.1",
            status=status,
            body_bytes_sent=100,
            http_referer=referer,
            http_user_agent=user_agent,
            request_time=request_time,
            raw_line="",
        )

    return _make


@pytest.fixture
def valid_log_line():
    return '192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045'


@pytest.fixture
def sample_multiline_log():
    return """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.120
192.168.1.2 - - [10/Oct/2023:13:55:38 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.115
192.168.1.2 - - [10/Oct/2023:13:55:39 -0300] "POST /login HTTP/1.1" 401 50 "-" "curl/7.68" 0.130
192.168.1.2 - - [10/Oct/2023:13:55:40 -0300] "POST /login HTTP/1.1" 500 50 "-" "curl/7.68" 1.500
"""
