import pytest
from datetime import datetime

from app.models import LogEntry
from app.analyzers import PerformanceAnalyzer, PerformanceResult


def _make_entry(path="/api/users", method="GET", request_time=0.1):
    return LogEntry(
        remote_addr="192.168.1.1",
        remote_user="-",
        timestamp=datetime(2023, 10, 10, 13, 0),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=200,
        body_bytes_sent=100,
        http_referer="-",
        http_user_agent="test",
        request_time=request_time,
        raw_line="",
    )


class TestPerformanceAnalyzer:
    def test_average_response_time_single_endpoint(self):
        entries = [
            _make_entry("/api/users", request_time=0.1),
            _make_entry("/api/users", request_time=0.2),
            _make_entry("/api/users", request_time=0.3),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert len(results) == 1
        assert results[0].endpoint == "GET /api/users"
        assert results[0].request_count == 3
        assert results[0].avg_response_time == pytest.approx(0.2)
        assert results[0].min_response_time == 0.1
        assert results[0].max_response_time == 0.3

    def test_multiple_endpoints_grouped_separately(self):
        entries = [
            _make_entry("/api/users", request_time=0.1),
            _make_entry("/api/users", request_time=0.3),
            _make_entry("/api/products", request_time=0.5),
            _make_entry("/api/products", request_time=0.7),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert len(results) == 2
        endpoints = {r.endpoint for r in results}
        assert "GET /api/users" in endpoints
        assert "GET /api/products" in endpoints

    def test_empty_entries_returns_empty_list(self):
        analyzer = PerformanceAnalyzer()
        assert analyzer.analyze([]) == []

    def test_single_entry_performance(self):
        entries = [_make_entry("/api/status", request_time=0.5)]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert len(results) == 1
        assert results[0].avg_response_time == 0.5
        assert results[0].min_response_time == 0.5
        assert results[0].max_response_time == 0.5

    def test_zero_response_times(self):
        entries = [
            _make_entry("/api/empty", request_time=0.0),
            _make_entry("/api/empty", request_time=0.0),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert results[0].avg_response_time == 0.0
        assert results[0].max_response_time == 0.0

    def test_sorted_by_avg_descending(self):
        entries = [
            _make_entry("/fast", request_time=0.01),
            _make_entry("/slow", request_time=5.0),
            _make_entry("/medium", request_time=0.5),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert results[0].endpoint == "GET /slow"
        assert results[1].endpoint == "GET /medium"
        assert results[2].endpoint == "GET /fast"

    def test_different_methods_same_path_grouped_differently(self):
        entries = [
            _make_entry("/api/data", method="GET", request_time=0.1),
            _make_entry("/api/data", method="POST", request_time=0.2),
            _make_entry("/api/data", method="DELETE", request_time=0.3),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)
        assert len(results) == 3
