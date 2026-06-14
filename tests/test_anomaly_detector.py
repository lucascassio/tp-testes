import pytest
from datetime import datetime

from app.models import LogEntry
from app.analyzers import AnomalyDetector, AnomalyResult


def _make_entry(ip="192.168.1.1", status=200, method="GET", path="/"):
    return LogEntry(
        remote_addr=ip,
        remote_user="-",
        timestamp=datetime(2023, 10, 10, 13, 0),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        body_bytes_sent=100,
        http_referer="-",
        http_user_agent="test",
        request_time=0.1,
        raw_line="",
    )


class TestAnomalyDetector:
    def test_detects_ip_with_excessive_4xx_errors(self):
        entries = [_make_entry(ip="10.0.0.1", status=403) for _ in range(5)]
        entries += [_make_entry(ip="10.0.0.2", status=200) for _ in range(3)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)
        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"
        assert results[0].total_errors == 5
        assert results[0].client_errors == 5
        assert results[0].server_errors == 0

    def test_detects_ip_with_excessive_5xx_errors(self):
        entries = [_make_entry(ip="10.0.0.3", status=500) for _ in range(6)]
        entries += [_make_entry(ip="10.0.0.4", status=200)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)
        assert len(results) == 1
        assert results[0].ip == "10.0.0.3"
        assert results[0].server_errors == 6

    def test_no_anomalies_when_below_threshold(self):
        entries = [_make_entry(ip="10.0.0.1", status=403) for _ in range(3)]
        entries += [_make_entry(ip="10.0.0.2", status=200) for _ in range(5)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)
        assert results == []

    def test_multiple_anomalous_ips(self):
        entries = [_make_entry(ip="10.0.0.1", status=403) for _ in range(5)]
        entries += [_make_entry(ip="10.0.0.2", status=500) for _ in range(6)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)
        assert len(results) == 2
        ips = {r.ip for r in results}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_results_sorted_by_total_errors_descending(self):
        entries = [_make_entry(ip="10.0.0.1", status=403) for _ in range(5)]
        entries += [_make_entry(ip="10.0.0.2", status=500) for _ in range(10)]
        detector = AnomalyDetector(error_threshold=3)
        results = detector.analyze(entries)
        assert results[0].ip == "10.0.0.2"
        assert results[0].total_errors == 10
        assert results[1].total_errors == 5

    def test_custom_threshold(self):
        entries = [_make_entry(ip="10.0.0.1", status=400) for _ in range(3)]
        detector_low = AnomalyDetector(error_threshold=2)
        detector_high = AnomalyDetector(error_threshold=5)
        assert len(detector_low.analyze(entries)) == 1
        assert len(detector_high.analyze(entries)) == 0

    def test_empty_entries_returns_empty_list(self):
        detector = AnomalyDetector()
        assert detector.analyze([]) == []

    def test_error_rate_calculation(self):
        entries = [_make_entry(ip="10.0.0.1", status=500) for _ in range(3)]
        entries += [_make_entry(ip="10.0.0.1", status=200) for _ in range(7)]
        detector = AnomalyDetector(error_threshold=3)
        results = detector.analyze(entries)
        assert len(results) == 1
        assert results[0].error_rate == 0.3
        assert results[0].total_requests == 10

    def test_mixed_client_and_server_errors(self):
        entries = [_make_entry(ip="10.0.0.1", status=403) for _ in range(2)]
        entries += [_make_entry(ip="10.0.0.1", status=500) for _ in range(3)]
        detector = AnomalyDetector(error_threshold=4)
        results = detector.analyze(entries)
        assert len(results) == 1
        assert results[0].client_errors == 2
        assert results[0].server_errors == 3
        assert results[0].total_errors == 5
