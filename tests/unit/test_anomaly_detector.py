import pytest
from app.analyzers import AnomalyDetector

pytestmark = pytest.mark.unit


class TestAnomalyDetector:
    @pytest.mark.parametrize("status,error_attr", [
        (403, "client_errors"),
        (500, "server_errors"),
    ])
    def test_detects_ip_with_excessive_errors(self, make_entry, status, error_attr):
        entries = [make_entry(ip="10.0.0.1", status=status) for _ in range(5)]
        entries += [make_entry(ip="10.0.0.2", status=200) for _ in range(3)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)

        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"
        assert results[0].total_errors == 5
        assert getattr(results[0], error_attr) == 5

    def test_no_anomalies_when_below_threshold(self, make_entry):
        entries = [make_entry(ip="10.0.0.1", status=403) for _ in range(3)]
        entries += [make_entry(ip="10.0.0.2", status=200) for _ in range(5)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)

        assert results == []

    def test_multiple_anomalous_ips(self, make_entry):
        entries = [make_entry(ip="10.0.0.1", status=403) for _ in range(5)]
        entries += [make_entry(ip="10.0.0.2", status=500) for _ in range(6)]
        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)

        assert len(results) == 2
        assert {r.ip for r in results} == {"10.0.0.1", "10.0.0.2"}

    def test_results_sorted_by_total_errors_descending(self, make_entry):
        entries = [make_entry(ip="10.0.0.1", status=403) for _ in range(5)]
        entries += [make_entry(ip="10.0.0.2", status=500) for _ in range(10)]
        detector = AnomalyDetector(error_threshold=3)
        results = detector.analyze(entries)

        assert results[0].ip == "10.0.0.2"
        assert results[0].total_errors == 10
        assert results[1].total_errors == 5

    @pytest.mark.parametrize("threshold,expected_count", [
        (2, 1),
        (5, 0),
    ])
    def test_threshold_controls_detection(self, make_entry, threshold, expected_count):
        entries = [make_entry(ip="10.0.0.1", status=400) for _ in range(3)]
        detector = AnomalyDetector(error_threshold=threshold)

        assert len(detector.analyze(entries)) == expected_count

    def test_empty_entries_returns_empty_list(self):
        detector = AnomalyDetector()
        assert detector.analyze([]) == []

    def test_error_rate_calculation(self, make_entry):
        entries = [make_entry(ip="10.0.0.1", status=500) for _ in range(3)]
        entries += [make_entry(ip="10.0.0.1", status=200) for _ in range(7)]
        detector = AnomalyDetector(error_threshold=3)
        results = detector.analyze(entries)

        assert len(results) == 1
        assert results[0].error_rate == pytest.approx(0.3)
        assert results[0].total_requests == 10

    def test_mixed_client_and_server_errors(self, make_entry):
        entries = [make_entry(ip="10.0.0.1", status=403) for _ in range(2)]
        entries += [make_entry(ip="10.0.0.1", status=500) for _ in range(3)]
        detector = AnomalyDetector(error_threshold=4)
        results = detector.analyze(entries)

        assert len(results) == 1
        assert results[0].client_errors == 2
        assert results[0].server_errors == 3
        assert results[0].total_errors == 5
