import pytest
from app.analyzers import PerformanceAnalyzer

pytestmark = pytest.mark.unit


class TestPerformanceAnalyzer:
    def test_average_response_time_single_endpoint(self, make_entry):
        entries = [
            make_entry(path="/api/users", request_time=0.1),
            make_entry(path="/api/users", request_time=0.2),
            make_entry(path="/api/users", request_time=0.3),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert len(results) == 1
        assert results[0].endpoint == "GET /api/users"
        assert results[0].request_count == 3
        assert results[0].avg_response_time == pytest.approx(0.2)
        assert results[0].min_response_time == 0.1
        assert results[0].max_response_time == 0.3

    def test_multiple_endpoints_grouped_separately(self, make_entry):
        entries = [
            make_entry(path="/api/users", request_time=0.1),
            make_entry(path="/api/users", request_time=0.3),
            make_entry(path="/api/products", request_time=0.5),
            make_entry(path="/api/products", request_time=0.7),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert len(results) == 2
        assert {r.endpoint for r in results} == {"GET /api/users", "GET /api/products"}

    def test_empty_entries_returns_empty_list(self):
        analyzer = PerformanceAnalyzer()
        assert analyzer.analyze([]) == []

    def test_single_entry_performance(self, make_entry):
        entries = [make_entry(path="/api/status", request_time=0.5)]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert len(results) == 1
        assert results[0].avg_response_time == 0.5
        assert results[0].min_response_time == 0.5
        assert results[0].max_response_time == 0.5

    def test_zero_response_times(self, make_entry):
        entries = [
            make_entry(path="/api/empty", request_time=0.0),
            make_entry(path="/api/empty", request_time=0.0),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert results[0].avg_response_time == 0.0
        assert results[0].max_response_time == 0.0

    def test_sorted_by_avg_descending(self, make_entry):
        entries = [
            make_entry(path="/fast", request_time=0.01),
            make_entry(path="/slow", request_time=5.0),
            make_entry(path="/medium", request_time=0.5),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert results[0].endpoint == "GET /slow"
        assert results[1].endpoint == "GET /medium"
        assert results[2].endpoint == "GET /fast"

    @pytest.mark.parametrize("method,request_time", [
        ("GET", 0.1),
        ("POST", 0.2),
        ("DELETE", 0.3),
    ])
    def test_different_methods_same_path_grouped_differently(self, make_entry, method, request_time):
        entries = [
            make_entry(path="/api/data", method="GET", request_time=0.1),
            make_entry(path="/api/data", method="POST", request_time=0.2),
            make_entry(path="/api/data", method="DELETE", request_time=0.3),
        ]
        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        assert len(results) == 3
        assert {r.endpoint for r in results} == {
            "GET /api/data",
            "POST /api/data",
            "DELETE /api/data",
        }
