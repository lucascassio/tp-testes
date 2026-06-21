import pytest

from app.models import LogEntry
from app.analyzers import AnomalyResult, PerformanceResult, SecurityAlert
from app.reporters import (
    generate_anomalies_csv,
    generate_performance_csv,
    generate_security_csv,
    generate_full_report,
)


class TestGenerateAnomaliesCsv:
    def test_empty_anomalies_produces_header_only(self):
        csv_text = generate_anomalies_csv([])
        lines = csv_text.splitlines()
        assert len(lines) == 1
        assert "IP" in lines[0]

    def test_single_anomaly_produces_correct_row(self):
        anomalies = [
            AnomalyResult(
                ip="10.0.0.1",
                total_errors=5,
                client_errors=3,
                server_errors=2,
                total_requests=10,
                error_rate=0.5,
            )
        ]
        csv_text = generate_anomalies_csv(anomalies)
        lines = csv_text.splitlines()
        assert len(lines) == 2
        assert "10.0.0.1" in lines[1]
        assert "5" in lines[1]
        assert "50.00%" in lines[1]


class TestGeneratePerformanceCsv:
    def test_empty_performance_produces_header_only(self):
        csv_text = generate_performance_csv([])
        lines = csv_text.splitlines()
        assert len(lines) == 1

    def test_performance_row_with_times(self):
        results = [
            PerformanceResult(
                endpoint="GET /api",
                request_count=5,
                avg_response_time=0.1234,
                min_response_time=0.01,
                max_response_time=0.5,
            )
        ]
        csv_text = generate_performance_csv(results)
        lines = csv_text.splitlines()
        assert len(lines) == 2
        assert "GET /api" in lines[1]
        assert "5" in lines[1]
        assert "0.1234" in lines[1]


class TestGenerateSecurityCsv:
    def test_empty_alerts_produces_header_only(self):
        csv_text = generate_security_csv([])
        lines = csv_text.splitlines()
        assert len(lines) == 1

    def test_security_alert_row(self):
        alerts = [
            SecurityAlert(
                path="/search?q=1 OR 1=1",
                method="GET",
                ip="10.0.0.1",
                pattern_type="SQL Injection",
                matched_content="OR",
            )
        ]
        csv_text = generate_security_csv(alerts)
        lines = csv_text.splitlines()
        assert len(lines) == 2
        assert "SQL Injection" in lines[1]
        assert "10.0.0.1" in lines[1]


class TestGenerateFullReport:
    def test_full_report_with_all_sections(self):
        anomalies = [
            AnomalyResult(
                ip="10.0.0.1",
                total_errors=5,
                client_errors=5,
                server_errors=0,
                total_requests=10,
                error_rate=0.5,
            )
        ]
        performance = [
            PerformanceResult(
                endpoint="GET /api",
                request_count=3,
                avg_response_time=0.2,
                min_response_time=0.1,
                max_response_time=0.3,
            )
        ]
        security = [
            SecurityAlert(
                path="/xss",
                method="GET",
                ip="10.0.0.1",
                pattern_type="XSS",
                matched_content="<script>",
            )
        ]
        report = generate_full_report(anomalies, performance, security, 15)

        assert "TRAFFIC ANOMALIES" in report
        assert "PERFORMANCE ANALYSIS" in report
        assert "SECURITY AUDIT" in report
        assert "Total log entries processed: 15" in report

    def test_full_report_shows_no_data_when_empty(self):
        report = generate_full_report([], [], [], 0)

        assert "No anomalies detected" in report
        assert "No performance data available" in report
        assert "No security issues detected" in report
        assert "Total log entries processed: 0" in report
