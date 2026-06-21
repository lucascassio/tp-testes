import pytest

from app.samples import (
    SAMPLES,
    generate_normal_traffic,
    generate_anomaly_scenario,
    generate_sqli_scenario,
    generate_xss_scenario,
    generate_traversal_scenario,
    generate_performance_scenario,
    generate_full_attack_scenario,
)
from app.parser import parse_text
from app.analyzers import AnomalyDetector, PerformanceAnalyzer, SecurityAuditor

pytestmark = pytest.mark.integration


GENERATORS = [
    ("normal", generate_normal_traffic, "Normal Traffic Baseline"),
    ("anomaly", generate_anomaly_scenario, "Brute Force & Server Errors"),
    ("sqli", generate_sqli_scenario, "SQL Injection Attacks"),
    ("xss", generate_xss_scenario, "XSS Attacks"),
    ("traversal", generate_traversal_scenario, "Path Traversal Attacks"),
    ("performance", generate_performance_scenario, "Slow Endpoints"),
    ("full-attack", generate_full_attack_scenario, "Full Attack Scenario"),
]


class TestSamplesRegistry:
    def test_all_seven_scenarios_registered(self):
        assert len(SAMPLES) == 7

    @pytest.mark.parametrize("key,label", [
        ("normal", "Normal Traffic Baseline"),
        ("anomaly", "Brute Force & Server Errors"),
        ("sqli", "SQL Injection Attacks"),
        ("xss", "XSS Attacks"),
        ("traversal", "Path Traversal Attacks"),
        ("performance", "Slow Endpoints"),
        ("full-attack", "Full Attack Scenario"),
    ])
    def test_sample_has_label_and_callable(self, key, label):
        assert key in SAMPLES
        assert SAMPLES[key][0] == label
        assert callable(SAMPLES[key][1])


class TestSampleGenerators:
    @pytest.mark.parametrize("key,generator,label", GENERATORS)
    def test_generator_returns_non_empty_string(self, key, generator, label):
        text = generator()
        assert isinstance(text, str)
        assert len(text) > 0
        assert "\n" in text or len(text) > 100

    @pytest.mark.parametrize("key,generator,label", GENERATORS)
    def test_generated_text_is_parseable(self, key, generator, label):
        text = generator()
        entries = parse_text(text)
        assert len(entries) > 0
        for entry in entries:
            assert entry.remote_addr is not None
            assert entry.method in ("GET", "POST", "PUT", "DELETE")
            assert entry.status >= 100
            assert entry.request_time >= 0.0

    @pytest.mark.parametrize("key,generator,label", GENERATORS)
    def test_generated_text_passes_all_analyzers_without_crashing(self, key, generator, label):
        text = generator()
        entries = parse_text(text)

        anomalies = AnomalyDetector(error_threshold=3).analyze(entries)
        performance = PerformanceAnalyzer().analyze(entries)
        security = SecurityAuditor().audit(entries)

        assert isinstance(anomalies, list), "AnomalyDetector should return a list"
        assert isinstance(performance, list), "PerformanceAnalyzer should return a list"
        assert isinstance(security, list), "SecurityAuditor should return a list"


class TestNormalTraffic:
    def test_has_mostly_successful_statuses(self):
        text = generate_normal_traffic()
        entries = parse_text(text)

        assert len(entries) >= 100
        success_count = sum(1 for e in entries if e.status < 400)
        assert success_count > len(entries) * 0.7

    def test_uses_multiple_ips_and_user_agents(self):
        text = generate_normal_traffic()
        entries = parse_text(text)

        ips = {e.remote_addr for e in entries}
        agents = {e.http_user_agent for e in entries}

        assert len(ips) >= 3
        assert len(agents) >= 3

    def test_normal_traffic_is_clean_no_security_alerts(self):
        text = generate_normal_traffic()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        assert alerts == []


class TestAnomalyScenario:
    def test_detects_ips_with_high_error_count(self):
        text = generate_anomaly_scenario()
        entries = parse_text(text)

        detector = AnomalyDetector(error_threshold=3)
        results = detector.analyze(entries)

        assert len(results) >= 1
        anomalous_ips = {r.ip for r in results}
        assert "192.168.1.100" in anomalous_ips or "10.0.0.99" in anomalous_ips

    def test_contains_server_errors(self):
        text = generate_anomaly_scenario()
        entries = parse_text(text)

        server_errors = [e for e in entries if e.is_server_error]
        assert len(server_errors) >= 15

    def test_contains_client_errors(self):
        text = generate_anomaly_scenario()
        entries = parse_text(text)

        client_errors = [e for e in entries if e.is_client_error]
        assert len(client_errors) >= 50


class TestSqliScenario:
    def test_detects_sql_injection_patterns(self):
        text = generate_sqli_scenario()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        sql_alerts = [a for a in alerts if a.pattern_type == "SQL Injection"]
        assert len(sql_alerts) >= 10
        assert all(a.method == "GET" for a in sql_alerts)

    def test_uses_attacker_ips(self):
        text = generate_sqli_scenario()
        entries = parse_text(text)

        attacker_ips = {e.remote_addr for e in entries if "UNION" in e.path or "DROP" in e.path}
        assert len(attacker_ips) >= 1

    def test_contains_normal_traffic_too(self):
        text = generate_sqli_scenario()
        entries = parse_text(text)

        normal_statuses = [e for e in entries if e.status < 400 and "UNION" not in e.path]
        assert len(normal_statuses) >= 20


class TestXssScenario:
    def test_detects_xss_patterns(self):
        text = generate_xss_scenario()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        xss_alerts = [a for a in alerts if a.pattern_type == "XSS"]
        assert len(xss_alerts) >= 10

    def test_xss_payloads_use_multiple_vectors(self):
        text = generate_xss_scenario()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        matched = {a.matched_content for a in alerts if a.pattern_type == "XSS"}
        assert len(matched) >= 2


class TestTraversalScenario:
    def test_detects_path_traversal_patterns(self):
        text = generate_traversal_scenario()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        traversal_alerts = [a for a in alerts if a.pattern_type == "Path Traversal"]
        assert len(traversal_alerts) >= 10

    def test_traversal_payloads_include_encoded_variants(self):
        text = generate_traversal_scenario()
        entries = parse_text(text)

        encoded = [e for e in entries if "%2e%2e" in e.path or "%2f" in e.path]
        assert len(encoded) >= 1


class TestPerformanceScenario:
    def test_detects_slow_endpoints(self):
        text = generate_performance_scenario()
        entries = parse_text(text)

        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        slow = [r for r in results if r.avg_response_time > 1.0]
        assert len(slow) >= 3

    def test_has_fast_endpoints_too(self):
        text = generate_performance_scenario()
        entries = parse_text(text)

        fast = [e for e in entries if e.path == "/api/ping"]
        assert len(fast) >= 15
        all_fast = all(e.request_time < 0.01 for e in fast)
        assert all_fast

    def test_response_times_are_non_negative(self):
        text = generate_performance_scenario()
        entries = parse_text(text)

        for entry in entries:
            assert entry.request_time >= 0.0


class TestFullAttackScenario:
    def test_is_largest_scenario(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        assert len(entries) >= 200

    def test_detects_all_three_attack_types(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        auditor = SecurityAuditor()
        alerts = auditor.audit(entries)

        pattern_types = {a.pattern_type for a in alerts}
        assert pattern_types >= {"SQL Injection", "XSS", "Path Traversal"}, \
            f"Missing attack types. Got: {pattern_types}"

    def test_detects_anomalies_in_full_attack(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        detector = AnomalyDetector(error_threshold=5)
        results = detector.analyze(entries)

        assert len(results) >= 2
        ips = {r.ip for r in results}
        assert "45.33.32.156" in ips, f"Expected attacker IP not found in {ips}"

    def test_performance_analysis_on_full_attack(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        analyzer = PerformanceAnalyzer()
        results = analyzer.analyze(entries)

        slow_endpoints = {r.endpoint for r in results if r.avg_response_time > 1.0}
        assert len(slow_endpoints) >= 3

    def test_full_attack_is_self_consistent(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        total = len(entries)

        detector = AnomalyDetector(error_threshold=3)
        anomalies = detector.analyze(entries)
        total_anomaly_requests = sum(r.total_requests for r in anomalies)

        assert total_anomaly_requests <= total

        for anomaly in anomalies:
            assert 0.0 <= anomaly.error_rate <= 1.0
            assert anomaly.total_errors <= anomaly.total_requests
            assert anomaly.client_errors + anomaly.server_errors == anomaly.total_errors


class TestEndToEndFullPipeline:
    def test_full_pipeline_on_full_attack_scenario(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        assert len(entries) > 0

        anomalies = AnomalyDetector(error_threshold=3).analyze(entries)
        performance = PerformanceAnalyzer().analyze(entries)
        security = SecurityAuditor().audit(entries)

        assert len(anomalies) >= 1
        assert len(performance) >= 1
        assert len(security) >= 1

        assert all(0.0 <= a.error_rate <= 1.0 for a in anomalies)
        assert all(p.avg_response_time >= 0.0 for p in performance)
        assert all(p.min_response_time <= p.max_response_time for p in performance)
        assert all(s.pattern_type in ("SQL Injection", "XSS", "Path Traversal") for s in security)

    def test_full_pipeline_consistent_counts(self):
        text = generate_full_attack_scenario()
        entries = parse_text(text)

        performance = PerformanceAnalyzer().analyze(entries)
        total_from_perf = sum(p.request_count for p in performance)

        assert total_from_perf == len(entries)

    def test_analyzers_handle_empty_gracefully(self):
        anomaly_result = AnomalyDetector().analyze([])
        performance_result = PerformanceAnalyzer().analyze([])
        security_result = SecurityAuditor().audit([])

        assert anomaly_result == []
        assert performance_result == []
        assert security_result == []
