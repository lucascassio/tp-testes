import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.models import LogEntry


@dataclass
class AnomalyResult:
    ip: str
    total_errors: int
    client_errors: int
    server_errors: int
    total_requests: int
    error_rate: float


class AnomalyDetector:
    def __init__(self, error_threshold: int = 5):
        self.error_threshold = error_threshold

    def analyze(self, entries: list[LogEntry]) -> list[AnomalyResult]:
        if not entries:
            return []

        ip_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"total": 0, "4xx": 0, "5xx": 0}
        )

        for entry in entries:
            stats = ip_stats[entry.remote_addr]
            stats["total"] += 1
            if entry.is_client_error:
                stats["4xx"] += 1
            elif entry.is_server_error:
                stats["5xx"] += 1

        anomalies: list[AnomalyResult] = []
        for ip, stats in ip_stats.items():
            total_errors = stats["4xx"] + stats["5xx"]
            if total_errors >= self.error_threshold:
                anomalies.append(
                    AnomalyResult(
                        ip=ip,
                        total_errors=total_errors,
                        client_errors=stats["4xx"],
                        server_errors=stats["5xx"],
                        total_requests=stats["total"],
                        error_rate=(
                            total_errors / stats["total"] if stats["total"] > 0 else 0.0
                        ),
                    )
                )

        anomalies.sort(key=lambda x: x.total_errors, reverse=True)
        return anomalies


@dataclass
class PerformanceResult:
    endpoint: str
    request_count: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float


class PerformanceAnalyzer:
    def analyze(self, entries: list[LogEntry]) -> list[PerformanceResult]:
        endpoint_stats: dict[str, dict[str, float | int]] = defaultdict(
            lambda: {"total_time": 0.0, "count": 0, "min": float("inf"), "max": 0.0}
        )

        for entry in entries:
            key = entry.endpoint
            stats = endpoint_stats[key]
            rt = entry.request_time
            stats["total_time"] += rt
            stats["count"] += 1
            if rt < stats["min"]:
                stats["min"] = rt
            if rt > stats["max"]:
                stats["max"] = rt

        results: list[PerformanceResult] = []
        for endpoint, stats in endpoint_stats.items():
            count = int(stats["count"])
            results.append(
                PerformanceResult(
                    endpoint=endpoint,
                    request_count=count,
                    avg_response_time=stats["total_time"] / count if count > 0 else 0.0,
                    min_response_time=(
                        stats["min"] if stats["min"] != float("inf") else 0.0
                    ),
                    max_response_time=stats["max"],
                )
            )

        results.sort(key=lambda x: x.avg_response_time, reverse=True)
        return results


@dataclass
class SecurityAlert:
    path: str
    method: str
    ip: str
    pattern_type: str
    matched_content: str


class SecurityAuditor:
    PATTERNS: dict[str, str] = {
        "SQL Injection": r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|--|\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d|')",
        "XSS": r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        "Path Traversal": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
    }

    def audit(self, entries: list[LogEntry]) -> list[SecurityAlert]:
        alerts: list[SecurityAlert] = []

        for entry in entries:
            for pattern_type, pattern in self.PATTERNS.items():
                match = re.search(pattern, entry.path, re.IGNORECASE)
                if match:
                    alerts.append(
                        SecurityAlert(
                            path=entry.path,
                            method=entry.method,
                            ip=entry.remote_addr,
                            pattern_type=pattern_type,
                            matched_content=match.group(0),
                        )
                    )

        return alerts
