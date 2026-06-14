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
