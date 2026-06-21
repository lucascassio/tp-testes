"""CSV and plain-text report generators for analysis results."""

import csv
import io
from typing import Optional

from app.analyzers import AnomalyResult, PerformanceResult, SecurityAlert


def generate_anomalies_csv(anomalies: list[AnomalyResult]) -> str:
    """Generate CSV with anomaly detection results."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Total Errors", "Client Errors (4xx)", "Server Errors (5xx)", "Total Requests", "Error Rate"])
    for a in anomalies:
        writer.writerow([a.ip, a.total_errors, a.client_errors, a.server_errors, a.total_requests, f"{a.error_rate:.2%}"])
    return output.getvalue()


def generate_performance_csv(results: list[PerformanceResult]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Endpoint", "Request Count", "Avg Response Time (s)", "Min (s)", "Max (s)"])
    for r in results:
        writer.writerow([r.endpoint, r.request_count, f"{r.avg_response_time:.4f}", f"{r.min_response_time:.4f}", f"{r.max_response_time:.4f}"])
    return output.getvalue()


def generate_security_csv(alerts: list[SecurityAlert]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Path", "Method", "IP", "Pattern Type", "Matched Content"])
    for a in alerts:
        writer.writerow([a.path, a.method, a.ip, a.pattern_type, a.matched_content])
    return output.getvalue()


def generate_full_report(
    anomalies: list[AnomalyResult],
    performance: list[PerformanceResult],
    security: list[SecurityAlert],
    total_entries: int,
) -> str:
    lines: list[str] = []
    lines.append("=== LOG ANALYZER REPORT ===")
    lines.append(f"Total log entries processed: {total_entries}")
    lines.append("")

    lines.append("--- TRAFFIC ANOMALIES ---")
    if anomalies:
        lines.append(generate_anomalies_csv(anomalies))
    else:
        lines.append("No anomalies detected.")
    lines.append("")

    lines.append("--- PERFORMANCE ANALYSIS ---")
    if performance:
        lines.append(generate_performance_csv(performance))
    else:
        lines.append("No performance data available.")
    lines.append("")

    lines.append("--- SECURITY AUDIT ---")
    if security:
        lines.append(generate_security_csv(security))
    else:
        lines.append("No security issues detected.")

    return "\n".join(lines)
