"""Log line parser for Nginx/Apache combined log format.

Parses raw log lines into structured LogEntry objects. Handles edge cases
including IPv6 addresses, query strings, HTTPS URLs, missing request times,
and non-numeric values (graceful fallback to 0.0).

The combined log format expected is:
    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time
"""

import re
from datetime import datetime
from typing import Optional

from app.models import LogEntry

LOG_PATTERN = re.compile(
    r'^(\S+) '
    r'(\S+) '
    r'(\S+) '
    r'\[(.*?)\] '
    r'"([^"]*)" '
    r'(\d+) '
    r'(\d+) '
    r'"([^"]*)" '
    r'"([^"]*)"'
    r'(?: (\S+))?$'
)

TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def parse_timestamp(raw: str) -> Optional[datetime]:
    """Parse a timestamp string using multiple common formats.

    Tries standard Apache format (with/without timezone) and ISO format.
    Returns None if no format matches.
    """
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_request(raw: str) -> tuple[str, str, str]:
    """Parse an HTTP request line into (method, path, protocol).

    Handles edge cases: empty input, missing protocol, URLs with spaces,
    and HTTPS URLs where the path starts with 'https://'.
    """
    if not raw:
        return "", "", ""
    parts = raw.split(" ")
    method = parts[0]
    protocol = ""
    path = ""
    if len(parts) >= 2:
        last = parts[-1]
        if last.upper().startswith("HTTP"):
            protocol = last
            path = " ".join(parts[1:-1])
        else:
            path = " ".join(parts[1:])
    return method, path, protocol


def _parse_request_time(raw: Optional[str]) -> float:
    if raw is None:
        return 0.0
    try:
        return float(raw)
    except ValueError:
        return 0.0


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse a single log line into a LogEntry. Returns None if unparseable."""
    if not line or not line.strip():
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    remote_addr = match.group(1)
    remote_user = match.group(3)
    timestamp_raw = match.group(4)
    request_raw = match.group(5)
    status_str = match.group(6)
    body_bytes_str = match.group(7)
    http_referer = match.group(8)
    http_user_agent = match.group(9)
    request_time_raw = match.group(10)

    timestamp = parse_timestamp(timestamp_raw)

    status = int(status_str)
    body_bytes_sent = int(body_bytes_str)

    method, path, protocol = parse_request(request_raw)
    request_time = _parse_request_time(request_time_raw)

    return LogEntry(
        remote_addr=remote_addr,
        remote_user=remote_user,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        body_bytes_sent=body_bytes_sent,
        http_referer=http_referer,
        http_user_agent=http_user_agent,
        request_time=request_time,
        raw_line=line.rstrip("\n"),
    )


def parse_text(text: str) -> list[LogEntry]:
    """Parse multi-line log text, skipping invalid lines."""
    entries: list[LogEntry] = []
    for line in text.splitlines():
        entry = parse_line(line)
        if entry is not None:
            entries.append(entry)
    return entries
