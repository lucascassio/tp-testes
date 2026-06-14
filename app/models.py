from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEntry:
    remote_addr: str
    remote_user: str
    timestamp: Optional[datetime]
    method: str
    path: str
    protocol: str
    status: int
    body_bytes_sent: int
    http_referer: str
    http_user_agent: str
    request_time: float = 0.0
    raw_line: str = field(repr=False)

    @property
    def endpoint(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status < 600

    @property
    def is_error(self) -> bool:
        return self.status >= 400
