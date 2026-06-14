import pytest

from app.parser import parse_line, parse_text, parse_timestamp, parse_request
from app.models import LogEntry


class TestParseLine:
    LOG_OK = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.045'
    LOG_EMPTY = ""
    LOG_BLANK = "   "
    LOG_MALFORMED = "this is not a log line at all"
    LOG_NO_TIMESTAMP = '192.168.1.1 - - "GET / HTTP/1.1" 200 0 "-" "Mozilla"'
    LOG_IPV6 = '::1 - - [10/Oct/2023:13:55:36 -0300] "GET / HTTP/1.1" 200 100 "-" "curl/7.0"'
    LOG_POST = '10.0.0.1 - admin [10/Oct/2023:14:00:00 -0300] "POST /api/data HTTP/1.1" 201 500 "https://site.com" "Mozilla/5.0"'
    LOG_500 = '10.0.0.2 - - [10/Oct/2023:14:01:00 -0300] "GET /error HTTP/1.1" 500 0 "-" "-"'
    LOG_404 = '10.0.0.3 - - [10/Oct/2023:14:02:00 -0300] "GET /notfound HTTP/1.1" 404 50 "-" "Mozilla/5.0"'
    LOG_QUERY = '10.0.0.4 - - [10/Oct/2023:14:03:00 -0300] "GET /search?q=hello&page=1 HTTP/1.1" 200 2000 "-" "Mozilla/5.0"'
    LOG_HTTPS = '10.0.0.5 - - [10/Oct/2023:14:04:00 -0300] "GET https://example.com/page HTTP/1.1" 200 300 "-" "Mozilla/5.0"'
    LOG_LONG_URL = '10.0.0.6 - - [10/Oct/2023:14:05:00 -0300] "GET /' + 'x' * 500 + ' HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    LOG_NO_RT = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    LOG_NEGATIVE_SIZE = '10.0.0.7 - - [10/Oct/2023:14:06:00 -0300] "GET / HTTP/1.1" 200 -1 "-" "Mozilla/5.0"'
    LOG_BAD_STATUS = '10.0.0.7 - - [10/Oct/2023:14:06:00 -0300] "GET / HTTP/1.1" ABC 100 "-" "Mozilla/5.0"'
    LOG_NON_NUMERIC_RT = '10.0.0.8 - - [10/Oct/2023:14:07:00 -0300] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" slow'

    def test_parse_valid_log_with_all_fields(self):
        entry = parse_line(self.LOG_OK)
        assert entry is not None
        assert entry.remote_addr == "192.168.1.1"
        assert entry.remote_user == "-"
        assert entry.timestamp is not None
        assert entry.method == "GET"
        assert entry.path == "/api/users"
        assert entry.protocol == "HTTP/1.1"
        assert entry.status == 200
        assert entry.body_bytes_sent == 1234
        assert entry.http_referer == "-"
        assert entry.http_user_agent == "Mozilla/5.0"
        assert entry.request_time == 0.045

    def test_parse_empty_line_returns_none(self):
        assert parse_line(self.LOG_EMPTY) is None

    def test_parse_blank_line_returns_none(self):
        assert parse_line(self.LOG_BLANK) is None

    def test_parse_malformed_line_returns_none(self):
        assert parse_line(self.LOG_MALFORMED) is None

    def test_parse_ipv6_address(self):
        entry = parse_line(self.LOG_IPV6)
        assert entry is not None
        assert entry.remote_addr == "::1"

    def test_parse_post_method(self):
        entry = parse_line(self.LOG_POST)
        assert entry is not None
        assert entry.method == "POST"
        assert entry.path == "/api/data"
        assert entry.status == 201
        assert entry.remote_user == "admin"

    def test_parse_500_server_error(self):
        entry = parse_line(self.LOG_500)
        assert entry is not None
        assert entry.status == 500
        assert entry.is_server_error is True
        assert entry.is_client_error is False
        assert entry.is_error is True

    def test_parse_404_client_error(self):
        entry = parse_line(self.LOG_404)
        assert entry is not None
        assert entry.status == 404
        assert entry.is_client_error is True
        assert entry.is_server_error is False
        assert entry.is_error is True

    def test_parse_url_with_query_string(self):
        entry = parse_line(self.LOG_QUERY)
        assert entry is not None
        assert entry.path == "/search?q=hello&page=1"

    def test_parse_line_without_request_time_defaults_to_zero(self):
        entry = parse_line(self.LOG_NO_RT)
        assert entry is not None
        assert entry.request_time == 0.0

    def test_parse_log_entry_endpoint_property(self):
        entry = parse_line(self.LOG_OK)
        assert entry is not None
        assert entry.endpoint == "GET /api/users"

    def test_parse_log_with_long_url_does_not_crash(self):
        entry = parse_line(self.LOG_LONG_URL)
        assert entry is not None
        assert entry.path == "/" + "x" * 500
        assert entry.status == 200

    def test_parse_all_fields_numeric_conversion(self):
        entry = parse_line(self.LOG_OK)
        assert entry is not None
        assert isinstance(entry.status, int)
        assert isinstance(entry.body_bytes_sent, int)
        assert isinstance(entry.request_time, float)

    def test_non_numeric_request_time_defaults_to_zero(self):
        entry = parse_line(self.LOG_NON_NUMERIC_RT)
        assert entry is not None
        assert entry.request_time == 0.0


class TestParseText:
    def test_parse_multiple_valid_lines(self):
        text = """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /a HTTP/1.1" 200 100 "-" "Mozilla"
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "GET /b HTTP/1.1" 200 200 "-" "Mozilla"
192.168.1.3 - - [10/Oct/2023:13:55:38 -0300] "GET /c HTTP/1.1" 200 300 "-" "Mozilla"
"""
        entries = parse_text(text)
        assert len(entries) == 3

    def test_parse_text_with_empty_string(self):
        entries = parse_text("")
        assert entries == []

    def test_parse_text_with_only_whitespace(self):
        entries = parse_text("\n\n\n")
        assert entries == []

    def test_parse_text_skips_invalid_lines(self):
        text = """192.168.1.1 - - [10/Oct/2023:13:55:36 -0300] "GET /a HTTP/1.1" 200 100 "-" "Mozilla"
this is garbage
192.168.1.2 - - [10/Oct/2023:13:55:37 -0300] "GET /b HTTP/1.1" 200 200 "-" "Mozilla"
"""
        entries = parse_text(text)
        assert len(entries) == 2

    def test_parse_no_timestamp_line_returns_none(self):
        entry = parse_line(TestParseLine.LOG_NO_TIMESTAMP)
        assert entry is None


class TestParseTimestamp:
    def test_standard_format_with_timezone(self):
        ts = parse_timestamp("10/Oct/2023:13:55:36 -0300")
        assert ts is not None
        assert ts.day == 10
        assert ts.month == 10
        assert ts.hour == 13
        assert ts.minute == 55

    def test_standard_format_without_timezone(self):
        ts = parse_timestamp("10/Oct/2023:13:55:36")
        assert ts is not None
        assert ts.hour == 13

    def test_iso_format_with_timezone(self):
        ts = parse_timestamp("2023-10-10T13:55:36-0300")
        assert ts is not None
        assert ts.year == 2023

    def test_iso_format_without_timezone(self):
        ts = parse_timestamp("2023-10-10 13:55:36")
        assert ts is not None

    def test_invalid_timestamp_returns_none(self):
        assert parse_timestamp("not-a-date") is None


class TestParseRequest:
    def test_full_request(self):
        m, p, proto = parse_request("GET /api/users HTTP/1.1")
        assert m == "GET"
        assert p == "/api/users"
        assert proto == "HTTP/1.1"

    def test_empty_request(self):
        m, p, proto = parse_request("")
        assert m == "" and p == "" and proto == ""

    def test_request_with_https_url(self):
        m, p, proto = parse_request("GET https://example.com/page HTTP/1.1")
        assert m == "GET"
        assert p == "https://example.com/page"
        assert proto == "HTTP/1.1"

    def test_request_without_http_protocol(self):
        m, p, proto = parse_request("GET /api/data")
        assert m == "GET"
        assert p == "/api/data"
        assert proto == ""

    def test_request_single_word(self):
        m, p, proto = parse_request("GET")
        assert m == "GET"
        assert p == ""
        assert proto == ""

    def test_request_with_spaces_in_url(self):
        m, p, proto = parse_request("GET /search?q=hello world HTTP/1.1")
        assert m == "GET"
        assert p == "/search?q=hello world"
        assert proto == "HTTP/1.1"
