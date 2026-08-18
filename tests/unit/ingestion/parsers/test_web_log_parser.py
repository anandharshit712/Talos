"""Three formats, one contract, and decoding exactly once (LLD 5.2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from talos.ingestion.parsers.web_log_parser import WebLogParser

COMBINED = (
    "203.0.113.9 - alice [15/Aug/2026:10:15:00 +0000] "
    '"GET /products?id=42&q=shoes HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
)
NGINX_JSON = json.dumps(
    {
        "time_iso8601": "2026-08-15T10:16:00+00:00",
        "remote_addr": "203.0.113.9",
        "request_method": "POST",
        "request_uri": "/cart/add",
        "status": 201,
        "http_user_agent": "curl/8.4",
        "request_body": "sku=1234&qty=2",
    }
)
WAF_JSON = json.dumps(
    {
        "timestamp": "2026-08-15T10:17:00Z",
        "client_ip": "203.0.113.9",
        "method": "GET",
        "uri": "/search?q=%3Cscript%3E",
        "status_code": 403,
        "rule_id": "941100",
        "blocked": True,
        "headers": {"User-Agent": "evil/1.0", "X-Session-Id": "sess-7"},
    }
)


@pytest.fixture
def parser() -> WebLogParser:
    return WebLogParser()


def test_combined_line_maps_every_field(parser: WebLogParser) -> None:
    event = parser.parse_line(COMBINED)
    assert event is not None and event.request is not None
    assert event.domain == "web"
    assert event.telemetry_source == "app_log"
    assert event.timestamp == datetime(2026, 8, 15, 10, 15, tzinfo=UTC)
    assert event.actor.source_ip == "203.0.113.9"
    assert event.actor.account == "alice"
    assert event.actor.user_agent == "Mozilla/5.0"
    assert event.request.method == "GET"
    assert event.request.path == "/products"
    assert event.request.query_params == {"id": "42", "q": "shoes"}
    assert event.request.status_code == 200
    assert event.raw == COMBINED


def test_nginx_json_is_read_as_an_app_log(parser: WebLogParser) -> None:
    event = parser.parse_line(NGINX_JSON)
    assert event is not None and event.request is not None
    assert event.telemetry_source == "app_log"
    assert event.request.method == "POST"
    assert event.request.path == "/cart/add"
    assert event.request.body == "sku=1234&qty=2"
    assert event.request.status_code == 201


def test_waf_json_is_labelled_and_keeps_its_verdict(parser: WebLogParser) -> None:
    event = parser.parse_line(WAF_JSON)
    assert event is not None and event.request is not None
    assert event.telemetry_source == "waf"
    assert event.meta == {"rule_id": "941100", "blocked": True}
    assert event.request.query_params == {"q": "<script>"}
    assert event.actor.user_agent == "evil/1.0"
    assert event.actor.session_id == "sess-7"


def test_the_dash_placeholder_is_not_a_username(parser: WebLogParser) -> None:
    line = COMBINED.replace(" alice ", " - ")
    event = parser.parse_line(line)
    assert event is not None
    assert event.actor.account is None


def test_query_is_decoded_exactly_once(parser: WebLogParser) -> None:
    """%2527 becomes %27, never a quote.

    Decoding to a fixed point lets the attacker choose the number of layers, and what the parser
    lands on is then not what the application received (LLD 5.2).
    """
    line = COMBINED.replace("id=42", "id=1%2527%20OR%201%3D1")
    event = parser.parse_line(line)
    assert event is not None and event.request is not None
    assert event.request.query_params["id"] == "1%27 OR 1=1"


def test_raw_keeps_the_original_encoding(parser: WebLogParser) -> None:
    """Evidence must quote what was on the wire, not the parser's interpretation of it."""
    line = COMBINED.replace("id=42", "id=%3Cscript%3E")
    event = parser.parse_line(line)
    assert event is not None
    assert "%3Cscript%3E" in event.raw


def test_numeric_path_tail_becomes_a_resource_id(parser: WebLogParser) -> None:
    """The raw material for IDOR reasoning in P6."""
    event = parser.parse_line(COMBINED.replace("/products?id=42&q=shoes", "/account/1042"))
    assert event is not None
    assert event.target.resource_id == "1042"


def test_a_slug_path_is_not_a_resource_id(parser: WebLogParser) -> None:
    event = parser.parse_line(COMBINED.replace("/products?id=42&q=shoes", "/about/company"))
    assert event is not None
    assert event.target.resource_id is None


def test_epoch_and_iso_timestamps_are_both_accepted(parser: WebLogParser) -> None:
    epoch = json.dumps({"timestamp": 1786000000, "remote_addr": "1.2.3.4", "uri": "/x"})
    event = parser.parse_line(epoch)
    assert event is not None
    assert event.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a log line at all",
        "{not json",
        '{"remote_addr": "1.2.3.4"}',  # no request target
        '203.0.113.9 - - [bad timestamp] "GET / HTTP/1.1" 200 1',
    ],
)
def test_unreadable_lines_are_skipped(parser: WebLogParser, line: str) -> None:
    assert parser.parse_line(line) is None


def test_stream_counts_what_it_skipped(parser: WebLogParser) -> None:
    events = list(parser.parse_stream([COMBINED, "junk", NGINX_JSON, "{bad"]))
    assert len(events) == 2
    assert parser.parse_errors == 2
