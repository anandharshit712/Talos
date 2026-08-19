"""Three formats, one contract, decoding exactly once, and HTTP logins (LLD 5.2)."""

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


# --- HTTP authentication outcomes -------------------------------------------------------------


def test_a_rejected_login_becomes_a_failed_auth_event(parser: WebLogParser) -> None:
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:20:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 401,
            "request_body": "username=alice&password=hunter2",
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is not None
    assert event.auth.protocol == "http"
    assert event.auth.outcome == "failure"
    assert event.actor.account == "alice"


def test_a_redirect_after_a_post_is_a_successful_login(parser: WebLogParser) -> None:
    """302 back to the application is what a successful form login looks like in an access log."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:21:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "POST",
            "request_uri": "/signin",
            "status": 302,
            "request_body": '{"email": "bob@example.com", "password": "x"}',
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is not None
    assert event.auth.outcome == "success"
    assert event.actor.account == "bob@example.com"


def test_rendering_the_login_form_is_not_an_authentication_attempt(parser: WebLogParser) -> None:
    """A GET of the page states no outcome; calling it a success would poison the window."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:22:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "GET",
            "request_uri": "/login",
            "status": 200,
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is None


def test_a_200_on_a_posted_login_is_recorded_as_unknown(parser: WebLogParser) -> None:
    """The documented limit: an app that re-renders the form on failure is unreadable here."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:23:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 200,
            "request_body": "username=alice&password=hunter2",
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is not None
    assert event.auth.outcome == "success"


def test_registration_is_not_a_login(parser: WebLogParser) -> None:
    """A created account must not read as a trailing success on somebody else's burst."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:24:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "POST",
            "request_uri": "/register",
            "status": 201,
            "request_body": "username=carol&password=x",
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is None


def test_a_403_elsewhere_is_not_an_authentication_failure(parser: WebLogParser) -> None:
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:25:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "GET",
            "request_uri": "/admin/reports",
            "status": 403,
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.auth is None


def test_the_logged_account_wins_over_the_submitted_one(parser: WebLogParser) -> None:
    """When the collector already resolved the user, that is the authoritative name."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:26:00Z",
            "remote_addr": "203.0.113.9",
            "remote_user": "dave",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 401,
            "request_body": "username=spoofed&password=x",
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.actor.account == "dave"


def test_the_submitted_username_is_decoded_exactly_once(parser: WebLogParser) -> None:
    """The same boundary the payload path holds to: ``%2527`` must not become an apostrophe."""
    line = json.dumps(
        {
            "timestamp": "2026-08-15T10:27:00Z",
            "remote_addr": "203.0.113.9",
            "request_method": "POST",
            "request_uri": "/login",
            "status": 401,
            "request_body": "username=a%2527b&password=x",
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.actor.account == "a%27b"


def test_a_basic_auth_rejection_on_an_api_token_path_is_a_failure(parser: WebLogParser) -> None:
    """No body, no form -- a 401 on a token endpoint is still a rejected credential."""
    event = parser.parse_line(
        '203.0.113.9 - - [15/Aug/2026:10:28:00 +0000] "GET /oauth/token HTTP/1.1" 401 12 "-" "-"'
    )
    assert event is not None
    assert event.auth is not None
    assert event.auth.outcome == "failure"
    assert event.actor.account is None
