"""sshd syslog and RDP event mapping, and the lines that must be skipped (LLD 5.3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from talos.ingestion.parsers.network_log_parser import NetworkLogParser

FAILED = (
    "Aug 15 10:15:00 bastion-01 sshd[4242]: Failed password for root "
    "from 203.0.113.7 port 51234 ssh2"
)
INVALID_USER_FAILED = (
    "Aug 15 10:15:02 bastion-01 sshd[4243]: Failed password for invalid user admin "
    "from 198.51.100.23 port 40122 ssh2"
)
ACCEPTED = (
    "Aug 15 10:16:11 bastion-01 sshd[4250]: Accepted password for root "
    "from 203.0.113.7 port 51299 ssh2"
)
INVALID_USER = "Aug 15 10:15:04 bastion-01 sshd[4244]: Invalid user admin from 198.51.100.23"


@pytest.fixture
def parser() -> NetworkLogParser:
    return NetworkLogParser(default_year=2026)


def test_failed_password_maps_every_field(parser: NetworkLogParser) -> None:
    event = parser.parse_line(FAILED)
    assert event is not None
    assert event.domain == "network"
    assert event.telemetry_source == "sshd"
    assert event.timestamp == datetime(2026, 8, 15, 10, 15, 0, tzinfo=UTC)
    assert event.actor.source_ip == "203.0.113.7"
    assert event.actor.account == "root"
    assert event.target.host == "bastion-01"
    assert event.target.port == 22
    assert event.auth is not None
    assert (event.auth.protocol, event.auth.outcome, event.auth.reason) == (
        "ssh",
        "failure",
        "invalid_password",
    )
    assert event.raw == FAILED


def test_invalid_user_is_distinguished_from_a_wrong_password(parser: NetworkLogParser) -> None:
    """Different reasons: one is a guessed username, the other a guessed password."""
    guessed_user = parser.parse_line(INVALID_USER_FAILED)
    assert guessed_user is not None and guessed_user.auth is not None
    assert guessed_user.auth.reason == "unknown_user"
    assert guessed_user.actor.account == "admin"

    standalone = parser.parse_line(INVALID_USER)
    assert standalone is not None and standalone.auth is not None
    assert standalone.auth.outcome == "failure"
    assert standalone.auth.reason == "unknown_user"


def test_accepted_password_is_a_success(parser: NetworkLogParser) -> None:
    event = parser.parse_line(ACCEPTED)
    assert event is not None and event.auth is not None
    assert event.auth.outcome == "success"


@pytest.mark.parametrize(
    "line",
    [
        "Aug 15 10:14:31 bastion-01 sshd[4101]: Server listening on 0.0.0.0 port 22.",
        "Aug 15 10:14:44 bastion-01 CRON[4110]: session opened for user backup",
        "Aug 15 10:16:11 bastion-01 sshd[4260] Failed password for",
        "not a syslog line at all",
        "",
    ],
)
def test_non_auth_lines_are_skipped(parser: NetworkLogParser, line: str) -> None:
    assert parser.parse_line(line) is None


def test_stream_counts_what_it_skipped(parser: NetworkLogParser) -> None:
    events = list(parser.parse_stream([FAILED, "junk", ACCEPTED, "more junk"]))
    assert len(events) == 2
    assert parser.parse_errors == 2


def test_year_less_stamp_is_read_as_the_recent_past() -> None:
    """A December line read in January belongs to last year, not next year."""
    tomorrow = datetime.now(UTC) + timedelta(days=3)
    line = (
        f"{tomorrow:%b %d} 10:15:00 bastion-01 sshd[1]: Failed password for root "
        f"from 203.0.113.7 port 22 ssh2"
    )
    event = NetworkLogParser(default_year=tomorrow.year).parse_line(line)
    assert event is not None
    assert event.timestamp.year == tomorrow.year - 1


def test_impossible_date_is_skipped() -> None:
    line = "Feb 30 10:15:00 bastion-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert NetworkLogParser(default_year=2026).parse_line(line) is None


# --- RDP: Windows Security events -------------------------------------------------------------


def _rdp_line(**overrides: object) -> str:
    """A 4625 RemoteInteractive failure, with fields overridden per test."""
    record: dict[str, object] = {
        "EventID": 4625,
        "TimeCreated": "2026-08-15T10:15:00Z",
        "Computer": "jump-01",
        "TargetUserName": "administrator",
        "IpAddress": "198.51.100.23",
        "LogonType": 10,
        "SubStatus": "0xC000006A",
    }
    record.update(overrides)
    return json.dumps(record)


def test_a_failed_rdp_logon_maps_onto_the_contract(parser: NetworkLogParser) -> None:
    event = parser.parse_line(_rdp_line())
    assert event is not None
    assert event.domain == "network"
    assert event.telemetry_source == "rdp"
    assert event.actor.source_ip == "198.51.100.23"
    assert event.actor.account == "administrator"
    assert event.target.host == "jump-01"
    assert event.target.port == 3389
    assert event.auth is not None
    assert event.auth.protocol == "rdp"
    assert event.auth.outcome == "failure"
    assert event.auth.reason == "invalid_password"
    assert event.timestamp == datetime(2026, 8, 15, 10, 15, tzinfo=UTC)


def test_a_successful_rdp_logon_is_a_success(parser: NetworkLogParser) -> None:
    event = parser.parse_line(_rdp_line(EventID=4624, SubStatus="0x0"))
    assert event is not None
    assert event.auth is not None
    assert event.auth.outcome == "success"
    assert event.auth.reason == "accepted"


def test_a_non_rdp_logon_type_is_skipped(parser: NetworkLogParser) -> None:
    """4625 also covers network and unlock logons; counting those as RDP inflates the burst."""
    assert parser.parse_line(_rdp_line(LogonType=3)) is None
    assert parser.parse_line(_rdp_line(LogonType=7)) is None


def test_an_unrelated_security_event_is_skipped(parser: NetworkLogParser) -> None:
    """4634 is a logoff. Only the two logon-outcome ids carry an authentication result."""
    assert parser.parse_line(_rdp_line(EventID=4634)) is None


def test_string_valued_ids_and_logon_types_are_accepted(parser: NetworkLogParser) -> None:
    """Exporters disagree on whether these are numbers; both shapes occur in real captures."""
    event = parser.parse_line(_rdp_line(EventID="4625", LogonType="10"))
    assert event is not None
    assert event.auth is not None
    assert event.auth.outcome == "failure"


def test_an_unnamed_sub_status_keeps_a_generic_reason(parser: NetworkLogParser) -> None:
    event = parser.parse_line(_rdp_line(SubStatus="0xC0000199"))
    assert event is not None
    assert event.auth is not None
    assert event.auth.reason == "logon_failed"
    assert event.meta["sub_status"] == "0xC0000199"


def test_a_locked_account_is_named_as_such(parser: NetworkLogParser) -> None:
    """Lockout after a burst is what an analyst needs to see; it is not a generic failure."""
    event = parser.parse_line(_rdp_line(SubStatus="0xc0000234"))
    assert event is not None
    assert event.auth is not None
    assert event.auth.reason == "account_locked"


def test_winlogbeat_field_names_are_read_too(parser: NetworkLogParser) -> None:
    line = json.dumps(
        {
            "event_id": 4625,
            "@timestamp": "2026-08-15T10:15:00+00:00",
            "computer_name": "jump-02",
            "target_user_name": "svc_backup",
            "ip_address": "198.51.100.24",
            "logon_type": 10,
        }
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.target.host == "jump-02"
    assert event.actor.account == "svc_backup"
    assert event.auth is not None
    assert event.auth.reason == "logon_failed"


@pytest.mark.parametrize(
    "overrides",
    [
        {"IpAddress": "-"},  # Windows writes this when it has no address
        {"IpAddress": "127.0.0.1"},  # a local logon, not a remote attempt
        {"TargetUserName": ""},  # nothing to key a window on
        {"TimeCreated": "not a timestamp"},
    ],
)
def test_events_missing_what_a_window_needs_are_skipped(
    parser: NetworkLogParser, overrides: dict[str, object]
) -> None:
    assert parser.parse_line(_rdp_line(**overrides)) is None


def test_a_broken_json_line_is_skipped_not_raised(parser: NetworkLogParser) -> None:
    assert parser.parse_line('{"EventID": 4625, truncated') is None


def test_a_mixed_file_reads_both_formats(parser: NetworkLogParser) -> None:
    """A collector that ships both channels into one file must not lose either."""
    events = list(parser.parse_stream([FAILED, _rdp_line(), "junk", ACCEPTED]))
    assert [event.auth.protocol for event in events if event.auth] == ["ssh", "rdp", "ssh"]
    assert parser.parse_errors == 1
