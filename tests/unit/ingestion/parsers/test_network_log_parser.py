"""sshd syslog field mapping, and the lines that must be skipped (LLD 5.3)."""

from __future__ import annotations

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
