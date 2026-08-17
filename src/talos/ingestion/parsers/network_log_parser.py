"""``sshd`` syslog into ``NormalizedEvent`` (LLD 5.3).

Handles the four line shapes that carry an authentication outcome, all prefixed by the syslog
stamp, host, and ``sshd[pid]:``::

    Failed password for root from 203.0.113.7 port 51234 ssh2
    Failed password for invalid user admin from 203.0.113.7 port 51236 ssh2
    Invalid user admin from 203.0.113.7 port 51236
    Accepted password for root from 203.0.113.7 port 51299 ssh2

Everything else on the sshd channel -- session teardown, key exchange chatter, other daemons --
returns ``None`` and is counted as a skipped line. RDP event logs extend this parser in P5.

**The syslog timestamp carries no year.** The parser takes ``default_year`` (current year by
default) and steps back one year when that would place the line in the future, which is what
makes a December log read in January parse correctly instead of landing 12 months ahead.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from talos.ingestion.parser_contract import BaseParser
from talos.schemas.event_schema import Actor, AuthEvent, NormalizedEvent, Target

#: ``Aug 19 10:15:00 bastion-01 sshd[4242]: <message>``
SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<daemon>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

_FAILED_PASSWORD = re.compile(
    r"^Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<account>\S+) "
    r"from (?P<source_ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey) for (?P<account>\S+) from (?P<source_ip>\S+) "
    r"port (?P<port>\d+)"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<account>\S+) from (?P<source_ip>\S+)(?: port \d+)?")

#: Daemons whose lines this parser reads. Anything else in the file is another service's.
_SSH_DAEMONS = frozenset({"sshd"})

#: sshd reports exactly two outcomes; the contract's vocabulary is the same two.
AuthOutcome = Literal["success", "failure"]

#: Slack allowed before a year-less timestamp is read as last year's rather than next year's.
_ONE_DAY = timedelta(days=1)

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


class NetworkLogParser(BaseParser):
    """sshd syslog -> ``NormalizedEvent(domain="network")``."""

    domain = "network"

    def __init__(self, default_year: int | None = None) -> None:
        super().__init__()
        self.default_year = default_year or datetime.now(UTC).year

    def parse_line(self, raw: str) -> NormalizedEvent | None:
        line = raw.rstrip("\n")
        syslog = SYSLOG_LINE.match(line)
        if syslog is None or syslog.group("daemon") not in _SSH_DAEMONS:
            return None

        auth = self._parse_auth(syslog.group("message"))
        if auth is None:
            return None
        account, source_ip, outcome, reason = auth

        timestamp = self._parse_timestamp(
            syslog.group("month"), syslog.group("day"), syslog.group("time")
        )
        if timestamp is None:
            return None

        return NormalizedEvent(
            event_id=uuid.uuid4().hex,
            timestamp=timestamp,
            domain="network",
            telemetry_source="sshd",
            actor=Actor(source_ip=source_ip, account=account),
            target=Target(host=syslog.group("host"), port=22),
            auth=AuthEvent(protocol="ssh", outcome=outcome, reason=reason),
            raw=line,
            meta={"daemon_pid": syslog.group("pid")} if syslog.group("pid") else {},
        )

    def _parse_auth(self, message: str) -> tuple[str, str, AuthOutcome, str] | None:
        """Return ``(account, source_ip, outcome, reason)`` for an auth line, else ``None``."""
        failed = _FAILED_PASSWORD.match(message)
        if failed is not None:
            reason = "unknown_user" if failed.group("invalid") else "invalid_password"
            return failed.group("account"), failed.group("source_ip"), "failure", reason

        accepted = _ACCEPTED.match(message)
        if accepted is not None:
            return accepted.group("account"), accepted.group("source_ip"), "success", "accepted"

        invalid = _INVALID_USER.match(message)
        if invalid is not None:
            return invalid.group("account"), invalid.group("source_ip"), "failure", "unknown_user"

        return None

    def _parse_timestamp(self, month: str, day: str, time: str) -> datetime | None:
        """Rebuild a full UTC timestamp from a year-less syslog stamp."""
        month_number = _MONTHS.get(month)
        if month_number is None:
            return None
        hour, minute, second = (int(part) for part in time.split(":"))
        try:
            stamped = datetime(
                self.default_year, month_number, int(day), hour, minute, second, tzinfo=UTC
            )
        except ValueError:
            return None  # e.g. "Feb 30" in a corrupted line
        # A log read in January still holds December lines; assume the recent past, not the
        # near future. One day of slack absorbs clock skew between the source and this host.
        if stamped - datetime.now(UTC) > _ONE_DAY:
            stamped = stamped.replace(year=self.default_year - 1)
        return stamped
