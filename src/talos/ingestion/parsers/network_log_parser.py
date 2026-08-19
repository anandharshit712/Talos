"""``sshd`` syslog and Windows RDP logon events into ``NormalizedEvent`` (LLD 5.3).

Handles the four line shapes that carry an authentication outcome, all prefixed by the syslog
stamp, host, and ``sshd[pid]:``::

    Failed password for root from 203.0.113.7 port 51234 ssh2
    Failed password for invalid user admin from 203.0.113.7 port 51236 ssh2
    Invalid user admin from 203.0.113.7 port 51236
    Accepted password for root from 203.0.113.7 port 51299 ssh2

Everything else on the sshd channel -- session teardown, key exchange chatter, other daemons --
returns ``None`` and is counted as a skipped line.

**RDP arrives as JSON, one Windows Security event per line**, the shape `wevtutil`, Winlogbeat,
and every EVTX-to-JSON exporter produce::

    {"EventID": 4625, "TimeCreated": "2026-08-15T10:15:00Z", "Computer": "jump-01",
     "TargetUserName": "administrator", "IpAddress": "198.51.100.23", "LogonType": 10,
     "SubStatus": "0xC000006A"}

Reading the export rather than the binary is a deliberate choice: parsing EVTX itself needs a
third-party library and a Windows-only file, and the collector that ships these logs has already
done the conversion. Only logon type 10 -- RemoteInteractive -- is read as RDP; 4624/4625 also
carry network and unlock logons, and calling those RDP would put unrelated failures in the same
window.

**The syslog timestamp carries no year.** The parser takes ``default_year`` (current year by
default) and steps back one year when that would place the line in the future, which is what
makes a December log read in January parse correctly instead of landing 12 months ahead.
"""

from __future__ import annotations

import json
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

#: Windows Security event ids that state a logon outcome.
RDP_EVENT_OUTCOMES: dict[int, AuthOutcome] = {4625: "failure", 4624: "success"}

#: ``LogonType`` 10 is RemoteInteractive -- an RDP session. 3 (network) and 7 (unlock) share the
#: same event ids and are other things entirely.
RDP_LOGON_TYPE = 10

#: RDP's default port, recorded so a report can name the exposed service.
RDP_PORT = 3389

#: Field names an exporter may use, first hit wins. Exporters disagree as much as web collectors
#: do: `wevtutil` keeps the Windows names, Winlogbeat lower-cases and prefixes them.
RDP_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "event_id": ("EventID", "event_id", "EventCode", "eventid"),
    "timestamp": ("TimeCreated", "@timestamp", "timestamp", "time_created", "EventTime"),
    "host": ("Computer", "computer_name", "host", "Hostname"),
    "account": ("TargetUserName", "target_user_name", "TargetAccountName", "user"),
    "source_ip": ("IpAddress", "ip_address", "source_ip", "SourceNetworkAddress"),
    "logon_type": ("LogonType", "logon_type"),
    "sub_status": ("SubStatus", "sub_status", "Status", "status"),
    "workstation": ("WorkstationName", "workstation_name"),
}

#: The `SubStatus` codes worth naming. Anything else keeps the generic reason: the code itself is
#: kept in ``meta`` either way, so nothing is lost by not enumerating all of them.
RDP_SUB_STATUS_REASONS = {
    "0xc0000064": "unknown_user",
    "0xc000006a": "invalid_password",
    "0xc0000072": "account_disabled",
    "0xc0000234": "account_locked",
    "0xc0000193": "account_expired",
    "0xc0000070": "workstation_restriction",
}

#: What a failed logon is called when the export names no `SubStatus`.
RDP_DEFAULT_FAILURE_REASON = "logon_failed"

#: An address Windows writes when it has none to write. Not a source.
RDP_EMPTY_ADDRESSES = frozenset({"", "-", "::1", "127.0.0.1"})


class NetworkLogParser(BaseParser):
    """sshd syslog or Windows RDP logon JSON -> ``NormalizedEvent(domain="network")``."""

    domain = "network"

    def __init__(self, default_year: int | None = None) -> None:
        super().__init__()
        self.default_year = default_year or datetime.now(UTC).year

    def parse_line(self, raw: str) -> NormalizedEvent | None:
        line = raw.rstrip("\n")
        if line.lstrip().startswith("{"):
            return self._parse_rdp_event(line)
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

    # --- RDP: Windows Security events as JSON ---------------------------------------------

    def _parse_rdp_event(self, line: str) -> NormalizedEvent | None:
        """One exported Windows Security event, or ``None`` if it is not an RDP logon."""
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None

        outcome = RDP_EVENT_OUTCOMES.get(_as_int(_rdp_field(record, "event_id")) or 0)
        if outcome is None:
            return None
        if _as_int(_rdp_field(record, "logon_type")) != RDP_LOGON_TYPE:
            # A 4625 for a network or unlock logon is a real failure, but not an RDP one, and
            # putting it in the RDP window would inflate a burst with unrelated events.
            return None

        timestamp = _parse_iso_time(_rdp_field(record, "timestamp"))
        source_ip = str(_rdp_field(record, "source_ip") or "").strip()
        account = _rdp_field(record, "account")
        if timestamp is None or source_ip in RDP_EMPTY_ADDRESSES or not account:
            return None

        sub_status = str(_rdp_field(record, "sub_status") or "")
        return NormalizedEvent(
            event_id=uuid.uuid4().hex,
            timestamp=timestamp,
            domain="network",
            telemetry_source="rdp",
            actor=Actor(source_ip=source_ip, account=str(account)),
            target=Target(host=_as_optional_str(_rdp_field(record, "host")), port=RDP_PORT),
            auth=AuthEvent(
                protocol="rdp",
                outcome=outcome,
                reason=_rdp_failure_reason(sub_status) if outcome == "failure" else "accepted",
            ),
            raw=line,
            meta={
                key: value
                for key, value in (
                    ("sub_status", sub_status or None),
                    ("workstation", _as_optional_str(_rdp_field(record, "workstation"))),
                )
                if value is not None
            },
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


def _rdp_field(record: dict[str, object], field: str) -> object:
    """The first aliased key present for a logical RDP field."""
    for key in RDP_FIELD_ALIASES[field]:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _rdp_failure_reason(sub_status: str) -> str:
    """Name the ``SubStatus`` code when it is one worth naming."""
    return RDP_SUB_STATUS_REASONS.get(sub_status.strip().lower(), RDP_DEFAULT_FAILURE_REASON)


def _parse_iso_time(value: object) -> datetime | None:
    """ISO-8601 as every EVTX exporter writes it. ``Z`` and a space separator both occur."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_int(value: object) -> int | None:
    """Exporters write ids and logon types as both numbers and strings."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _as_optional_str(value: object) -> str | None:
    return None if value is None else str(value)
