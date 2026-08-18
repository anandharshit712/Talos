"""HTTP access, nginx-JSON, and WAF-JSON logs into ``NormalizedEvent`` (LLD 5.2).

Three formats, autodetected per line, because a real collector interleaves them and a parser
that has to be told which one it is reading is a parser somebody configures wrongly:

* **combined / common** — the Apache and nginx default, quote-and-bracket delimited
* **nginx JSON** — one JSON object per line, `remote_addr` / `request` / `status` keys
* **WAF JSON** — the same idea with a body, headers, and often a rule verdict

**Decoding happens exactly once.** `%2527` decodes to `%27`, not to `'`. Decoding until the
string stops changing is how a filter gets walked past: the attacker picks the number of layers,
and whatever the parser lands on is not what the application saw. One layer is what a web server
gives the application, so one layer is what a detector reasons about — and `raw` keeps the
original so evidence quotes what was actually on the wire (LLD 5.2).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from talos.ingestion.parser_contract import BaseParser
from talos.schemas.event_schema import Actor, NormalizedEvent, Target, WebRequest

#: Apache/nginx combined: host, ident, user, [time], "request", status, size, "referer", "agent"
COMBINED_LINE = re.compile(
    r"^(?P<source_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

#: The request line inside the quotes: METHOD SP target SP protocol
REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+(?P<protocol>\S+))?$")

#: Timestamp inside the brackets, e.g. 15/Aug/2026:10:15:00 +0000
CLF_TIME = "%d/%b/%Y:%H:%M:%S %z"

#: Keys a JSON line may use for each field. First hit wins; collectors disagree on names.
JSON_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip": ("remote_addr", "client_ip", "src_ip", "clientIp", "source_ip"),
    "timestamp": ("time_iso8601", "timestamp", "@timestamp", "time", "time_local"),
    "method": ("request_method", "method", "http_method"),
    "target": ("request_uri", "uri", "request", "path", "url"),
    "status": ("status", "status_code", "response_code"),
    "user_agent": ("http_user_agent", "user_agent", "userAgent"),
    "body": ("request_body", "body", "payload", "post_data"),
    "headers": ("request_headers", "headers"),
    "host": ("host", "http_host", "server_name"),
    "account": ("remote_user", "user", "username", "account"),
    "session": ("session_id", "sessionid", "cookie_session"),
}

#: How the source is labelled in ``NormalizedEvent.telemetry_source``.
SOURCE_WAF = "waf"
SOURCE_APP_LOG = "app_log"

#: A JSON line carrying any of these is a WAF record rather than a plain access log.
WAF_MARKERS = ("rule_id", "waf", "attack_type", "anomaly_score", "blocked", "action")


class WebLogParser(BaseParser):
    """Combined, nginx-JSON, or WAF-JSON -> ``NormalizedEvent(domain="web")``."""

    domain = "web"

    def parse_line(self, raw: str) -> NormalizedEvent | None:
        line = raw.strip()
        if not line:
            return None
        if line.startswith("{"):
            return self._parse_json(line)
        return self._parse_combined(line)

    # --- combined / common ---------------------------------------------------------------

    def _parse_combined(self, line: str) -> NormalizedEvent | None:
        match = COMBINED_LINE.match(line)
        if match is None:
            return None
        request = REQUEST_LINE.match(match.group("request") or "")
        if request is None:
            return None

        path, query = _split_target(request.group("target"))
        agent = match.group("agent")
        user = match.group("user")
        return self._build(
            timestamp=_parse_clf_time(match.group("timestamp")),
            source_ip=match.group("source_ip"),
            account=None if user in (None, "-") else user,
            user_agent=None if agent in (None, "-") else agent,
            host=None,
            method=request.group("method"),
            path=path,
            query_params=query,
            body=None,
            headers={},
            status=int(match.group("status")),
            telemetry_source=SOURCE_APP_LOG,
            raw=line,
            meta={},
        )

    # --- JSON: nginx or WAF --------------------------------------------------------------

    def _parse_json(self, line: str) -> NormalizedEvent | None:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None

        target = _first(record, "target")
        if target is None:
            return None
        # nginx's "request" key holds the whole request line; "request_uri" holds only the target.
        request_line = REQUEST_LINE.match(str(target))
        method = _first(record, "method")
        if request_line is not None:
            method = method or request_line.group("method")
            target = request_line.group("target")

        path, query = _split_target(str(target))
        headers = _as_str_map(_first(record, "headers"))
        is_waf = any(marker in record for marker in WAF_MARKERS)
        status = _as_int(_first(record, "status"))

        return self._build(
            timestamp=_parse_json_time(_first(record, "timestamp")),
            source_ip=str(_first(record, "source_ip") or "unknown"),
            account=_as_optional_str(_first(record, "account")),
            user_agent=_as_optional_str(_first(record, "user_agent")) or headers.get("user-agent"),
            host=_as_optional_str(_first(record, "host")),
            method=_as_optional_str(method),
            path=path,
            query_params=query,
            body=_as_optional_str(_first(record, "body")),
            headers=headers,
            status=status,
            telemetry_source=SOURCE_WAF if is_waf else SOURCE_APP_LOG,
            raw=line,
            meta={key: record[key] for key in WAF_MARKERS if key in record},
        )

    # --- shared --------------------------------------------------------------------------

    def _build(
        self,
        *,
        timestamp: datetime | None,
        source_ip: str,
        account: str | None,
        user_agent: str | None,
        host: str | None,
        method: str | None,
        path: str | None,
        query_params: dict[str, str],
        body: str | None,
        headers: dict[str, str],
        status: int | None,
        telemetry_source: str,
        raw: str,
        meta: dict[str, Any],
    ) -> NormalizedEvent | None:
        if timestamp is None or not source_ip:
            return None
        session = headers.get("x-session-id")
        return NormalizedEvent(
            event_id=uuid.uuid4().hex,
            timestamp=timestamp,
            domain="web",
            telemetry_source=telemetry_source,
            actor=Actor(
                source_ip=source_ip,
                account=account,
                session_id=session,
                user_agent=user_agent,
            ),
            target=Target(host=host, endpoint=path, resource_id=_resource_id(path)),
            request=WebRequest(
                method=method,
                path=path,
                query_params=query_params,
                body=_decode_once(body) if body else None,
                headers=headers,
                status_code=status,
            ),
            raw=raw,
            meta=meta,
        )


def _split_target(target: str) -> tuple[str, dict[str, str]]:
    """Split a request target into its path and its query parameters, decoded exactly once.

    ``parse_qsl`` already performs one percent-decode, so nothing further is applied here. An
    extra pass would turn ``%2527`` into ``'`` instead of ``%27`` -- double decoding, which is the
    evasion the once-only rule exists to prevent (LLD 5.2). A test asserts the boundary.
    """
    parts = urlsplit(target)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    return parts.path or target, params


def _decode_once(value: str) -> str:
    """URL-decode exactly one layer (LLD 5.2).

    ``%2527`` becomes ``%27``, never ``'``. Decoding to a fixed point lets the attacker choose
    how many layers the parser unwraps, and the result is not what the application received.
    """
    return unquote_plus(value)


def _resource_id(path: str | None) -> str | None:
    """The trailing path segment when it looks like an object id -- the raw material for IDOR."""
    if not path:
        return None
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return last if last.isdigit() else None


def _parse_clf_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, CLF_TIME)
    except ValueError:
        return None


def _parse_json_time(value: object) -> datetime | None:
    """Accept ISO-8601, epoch seconds, or the CLF stamp -- collectors emit all three."""
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return _parse_clf_time(value)


def _first(record: dict[str, Any], field: str) -> Any:
    """The first aliased key present for a logical field."""
    for key in JSON_FIELD_ALIASES[field]:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _as_str_map(value: object) -> dict[str, str]:
    """Header maps arrive with mixed casing and non-string values; normalise both."""
    if not isinstance(value, dict):
        return {}
    return {str(key).lower(): str(item) for key, item in value.items()}


def _as_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _as_optional_str(value: object) -> str | None:
    return None if value is None else str(value)
