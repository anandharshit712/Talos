"""Synthesise sample logs for a demo, and benign counterparts for measuring precision.

Every generator here comes in a pair: an attack and the benign traffic it must be told apart
from. That is not symmetry for its own sake -- a corpus with only attacks measures recall, and
recall alone is what a detector that fires on everything scores perfectly.

Usage::

    python scripts/generate_sample_logs.py --out out/samples
    python scripts/generate_sample_logs.py --out out/samples --only ssh_brute_force
    python scripts/generate_sample_logs.py --list

The output is deliberately reproducible: fixed start times, fixed addresses, no randomness. A
corpus that changes between runs cannot be used to compare two versions of a detector.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timedelta
from pathlib import Path

#: Fixed, so a regenerated corpus is byte-identical.
START = datetime(2026, 9, 1, 10, 0, 0)

CLF_TIME = "%d/%b/%Y:%H:%M:%S +0000"
SYSLOG_TIME = "%b %d %H:%M:%S"

Generator = Callable[[], Iterator[str]]


# ---------------------------------------------------------------------------
# Line builders -- one per telemetry format Talos parses
# ---------------------------------------------------------------------------


def _sshd(when: datetime, *, host: str, account: str, source_ip: str, ok: bool) -> str:
    verb = "Accepted" if ok else "Failed"
    return (
        f"{when.strftime(SYSLOG_TIME)} {host} sshd[4242]: {verb} password for {account} "
        f"from {source_ip} port 51234 ssh2"
    )


def _combined(
    when: datetime,
    *,
    source_ip: str,
    account: str | None,
    method: str,
    path: str,
    status: int,
) -> str:
    return (
        f"{source_ip} - {account or '-'} [{when.strftime(CLF_TIME)}] "
        f'"{method} {path} HTTP/1.1" {status} 3120 "-" "Mozilla/5.0"'
    )


def _nginx_json(
    when: datetime,
    *,
    source_ip: str,
    method: str,
    path: str,
    status: int,
    body: str | None = None,
) -> str:
    record: dict[str, object] = {
        "time_iso8601": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "remote_addr": source_ip,
        "request_method": method,
        "request_uri": path,
        "status": status,
        "http_user_agent": "Mozilla/5.0",
    }
    if body is not None:
        record["request_body"] = body
    return json.dumps(record)


# ---------------------------------------------------------------------------
# Attack corpora, each with its benign counterpart
# ---------------------------------------------------------------------------


def ssh_brute_force() -> Iterator[str]:
    """Twelve failures against one account from one address, then a success."""
    for index in range(12):
        yield _sshd(
            START + timedelta(seconds=index * 4),
            host="bastion-01",
            account="root",
            source_ip="203.0.113.7",
            ok=False,
        )
    yield _sshd(
        START + timedelta(seconds=60),
        host="bastion-01",
        account="root",
        source_ip="203.0.113.7",
        ok=True,
    )


def ssh_benign() -> Iterator[str]:
    """Ordinary logins, including two typos -- the shape a threshold must tolerate."""
    for index, (account, ok) in enumerate(
        [
            ("alice", True),
            ("bob", False),
            ("bob", True),
            ("carol", True),
            ("dave", False),
            ("dave", True),
            ("alice", True),
        ]
    ):
        yield _sshd(
            START + timedelta(seconds=index * 30),
            host="bastion-01",
            account=account,
            source_ip=f"198.51.100.{20 + index}",
            ok=ok,
        )


def credential_stuffing() -> Iterator[str]:
    """Twenty accounts, two tries each, from one address: breadth, not depth."""
    for index in range(20):
        account = f"user{index:03d}"
        for attempt in range(2):
            yield _nginx_json(
                START + timedelta(seconds=index * 6 + attempt * 2),
                source_ip="203.0.113.66",
                method="POST",
                path="/login",
                status=401,
                body=f"username={account}&password=Autumn2026",
            )


def credential_stuffing_benign() -> Iterator[str]:
    """A busy morning: many people logging in, each succeeding after at most one typo."""
    for index in range(20):
        account = f"user{index:03d}"
        if index % 4 == 0:
            yield _nginx_json(
                START + timedelta(seconds=index * 20),
                source_ip=f"198.51.100.{50 + index}",
                method="POST",
                path="/login",
                status=401,
                body=f"username={account}&password=typo",
            )
        yield _nginx_json(
            START + timedelta(seconds=index * 20 + 5),
            source_ip=f"198.51.100.{50 + index}",
            method="POST",
            path="/login",
            status=302,
            body=f"username={account}&password=correct-horse",
        )


def sql_injection() -> Iterator[str]:
    """Three payload classes, each on a real endpoint, plus one that was blocked."""
    payloads = [
        ("/products?id=1%27%20OR%20%271%27%3D%271", 200),
        ("/products?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users", 200),
        ("/search?q=%27%3B%20DROP%20TABLE%20orders%3B--", 500),
        ("/products?id=1%27%20AND%20SLEEP%285%29--", 403),
    ]
    for index, (path, status) in enumerate(payloads):
        yield _combined(
            START + timedelta(seconds=index * 10),
            source_ip="203.0.113.90",
            account=None,
            method="GET",
            path=path,
            status=status,
        )


def sql_injection_benign() -> Iterator[str]:
    """Searches that look like injection and are not: an apostrophe, the word select, a union."""
    for index, path in enumerate(
        [
            "/search?q=O%27Brien",
            "/search?q=select%20a%20plan",
            "/search?q=union%20square%20hotel",
            "/search?q=5%20%3E%203",
            "/products?id=42",
        ]
    ):
        yield _combined(
            START + timedelta(seconds=index * 8),
            source_ip=f"198.51.100.{80 + index}",
            account=None,
            method="GET",
            path=path,
            status=200,
        )


def idor_enumeration() -> Iterator[str]:
    """A matured account, then the same account walking twelve consecutive object ids."""
    scatter = [1004, 1011, 1000, 1017, 1008, 1019, 1002, 1013, 1006, 1015]
    for index in range(55):
        yield _combined(
            START + timedelta(seconds=index * 60),
            source_ip="198.51.100.40",
            account="mallory",
            method="GET",
            path=f"/api/orders/{scatter[index % len(scatter)]}",
            status=200,
        )
    later = START + timedelta(seconds=55 * 60 + 1800)
    for index in range(12):
        yield _combined(
            later + timedelta(seconds=index),
            source_ip="198.51.100.40",
            account="mallory",
            method="GET",
            path=f"/api/orders/{8001 + index}",
            status=200,
        )


def idor_benign() -> Iterator[str]:
    """The same warm-up, then the three cases most easily mistaken for enumeration."""
    scatter = [1004, 1011, 1000, 1017, 1008, 1019, 1002, 1013, 1006, 1015]
    for index in range(55):
        yield _combined(
            START + timedelta(seconds=index * 60),
            source_ip="198.51.100.20",
            account="alice",
            method="GET",
            path=f"/api/orders/{scatter[index % len(scatter)]}",
            status=200,
        )
    later = START + timedelta(seconds=55 * 60 + 1800)
    for offset, path in enumerate(
        ["/api/orders/1005", "/api/orders/1006", "/api/orders/1007", "/api/invoices/1010"]
    ):
        yield _combined(
            later + timedelta(seconds=offset * 5),
            source_ip="198.51.100.20",
            account="alice",
            method="GET",
            path=path,
            status=200,
        )


#: Every corpus this script can write. The pairing is the point, so both halves are named here.
CORPORA: dict[str, tuple[Generator, str]] = {
    "ssh_brute_force": (ssh_brute_force, "network_ssh_brute_force_sshd.log"),
    "ssh_benign": (ssh_benign, "network_ssh_benign_sshd.log"),
    "credential_stuffing": (credential_stuffing, "web_credential_stuffing_access.log"),
    "credential_stuffing_benign": (credential_stuffing_benign, "web_login_benign_access.log"),
    "sql_injection": (sql_injection, "web_sql_injection_combined.log"),
    "sql_injection_benign": (sql_injection_benign, "web_search_benign_combined.log"),
    "idor_enumeration": (idor_enumeration, "web_idor_enumeration_combined.log"),
    "idor_benign": (idor_benign, "web_idor_benign_access_combined.log"),
}


def write_corpus(name: str, out_dir: Path) -> Path:
    """Write one corpus and return the path it landed at."""
    generator, filename = CORPORA[name]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    path.write_text("\n".join(generator()) + "\n", encoding="utf-8")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate reproducible sample logs for Talos.")
    parser.add_argument("--out", type=Path, default=Path("out/samples"), help="output directory")
    parser.add_argument(
        "--only", action="append", choices=sorted(CORPORA), help="write just this corpus"
    )
    parser.add_argument("--list", action="store_true", help="show the corpora and their filenames")
    args = parser.parse_args(argv)

    if args.list:
        for name, (_, filename) in sorted(CORPORA.items()):
            print(f"  {name:28} {filename}")
        return 0

    for name in args.only or sorted(CORPORA):
        path = write_corpus(name, args.out)
        lines = sum(1 for _ in path.open(encoding="utf-8"))
        print(f"wrote {path} ({lines} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
