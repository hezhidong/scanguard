"""Log parsers. Extract (ip, timestamp, request/message, status) tuples."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# nginx/apache combined log:
# 1.2.3.4 - - [29/Jul/2026:00:44:25 +0800] "GET /path HTTP/1.1" 200 123 ...
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3})'
)
WEB_TS = "%d/%b/%Y:%H:%M:%S %z"

# auth.log / secure: "Aug  5 11:00:00 host sshd[..]: Failed password for ... from 1.2.3.4"
AUTH_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) .*?(?:Failed password|Invalid user|authentication failure).*?'
    r'(?:from |rhost=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)


@dataclass
class LogEvent:
    ip: str
    ts: datetime
    message: str          # request line or full message
    status: Optional[int] = None


def parse_line(kind: str, line: str) -> Optional[LogEvent]:
    if kind in ("nginx", "apache"):
        return _parse_web(line)
    if kind == "auth":
        return _parse_auth(line)
    # generic: best-effort IP extraction, no timestamp
    return _parse_generic(line)


def _parse_web(line: str) -> Optional[LogEvent]:
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), WEB_TS)
    except ValueError:
        return None
    return LogEvent(
        ip=m.group("ip"),
        ts=ts,
        message=f"{m.group('method')} {m.group('path')}",
        status=int(m.group("status")),
    )


def _parse_auth(line: str) -> Optional[LogEvent]:
    m = AUTH_RE.search(line)
    if not m:
        return None
    # syslog has no year; assume current year
    year = datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return LogEvent(ip=m.group("ip"), ts=ts, message=line.strip())


_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


def _parse_generic(line: str) -> Optional[LogEvent]:
    m = _IP_RE.search(line)
    if not m:
        return None
    return LogEvent(ip=m.group(1), ts=datetime.now(), message=line.strip())
