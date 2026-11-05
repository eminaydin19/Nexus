from __future__ import annotations

import calendar
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Optional, Tuple

MAX_LINE = 16 * 1024
MAX_RAW = 300

# The sshd header is anchored at line start so text inside a username or URL can never
# pose as a header; a line from another program fails here.
_SSH_HEADER = (
    r"(?:(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ )?"
    r"sshd(?:-session)?\[\d+\]: "
)
# Publickey lines end with the key type and fingerprint, which have a fixed shape.
_SSH_TAIL = r"(?: ssh2(?:: [A-Za-z0-9-]+ SHA256:\S+)?)?\Z"
_SSH_FAIL = (
    re.compile(_SSH_HEADER + r"Failed \S+ for .* from (\S+) port (\d{1,5})" + _SSH_TAIL),
    re.compile(_SSH_HEADER + r"Invalid user .* from (\S+) port (\d{1,5})(?: \[preauth\])?\Z"),
    re.compile(_SSH_HEADER + r"Connection closed by authenticating user .* (\S+) port (\d{1,5}) \[preauth\]\Z"),
)
_SSH_OK = re.compile(
    _SSH_HEADER
    + r"Accepted (?:password|publickey|keyboard-interactive/pam) for .* from (\S+) port (\d{1,5})"
    + _SSH_TAIL
)
# Classify on the text right after the header: a username may contain "Accepted password"
# or "Failed password", so searching the whole line would let it flip the kind.
_SSH_CLASSIFY = re.compile(_SSH_HEADER + r"(Failed |Invalid user |Connection closed by authenticating user |Accepted )")

_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_WEB = re.compile(
    r"(\S+) \S+ \S+ \[[^\]\n]*\] " + _QUOTED + r" (\d{3}) (?:\d+|-)"
    r"(?: " + _QUOTED + " " + _QUOTED + r")?\Z"
)
_REQUEST = re.compile(r"([A-Z]+) (\S+)(?: HTTP/\d(?:\.\d)?)?\Z")

# Anchored like the sshd header: a local `logger` line carries its own tag instead of "kernel:", so it cannot pose as a scan.
_SCAN_HEAD = re.compile(
    r"(?:(?:(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ )?"
    r"kernel: (?:\[ *\d+\.\d+\] )?)?nexus-scan "
)
_SCAN_SRC = re.compile(r" SRC=(\S+)")
_SCAN_DPT = re.compile(r" DPT=(\d{1,5})(?: |\Z)")

MAX_LINE_AGE = 600
_MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}
_SYSLOG_TIME = re.compile(r"([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) ")
_ISO_TIME = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)? ")
_WEB_TIME = re.compile(r"\S+ \S+ \S+ \[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-]\d{4})\]")


@dataclass(frozen=True)
class LogEvent:
    kind: str  # "ssh_fail" | "ssh_ok" | "web"
    ip: str
    ts: float
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    raw: str = ""
    user_agent: Optional[str] = None  # raw is truncated, so the agent string is kept separately
    src_port: Optional[int] = None  # ssh: tells which lines belong to the same connection
    password_try: bool = False  # ssh: a "Failed ..." line, one real try among several on a connection


def normalize_ip(s: str) -> Optional[str]:
    if not isinstance(s, str) or len(s) > 64:
        return None
    s = s.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def _prepare(line):
    if not isinstance(line, str) or len(line) > MAX_LINE:
        return None
    return line.rstrip("\r\n")


def parse_ssh_line(line: str, now: float) -> Optional[LogEvent]:
    line = _prepare(line)
    if line is None:
        return None
    head = _SSH_CLASSIFY.match(line)
    if head is None:
        return None
    if head.group(1) == "Accepted ":
        kind, patterns = "ssh_ok", (_SSH_OK,)
    else:
        kind, patterns = "ssh_fail", _SSH_FAIL
    for pat in patterns:
        m = pat.match(line)
        if m:
            ip = normalize_ip(m.group(1))
            if ip is None:
                return None
            return LogEvent(kind, ip, now, raw=line[:MAX_RAW], src_port=int(m.group(2)),
                            password_try=head.group(1) == "Failed ")
    return None


def parse_web_line(line: str, now: float) -> Optional[LogEvent]:
    line = _prepare(line)
    if line is None:
        return None
    m = _WEB.match(line)
    if m is None:
        return None
    ip = normalize_ip(m.group(1))
    if ip is None:
        return None
    req = _REQUEST.match(m.group(2))
    method, path = (req.group(1), req.group(2)) if req else (None, None)
    ua = m.group(5)
    return LogEvent("web", ip, now, method, path, int(m.group(3)), line[:MAX_RAW], None if ua in (None, "-") else ua)


def parse_scan_line(line: str) -> Optional[Tuple[str, int]]:
    line = _prepare(line)
    if line is None:
        return None
    head = _SCAN_HEAD.match(line)
    if head is None:
        return None
    src, dpt = _SCAN_SRC.search(line, head.end() - 1), _SCAN_DPT.search(line, head.end() - 1)
    if src is None or dpt is None:
        return None
    ip, port = normalize_ip(src.group(1)), int(dpt.group(1))
    if ip is None or not 1 <= port <= 65535:
        return None
    return ip, port


def _utc(year, month, day, hh, mm, ss, offset: str) -> float:
    secs = calendar.timegm((year, month, day, hh, mm, ss))
    if offset and offset != "Z":
        digits = offset[1:].replace(":", "")
        delta = int(digits[:2]) * 3600 + int(digits[2:]) * 60
        secs += -delta if offset[0] == "+" else delta
    return float(secs)


def _ssh_line_time(line: str, now: float) -> Optional[float]:
    m = _ISO_TIME.match(line)
    if m:
        y, mo, d, hh, mi, ss = map(int, m.groups()[:6])
        if m.group(7):
            return _utc(y, mo, d, hh, mi, ss, m.group(7))
        return time.mktime((y, mo, d, hh, mi, ss, 0, 0, -1))
    m = _SYSLOG_TIME.match(line)
    if m:
        mo = _MONTHS[m.group(1)]
        d, hh, mi, ss = map(int, m.groups()[1:])
        year = time.localtime(now).tm_year
        ts = time.mktime((year, mo, d, hh, mi, ss, 0, 0, -1))
        # Syslog has no year, so a December line read in January would otherwise land in the future.
        return time.mktime((year - 1, mo, d, hh, mi, ss, 0, 0, -1)) if ts > now + 86400 else ts
    return None


def ssh_line_is_stale(line: str, now: float) -> bool:
    try:
        ts = _ssh_line_time(line, now)
    except (KeyError, ValueError, OverflowError):
        return False  # no parseable timestamp counts as now
    return ts is not None and now - ts > MAX_LINE_AGE


def web_line_is_stale(line: str, now: float) -> bool:
    m = _WEB_TIME.match(line)
    if m is None:
        return False
    try:
        ts = _utc(int(m.group(3)), _MONTHS[m.group(2)], int(m.group(1)), int(m.group(4)), int(m.group(5)),
                  int(m.group(6)), m.group(7))
    except (KeyError, ValueError, OverflowError):
        return False
    return now - ts > MAX_LINE_AGE
