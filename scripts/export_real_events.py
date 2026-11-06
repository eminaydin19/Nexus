"""Build the script that exports anonymized log events from a server. It writes no file on the server.

python3 scripts/export_real_events.py <web-container>... | ssh root@server python3 - > events.jsonl

Addresses, usernames, non-scanner paths and user agents leave only as HMAC values under a key made for this run and never
stored. Query strings never leave: only whether a known exploit pattern matched.
"""
import sys
from pathlib import Path
from typing import List

BODY = r'''
import hashlib, hmac, ipaddress, json, secrets, subprocess, time
from urllib.parse import unquote_plus

KEY = secrets.token_bytes(32)


def h(value, size=12):
    return hmac.new(KEY, str(value).encode(), hashlib.sha256).hexdigest()[:size]


def public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def emit(**row):
    print(json.dumps(row, separators=(",", ":")))


SSH = (
    ("invalid", re.compile(r"Invalid user (\S*) from (\S+) port (\d+)")),
    ("closed", re.compile(r"Connection closed by authenticating user (\S*) (\S+) port (\d+) \[preauth\]")),
    ("failed", re.compile(r"Failed \S+ for (?:invalid user )?(\S*) from (\S+) port (\d+)")),
    ("ok", re.compile(r"Accepted \S+ for (\S*) from (\S+) port (\d+)")),
)
journal = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "short-unix"],
                         capture_output=True, text=True, errors="replace").stdout
for line in journal.splitlines():
    parts = line.split(" ", 1)
    if len(parts) != 2 or "sshd" not in parts[1]:
        continue
    for kind, pattern in SSH:
        m = pattern.search(parts[1])
        if m:
            if public(m.group(2)):
                emit(src="ssh", t=float(parts[0]), kind=kind, ip=h(m.group(2)), user=h(m.group(1), 8), port=int(m.group(3)))
            break

WEB = re.compile(r'^\S+ \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"(?: .*)? "([^"]*)"$')
STATIC = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".map")
for container in CONTAINERS:
    logs = subprocess.run(["docker", "logs", container], capture_output=True, text=True, errors="replace")
    for line in (logs.stdout + logs.stderr).splitlines():
        m = WEB.match(line)
        if not m:
            continue
        client = m.group(6).split(",")[0].strip()
        if not public(client):
            continue
        try:
            ts = time.mktime(time.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z"))
        except ValueError:
            continue
        uri = m.group(3)
        path = uri.partition("?")[0]
        lowered = path.lower()
        safe = lowered if lowered in PROBES else "/p/" + h(path, 8) + next((e for e in STATIC if lowered.endswith(e)), "")
        text = unquote_plus(unquote_plus(uri))
        ua = m.group(5)
        emit(src="web", t=ts, ip=h(client), site=container, method=m.group(2)[:8], path=safe, status=int(m.group(4)),
             exploit=any(p.search(text) for p in EXPLOITS), ua="-" if ua in ("", "-") else ("Mozilla/5.0 (" if ua.startswith("Mozilla/5.0 (") else "") + h(ua, 8))

jail = {}
for name in ("maxretry", "findtime", "bantime"):
    jail[name] = subprocess.run(["fail2ban-client", "get", "sshd", name], capture_output=True, text=True).stdout.strip()
emit(src="meta", jail=jail)
BAN = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ .*\[sshd\] Ban (\S+)")
for name in ("/var/log/fail2ban.log", "/var/log/fail2ban.log.1"):
    try:
        for line in open(name, errors="replace"):
            m = BAN.match(line)
            if m:
                emit(src="ban", t=time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")), ip=h(m.group(2)))
    except OSError:
        pass
'''


def _lines(name: str) -> list:
    data = Path(__file__).resolve().parent.parent / "nexus_agent" / "data"
    return [x.strip() for x in (data / name).read_text().splitlines() if x.strip() and not x.startswith("#")]


def build(containers: List[str]) -> str:
    probes = sorted(p.lower() for p in _lines("probe_paths.txt"))
    return "import re\nPROBES = frozenset(%r)\nEXPLOITS = [re.compile(p, re.I) for p in %r]\nCONTAINERS = %r\n%s" % (
        probes, _lines("exploit_patterns.txt"), containers, BODY)


if __name__ == "__main__":
    print(build(sys.argv[1:]))
