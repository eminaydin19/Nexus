from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from bisect import bisect_right
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .parsers import normalize_ip

log = logging.getLogger("nexus_agent.protect")

MAX_TRUST_IPS = 100000
MAX_SSH_IPS = 10000
MAX_BOT_CACHE = 10000
TRUST_WINDOW = 3600
TRUST_REQUESTS = 20
TRUST_MULTIPLIER = 3
SSH_OK_TTL = 86400
BOT_TTL = 3600
BOT_FAIL_TTL = 60
DNS_TIMEOUT = 2.0
FETCH_TIMEOUT = 10
MAX_FETCH_BYTES = 10 * 1024 * 1024
MIN_RANGES = 5

_BOT_TOKENS = ("googlebot", "bingbot")
_BOT_SUFFIXES = (".googlebot.com", ".google.com", ".search.msn.com")

# Not ipaddress.is_private: it also matches the TEST-NET documentation ranges, which must stay blockable.
_STATIC = (
    ("loopback", ("127.0.0.0/8", "::1/128")),
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "0.0.0.0/8", "::/128")),
    ("link-local", ("169.254.0.0/16", "fe80::/10")),
    ("cgnat", ("100.64.0.0/10",)),
    ("multicast", ("224.0.0.0/4", "ff00::/8")),
)

_CDN_SOURCES = {
    "cloudflare": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
    "fastly": "https://api.fastly.com/public-ip-list",
    "cloudfront": "https://ip-ranges.amazonaws.com/ip-ranges.json",
}
_CDN_FILE = Path(__file__).parent / "data" / "cdn_ranges.json"


class _NetIndex:
    """Sorted, merged integer ranges per IP version, so a lookup is one bisect instead of a scan."""

    def __init__(self, items=()):
        by_ver = {4: [], 6: []}  # type: Dict[int, list]
        for net, label in items:
            by_ver[net.version].append((int(net.network_address), int(net.broadcast_address), label))
        self._idx = {}
        for ver, spans in by_ver.items():
            spans.sort()
            merged = []  # type: list
            for s, e, label in spans:
                if merged and s <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e, label])
            self._idx[ver] = ([m[0] for m in merged], merged)

    def find(self, ip: str) -> Optional[str]:
        addr = ipaddress.ip_address(ip)
        starts, merged = self._idx[addr.version]
        i = bisect_right(starts, int(addr)) - 1
        if i >= 0 and int(addr) <= merged[i][1]:
            return merged[i][2]
        return None


_STATIC_INDEX = _NetIndex((ipaddress.ip_network(c), why) for why, nets in _STATIC for c in nets)


def _parse_nets(items: Iterable, what: str) -> list:
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item.strip(), strict=False))
        except (ValueError, AttributeError):
            log.warning("ignoring invalid %s entry: %r", what, item)
    return nets


def _ip_set(value) -> set:
    if value is None:
        return set()
    if isinstance(value, str):
        value = [value]
    out = set()
    for v in value:
        n = normalize_ip(v)
        if n is None:
            log.warning("ignoring invalid protected address: %r", v)
        else:
            out.add(n)
    return out


def _cdn_index(ranges: Dict[str, List[str]]) -> _NetIndex:
    return _NetIndex((n, name) for name, cidrs in ranges.items() for n in _parse_nets(cidrs, "cdn range"))


class Protector:
    def __init__(self, allowlist=(), central_ip=None, gateway=None, resolvers=(), clock=time.time, resolver=socket):
        self._clock = clock
        self._resolver = resolver
        self._lock = threading.Lock()
        self._central = _ip_set(central_ip)
        self._gateway = _ip_set(gateway)
        self._resolvers = _ip_set(resolvers)
        self._allow = _NetIndex()
        self.set_allowlist(allowlist)
        self._active_ssh = set()  # type: set
        self._ssh_ok = {}  # type: Dict[str, float]
        # ip -> [window_start, ok_count, login_until, probe_until]; counters, not per-request lists.
        self._trust = OrderedDict()  # type: OrderedDict
        self._bots = {}  # type: Dict[str, tuple]
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="nexus-dns")
        self._cdn_ranges = {}  # type: Dict[str, List[str]]
        try:
            self._cdn_ranges = json.loads(_CDN_FILE.read_text())["ranges"]
        except (OSError, ValueError, KeyError):
            log.exception("cannot load bundled CDN ranges")
        self._cdn = _cdn_index(self._cdn_ranges)

    def set_allowlist(self, items) -> None:
        self._allow = _NetIndex((n, "allowlist") for n in _parse_nets(items or (), "allowlist"))

    def set_active_ssh(self, ips) -> None:
        self._active_ssh = {n for n in (normalize_ip(i) for i in ips) if n}

    def note_ssh_ok(self, ip: str) -> None:
        ip = normalize_ip(ip)
        if ip is None:
            return
        now = self._clock()
        with self._lock:
            if len(self._ssh_ok) >= MAX_SSH_IPS:
                self._ssh_ok = {k: v for k, v in self._ssh_ok.items() if v > now}
            if len(self._ssh_ok) < MAX_SSH_IPS:
                self._ssh_ok[ip] = now + SSH_OK_TTL

    def export_ssh_ok(self) -> List[list]:
        now = self._clock()
        with self._lock:
            return sorted([ip, exp] for ip, exp in self._ssh_ok.items() if exp > now)

    def import_ssh_ok(self, items) -> None:
        now = self._clock()
        with self._lock:
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, list) or len(item) != 2:
                    continue
                ip, exp = normalize_ip(item[0]), item[1]
                if (ip is None or isinstance(exp, bool) or not isinstance(exp, (int, float))
                        or not now < exp <= now + SSH_OK_TTL or len(self._ssh_ok) >= MAX_SSH_IPS):
                    continue
                self._ssh_ok[ip] = float(exp)

    def update_network(self, central_ip=None, gateway=None, resolvers=None) -> None:
        # An empty answer is a failed lookup, and forgetting the old address would make it blockable.
        if central_ip:
            self._central = _ip_set(central_ip)
        if gateway:
            self._gateway = _ip_set(gateway)
        if resolvers:
            self._resolvers = _ip_set(resolvers)

    def is_cdn(self, ip: str) -> bool:
        ip = normalize_ip(ip)
        return ip is not None and self._cdn.find(ip) is not None

    def reason(self, ip: str) -> Optional[str]:
        ip = normalize_ip(ip)
        if ip is None:
            return "invalid"
        why = _STATIC_INDEX.find(ip)
        if why:
            return why
        if self._allow.find(ip):
            return "allowlist"
        if ip in self._central:
            return "central"
        if ip in self._gateway:
            return "gateway"
        if ip in self._resolvers:
            return "resolver"
        if ip in self._active_ssh:
            return "active-ssh"
        if self._ssh_ok.get(ip, 0) > self._clock():
            return "recent-ssh"
        if self._cdn.find(ip):
            return "cdn"
        return None

    def _entry(self, ip: str, now: float) -> list:
        e = self._trust.get(ip)
        if e is None:
            e = self._trust[ip] = [now, 0, 0.0, 0.0]
            if len(self._trust) > MAX_TRUST_IPS:
                self._trust.popitem(last=False)
        else:
            self._trust.move_to_end(ip)
        return e

    def note_web(self, event) -> None:
        ip = normalize_ip(event.ip)
        if ip is None or event.status is None or not 200 <= event.status < 400:
            return
        now = self._clock()
        with self._lock:
            e = self._entry(ip, now)
            if now - e[0] >= TRUST_WINDOW:
                e[0], e[1] = now, 0
            e[1] += 1

    def note_login_ok(self, ip: str) -> None:
        ip = normalize_ip(ip)
        if ip is None:
            return
        now = self._clock()
        with self._lock:
            self._entry(ip, now)[2] = now + TRUST_WINDOW

    def note_probe(self, ip: str) -> None:
        ip = normalize_ip(ip)
        if ip is None:
            return
        now = self._clock()
        with self._lock:
            e = self._entry(ip, now)
            e[0], e[1], e[2], e[3] = now, 0, 0.0, now + TRUST_WINDOW

    def threshold_multiplier(self, ip: str) -> int:
        ip = normalize_ip(ip)
        e = self._trust.get(ip) if ip else None
        if e is None:
            return 1
        now = self._clock()
        if e[3] > now:
            return 1  # a probe hit voids trust for an hour, whatever else the IP does meanwhile
        if e[2] > now:
            return TRUST_MULTIPLIER
        if e[3] <= now and now - e[0] < TRUST_WINDOW and e[1] >= TRUST_REQUESTS:
            return TRUST_MULTIPLIER
        return 1

    def verify_bot(self, ip: str, user_agent) -> bool:
        ip = normalize_ip(ip)
        ua = (user_agent or "").lower() if isinstance(user_agent, str) else ""
        if ip is None or not any(t in ua for t in _BOT_TOKENS):
            return False
        now = self._clock()
        with self._lock:
            hit = self._bots.get(ip)
        if hit and hit[0] > now:
            return hit[1]
        try:
            ok = self._pool.submit(self._check_bot, ip).result(timeout=DNS_TIMEOUT)
            ttl = BOT_TTL
        except Exception:
            ok, ttl = False, BOT_FAIL_TTL
        with self._lock:
            if len(self._bots) >= MAX_BOT_CACHE:
                self._bots = {k: v for k, v in self._bots.items() if v[0] > now}
            if len(self._bots) < MAX_BOT_CACHE:
                self._bots[ip] = (now + ttl, ok)
        return ok

    def _check_bot(self, ip: str) -> bool:
        try:
            host = self._resolver.gethostbyaddr(ip)[0].lower().rstrip(".")
            if not host.endswith(_BOT_SUFFIXES):
                return False
            infos = self._resolver.getaddrinfo(host, None)
        except OSError:
            return False
        return ip in {normalize_ip(i[4][0]) for i in infos}

    def refresh_cdn_ranges(self) -> bool:
        try:
            import requests

            def get(name):
                r = requests.get(_CDN_SOURCES[name], timeout=FETCH_TIMEOUT)
                r.raise_for_status()
                if len(r.content) > MAX_FETCH_BYTES:
                    raise ValueError("response too large")
                return r

            fastly = get("fastly").json()
            aws = get("cloudfront").json()
            new = {
                "cloudflare": get("cloudflare").text.split() + get("cloudflare_v6").text.split(),
                "fastly": list(fastly["addresses"]) + list(fastly["ipv6_addresses"]),
                "cloudfront": [p["ip_prefix"] for p in aws["prefixes"] if p["service"] == "CLOUDFRONT"]
                + [p["ipv6_prefix"] for p in aws["ipv6_prefixes"] if p["service"] == "CLOUDFRONT"],
            }
            for name, cidrs in new.items():
                for c in cidrs:
                    ipaddress.ip_network(c)
                if len(cidrs) < MIN_RANGES:
                    raise ValueError("%s list too small: %d" % (name, len(cidrs)))
        except Exception:
            log.warning("CDN range refresh failed, keeping previous list", exc_info=True)
            return False
        self._cdn_ranges, self._cdn = new, _cdn_index(new)
        return True
