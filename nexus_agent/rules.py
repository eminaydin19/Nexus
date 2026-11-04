from __future__ import annotations

import itertools
import logging
import os
import re
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import unquote_plus

from .parsers import LogEvent

log = logging.getLogger("nexus_agent.rules")

WINDOW = 300
SCAN_WINDOW = 60
SWEEP_EVERY = 60
OFFENSE_MEMORY = 7 * 86400
MAX_TTL = 86400
FLOOD_COOLDOWN = 600
FLOOD_RATIO = 5
FLOOD_MIN_TOTAL = 1000
FLOOD_ALPHA = 0.05
MIN_WINDOW_EVENTS = 1000
EVIDENCE_LINES = 3
EVIDENCE_CHARS = 500
MAX_DECODES = 2

# rule -> (action, base ttl in seconds)
_RULES = {
    "ssh_bruteforce": ("block_port", 3600),
    "web_login_bruteforce": ("block_port", 900),
    "web_probe": ("block_port", 1800),
    "web_exploit": ("block_port", 3600),
    "port_scan": ("block_all", 900),
    "conn_flood": ("rate_limit", 600),
}
_WEB_RULES = frozenset(("web_login_bruteforce", "web_probe", "web_exploit"))

_DATA = Path(__file__).parent / "data"


def _load_lines(name: str) -> List[str]:
    out = []
    for line in (_DATA / name).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


_PROBE_PATHS = frozenset(p.lower() for p in _load_lines("probe_paths.txt"))
_EXPLOIT = tuple(re.compile(p, re.I) for p in _load_lines("exploit_patterns.txt"))


def _decode(s: str) -> str:
    # Bounded, because a request can be encoded any number of times; errors="replace" keeps invalid UTF-8 from raising.
    for _ in range(MAX_DECODES):
        d = unquote_plus(s, errors="replace")
        if d == s:
            break
        s = d
    return s


def exploit_hits(path_and_query: str) -> Tuple[int, ...]:
    text = _decode(path_and_query)
    return tuple(i for i, pat in enumerate(_EXPLOIT) if pat.search(text))


@dataclass(frozen=True)
class Decision:
    rule: str
    ip: str
    action: str  # "block_port" | "block_all" | "rate_limit" | "alert"
    ports: Tuple[int, ...]
    ttl: int
    evidence: str


@dataclass
class RuleConfig:
    ssh_fail_threshold: int = 10
    web_login_threshold: int = 30
    probe_threshold: int = 10
    exploit_threshold: int = 3
    scan_ports: int = 20
    max_conn_per_ip: int = 200
    syn_recv_alert: int = 500
    max_tracked_ips: int = 100000
    login_paths: Tuple[str, ...] = ("/login", "/wp-login.php", "/admin", "/api/login")
    ssh_ports: Tuple[int, ...] = (22,)
    web_ports: Tuple[int, ...] = (80, 443)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "RuleConfig":
        env = os.environ if env is None else env
        cfg = cls()
        for f in fields(cls):
            name = "NEXUS_RULE_" + f.name.upper()
            raw = env.get(name)
            if raw is None:
                continue
            default = getattr(cfg, f.name)
            try:
                if isinstance(default, tuple):
                    kind = type(default[0])
                    value = tuple(kind(x.strip()) for x in raw.split(",") if x.strip())
                    if not value:
                        raise ValueError("empty list")
                    if kind is int and any(not 0 < v < 65536 for v in value):
                        raise ValueError("port out of range")
                    if kind is str and any(not v.startswith("/") for v in value):
                        raise ValueError("path must start with /")
                else:
                    value = int(raw)
                    if value <= 0:
                        raise ValueError("must be positive")
            except ValueError as exc:
                log.warning("ignoring invalid %s=%r (%s); keeping %r", name, raw, exc, default)
                continue
            setattr(cfg, f.name, value)
        return cfg


class RuleEngine:
    def __init__(self, cfg: RuleConfig, protector, clock=time.time):
        self._cfg = cfg
        self._p = protector
        self._clock = clock
        self._lock = threading.RLock()
        self._login = frozenset(p.rstrip("/") for p in cfg.login_paths)
        self._behind_cdn = False
        self._seq = itertools.count()
        # (rule, ip) -> deque of (ts, keys, raw); OrderedDict order is least-recently-seen first.
        self._win = OrderedDict()  # type: OrderedDict
        self._active = OrderedDict()  # type: OrderedDict  # (rule, ip) -> expiry of its last Decision
        self._offense = OrderedDict()  # type: OrderedDict  # (rule, ip) -> [count, last_ts]
        self._conn_suppressed = set()  # type: set
        self._last_sweep = None  # type: Optional[float]
        self._avg = None  # type: Optional[float]
        self._last_flood = None  # type: Optional[float]
        self.suppressed = Counter()  # type: Counter

    def set_behind_cdn(self, value: bool) -> None:
        self._behind_cdn = bool(value)

    def forget(self, ip: str) -> None:
        # Offense history is kept on purpose: a manually unblocked repeat offender still earns a longer next ttl.
        with self._lock:
            for od in (self._win, self._active):
                for key in [k for k in od if k[1] == ip]:
                    del od[key]
            self._conn_suppressed.discard(ip)

    def feed(self, event: LogEvent) -> List[Decision]:
        with self._lock:
            self._sweep(self._clock())
            if event.kind == "ssh_ok":
                self._p.note_ssh_ok(event.ip)
                return []
            if event.kind == "ssh_fail":
                mult = self._p.threshold_multiplier(event.ip)
                return self._hit("ssh_bruteforce", event.ip, (next(self._seq),), event.raw,
                                 self._cfg.ssh_fail_threshold * mult)
            if event.kind == "web":
                return self._web(event)
            return []

    def feed_scan(self, ip: str, port: int) -> List[Decision]:
        with self._lock:
            self._sweep(self._clock())
            return self._hit("port_scan", ip, (port,), "port %d" % port, self._cfg.scan_ports)

    def feed_connections(self, per_ip: Dict[str, int], syn_recv: int) -> List[Decision]:
        with self._lock:
            now = self._clock()
            self._sweep(now)
            out = []  # type: List[Decision]
            over_protected = set()
            for ip, n in per_ip.items():
                if n <= self._cfg.max_conn_per_ip or n <= self._cfg.max_conn_per_ip * self._p.threshold_multiplier(ip):
                    continue
                why = self._p.reason(ip)
                if why:
                    over_protected.add(ip)
                    if ip not in self._conn_suppressed:
                        self.suppressed[why] += 1
                    continue
                out += self._fire("conn_flood", ip, now, "%d concurrent connections" % n, None)
            self._conn_suppressed = over_protected
            return out + self._flood(now, sum(per_ip.values()), syn_recv)

    def _flood(self, now: float, total: int, syn_recv: int) -> List[Decision]:
        # Compare against the old average first: updating it first would let the spike dilute itself.
        avg = self._avg
        spike = avg is not None and total > FLOOD_RATIO * avg and total > FLOOD_MIN_TOTAL
        self._avg = float(total) if avg is None else avg + FLOOD_ALPHA * (total - avg)
        if not (syn_recv > self._cfg.syn_recv_alert or spike):
            return []
        if self._last_flood is not None and now - self._last_flood < FLOOD_COOLDOWN:
            return []
        self._last_flood = now
        ev = "syn_recv=%d connections=%d average=%.0f" % (syn_recv, total, avg or 0)
        return [Decision("distributed_flood", "0.0.0.0", "alert", (), 0, ev)]

    def _web(self, ev: LogEvent) -> List[Decision]:
        p = self._p
        p.note_web(ev)
        if ev.path is None or ev.status is None:
            return []
        mult = p.threshold_multiplier(ev.ip)
        path, _, _query = ev.path.partition("?")
        out = []  # type: List[Decision]
        if ev.method == "POST" and path.rstrip("/") in self._login:
            if ev.status in (401, 403):
                out += self._hit("web_login_bruteforce", ev.ip, (next(self._seq),), ev.raw,
                                 self._cfg.web_login_threshold * mult, ev.user_agent)
            elif 200 <= ev.status < 400:
                p.note_login_ok(ev.ip)
        lowered = path.lower()
        if lowered in _PROBE_PATHS and 400 <= ev.status < 500:
            p.note_probe(ev.ip)
            out += self._hit("web_probe", ev.ip, (lowered,), ev.raw, self._cfg.probe_threshold * mult, ev.user_agent)
        hits = exploit_hits(ev.path)
        if hits:
            out += self._hit("web_exploit", ev.ip, hits, ev.raw, self._cfg.exploit_threshold * mult, ev.user_agent)
        return out

    def _hit(self, rule: str, ip: str, keys: tuple, raw: str, threshold: int, ua: Optional[str] = None) -> List[Decision]:
        now = self._clock()
        span = SCAN_WINDOW if rule == "port_scan" else WINDOW
        wk = (rule, ip)
        dq = self._win.get(wk)
        if dq is None:
            dq = self._win[wk] = deque(maxlen=max(MIN_WINDOW_EVENTS, 4 * threshold))
            while len(self._win) > self._cfg.max_tracked_ips:
                self._win.popitem(last=False)
        else:
            self._win.move_to_end(wk)
        while dq and dq[0][0] <= now - span:
            dq.popleft()
        dq.append((now, keys, raw))
        if len(set().union(*(e[1] for e in dq))) < threshold:
            return []
        evidence = "\n".join(e[2] for e in list(dq)[-EVIDENCE_LINES:])[:EVIDENCE_CHARS]
        del self._win[wk]
        return self._fire(rule, ip, now, evidence, ua)

    def _fire(self, rule: str, ip: str, now: float, evidence: str, ua: Optional[str]) -> List[Decision]:
        key = (rule, ip)
        if self._active.get(key, 0) > now:
            return []
        web = rule in _WEB_RULES
        if web and (self._behind_cdn or self._p.is_cdn(ip)):
            return [Decision(rule, ip, "alert", (), 0, evidence)]
        why = self._p.reason(ip)
        if why:
            self.suppressed[why] += 1
            return []
        if web and self._p.verify_bot(ip, ua):
            self.suppressed["verified-bot"] += 1
            return []
        off = self._offense.get(key)
        repeats = off[0] if off and now - off[1] < OFFENSE_MEMORY else 0
        action, base = _RULES[rule]
        ttl = min(base * 2 ** min(repeats, 10), MAX_TTL)
        self._remember(self._offense, key, [repeats + 1, now])
        self._remember(self._active, key, now + ttl)
        ports = self._cfg.ssh_ports if rule == "ssh_bruteforce" else self._cfg.web_ports if web else ()
        return [Decision(rule, ip, action, tuple(ports), ttl, evidence)]

    def _remember(self, od: OrderedDict, key, value) -> None:
        od[key] = value
        od.move_to_end(key)
        while len(od) > self._cfg.max_tracked_ips:
            od.popitem(last=False)

    def _sweep(self, now: float) -> None:
        if self._last_sweep is not None and now - self._last_sweep < SWEEP_EVERY:
            return
        self._last_sweep = now
        for wk in list(self._win):
            dq = self._win[wk]
            span = SCAN_WINDOW if wk[0] == "port_scan" else WINDOW
            while dq and dq[0][0] <= now - span:
                dq.popleft()
            if not dq:
                del self._win[wk]
        for key in [k for k, exp in self._active.items() if exp <= now]:
            del self._active[key]
        for key in [k for k, v in self._offense.items() if now - v[1] >= OFFENSE_MEMORY]:
            del self._offense[key]
