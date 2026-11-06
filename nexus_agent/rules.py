from __future__ import annotations

import ipaddress
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

from .anomaly import Behavior
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
EXPLOIT_MIN_REQUESTS = 5
NEW_CONN_SUSTAINED_SAMPLES = 2
EVIDENCE_LINES = 3
EVIDENCE_CHARS = 500
MAX_DECODES = 2

_RULES = {
    "ssh_bruteforce": "block_port",
    "web_login_bruteforce": "block_port",
    "web_probe": "block_port",
    "web_exploit": "block_port",
    "port_scan": "block_all",
    "conn_flood": "rate_limit",
    "anomaly_ssh": "block_port",
    "anomaly_web": "block_port",
}
_WEB_RULES = frozenset(("web_login_bruteforce", "web_probe", "web_exploit", "anomaly_web"))
_SSH_USER = re.compile(r"(?:Invalid user|authenticating user|Failed \S+ for(?: invalid user)?) (\S*) ")

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


def _ident(ip: str) -> str:
    if ":" not in ip:
        return ip
    try:
        return str(ipaddress.ip_network(ip + "/64", strict=False))
    except ValueError:
        return ip


def _decode(s: str) -> str:
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
    action: str
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
    max_conn_per_ip: int = 1000
    max_new_conn_rate: int = 100
    syn_recv_alert: int = 500
    max_tracked_ips: int = 100000
    login_paths: Tuple[str, ...] = ("/login", "/wp-login.php", "/admin", "/api/login")
    ssh_ports: Tuple[int, ...] = (22,)
    web_ports: Tuple[int, ...] = (80, 443)
    ttl_ssh_bruteforce: int = 3600
    ttl_web_login_bruteforce: int = 900
    ttl_web_probe: int = 1800
    ttl_web_exploit: int = 3600
    ttl_port_scan: int = 900
    ttl_conn_flood: int = 600
    ttl_anomaly_ssh: int = 900
    ttl_anomaly_web: int = 900
    anomaly_block: int = 0
    anomaly_min_evidence: int = 3

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
                    if f.name.startswith("ttl_"):
                        value = min(value, MAX_TTL)
            except ValueError as exc:
                log.warning("ignoring invalid %s=%r (%s); keeping %r", name, raw, exc, default)
                continue
            setattr(cfg, f.name, value)
        return cfg


class RuleEngine:
    def __init__(self, cfg: RuleConfig, protector, clock=time.time, models: Optional[dict] = None):
        self._cfg = cfg
        self._models = models or {}
        self._behavior = Behavior(cfg.max_tracked_ips, clock)
        self._p = protector
        self._clock = clock
        self._lock = threading.RLock()
        self._login = frozenset(p.rstrip("/") for p in cfg.login_paths)
        self._behind_cdn = False
        self._seq = itertools.count()
        self._win = OrderedDict()  # type: OrderedDict
        self._active = OrderedDict()  # type: OrderedDict  # (rule, ip) -> expiry of its last Decision
        self._offense = OrderedDict()  # type: OrderedDict  # (rule, ip) -> [count, last_ts]
        self._conn_suppressed = set()  # type: set
        self._new_streak = {}  # type: Dict[str, int]
        self._bad = OrderedDict()  # type: OrderedDict  # key -> [last bad ts, last bad ts while trusted]
        self._last_sweep = None  # type: Optional[float]
        self._avg = None  # type: Optional[float]
        self._last_flood = None  # type: Optional[float]
        self.suppressed = Counter()  # type: Counter

    def set_behind_cdn(self, value: bool) -> None:
        self._behind_cdn = bool(value)

    def forget(self, ip: str) -> None:
        with self._lock:
            ident = _ident(ip)
            for od in (self._win, self._active, self._offense):
                for key in [k for k in od if k[1] == ident]:
                    del od[key]
            self._bad.pop(ident, None)
            self._conn_suppressed.discard(ident)
            self._behavior.forget(ident)

    def feed(self, event: LogEvent) -> List[Decision]:
        with self._lock:
            self._sweep(self._clock())
            if event.kind == "ssh_ok":
                self._p.note_ssh_ok(event.ip)
                return []
            if event.kind == "ssh_fail":
                self._mark_bad(event.ip)
                out = self._hit("ssh_bruteforce", event.ip, (self._ssh_key(event),), event.raw, self._cfg.ssh_fail_threshold,
                                tag=event.password_try)
                user = _SSH_USER.search(event.raw)
                self._behavior.note_ssh(_ident(event.ip), user.group(1) if user else None, "Invalid user" in event.raw,
                                        event.src_port, event.password_try)
                return out or self._anomaly("ssh", event.ip, 1, None)
            if event.kind == "web":
                out = self._web(event)
                if event.via_proxy:
                    return [Decision(d.rule, d.ip, "alert", (), 0, d.evidence) for d in out]
                return out
            return []

    def feed_scan(self, ip: str, port: int) -> List[Decision]:
        with self._lock:
            self._sweep(self._clock())
            return self._hit("port_scan", ip, (port,), "port %d" % port, self._cfg.scan_ports)

    def _ssh_key(self, event: LogEvent) -> tuple:
        if event.src_port is None:
            return (next(self._seq),)
        dq = self._win.get(("ssh_bruteforce", _ident(event.ip)), ())
        tries = sum(1 for e in dq if e[1][0][0] == event.src_port and e[3])
        return (event.src_port, tries + 1 if event.password_try else 1)

    def feed_connections(self, per_ip: Dict[str, int], syn_recv: int,
                         new_per_sec: Optional[Dict[str, float]] = None) -> List[Decision]:
        with self._lock:
            now = self._clock()
            self._sweep(now)
            out = []  # type: List[Decision]
            over_protected = set()
            over = {}  # type: Dict[str, str]
            for ip, n in per_ip.items():
                if n >= self._cfg.max_conn_per_ip * self._p.threshold_multiplier(ip):
                    over[ip] = "%d concurrent connections" % n
            streak = {}  # type: Dict[str, int]
            for ip, rate in (new_per_sec or {}).items():
                if rate >= self._cfg.max_new_conn_rate:
                    streak[ip] = self._new_streak.get(ip, 0) + 1
                    if streak[ip] >= NEW_CONN_SUSTAINED_SAMPLES:
                        over[ip] = "%d new connections per second" % rate
            self._new_streak = streak
            for ip, evidence in over.items():
                ident = _ident(ip)
                why = self._p.reason(ip)
                if why:
                    over_protected.add(ident)
                    if ident not in self._conn_suppressed:
                        self.suppressed[why] += 1
                    continue
                out += self._fire("conn_flood", ip, now, evidence, None)
            self._conn_suppressed = over_protected
            return out + self._flood(now, sum(per_ip.values()), syn_recv)

    def _flood(self, now: float, total: int, syn_recv: int) -> List[Decision]:
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
        out = self._web_rules(ev)
        path = ev.path.partition("?")[0]
        norm = path.rstrip("/")
        evidence = (path.lower() in _PROBE_PATHS or bool(exploit_hits(ev.path))
                    or (ev.method == "POST" and norm in self._login and ev.status in (401, 403)))
        self._behavior.note_web(_ident(ev.ip), path, ev.status, ev.user_agent, evidence)
        if out or not evidence:
            return out
        return self._anomaly("web", ev.ip, p.threshold_multiplier(ev.ip), ev.user_agent)

    def _anomaly(self, channel: str, ip: str, mult: int, ua: Optional[str]) -> List[Decision]:
        model = self._models.get(channel)
        ident = _ident(ip)
        evidence = self._behavior.evidence(channel, ident)
        if model is None or evidence < self._cfg.anomaly_min_evidence * mult:
            return []
        row = self._behavior.features(channel, ident)
        score = model.score(row)
        if score < model.threshold:
            return []
        detail = "score=%.3f threshold=%.3f evidence=%d %s" % (
            score, model.threshold, evidence, " ".join("%s=%.2f" % pair for pair in zip(model.features, row)))
        out = self._fire("anomaly_" + channel, ip, self._clock(), detail, ua)
        if not self._cfg.anomaly_block:
            return [Decision(d.rule, d.ip, "alert", (), 0, d.evidence) for d in out]
        return out

    def _web_rules(self, ev: LogEvent) -> List[Decision]:
        p = self._p
        mult = p.threshold_multiplier(ev.ip)
        path, _, _query = ev.path.partition("?")
        out = []  # type: List[Decision]
        norm = path.rstrip("/")
        trusted = mult > 1
        if ev.method == "POST" and norm in self._login:
            wp = norm == "/wp-login.php"
            if ev.status in (401, 403) or (wp and ev.status == 200):
                self._mark_bad(ev.ip, trusted)
                out += self._hit("web_login_bruteforce", ev.ip, (next(self._seq),), ev.raw,
                                 self._cfg.web_login_threshold * mult, ev.user_agent)
            elif wp and ev.status == 302:
                p.note_login_ok(ev.ip)
        lowered = path.lower()
        if lowered in _PROBE_PATHS and 400 <= ev.status < 500:
            self._mark_bad(ev.ip, trusted)
            p.note_probe(ev.ip)
            out += self._hit("web_probe", ev.ip, (lowered,), ev.raw, self._cfg.probe_threshold * mult, ev.user_agent)
        hits = exploit_hits(ev.path)
        if hits:
            self._mark_bad(ev.ip, trusted)
            out += self._hit("web_exploit", ev.ip, hits, ev.raw, self._cfg.exploit_threshold * mult, ev.user_agent,
                             EXPLOIT_MIN_REQUESTS, ev.path)
        return out

    def _mark_bad(self, ip: str, trusted: bool = False) -> None:
        now = self._clock()
        ident = _ident(ip)
        rec = self._bad.get(ident) or [now, float("-inf")]
        rec[0] = now
        if trusted or self._p.threshold_multiplier(ip) > 1:
            rec[1] = now
        self._remember(self._bad, ident, rec)

    def _hit(self, rule: str, ip: str, keys: tuple, raw: str, threshold: int, ua: Optional[str] = None,
             min_requests: int = 1, tag=None) -> List[Decision]:
        now = self._clock()
        span = SCAN_WINDOW if rule == "port_scan" else WINDOW
        ident = _ident(ip)
        wk = (rule, ident)
        dq = self._win.get(wk)
        if dq is None:
            dq = self._win[wk] = deque(maxlen=max(MIN_WINDOW_EVENTS, 4 * threshold))
            while len(self._win) > self._cfg.max_tracked_ips:
                self._win.popitem(last=False)
        else:
            self._win.move_to_end(wk)
        while dq and dq[0][0] <= now - span:
            dq.popleft()
        dq.append((now, keys, raw, tag))
        if len({e[3] for e in dq}) < min_requests or len(set().union(*(e[1] for e in dq))) < threshold:
            return []
        evidence = "\n".join(e[2] for e in list(dq)[-EVIDENCE_LINES:])[:EVIDENCE_CHARS]
        del self._win[wk]
        return self._fire(rule, ip, now, evidence, ua)

    def _fire(self, rule: str, ip: str, now: float, evidence: str, ua: Optional[str]) -> List[Decision]:
        key = (rule, _ident(ip))
        if self._active.get(key, 0) > now:
            return []
        web = rule in _WEB_RULES
        if web and (self._behind_cdn or self._p.is_cdn(ip) or self._p.is_shared(ip)):
            return [Decision(rule, ip, "alert", (), 0, evidence)]
        why = self._p.reason(ip)
        if why:
            self.suppressed[why] += 1
            return []
        if rule == "port_scan":
            bad = self._bad.get(key[1])
            proven = bad is not None and now - bad[0] < WINDOW
            trusted = (self._p.threshold_multiplier(ip) > 1 or self._p.is_shared(ip)
                       or (bad is not None and now - bad[1] < WINDOW))
            if not proven or trusted:
                return [Decision(rule, ip, "alert", (), 0, evidence)]
        if web and self._p.verify_bot(ip, ua):
            self.suppressed["verified-bot"] += 1
            return []
        off = self._offense.get(key)
        repeats = off[0] if off and now - off[1] < OFFENSE_MEMORY and rule != "conn_flood" else 0
        action, base = _RULES[rule], getattr(self._cfg, "ttl_" + rule)
        ttl = min(base * 2 ** min(repeats, 10), MAX_TTL)
        self._remember(self._offense, key, [repeats + 1, now])
        self._remember(self._active, key, now + ttl)
        ports = self._cfg.ssh_ports if rule in ("ssh_bruteforce", "anomaly_ssh") else self._cfg.web_ports if web else ()
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
        for key in [k for k, v in self._bad.items() if now - v[0] >= WINDOW]:
            del self._bad[key]
        for key in [k for k, exp in self._active.items() if exp <= now]:
            del self._active[key]
        for key in [k for k, v in self._offense.items() if now - v[1] >= OFFENSE_MEMORY]:
            del self._offense[key]
