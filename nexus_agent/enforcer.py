from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from .rules import Decision

log = logging.getLogger("nexus_agent.enforcer")

Runner = Callable[..., Tuple[int, str]]

TABLE = "nexus"
CHAIN = "prerouting"
MODES = ("off", "observe", "enforce")
MAX_TTL = 86400
BREAKER_TTL = 600
BREAKER_WINDOW = 300
MAX_ACTIVE_REPORT = 1000
MAX_PORTS_REPORT = 16
V6_MASK = "ffff:ffff:ffff:ffff::"
BLOCK_SETS = ("port4", "port6", "all4", "all6", "limit4", "limit6")
NEW_CONN_SETS = ("seen4", "seen6")
SEEN_BIT = "0x40000000"
_KIND = {"port": "block_port", "all": "block_all", "limit": "rate_limit"}
_SET_FOR = {"block_port": "port", "block_all": "all", "rate_limit": "limit"}

Key = Tuple[str, str, int]


@dataclass
class ApplyResult:
    ok: bool
    simulated: bool
    detail: str = ""
    ttl: int = field(default=0, compare=False)


@dataclass
class BlockIn:
    ip: str
    rule: str
    ports: List[int]
    until: float
    simulated: bool = False
    kind: str = "block_all"


def run_command(argv: List[str], input_text: Optional[str] = None, timeout: float = 10) -> Tuple[int, str]:
    try:
        p = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, p.stdout if p.returncode == 0 else p.stdout + p.stderr


def _address(ip: str) -> Tuple[str, str]:
    if not isinstance(ip, str) or "%" in ip:
        raise ValueError("invalid ip: %r" % (ip,))
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.version == 4:
        return "4", str(addr)
    return "6", str(ipaddress.IPv6Network((addr, 64), strict=False).network_address)


def _safe_comment(rule: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", rule)[:64]


def _port(p: object) -> int:
    if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
        raise ValueError("invalid port: %r" % (p,))
    return p


def _setup_script(with_rules: bool) -> str:
    lines = ["add table inet nexus"]
    for fam, t in (("4", "ipv4_addr"), ("6", "ipv6_addr")):
        lines.append("add set inet nexus port%s { type %s . inet_service; flags timeout; }" % (fam, t))
        for name in ("all", "limit"):
            lines.append("add set inet nexus %s%s { type %s; flags timeout; }" % (name, fam, t))
        lines.append("add set inet nexus meter%s { type %s; flags dynamic,timeout; timeout 1m; size 65535; }" % (fam, t))
        lines.append("add set inet nexus seen%s { type %s; flags dynamic,timeout; timeout 1m; size 65535; }" % (fam, t))
    lines.append("add set inet nexus listening { type inet_service; }")
    lines.append("add chain inet nexus prerouting { type filter hook prerouting priority -150; policy accept; }")
    if with_rules:
        s6 = "ip6 saddr & ffff:ffff:ffff:ffff::"
        rate = "limit rate over 100/second burst 200 packets"
        first = ("ct status assured ct direction original ct mark & %s == 0 meta l4proto tcp ct mark set ct mark | %s"
                 % (SEEN_BIT, SEEN_BIT))
        lines += [
            "add rule inet nexus prerouting ip saddr . tcp dport @port4 drop",
            "add rule inet nexus prerouting %s . tcp dport @port6 drop" % s6,
            "add rule inet nexus prerouting ip saddr @all4 drop",
            "add rule inet nexus prerouting %s @all6 drop" % s6,
            "add rule inet nexus prerouting ip saddr @limit4 ct state new "
            "update @meter4 { ip saddr %s } drop" % rate,
            "add rule inet nexus prerouting %s @limit6 ct state new "
            "update @meter6 { %s %s } drop" % (s6, s6, rate),
            "add rule inet nexus prerouting meta nfproto ipv4 %s update @seen4 { ip saddr counter }" % first,
            "add rule inet nexus prerouting meta nfproto ipv6 %s update @seen6 { %s counter }" % (first, s6),
            'add rule inet nexus prerouting fib daddr type local iif != "lo" ct state new tcp flags syn '
            'tcp dport != @listening '
            'limit rate 50/second log prefix "nexus-scan "',
        ]
    return "\n".join(lines) + "\n"


class Enforcer:
    def __init__(self, mode: str = "observe", runner: Optional[Runner] = None,
                 clock: Callable[[], float] = time.time, max_new_per_5m: int = 50, max_active: int = 2000):
        if mode not in MODES:
            raise ValueError("invalid mode: %r" % (mode,))
        self.mode = mode
        self._run = runner or run_command
        self._clock = clock
        self.max_new_per_5m = max_new_per_5m
        self.max_active = max_active
        self.capable = False
        self._lift_pending = False
        self._open = False
        self._events: Deque[float] = deque()
        self._live: Dict[Key, Tuple[float, str]] = {}
        self._sim: Dict[Key, Tuple[float, str]] = {}
        self._listening: Optional[frozenset] = None
        self._lock = threading.RLock()

    def _cur(self) -> Dict[Key, Tuple[float, str]]:
        return self._sim if self.mode == "observe" else self._live

    def _prune(self) -> None:
        now = self._clock()
        while self._events and self._events[0] <= now - BREAKER_WINDOW:
            self._events.popleft()
        for d in (self._live, self._sim):
            for k in [k for k, v in d.items() if v[0] <= now]:
                del d[k]

    def _full_active(self) -> int:
        return sum(1 for k in self._cur() if not k[0].startswith("limit"))

    @property
    def breaker_open(self) -> bool:
        with self._lock:
            if self._open:
                self._prune()
                if len(self._events) < self.max_new_per_5m and self._full_active() < self.max_active:
                    self._open = False
            return self._open

    def _exec(self, argv: List[str], input_text: Optional[str] = None) -> Tuple[bool, int, str]:
        rc, out = self._run(argv, input_text)
        return rc == 0 or "File exists" in out, rc, out

    def setup(self) -> bool:
        with self._lock:
            rc, out = self._run(["nft", "-j", "list", "chain", "inet", TABLE, CHAIN])
            if rc == 127:
                self.capable = False
                log.error("nft not found; firewall enforcement unavailable")
                return False
            has_rules = False
            if rc == 0:
                try:
                    has_rules = any("rule" in e for e in json.loads(out).get("nftables", []))
                except (ValueError, AttributeError, TypeError):
                    log.error("unreadable chain listing; refusing to add rules blindly")
                    self.capable = False
                    return False
            elif "No such file" not in out:
                log.error("cannot inspect chain (%s): %s", rc, out.strip())
                self.capable = False
                return False
            rc, out = self._run(["nft", "-f", "-"], _setup_script(not has_rules))
            if rc != 0:
                self.capable = False
                log.error("nft setup failed (%s): %s", rc, out.strip())
                return False
            self.capable = True
            self._listening = None
            rows = self._read_kernel()
            if rows is not None:
                now = self._clock()
                self._live = {
                    (s, a, p): (now + exp, rule or self._live.get((s, a, p), (0, "unknown"))[1])
                    for s, a, p, exp, rule in rows
                }
            return True

    def teardown(self) -> bool:
        with self._lock:
            ok, rc, out = self._exec(["nft", "delete", "table", "inet", TABLE])
            if not ok and "No such file" in out:
                ok = True
            if ok:
                self.capable, self._listening, self._open, self._lift_pending = False, None, False, False
                self._live.clear()
                self._events.clear()
            else:
                log.error("nft teardown failed (%s): %s", rc, out.strip())
            return ok

    def _read_kernel(self, set_name: Optional[str] = None) -> Optional[List[Tuple[str, str, int, float, str]]]:
        what = ["set", "inet", TABLE, set_name] if set_name else ["table", "inet", TABLE]
        rc, out = self._run(["nft", "-j", "list"] + what)
        if rc == 127 or (rc != 0 and "No such file" in out):
            return []
        if rc != 0:
            log.warning("cannot list %s (%s): %s", " ".join(what), rc, out.strip())
            return None
        rows = []
        try:
            for item in json.loads(out).get("nftables", []):
                s = item.get("set")
                if not s or s.get("name") not in BLOCK_SETS:
                    continue
                for el in s.get("elem", []):
                    el = el.get("elem", el) if isinstance(el, dict) else el
                    val = el.get("val", el) if isinstance(el, dict) else el
                    expires = float(el.get("expires", 0)) if isinstance(el, dict) else 0.0
                    rule = el.get("comment", "") if isinstance(el, dict) else ""
                    if isinstance(val, dict):
                        addr, port = val["concat"]
                    else:
                        addr, port = val, 0
                    rows.append((s["name"], str(ipaddress.ip_address(addr)), int(port), expires, rule))
        except (ValueError, KeyError, TypeError, AttributeError):
            log.error("unparseable nft output for table inet %s", TABLE)
            return None
        return rows

    def apply(self, d: Decision) -> ApplyResult:
        if d.action == "alert":
            return ApplyResult(True, False, "alert")
        if d.action not in _SET_FOR:
            raise ValueError("unknown action: %r" % (d.action,))
        fam, addr = _address(d.ip)
        if isinstance(d.ttl, bool) or not isinstance(d.ttl, int) or d.ttl <= 0:
            raise ValueError("invalid ttl: %r" % (d.ttl,))
        ttl = min(d.ttl, MAX_TTL)
        ports = sorted({_port(p) for p in d.ports})
        if d.action == "block_port" and not ports:
            raise ValueError("block_port needs at least one port")
        with self._lock:
            if self.mode == "off":
                return ApplyResult(False, False, "off")
            action, detail = d.action, ""
            self._prune()
            if action != "rate_limit":
                keys = self._keys(action, fam, addr, ports)
                is_new = any(k not in self._cur() for k in keys)
                if self.breaker_open or (is_new and (
                        len(self._events) + 1 > self.max_new_per_5m
                        or self._full_active() + len(keys) > self.max_active)):
                    self._open = True
                    action, detail, ttl, ports = "rate_limit", "breaker: rate_limit", min(ttl, BREAKER_TTL), []
            keys = self._keys(action, fam, addr, ports)
            is_new = any(k not in self._cur() for k in keys)
            now = self._clock()
            if self.mode == "observe":
                for k in keys:
                    self._sim[k] = (max(now + ttl, self._sim.get(k, (0, ""))[0]), d.rule)
                result = ApplyResult(True, True, detail or "observe")
            else:
                result = self._write(keys, addr, ttl, d.rule, now, detail)
            result.ttl = ttl
            if result.ok and is_new and action != "rate_limit":
                self._events.append(now)
            return result

    def _write(self, keys: List[Key], addr: str, ttl: int, rule: str, now: float, detail: str) -> ApplyResult:
        setname = keys[0][0]
        left = {(a, p): e for _, a, p, e, _ in self._read_kernel(setname) or []}
        todo = [k for k in keys if left.get((k[1], k[2]), -1) < ttl - 1]
        for k in keys:
            if k not in todo and k not in self._live:
                self._live[k] = (now + left[(k[1], k[2])], rule)
        if not todo:
            return ApplyResult(True, False, detail)
        items = "{ %s }" % ", ".join(
            '%s timeout %ds comment "%s"' % (self._elem(k), ttl, _safe_comment(rule)) for k in todo)
        replace = [k for k in todo if (k[1], k[2]) in left]
        if replace:
            script = "".join("delete element inet %s %s { %s }\n" % (TABLE, setname, self._elem(k)) for k in replace)
            ok, rc, out = self._exec(["nft", "-f", "-"], script + "add element inet %s %s %s\n" % (TABLE, setname, items))
        else:
            ok, rc, out = self._exec(["nft", "add", "element", "inet", TABLE, setname, items])
        if not ok:
            error = out.strip()[:200] or "nft exit %d" % rc
            return ApplyResult(False, False, "%s: %s" % (detail, error) if detail else error)
        for k in todo:
            self._live[k] = (now + ttl, rule)
        return ApplyResult(True, False, detail)

    @staticmethod
    def _elem(k: Key) -> str:
        return "%s . %d" % (k[1], k[2]) if k[2] else k[1]

    @staticmethod
    def _keys(action: str, fam: str, addr: str, ports: Iterable[int]) -> List[Key]:
        name = _SET_FOR[action] + fam
        return [(name, addr, p) for p in ports] if action == "block_port" else [(name, addr, 0)]

    def active(self, limit: Optional[int] = MAX_ACTIVE_REPORT, strict: bool = False) -> Optional[List[BlockIn]]:
        with self._lock:
            self._prune()
            now = self._clock()
            kernel = self._read_kernel()
            if kernel is None and strict:
                return None
            rows = [(s, a, p, now + e, rule or self._live.get((s, a, p), (0, "unknown"))[1], False)
                    for s, a, p, e, rule in kernel or []]
            if self.mode == "observe":
                rows += [(s, a, p, v[0], v[1], True) for (s, a, p), v in self._sim.items()]
            grouped: Dict[Tuple[str, str, bool], BlockIn] = {}
            for s, a, p, until, rule, simulated in rows:
                b = grouped.setdefault((s, a, simulated), BlockIn(a, rule, [], until, simulated, _KIND[s[:-1]]))
                b.until = max(b.until, until)
                if p and p not in b.ports:
                    b.ports.append(p)
            out = list(grouped.values())
            for b in out:
                b.ports = sorted(b.ports)[:MAX_PORTS_REPORT]
            out.sort(key=lambda b: b.until, reverse=True)
            return out[:limit]

    def remove(self, ip: str) -> bool:
        fam, addr = _address(ip)
        with self._lock:
            rows = self._read_kernel()
            if rows is None:
                return False
            targets = [(s, a, p) for s, a, p, _, _ in rows if a == addr and s.endswith(fam)]
            if targets:
                script = "".join("delete element inet %s %s { %s }\n" % (TABLE, s, self._elem((s, a, p)))
                                 for s, a, p in targets)
                rc, out = self._run(["nft", "-f", "-"], script)
                if rc != 0:
                    for s, a, p in targets:
                        done, rc, out = self._exec(
                            ["nft", "delete", "element", "inet", TABLE, s, "{ %s }" % self._elem((s, a, p))])
                        if not done and "No such file" not in out:
                            log.error("remove %s from %s failed (%s): %s", a, s, rc, out.strip())
                            return False
            for d in (self._sim, self._live):
                for k in [k for k in d if k[1] == addr]:
                    del d[k]
            return True

    def new_connections(self) -> Dict[str, int]:
        out = {}  # type: Dict[str, int]
        with self._lock:
            if self.mode != "enforce":
                return out
            for name in NEW_CONN_SETS:
                rc, text = self._run(["nft", "-j", "list", "set", "inet", TABLE, name])
                if rc != 0:
                    continue
                try:
                    for item in json.loads(text).get("nftables", []):
                        for el in (item.get("set") or {}).get("elem", []):
                            el = el["elem"]
                            out[str(ipaddress.ip_address(el["val"]))] = int(el["counter"]["packets"])
                except (ValueError, KeyError, TypeError, AttributeError):
                    log.warning("unparseable nft output for set %s", name)
        return out

    def update_listening(self, ports: Iterable[int]) -> bool:
        wanted = frozenset(_port(p) for p in ports)
        with self._lock:
            if self.mode != "enforce" or wanted == self._listening:
                return True
            script = "flush set inet nexus listening\n"
            if wanted:
                script += "add element inet nexus listening { %s }\n" % ", ".join(map(str, sorted(wanted)))
            rc, out = self._run(["nft", "-f", "-"], script)
            if rc != 0:
                log.error("update listening failed (%s): %s", rc, out.strip())
                return False
            self._listening = wanted
            return True

    def _flush_blocks(self, quiet: bool = False) -> bool:
        script = "".join("flush set inet %s %s\n" % (TABLE, n) for n in BLOCK_SETS + ("meter4", "meter6") + NEW_CONN_SETS)
        rc, out = self._run(["nft", "-f", "-"], script)
        if rc == 127 or (rc != 0 and "No such file" in out):
            return True
        if rc != 0:
            if not quiet:
                log.error("cannot lift kernel blocks (%s): %s", rc, out.strip())
            return False
        return True

    def _lift(self) -> bool:
        ok = self._flush_blocks(quiet=self._lift_pending)
        if ok:
            self._live.clear()
            if self._lift_pending:
                log.info("kernel blocks lifted after an earlier failure")
        self._lift_pending = not ok
        return ok

    @property
    def lift_pending(self) -> bool:
        return self._lift_pending

    def retry_lift(self) -> None:
        with self._lock:
            if self._lift_pending:
                self._lift()

    def lift_leftovers(self) -> bool:
        with self._lock:
            return self._lift()

    def set_mode(self, mode: str) -> bool:
        if mode not in MODES:
            raise ValueError("invalid mode: %r" % (mode,))
        with self._lock:
            if mode == self.mode and (mode != "enforce" or self.capable):
                self.retry_lift()
                return not self._lift_pending
            ok = True
            if mode == "enforce":
                if not self.setup():
                    log.error("cannot enforce; falling back to observe")
                    mode, ok = "observe", False
                else:
                    self._sim.clear()
                    self._lift_pending = False
            elif self.mode == "enforce" or self._lift_pending:
                ok = self._lift()
            self._events.clear()
            self._open = False
            self.mode = mode
            return ok
