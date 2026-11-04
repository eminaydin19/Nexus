from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import shutil
import signal
import socket
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from . import __version__
from .client import Client, ClientError, Command
from .collectors import (
    WEB_LOGS, LineQueue, LogCollectors, read_connections, sample_connections, sample_metrics, web_peers,
)
from .config import AgentConfig, is_insecure, load_state, read_gateways, read_resolvers, resolve_host, save_state
from .enforcer import BREAKER_TTL, MAX_TTL, MODES, Enforcer
from .parsers import normalize_ip, parse_scan_line, parse_ssh_line, parse_web_line
from .protect import Protector, _parse_nets
from .rules import Decision, RuleEngine

log = logging.getLogger("nexus_agent")

TICK = 1
SEND_INTERVAL = 5
CONN_INTERVAL = 5
DRAIN_INTERVAL = 1
MAX_BACKOFF = 60
MAX_EVENTS = 5000
MAX_LINES_PER_TICK = 20000
# Ingest model limits; going over them gets the whole request refused.
MAX_EVENTS_PER_SEND = 500
MAX_ACKS_PER_SEND = 500
MAX_PORTS = 16
MAX_EVIDENCE = 500
MAX_LATENCY_MS = 1e7
REJECTED_STATUSES = (400, 413, 422)
CDN_MIN_PEERS = 20
CDN_ON_SHARE = 0.5
CDN_OFF_SHARE = 0.1
CDN_FIRST_REFRESH = 3600
CDN_REFRESH = 86400


class Agent:
    def __init__(self, cfg: AgentConfig, client, protector: Protector, engine: RuleEngine, enforcer: Enforcer,
                 can_enforce: Optional[bool] = None, collectors: Optional[LogCollectors] = None, clock=time.time):
        self.cfg, self.client, self.protector, self.engine, self.enforcer = cfg, client, protector, engine, enforcer
        self.collectors, self.clock = collectors, clock
        self.lines = LineQueue()
        self.events_dropped = 0
        self._can_enforce = (sys.platform.startswith("linux") and shutil.which("nft") is not None
                             if can_enforce is None else can_enforce)
        self._enforce_rejected = False
        self._state_mode = "observe"
        self._allow = []  # type: List[str]
        self._listening = set()  # type: set
        self._behind_cdn = False
        self._breaker_was = False
        self._next_conn = 0.0
        self._failures = 0
        self._latency_ms = 0.0
        self._lock = threading.Lock()
        self._events = deque()  # type: deque
        self._acks = []  # type: List[int]
        self._commands = deque()  # type: deque
        self._handlers = {"unblock": self._cmd_unblock, "allowlist": self._cmd_allowlist, "mode": self._cmd_mode}

    # -- startup ------------------------------------------------------------

    def startup(self) -> None:
        mode, self._allow = load_state(self.cfg.state_dir) or ("observe", [])
        self.protector.set_allowlist(list(self.cfg.allowlist) + self._allow)
        # Before enforce: setup starts the scan log rule, and an unknown listening set would flag every open port.
        self._sample_connections()
        self._next_conn = self.clock() + CONN_INTERVAL
        self._state_mode = self._clamp(mode)
        self._apply_mode(self._state_mode)
        if self.enforcer.mode != "enforce":
            self.enforcer.lift_leftovers()

    def _clamp(self, mode: str) -> str:
        return min(mode, self.cfg.max_mode, key=MODES.index)

    def _apply_mode(self, mode: str) -> None:
        self._enforce_rejected = False
        if mode == "enforce" and not self._can_enforce:
            self._enforce_rejected = True
            mode = "observe"
        ok = self.enforcer.set_mode(mode)
        if mode == "enforce":
            if ok and self.enforcer.capable:
                self._push_listening()
            else:
                self._enforce_rejected = True
        elif not ok:
            log.error("switching to %s could not lift kernel blocks", mode)

    def _push_listening(self) -> None:
        if self._listening:
            self.enforcer.update_listening(self._listening)

    def _persist(self) -> None:
        save_state(self.cfg.state_dir, self._state_mode, self._allow)

    # -- commands -----------------------------------------------------------

    def handle_command(self, cmd: Command) -> None:
        with self._lock:
            if cmd.id in self._acks:
                return
        handler = self._handlers.get(cmd.type)
        done = True
        if handler is None:
            log.warning("ignoring unknown command type %r (id %s)", cmd.type, cmd.id)
        else:
            try:
                done = handler(cmd.payload)
            except (ValueError, TypeError, KeyError) as exc:
                log.warning("ignoring malformed %s command %s: %r", cmd.type, cmd.id, exc)
        if done:
            with self._lock:
                self._acks.append(cmd.id)

    def _cmd_unblock(self, payload: Dict) -> bool:
        # Central keeps "::ffff:a.b.c.d" as sent, and the engine would read that form as an IPv6 /64.
        ip = normalize_ip(payload["ip"])
        if ip is None:
            raise ValueError("invalid ip")
        if not self.enforcer.remove(ip):
            return False  # no ack, so central redelivers once the kernel answers again
        self.engine.forget(ip)
        return True

    def _cmd_allowlist(self, payload: Dict) -> bool:
        items = payload["ips"]
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise ValueError("ips must be a list of strings")
        self._allow = items
        # Union: local env entries are the operator's own safety net, which central must not be able to remove.
        self.protector.set_allowlist(list(self.cfg.allowlist) + items)
        self._persist()
        nets = _parse_nets(items, "allowlist")
        done = True
        for block in self.enforcer.active(limit=None):
            if self._now_allowed(block.ip, nets):
                done = self.enforcer.remove(block.ip) and done
                self.engine.forget(block.ip)
        return done

    def _now_allowed(self, ip: str, nets: list) -> bool:
        if self.protector.reason(ip):
            return True
        # A v6 block is held as its /64 network address, which reason() cannot match to an allowed host inside it.
        if ":" not in ip:
            return False
        block = _parse_nets([ip + "/64"], "block")[0]
        return any(n.version == 6 and n.overlaps(block) for n in nets)

    def _cmd_mode(self, payload: Dict) -> bool:
        mode = payload["mode"]
        if mode not in MODES:
            raise ValueError("invalid mode")
        self._apply_mode(self._clamp(mode))
        self._state_mode = self.enforcer.mode
        self._persist()
        return True

    # -- tick ---------------------------------------------------------------

    def tick(self) -> None:
        while self._commands:
            self.handle_command(self._commands.popleft())
        self._process_lines()
        now = self.clock()
        if now >= self._next_conn:
            self._next_conn = now + CONN_INTERVAL
            per_ip, syn_recv = self._sample_connections()
            if self._listening and self.enforcer.mode != "off":
                self._apply(self.engine.feed_connections(per_ip, syn_recv))
        self._note_breaker()

    def _process_lines(self) -> None:
        now = self.clock()
        off = self.enforcer.mode == "off"
        for source, line in self.lines.drain(MAX_LINES_PER_TICK):
            # Off means no detection: engine state built now would suppress real decisions after switching back.
            if off:
                continue
            if source == "ssh":
                event = parse_ssh_line(line, now)
            elif source == "web":
                event = parse_web_line(line, now)
            else:
                event = None
                hit = parse_scan_line(line)
                # An empty set means the sample failed, not that every port is closed.
                if hit and self._listening and hit[1] not in self._listening:
                    self._apply(self.engine.feed_scan(hit[0], hit[1]))
            if event is not None:
                self._apply(self.engine.feed(event))

    def _sample_connections(self):
        conns = read_connections()
        per_ip, syn_recv, active_ssh, listening = sample_connections(self.cfg.rules.ssh_ports, conns)
        if not listening:
            return per_ip, syn_recv
        self.protector.set_active_ssh(active_ssh)
        self._listening = listening
        self._push_listening()
        self._update_behind_cdn(web_peers(self.cfg.rules.web_ports, conns))
        return per_ip, syn_recv

    def _update_behind_cdn(self, peers: set) -> None:
        if len(peers) < CDN_MIN_PEERS:
            return
        share = sum(1 for p in peers if self.protector.is_cdn(p)) / len(peers)
        value = True if share > CDN_ON_SHARE else False if share < CDN_OFF_SHARE else self._behind_cdn
        if value != self._behind_cdn:
            log.info("behind CDN: %s", value)
            self._behind_cdn = value
            self.engine.set_behind_cdn(value)

    # -- decisions ----------------------------------------------------------

    def _apply(self, decisions: List[Decision]) -> None:
        for d in decisions:
            try:
                res = self.enforcer.apply(d)
            except ValueError as exc:
                log.error("cannot apply %s for %r: %s", d.rule, d.ip, exc)
                self._push(self._event(d, d.action, d.ports, d.ttl, False, False))
                continue
            if d.action in ("block_port", "block_all") and self.enforcer.breaker_open:
                self._push(self._event(d, "rate_limit", (), min(d.ttl, BREAKER_TTL), res.simulated, res.ok))
            else:
                self._push(self._event(d, d.action, d.ports, d.ttl, res.simulated, res.ok))
            self._note_breaker()

    def _event(self, d: Decision, action: str, ports, ttl, simulated: bool, ok: bool) -> dict:
        # A failed decision still has to fit the ingest model, or its bad field would get the whole batch refused.
        clean = [p for p in ports if isinstance(p, int) and 0 < p < 65536][:MAX_PORTS]
        return {
            "rule": d.rule,
            "ip": normalize_ip(d.ip) or "0.0.0.0",
            "action": action,
            "ports": clean,
            "ttl": max(0, min(ttl, MAX_TTL)) if isinstance(ttl, int) else 0,
            "evidence": d.evidence[:MAX_EVIDENCE],
            "simulated": simulated,
            "ok": ok,
            "ts": self.clock(),
        }

    def _note_breaker(self) -> None:
        now_open = self.enforcer.breaker_open
        if now_open and not self._breaker_was:
            log.warning("circuit breaker open: new blocks are downgraded to rate limits")
            self._push({"rule": "breaker", "ip": "0.0.0.0", "action": "alert", "ports": [], "ttl": 0,
                        "evidence": "too many new blocks; downgrading to rate limit",
                        "simulated": self.enforcer.mode == "observe", "ok": True, "ts": self.clock()})
        self._breaker_was = now_open

    def _push(self, event: dict) -> None:
        with self._lock:
            if len(self._events) >= MAX_EVENTS:
                self._events.popleft()
                self.events_dropped += 1
            self._events.append(event)

    # -- sending ------------------------------------------------------------

    def send_once(self) -> float:
        """Send one batch and return the seconds to wait before the next one."""
        with self._lock:
            batch = [self._events.popleft() for _ in range(min(MAX_EVENTS_PER_SEND, len(self._events)))]
            acks = self._acks[:MAX_ACKS_PER_SEND]
        try:
            payload = self._payload(batch, acks)
            started = time.perf_counter()
            commands = self.client.send(payload)
        except ClientError as exc:
            log.warning("central send failed: %s", exc)
            if exc.status in REJECTED_STATUSES:
                # Retrying the same batch can never succeed and would stall every later event behind it.
                with self._lock:
                    self.events_dropped += len(batch)
            else:
                self._requeue(batch)
            return self._backoff()
        except Exception:
            log.exception("central send failed")
            self._requeue(batch)
            return self._backoff()
        self._latency_ms = min((time.perf_counter() - started) * 1000.0, MAX_LATENCY_MS)
        self._failures = 0
        with self._lock:
            del self._acks[:len(acks)]
            backlog = bool(self._events)
        self._commands.extend(commands)
        return DRAIN_INTERVAL if backlog else SEND_INTERVAL

    def _backoff(self) -> float:
        delay = min(SEND_INTERVAL << min(self._failures, 4), MAX_BACKOFF)
        self._failures += 1
        return delay

    def _requeue(self, batch: List[dict]) -> None:
        with self._lock:
            free = MAX_EVENTS - len(self._events)
            keep = batch[-free:] if free > 0 else []
            self.events_dropped += len(batch) - len(keep)
            self._events.extendleft(reversed(keep))

    def _payload(self, events: List[dict], acks: List[int]) -> dict:
        payload = dict(sample_metrics())
        payload.update(
            timestamp=self.clock(),
            latency_ms=self._latency_ms,
            events=events,
            active_blocks=[dataclasses.asdict(b) for b in self.enforcer.active()],
            version=__version__,
            capabilities={
                "enforce": self._can_enforce and not self._enforce_rejected,
                "platform": sys.platform,
            },
            config=self._config(),
            acked_commands=acks,
        )
        return payload

    def _config(self) -> dict:
        rules = dataclasses.asdict(self.cfg.rules)
        rules.pop("login_paths", None)
        rules["ssh_ports"] = list(rules["ssh_ports"])[:MAX_PORTS]
        rules["web_ports"] = list(rules["web_ports"])[:MAX_PORTS]
        return {
            "max_mode": self.cfg.max_mode,
            "mode": self.enforcer.mode,
            "enforce_rejected": self._enforce_rejected,
            "breaker_open": self._breaker_was,
            "behind_cdn": self._behind_cdn,
            "events_dropped": self.events_dropped,
            "lines_dropped": self.lines.dropped,
            "suppressed": dict(self.engine.suppressed),
            "rules": rules,
        }

    # -- threads ------------------------------------------------------------

    def _send_loop(self, stop: threading.Event) -> None:
        # Its own thread: a blackholed central stalls a send for up to 20s, and detection must not wait for that.
        delay = SEND_INTERVAL
        while not stop.wait(delay):
            delay = self.send_once()

    def _cdn_loop(self, stop) -> None:
        delay = CDN_FIRST_REFRESH
        while not stop.wait(delay):
            try:
                self.protector.refresh_cdn_ranges()
            except Exception:
                log.exception("CDN range refresh failed")
            delay = CDN_REFRESH

    def run(self, stop: threading.Event) -> None:
        if self.collectors is not None:
            self.collectors.start(stop)
        for target, name in ((self._send_loop, "nexus-send"), (self._cdn_loop, "nexus-cdn")):
            threading.Thread(target=target, args=(stop,), daemon=True, name=name).start()
        try:
            while not stop.wait(TICK):
                try:
                    self.tick()
                except Exception:
                    log.exception("tick failed")
        finally:
            if self.collectors is not None:
                self.collectors.terminate()


def build_agent(cfg: AgentConfig) -> Agent:
    client = Client(cfg.url, cfg.key, cfg.allow_insecure)
    protector = Protector(central_ip=resolve_host(urlsplit(cfg.url).hostname), gateway=read_gateways(),
                          resolvers=read_resolvers())
    agent = Agent(cfg, client, protector, RuleEngine(cfg.rules, protector), Enforcer("observe"))
    agent.collectors = LogCollectors(agent.lines, web_logs=WEB_LOGS + cfg.web_logs,
                                     journalctl=shutil.which("journalctl"))
    return agent


def _run() -> int:
    try:
        cfg = AgentConfig.from_env()
        agent = build_agent(cfg)
    except ValueError as exc:
        raise SystemExit("nexus-agent: %s" % exc)
    stop = threading.Event()
    # No teardown on purpose: blocks stay in the kernel and expire by their own timeout.
    # stop.set runs in a thread: main may hold the event lock inside stop.wait when the signal arrives, which would deadlock.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: threading.Thread(target=stop.set).start())
    agent.startup()
    log.info("agent started: node=%s mode=%s max_mode=%s", cfg.node_id or socket.gethostname(),
             agent.enforcer.mode, cfg.max_mode)
    agent.run(stop)
    log.info("agent stopped")
    return 0


def _enroll(args: argparse.Namespace) -> int:
    try:
        node_id, api_key = Client.enroll(args.url, args.token, socket.gethostname(),
                                         allow_insecure=args.insecure or is_insecure(os.environ))
    except (ValueError, ClientError) as exc:
        raise SystemExit("nexus-agent: %s" % exc)
    print(json.dumps({"node_id": node_id, "api_key": api_key}))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="nexus-agent")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="run the agent (default)")
    enroll = sub.add_parser("enroll", help="exchange a one-time token for a key; prints JSON")
    enroll.add_argument("--url", required=True)
    enroll.add_argument("--token", required=True)
    enroll.add_argument("--insecure", action="store_true")
    sub.add_parser("uninstall", help="delete the nftables table")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    if args.command == "enroll":
        return _enroll(args)
    if args.command == "uninstall":
        return 0 if Enforcer("observe").teardown() else 1
    return _run()
