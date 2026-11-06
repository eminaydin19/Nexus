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
from .anomaly import load_models
from .collectors import (
    WEB_LOGS, LineQueue, LogCollectors, read_connections, sample_connections, sample_metrics, ssh_peers, web_peers,
)
from .config import (
    AgentConfig, is_insecure, load_ssh_ok, load_state, read_gateways, read_resolvers, resolve_host, save_state,
)
from .enforcer import MAX_TTL, MODES, Enforcer
from .parsers import (
    caddy_line_is_stale, normalize_ip, parse_caddy_line, parse_scan_line, parse_ssh_line, parse_web_line, ssh_line_is_stale,
    web_line_is_stale,
)
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
NETWORK_REFRESH = 300
NETWORK_RETRY = 60
SSH_STATE_INTERVAL = 60
SSH_SILENCE_WARN = 3600
LAST_SEND_SAVE_INTERVAL = 60
JOURNAL_SOCKET = "/run/systemd/journal/socket"
# sshd drops an unauthenticated connection after LoginGraceTime (120 s by default), so one that outlives this is a session.
# shortcut: a longer LoginGraceTime lets a held unauthenticated connection pass as a session; read sshd_config if that shows up.
SSH_SESSION_MIN_AGE = 150


class Agent:
    def __init__(self, cfg: AgentConfig, client, protector: Protector, engine: RuleEngine, enforcer: Enforcer,
                 can_enforce: Optional[bool] = None, collectors: Optional[LogCollectors] = None, clock=time.time,
                 mono=time.monotonic):
        self.cfg, self.client, self.protector, self.engine, self.enforcer = cfg, client, protector, engine, enforcer
        self.collectors, self.clock, self.mono = collectors, clock, mono
        self.lines = LineQueue()
        self.events_dropped = 0
        self.stale_lines = 0
        self._can_enforce = (sys.platform.startswith("linux") and shutil.which("nft") is not None
                             if can_enforce is None else can_enforce)
        self._rejected_reason = None  # type: Optional[str]
        self._await_sample = False
        self._ssh_silence_warned = False
        self._saved_ssh = []  # type: list
        self._last_send = None  # type: Optional[float]
        self._last_send_saved = None  # type: Optional[float]
        self._next_ssh_save = 0.0
        self._send_thread = None  # type: Optional[threading.Thread]
        self._state_mode = "observe"
        self._allow = []  # type: List[str]
        self._listening = set()  # type: set
        self._behind_cdn = False
        self._breaker_was = False
        self._next_conn = 0.0
        self._ssh_seen = None  # type: Optional[Dict[tuple, float]]
        self._new_counts = {}  # type: Dict[str, int]
        self._new_at = None  # type: Optional[float]
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
        self.protector.import_ssh_ok(load_ssh_ok(self.cfg.state_dir))
        self._saved_ssh = self.protector.export_ssh_ok()
        self._next_ssh_save = self.mono() + SSH_STATE_INTERVAL
        # Before enforce: setup starts the scan log rule, and an unknown listening set would flag every open port.
        self._sample_connections()
        self._next_conn = self.mono() + CONN_INTERVAL
        self._state_mode = self._clamp(mode)
        self._request_mode(mode)
        if self.enforcer.mode != "enforce":
            self.enforcer.lift_leftovers()

    def _clamp(self, mode: str) -> str:
        return min(mode, self.cfg.max_mode, key=MODES.index)

    def _request_mode(self, mode: str) -> None:
        self._apply_mode(self._clamp(mode))
        if mode == "enforce" and self.cfg.max_mode != "enforce":
            self._rejected_reason = "max_mode"

    def _apply_mode(self, mode: str) -> None:
        self._rejected_reason = None
        self._await_sample = False
        if mode == "enforce" and not self._can_enforce:
            self._rejected_reason = "no_nft"
            mode = "observe"
        elif mode == "enforce" and not self._listening:
            # Until a sample succeeds every open port would look closed to the scan rule.
            self._await_sample = True
            mode = "observe"
        ok = self.enforcer.set_mode(mode)
        if mode == "enforce":
            if ok and self.enforcer.capable:
                self._push_listening()
            else:
                self._rejected_reason = "setup_failed"

    def _push_listening(self) -> None:
        if self._listening:
            self.enforcer.update_listening(self._listening)

    def _persist(self) -> None:
        self._saved_ssh = self.protector.export_ssh_ok()
        self._last_send_saved = self._last_send
        save_state(self.cfg.state_dir, self._state_mode, self._allow, self._saved_ssh, self._last_send)

    def _save_ssh_if_changed(self) -> None:
        if self.protector.export_ssh_ok() != self._saved_ssh:
            self._persist()

    def _save_last_send_if_due(self) -> None:
        sent, saved = self._last_send, self._last_send_saved
        if sent is not None and (saved is None or sent - saved >= LAST_SEND_SAVE_INTERVAL):
            self._persist()

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
        blocks = self.enforcer.active(limit=None, strict=True)
        if blocks is None:
            return False  # an unread kernel may still hold a block on an allowed customer, so central must retry
        done = True
        for block in blocks:
            if self._now_allowed(block.ip, nets):
                if self.enforcer.remove(block.ip):
                    self.engine.forget(block.ip)
                else:
                    done = False
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
        self._request_mode(mode)
        self._state_mode = "enforce" if self._await_sample else self.enforcer.mode
        self._persist()
        return True

    # -- tick ---------------------------------------------------------------

    def tick(self) -> None:
        self.enforcer.retry_lift()
        while self._commands:
            self.handle_command(self._commands.popleft())
        self._process_lines()
        # Here, not in the send thread, so a late send cannot overwrite a newer mode with its older copy.
        self._save_last_send_if_due()
        now = self.mono()
        if now >= self._next_ssh_save:
            self._next_ssh_save = now + SSH_STATE_INTERVAL
            self._save_ssh_if_changed()
        if now >= self._next_conn:
            self._next_conn = now + CONN_INTERVAL
            per_ip, syn_recv = self._sample_connections()
            if self._listening and self.enforcer.mode != "off":
                self._apply(self.engine.feed_connections(per_ip, syn_recv, self._new_conn_rates(now)))
        self._note_breaker()

    def _process_lines(self) -> None:
        now = self.clock()
        off = self.enforcer.mode == "off"
        for source, line in self.lines.drain(MAX_LINES_PER_TICK):
            if source == "ssh":
                if ssh_line_is_stale(line, now):
                    self.stale_lines += 1
                    continue
                event = parse_ssh_line(line, now)
            elif off:
                continue
            elif source == "web":
                caddy = self.cfg.web_log_format == "caddy-json"
                if (caddy_line_is_stale if caddy else web_line_is_stale)(line, now):
                    self.stale_lines += 1
                    continue
                event = (parse_caddy_line if caddy else parse_web_line)(line, now)
            else:
                event = None
                hit = parse_scan_line(line)
                # An empty set means the sample failed, not that every port is closed.
                if hit and self._listening and hit[1] not in self._listening:
                    self._apply(self.engine.feed_scan(hit[0], hit[1]))
            if event is None:
                continue
            # Off means no detection: engine state built now would suppress real decisions after switching back.
            # A login still has to reach the Protector, or the customer loses recent-SSH trust while off.
            if not off:
                self._apply(self.engine.feed(event))
            elif event.kind == "ssh_ok":
                self.protector.note_ssh_ok(event.ip)

    def _sample_connections(self):
        conns = read_connections()
        per_ip, syn_recv, active_ssh, listening = sample_connections(self.cfg.rules.ssh_ports, conns)
        if not listening:
            return per_ip, syn_recv
        self._note_ssh_sessions(conns)
        self._listening = listening
        self._push_listening()
        if self._await_sample:
            self._apply_mode("enforce")
        self._warn_if_ssh_silent(active_ssh)
        self._update_behind_cdn(web_peers(self.cfg.rules.web_ports, conns))
        return per_ip, syn_recv

    def _note_ssh_sessions(self, conns: list) -> None:
        # An open connection proves nothing: one held before login would make its owner unblockable on every rule.
        now = self.mono()
        # Connections older than this agent get the benefit of the doubt: a restart must not expose a long-running admin.
        default = now if self._ssh_seen is not None else now - SSH_SESSION_MIN_AGE
        seen = self._ssh_seen or {}
        self._ssh_seen = {peer: seen.get(peer, default) for peer in ssh_peers(self.cfg.rules.ssh_ports, conns)}
        self.protector.set_active_ssh({peer[0] for peer, first in self._ssh_seen.items() if now - first >= SSH_SESSION_MIN_AGE})

    def _new_conn_rates(self, now: float) -> Dict[str, float]:
        counts = self.enforcer.new_connections()
        previous, at = self._new_counts, self._new_at
        self._new_counts, self._new_at = counts, now
        if at is None or now <= at:
            return {}
        return {ip: (n - previous.get(ip, 0)) / (now - at) for ip, n in counts.items() if n > previous.get(ip, 0)}

    def _warn_if_ssh_silent(self, active_ssh: set) -> None:
        idle = getattr(self.collectors, "ssh_idle_seconds", None)
        if idle is None:
            return
        silent = idle() >= SSH_SILENCE_WARN
        if silent and active_ssh and not self._ssh_silence_warned:
            log.warning("ssh sessions are active but the ssh log source produced no line for an hour; "
                        "ssh detection and recent-ssh protection may be blind")
            self._ssh_silence_warned = True
        elif not silent:
            self._ssh_silence_warned = False

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
            ttl = res.ttl or d.ttl
            if res.detail.startswith("breaker"):
                self._push(self._event(d, "rate_limit", (), ttl, res.simulated, res.ok))
            else:
                self._push(self._event(d, d.action, d.ports, ttl, res.simulated, res.ok))
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
                        "simulated": False, "ok": True, "ts": self.clock()})
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
        self._last_send = self.clock()
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
                "enforce": self._can_enforce and self._rejected_reason != "setup_failed",
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
            "enforce_rejected": self._rejected_reason is not None,
            "enforce_rejected_reason": self._rejected_reason,
            "enforce_waiting_sample": self._await_sample,
            "lift_pending": self.enforcer.lift_pending,
            "breaker_open": self._breaker_was,
            "behind_cdn": self._behind_cdn,
            "events_dropped": self.events_dropped,
            "lines_dropped": self.lines.dropped,
            "stale_lines": self.stale_lines,
            "suppressed": dict(self.engine.suppressed),
            "rules": rules,
        }

    # -- threads ------------------------------------------------------------

    def _send_loop(self, stop: threading.Event) -> None:
        # Its own thread: a blackholed central stalls a send for up to 20s, and detection must not wait for that.
        delay = SEND_INTERVAL
        while not stop.wait(delay):
            try:
                delay = self.send_once()
            except Exception:
                log.exception("send loop failed")
                delay = SEND_INTERVAL

    def _cdn_loop(self, stop) -> None:
        delay = CDN_FIRST_REFRESH
        while not stop.wait(delay):
            try:
                self.protector.refresh_cdn_ranges()
            except Exception:
                log.exception("CDN range refresh failed")
            delay = CDN_REFRESH

    def _refresh_network(self) -> bool:
        """False when any lookup came back empty, which is a reason to retry soon."""
        central, gateway, resolvers = resolve_host(urlsplit(self.cfg.url).hostname), read_gateways(), read_resolvers()
        self.protector.update_network(central, gateway, resolvers)
        return bool(central and gateway and resolvers)

    def _network_loop(self, stop) -> None:
        delay = NETWORK_REFRESH
        while not stop.wait(delay):
            try:
                delay = NETWORK_REFRESH if self._refresh_network() else NETWORK_RETRY
            except Exception:
                log.exception("network refresh failed")
                delay = NETWORK_RETRY

    def _start_send(self, stop: threading.Event) -> None:
        self._send_thread = threading.Thread(target=self._send_loop, args=(stop,), daemon=True, name="nexus-send")
        self._send_thread.start()

    def _check_threads(self, stop: threading.Event) -> None:
        if self._send_thread is not None and not self._send_thread.is_alive():
            log.error("send thread died; restarting")
            self._start_send(stop)
        if self.collectors is not None:
            self.collectors.ensure_poll_alive(stop)

    def run(self, stop: threading.Event) -> None:
        if self.collectors is not None:
            self.collectors.start(stop)
        self._start_send(stop)
        for target, name in ((self._cdn_loop, "nexus-cdn"), (self._network_loop, "nexus-net")):
            threading.Thread(target=target, args=(stop,), daemon=True, name=name).start()
        try:
            while not stop.wait(TICK):
                try:
                    self._check_threads(stop)
                    self.tick()
                except Exception:
                    log.exception("tick failed")
        finally:
            if self.collectors is not None:
                self.collectors.terminate()
            self._save_ssh_if_changed()


def build_agent(cfg: AgentConfig) -> Agent:
    client = Client(cfg.url, cfg.key, cfg.allow_insecure)
    protector = Protector(central_ip=resolve_host(urlsplit(cfg.url).hostname), gateway=read_gateways(),
                          resolvers=read_resolvers())
    agent = Agent(cfg, client, protector, RuleEngine(cfg.rules, protector, models=load_models()), Enforcer("observe"))
    # The binary alone proves nothing: containers and LXC ship it with no journald, which would leave scans unread.
    journalctl = shutil.which("journalctl") if os.path.exists(JOURNAL_SOCKET) else None
    agent.collectors = LogCollectors(agent.lines, web_logs=WEB_LOGS + cfg.web_logs, journalctl=journalctl)
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
    # Env first: argv is visible to every local user in ps.
    token = os.environ.get("NEXUS_ENROLL_TOKEN") or args.token
    if not token:
        raise SystemExit("nexus-agent: set NEXUS_ENROLL_TOKEN or pass --token")
    try:
        node_id, api_key = Client.enroll(args.url, token, socket.gethostname(),
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
    enroll.add_argument("--token")
    enroll.add_argument("--insecure", action="store_true")
    sub.add_parser("uninstall", help="delete the nftables table")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    if args.command == "enroll":
        return _enroll(args)
    if args.command == "uninstall":
        if shutil.which("nft") is None:
            print("nft not found; no firewall table to remove")
            return 0
        return 0 if Enforcer("observe").teardown() else 1
    return _run()
