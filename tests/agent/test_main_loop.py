from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import namedtuple

import psutil
import pytest

from nexus_agent import main as agent_main
from nexus_agent.client import ClientError, Command
from nexus_agent.config import AgentConfig, load_state, save_state
from nexus_agent.enforcer import Enforcer
from nexus_agent.main import Agent, main
from nexus_agent.protect import Protector
from nexus_agent.rules import Decision, RuleConfig, RuleEngine

IP = "203.0.113.9"
SSH_FAIL = "sshd[1234]: Failed password for root from %s port 4242 ssh2\n"
Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "laddr raddr status")


def listen(port):
    return Conn(Addr("0.0.0.0", port), (), "LISTEN")


def est(port, ip):
    return Conn(Addr("198.51.100.1", port), Addr(ip, 50000), "ESTABLISHED")


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t


class FakeNft:
    """Just enough of nft to hold set elements, so the real Enforcer can list and remove what it added."""

    start_failing = False

    def __init__(self, clock):
        self.clock, self.elems, self.calls, self.setup_fails, self.flushes = clock, {}, [], self.start_failing, 0
        self.list_fails, self.flush_fails = False, False

    def __call__(self, argv, input_text=None):
        self.calls.append((list(argv), input_text))
        if argv[:2] == ["nft", "-j"]:
            return (124, "timeout") if self.list_fails else (0, self._list())
        text = input_text if argv[:3] == ["nft", "-f", "-"] else " ".join(argv[1:])
        if self.setup_fails and "add table" in text:
            return 1, "Operation not permitted"
        if self.flush_fails and "flush set inet nexus port4" in text:
            return 1, "Error: busy"
        for line in text.splitlines():
            self._line(line)
        return 0, ""

    def _line(self, line):
        m = re.match(r"(add|delete) element inet nexus (\w+) \{ (.*) \}", line)
        if m:
            verb, name, body = m.groups()
            if name == "listening":
                return
            for item in body.split(", "):
                hit = re.match(r"(\S+)(?: \. (\d+))?(?: timeout (\d+)s)?", item)
                key = (name, hit.group(1), int(hit.group(2) or 0))
                if verb == "add":
                    self.elems[key] = self.clock() + int(hit.group(3))
                else:
                    self.elems.pop(key, None)
        elif line.startswith("flush set"):
            name = line.split()[-1]
            if name != "listening":
                self.flushes += 1
            self.elems = {k: v for k, v in self.elems.items() if k[0] != name}

    def _list(self):
        sets = {}
        for (name, addr, port), until in self.elems.items():
            val = {"concat": [addr, port]} if port else addr
            sets.setdefault(name, []).append({"elem": {"val": val, "expires": int(until - self.clock())}})
        return json.dumps({"nftables": [{"set": {"name": n, "elem": e}} for n, e in sets.items()]})

    def scripts(self):
        return [text for _, text in self.calls if text]


class FakeClient:
    def __init__(self):
        self.sent, self.down, self.commands, self.status = [], False, [], None

    def send(self, payload):
        if self.down:
            raise ClientError("central down", self.status)
        self.sent.append(payload)
        cmds, self.commands = self.commands, []
        return cmds


@pytest.fixture(autouse=True)
def default_sockets(monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22), listen(80), listen(443)])


class Rig:
    def __init__(self, tmp_path, mode="observe", max_mode="enforce", can_enforce=True, allowlist=(), rules=None,
                 max_new=50):
        self.clock = Clock()
        self.nft = FakeNft(self.clock)
        self.client = FakeClient()
        self.protector = Protector(clock=self.clock)
        self.cfg = AgentConfig("https://c.example", "k", "n", max_mode, (), tmp_path, tuple(allowlist), False,
                               rules or RuleConfig())
        self.engine = RuleEngine(self.cfg.rules, self.protector, self.clock)
        self.enforcer = Enforcer("observe", self.nft, self.clock, max_new_per_5m=max_new)
        if mode != "observe":
            save_state(tmp_path, mode, [])
        self.agent = Agent(self.cfg, self.client, self.protector, self.engine, self.enforcer,
                           can_enforce=can_enforce, clock=self.clock, mono=self.clock)
        self.agent.startup()

    def ssh_fails(self, ip=IP, n=10):
        for _ in range(n):
            self.agent.lines.put("ssh", SSH_FAIL % ip)
        self.agent.tick()

    def send(self):
        self.agent.send_once()
        return self.client.sent[-1]

    def events(self):
        return [e for p in self.client.sent for e in p["events"]]

    def block(self, ip=IP):
        self.ssh_fails(ip)
        assert self.enforcer.active()


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


@pytest.fixture
def enforcing(tmp_path):
    return Rig(tmp_path, mode="enforce")


def event(agent, n):
    agent._push({"rule": "r", "ip": IP, "action": "alert", "ports": [], "ttl": 0, "evidence": str(n),
                 "simulated": False, "ok": True, "ts": 0.0})


# -- queue and central outage -------------------------------------------------


def test_queue_bounded_drops_oldest_when_central_down(rig):
    rig.client.down = True
    for n in range(5100):
        event(rig.agent, n)
    rig.agent.send_once()
    assert len(rig.agent._events) == 5000
    rig.client.down = False
    p = rig.send()
    assert p["events"][0]["evidence"] == "100"
    assert p["config"]["events_dropped"] == 100


def test_failed_send_requeues_in_order_and_new_events_can_overflow_it(rig, monkeypatch):
    for n in range(4900):
        event(rig.agent, n)

    def down_and_flooded(payload):
        for n in range(4900, 9700):
            event(rig.agent, n)
        raise ClientError("down")

    monkeypatch.setattr(rig.client, "send", down_and_flooded)
    rig.agent.send_once()
    assert len(rig.agent._events) == 5000
    assert rig.agent._events[0]["evidence"] == "4700"
    assert rig.agent._events[-1]["evidence"] == "9699"
    assert rig.agent.events_dropped == 4700


def test_each_send_respects_ingest_limit_and_drains_without_waiting(rig):
    for n in range(700):
        event(rig.agent, n)
    assert rig.agent.send_once() < 5
    assert len(rig.client.sent[-1]["events"]) == 500
    assert rig.agent.send_once() == 5
    assert [e["evidence"] for e in rig.client.sent[-1]["events"]] == [str(n) for n in range(500, 700)]


def test_blocks_continue_when_central_down(enforcing):
    enforcing.client.down = True
    enforcing.agent.send_once()
    enforcing.ssh_fails()
    assert (("port4", IP, 22) in enforcing.nft.elems)


def test_backoff_doubles_to_60_and_resets(rig):
    rig.client.down = True
    assert [rig.agent.send_once() for _ in range(6)] == [5, 10, 20, 40, 60, 60]
    rig.client.down = False
    assert rig.agent.send_once() == 5
    rig.client.down = True
    assert rig.agent.send_once() == 5


def test_metrics_are_current_and_not_queued(rig):
    rig.client.down = True
    rig.agent.send_once()
    rig.client.down = False
    rig.clock.t += 100
    rig.send()
    assert len(rig.client.sent) == 1
    assert rig.client.sent[0]["timestamp"] == rig.clock.t


def test_rejected_payload_drops_events_but_keeps_acks(rig):
    event(rig.agent, 1)
    rig.agent.handle_command(Command(7, "nonsense", {}))
    rig.client.down, rig.client.status = True, 422
    assert rig.agent.send_once() == 5
    assert not rig.agent._events and rig.agent.events_dropped == 1
    rig.client.down = False
    assert rig.send()["acked_commands"] == [7]


def test_unauthorized_keeps_events(rig):
    event(rig.agent, 1)
    rig.client.down, rig.client.status = True, 401
    rig.agent.send_once()
    assert len(rig.agent._events) == 1


def test_unexpected_send_error_does_not_lose_events_or_kill_thread(rig, monkeypatch):
    event(rig.agent, 1)
    monkeypatch.setattr(agent_main, "sample_metrics", lambda: 1 / 0)
    assert rig.agent.send_once() == 5
    assert len(rig.agent._events) == 1


def test_acks_retained_until_send_succeeds_and_sent_once(rig):
    rig.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    rig.client.down = True
    rig.agent.send_once()
    rig.client.down = False
    assert rig.send()["acked_commands"] == [1]
    assert rig.send()["acked_commands"] == []


def test_ack_batch_respects_ingest_limit(rig):
    for n in range(600):
        rig.agent.handle_command(Command(n, "nonsense", {}))
    assert len(rig.send()["acked_commands"]) == 500
    assert rig.send()["acked_commands"] == list(range(500, 600))


def test_commands_from_a_response_run_on_next_tick_and_ack_next_send(enforcing):
    enforcing.block()
    enforcing.client.commands = [Command(9, "unblock", {"ip": IP})]
    enforcing.send()
    assert enforcing.nft.elems  # the sender thread never touches the firewall itself
    enforcing.agent.tick()
    assert not enforcing.nft.elems
    assert enforcing.send()["acked_commands"] == [9]


def test_command_redelivered_before_ack_is_not_run_twice(enforcing):
    enforcing.agent.handle_command(Command(5, "unblock", {"ip": IP}))
    enforcing.block()
    enforcing.agent.handle_command(Command(5, "unblock", {"ip": IP}))
    assert enforcing.nft.elems


# -- payload ------------------------------------------------------------------


def test_payload_shape(enforcing):
    enforcing.block()
    p = enforcing.send()
    assert set(p) == {"timestamp", "cpu_pct", "memory_pct", "net_kbps", "latency_ms", "events", "active_blocks",
                      "version", "capabilities", "config", "acked_commands"}
    assert p["capabilities"]["enforce"] is True and p["capabilities"]["platform"] == sys.platform
    cfg = p["config"]
    assert cfg["max_mode"] == "enforce" and cfg["mode"] == "enforce"
    assert cfg["rules"]["ssh_fail_threshold"] == 10 and cfg["rules"]["ssh_ports"] == [22]
    assert cfg["behind_cdn"] is False
    assert p["active_blocks"][0]["ip"] == IP and p["active_blocks"][0]["kind"] == "block_port"
    assert p["active_blocks"][0]["simulated"] is False
    assert p["latency_ms"] == 0.0
    assert enforcing.send()["latency_ms"] > 0


def test_payload_is_accepted_by_the_real_ingest_model(enforcing):
    pytest.importorskip("torch")
    from backend.main import IngestPayload

    enforcing.block()
    enforcing.agent.tick()
    enforcing.agent._apply([Decision("x", "bad-ip", "block_all", (), 60, "e" * 900)])
    p = enforcing.send()
    assert len(p["events"]) == 2
    IngestPayload(**json.loads(json.dumps(p)))


def test_config_stays_within_ingest_size_limit(tmp_path):
    rules = RuleConfig(ssh_ports=tuple(range(1000, 3000)), web_ports=tuple(range(3000, 5000)))
    rig = Rig(tmp_path, rules=rules)
    assert len(json.dumps(rig.send()["config"])) < 8192


# -- commands -----------------------------------------------------------------


def test_max_mode_cannot_be_exceeded_by_command(tmp_path):
    rig = Rig(tmp_path, max_mode="observe")
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "observe"
    assert not any("add table" in s for s in rig.nft.scripts())
    assert load_state(tmp_path)[0] == "observe"
    assert rig.send()["acked_commands"] == [1]


def test_max_off_clamps_everything_to_off(tmp_path):
    rig = Rig(tmp_path, max_mode="off")
    assert rig.enforcer.mode == "off"
    rig.agent.handle_command(Command(1, "mode", {"mode": "observe"}))
    assert rig.enforcer.mode == "off"


def test_mode_command_switches_and_persists(tmp_path):
    rig = Rig(tmp_path)
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "enforce" and rig.enforcer.capable
    assert load_state(tmp_path)[0] == "enforce"
    rig.agent.handle_command(Command(2, "mode", {"mode": "off"}))
    assert rig.enforcer.mode == "off" and load_state(tmp_path)[0] == "off"


def test_enforce_pushes_listening_ports_right_after_setup(tmp_path):
    rig = Rig(tmp_path)
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    scripts = rig.nft.scripts()
    setup = next(i for i, s in enumerate(scripts) if "add table" in s)
    assert "add element inet nexus listening { 22, 80, 443 }" in scripts[setup + 1]


@pytest.mark.parametrize("mode", [None, "bogus", 3, ["enforce"]])
def test_invalid_mode_command_is_logged_acked_and_ignored(rig, mode, caplog):
    rig.agent.handle_command(Command(1, "mode", {"mode": mode}))
    assert rig.enforcer.mode == "observe"
    assert "mode" in caplog.text
    assert rig.send()["acked_commands"] == [1]


def test_rejected_enforce_is_reported_and_leaves_observe(tmp_path):
    rig = Rig(tmp_path)
    rig.nft.setup_fails = True
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "observe"
    p = rig.send()
    assert p["config"]["mode"] == "observe" and p["config"]["enforce_rejected"] is True
    assert p["capabilities"]["enforce"] is False
    assert p["acked_commands"] == [1]
    assert load_state(tmp_path)[0] == "observe"
    rig.nft.setup_fails = False
    rig.agent.handle_command(Command(2, "mode", {"mode": "enforce"}))
    p = rig.send()
    assert p["config"]["mode"] == "enforce" and p["config"]["enforce_rejected"] is False
    assert p["capabilities"]["enforce"] is True


def test_unblock_command_removes(enforcing):
    enforcing.block()
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    assert not enforcing.nft.elems
    assert enforcing.send()["acked_commands"] == [1]
    # forget() cleared the offense count, so the next block starts from the base ttl again.
    enforcing.ssh_fails()
    assert enforcing.agent._events[-1]["ttl"] == 3600


def test_unblock_with_mapped_ip_reaches_the_ipv4_block_and_engine_state(enforcing):
    enforcing.block()
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": "::ffff:" + IP}))
    assert not enforcing.nft.elems
    enforcing.ssh_fails(n=9)
    assert not enforcing.nft.elems
    enforcing.ssh_fails(n=1)
    assert enforcing.nft.elems


def test_unblock_is_idempotent(enforcing):
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    enforcing.agent.handle_command(Command(2, "unblock", {"ip": IP}))
    assert enforcing.send()["acked_commands"] == [1, 2]


def test_unblock_not_acked_when_kernel_is_unreadable_so_central_retries(enforcing, monkeypatch):
    monkeypatch.setattr(enforcing.enforcer, "remove", lambda ip: False)
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    assert enforcing.send()["acked_commands"] == []


@pytest.mark.parametrize("payload", [{}, {"ip": "nope"}, {"ip": 5}])
def test_malformed_unblock_is_logged_and_acked(rig, payload, caplog):
    rig.agent.handle_command(Command(1, "unblock", payload))
    assert rig.send()["acked_commands"] == [1]
    assert caplog.text


def test_allowlist_command_lifts_existing_block(tmp_path):
    rig = Rig(tmp_path, mode="enforce")
    rig.block()
    other = "203.0.113.77"
    rig.block(other)
    rig.agent.handle_command(Command(1, "allowlist", {"ips": ["203.0.113.9/32"]}))
    assert [k[1] for k in rig.nft.elems] == [other]
    assert load_state(tmp_path) == ("enforce", ["203.0.113.9/32"])
    # Engine state is gone and the Protector now suppresses it.
    rig.ssh_fails()
    assert [k[1] for k in rig.nft.elems] == [other]
    assert rig.send()["acked_commands"] == [1]


def test_allowlist_lifts_v6_block_when_the_host_inside_its_64_is_allowed(enforcing):
    enforcing.block("2001:db8:1:2::abcd")
    assert ("port6", "2001:db8:1:2::", 22) in enforcing.nft.elems
    enforcing.agent.handle_command(Command(1, "allowlist", {"ips": ["2001:db8:1:2::abcd/128"]}))
    assert not enforcing.nft.elems


def test_allowlist_lifts_blocks_past_the_report_cap(tmp_path):
    rig = Rig(tmp_path, mode="enforce", max_new=10 ** 6)
    rig.enforcer.max_active = 10 ** 6
    for n in range(1100):
        ip = "203.0.113.1" if n == 0 else "198.18.%d.%d" % (n // 256, n % 256)
        rig.enforcer.apply(Decision("r", ip, "block_all", (), 3600 + n, "e"))
    rig.agent.handle_command(Command(1, "allowlist", {"ips": ["203.0.113.1/32"]}))
    assert ("all4", "203.0.113.1", 0) not in rig.nft.elems


def test_allowlist_lifts_simulated_block_in_observe(rig):
    rig.block()
    assert rig.enforcer.active()[0].simulated
    rig.agent.handle_command(Command(1, "allowlist", {"ips": [IP]}))
    assert rig.enforcer.active() == []


@pytest.mark.parametrize("payload", [{}, {"ips": "x"}, {"ips": [1]}, {"items": ["192.0.2.1"]}])
def test_malformed_allowlist_is_acked_and_changes_nothing(tmp_path, payload):
    rig = Rig(tmp_path, allowlist=["198.51.100.9"])
    rig.block()
    rig.agent.handle_command(Command(1, "allowlist", payload))
    assert rig.enforcer.active()
    assert rig.protector.reason("198.51.100.9") == "allowlist"
    assert rig.send()["acked_commands"] == [1]


def test_central_allowlist_cannot_remove_the_local_env_entries(tmp_path):
    rig = Rig(tmp_path, allowlist=["198.51.100.9"])
    rig.agent.handle_command(Command(1, "allowlist", {"ips": ["192.0.2.1"]}))
    assert rig.protector.reason("198.51.100.9") == "allowlist"
    assert rig.protector.reason("192.0.2.1") == "allowlist"
    assert load_state(tmp_path)[1] == ["192.0.2.1"]


def test_unknown_command_ignored_and_logged(rig, caplog):
    rig.agent.handle_command(Command(1, "exec", {"cmd": "rm -rf /"}))
    assert "exec" in caplog.text
    assert rig.nft.calls == [c for c in rig.nft.calls if "rm" not in " ".join(c[0])]
    assert rig.send()["acked_commands"] == [1]


def test_state_write_failure_keeps_running(tmp_path, monkeypatch):
    rig = Rig(tmp_path)
    monkeypatch.setattr(agent_main, "save_state", lambda *a: False)
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "enforce"
    assert rig.send()["acked_commands"] == [1]


# -- startup ------------------------------------------------------------------


def test_metrics_keep_working_on_macos_without_nft(tmp_path):
    rig = Rig(tmp_path, can_enforce=False)
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "observe"
    assert not any("add table" in s for s in rig.nft.scripts())
    p = rig.send()
    assert p["capabilities"]["enforce"] is False
    assert p["config"]["mode"] == "observe" and p["config"]["enforce_rejected"] is True
    assert 0 <= p["cpu_pct"] <= 100
    rig.ssh_fails()
    assert rig.agent._events[-1]["simulated"] is True


def test_persisted_enforce_without_nft_starts_observe_but_keeps_the_wish(tmp_path):
    rig = Rig(tmp_path, mode="enforce", can_enforce=False)
    assert rig.enforcer.mode == "observe"
    assert load_state(tmp_path)[0] == "enforce"


def test_startup_defaults_to_observe_with_env_allowlist(tmp_path):
    (tmp_path / "state.json").write_text("{broken")
    rig = Rig(tmp_path, allowlist=["198.51.100.9"])
    assert rig.enforcer.mode == "observe"
    assert rig.protector.reason("198.51.100.9") == "allowlist"


def test_startup_restores_state(tmp_path):
    save_state(tmp_path, "enforce", ["192.0.2.1"])
    rig = Rig(tmp_path)
    assert rig.enforcer.mode == "enforce" and rig.enforcer.capable
    assert rig.protector.reason("192.0.2.1") == "allowlist"
    assert any("listening { 22, 80, 443 }" in s for s in rig.nft.scripts())


def test_startup_clamps_persisted_enforce_and_flushes_leftovers(tmp_path):
    save_state(tmp_path, "enforce", [])
    rig = Rig(tmp_path, max_mode="observe")
    assert rig.enforcer.mode == "observe"
    assert rig.nft.flushes == 8  # six block sets and two meters
    assert not any("add table" in s for s in rig.nft.scripts())


def test_startup_in_enforce_keeps_kernel_blocks(tmp_path):
    rig = Rig(tmp_path, mode="enforce")
    assert rig.nft.flushes == 0


def test_observe_flush_happens_only_once(rig):
    rig.agent.tick()
    rig.agent.handle_command(Command(1, "mode", {"mode": "observe"}))
    assert rig.nft.flushes == 8


def test_failed_startup_enforce_is_reported(tmp_path, monkeypatch):
    save_state(tmp_path, "enforce", [])
    monkeypatch.setattr(FakeNft, "start_failing", True)
    rig = Rig(tmp_path)
    assert rig.enforcer.mode == "observe"
    assert rig.send()["config"]["enforce_rejected"] is True
    assert load_state(tmp_path)[0] == "enforce"  # a passing nft problem must not lose the operator's choice


# -- decisions ----------------------------------------------------------------


def test_alert_from_observe_marks_simulated(rig):
    rig.ssh_fails()
    p = rig.send()
    e = p["events"][0]
    assert e["rule"] == "ssh_bruteforce" and e["action"] == "block_port"
    assert e["simulated"] is True and e["ok"] is True
    assert e["ports"] == [22] and e["ttl"] == 3600
    assert rig.nft.calls == [c for c in rig.nft.calls if "add element" not in str(c)]


def test_true_alert_carries_the_enforcer_result(rig):
    rig.agent._apply([Decision("distributed_flood", "0.0.0.0", "alert", (), 0, "ev")])
    e = rig.agent._events[-1]
    assert e["action"] == "alert" and e["simulated"] is False and e["ok"] is True and e["ttl"] == 0


def test_real_block_is_not_simulated(enforcing):
    enforcing.ssh_fails()
    e = enforcing.send()["events"][0]
    assert e["simulated"] is False and e["ok"] is True


def test_breaker_downgrade_and_single_breaker_event(tmp_path):
    rig = Rig(tmp_path, mode="enforce", max_new=2)
    decisions = [Decision("ssh_bruteforce", "203.0.113.%d" % n, "block_port", (22,), 3600, "e") for n in range(1, 6)]
    rig.agent._apply(decisions)
    events = list(rig.agent._events)
    breaker = [e for e in events if e["rule"] == "breaker"]
    assert len(breaker) == 1
    assert (breaker[0]["action"], breaker[0]["ip"], breaker[0]["ports"], breaker[0]["ttl"]) == ("alert", "0.0.0.0", [], 0)
    down = [e for e in events if e["rule"] != "breaker"][2:]
    assert all(e["action"] == "rate_limit" and e["ttl"] == 600 and e["ports"] == [] and e["ok"] for e in down)
    assert [k[0] for k in rig.nft.elems].count("limit4") == 3
    # A later close and reopen is a new transition.
    rig.clock.t += 400
    rig.agent.tick()
    rig.agent._apply([Decision("r", "203.0.113.%d" % n, "block_port", (22,), 3600, "e") for n in range(10, 13)])
    assert len([e for e in rig.agent._events if e["rule"] == "breaker"]) == 2


def test_value_error_from_apply_does_not_stop_the_loop(rig, caplog):
    rig.agent._apply([Decision("r", "bad-ip", "block_all", (), 60, "e"),
                      Decision("r", IP, "block_port", (0, 22), 90000, "e"),
                      Decision("ssh_bruteforce", IP, "block_port", (22,), 60, "e")])
    bad, bad2, good = rig.agent._events
    assert bad["ok"] is False and bad["ip"] == "0.0.0.0"
    assert bad2["ok"] is False and bad2["ports"] == [22] and bad2["ttl"] == 86400
    assert good["ok"] is True
    assert "bad-ip" in caplog.text


def test_tick_error_is_contained_and_the_run_loop_continues(rig, monkeypatch):
    stop = threading.Event()
    calls = []

    def tick():
        calls.append(1)
        if len(calls) == 2:
            stop.set()
        raise RuntimeError("boom")

    monkeypatch.setattr(rig.agent, "tick", tick)
    monkeypatch.setattr(agent_main, "TICK", 0.01)
    rig.agent.collectors = None
    rig.agent.run(stop)
    assert len(calls) == 2


# -- logs ---------------------------------------------------------------------


def scan(ip, port):
    return ("Nov  4 13:22:11 web01 kernel: [1.5] nexus-scan IN=eth0 OUT= SRC=%s DST=198.51.100.1 "
            "PROTO=TCP SPT=1 DPT=%d SYN\n" % (ip, port))


def test_scan_of_listening_port_is_not_fed(rig, monkeypatch):
    fed = []
    monkeypatch.setattr(rig.engine, "feed_scan", lambda ip, port: fed.append((ip, port)) or [])
    rig.agent.lines.put("scan", scan(IP, 22))
    rig.agent.lines.put("scan", scan("::ffff:" + IP, 23))
    rig.agent.tick()
    assert fed == [(IP, 23)]


def test_scan_ignored_while_listening_ports_are_unknown(tmp_path, monkeypatch):
    def deny(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", deny)
    rig = Rig(tmp_path)
    fed = []
    monkeypatch.setattr(rig.engine, "feed_scan", lambda ip, port: fed.append(port) or [])
    rig.agent.lines.put("scan", scan(IP, 23))
    rig.agent.tick()
    assert fed == []


def test_mapped_ip_from_a_log_line_reaches_the_engine_as_ipv4(enforcing):
    enforcing.ssh_fails("::ffff:" + IP)
    assert ("port4", IP, 22) in enforcing.nft.elems
    assert enforcing.agent._events[-1]["ip"] == IP


def test_invalid_utf8_and_junk_lines_are_harmless(rig):
    for bad in ("�� garbage", "x" * 100000, "", "sshd"):
        rig.agent.lines.put("ssh", bad)
        rig.agent.lines.put("web", bad)
        rig.agent.lines.put("scan", bad)
    rig.agent.tick()
    assert not rig.agent._events


def test_tick_processes_at_most_the_limit(rig, monkeypatch):
    monkeypatch.setattr(agent_main, "MAX_LINES_PER_TICK", 5)
    for _ in range(8):
        rig.agent.lines.put("ssh", "junk")
    rig.agent.tick()
    assert len(list(rig.agent.lines.drain(100))) == 3


def test_line_drops_are_reported(tmp_path):
    rig = Rig(tmp_path)
    rig.agent.lines._q.maxsize = 1
    rig.agent.lines.put("ssh", "a")
    rig.agent.lines.put("ssh", "b")
    assert rig.send()["config"]["lines_dropped"] == 1


def test_off_mode_does_not_run_rules(tmp_path):
    rig = Rig(tmp_path, mode="off")
    rig.ssh_fails()
    assert not rig.agent._events
    assert not rig.agent.lines._q.qsize()


# -- connection sampling ------------------------------------------------------


def test_connections_feed_active_ssh_listening_and_rules(enforcing, monkeypatch):
    many = [est(80, IP) for _ in range(200)]
    monkeypatch.setattr(psutil, "net_connections",
                        lambda kind: [listen(22), listen(80), listen(8080), est(22, "198.51.100.7")] + many)
    enforcing.clock.t += 5
    enforcing.agent.tick()
    assert enforcing.protector.reason("198.51.100.7") == "active-ssh"
    assert ("limit4", IP, 0) in enforcing.nft.elems
    assert any("listening { 22, 80, 8080 }" in s for s in enforcing.nft.scripts())


def test_connection_sampling_runs_every_five_seconds(rig, monkeypatch):
    calls = []
    monkeypatch.setattr(psutil, "net_connections", lambda kind: calls.append(1) or [listen(22)])
    rig.agent.tick()
    rig.agent.tick()
    n = len(calls)
    rig.clock.t += 4
    rig.agent.tick()
    assert len(calls) == n
    rig.clock.t += 1
    rig.agent.tick()
    assert len(calls) == n + 1


def test_denied_sample_keeps_listening_and_active_ssh(rig, monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22), est(22, "198.51.100.7")])
    rig.clock.t += 5
    rig.agent.tick()

    def deny(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", deny)
    rig.clock.t += 5
    rig.agent.tick()
    assert rig.protector.reason("198.51.100.7") == "active-ssh"


def peers(cdn, other):
    return ([listen(443)] + [est(443, "104.16.0.%d" % n) for n in range(1, cdn + 1)]
            + [est(443, "198.18.0.%d" % n) for n in range(1, other + 1)])


def test_behind_cdn_hysteresis(rig, monkeypatch):
    def sample(conns):
        monkeypatch.setattr(psutil, "net_connections", lambda kind: conns)
        rig.clock.t += 5
        rig.agent.tick()
        return rig.send()["config"]["behind_cdn"]

    assert sample(peers(19, 0)) is False       # below 20 peers: keeps prior value
    assert sample(peers(10, 10)) is False      # exactly 50% is not more than 50%
    assert sample(peers(11, 10)) is True
    assert rig.engine._behind_cdn is True
    assert sample(peers(3, 20)) is True        # between 10% and 50%: unchanged
    assert sample(peers(0, 5)) is True         # below 20 peers: keeps prior value
    assert sample(peers(2, 18)) is True        # exactly 10% is not under 10%
    assert sample(peers(1, 19)) is False
    assert rig.engine._behind_cdn is False


def test_behind_cdn_known_before_first_decision(tmp_path, monkeypatch):
    monkeypatch.setattr(psutil, "net_connections", lambda kind: peers(30, 0))
    rig = Rig(tmp_path)
    assert rig.engine._behind_cdn is True


# -- background ---------------------------------------------------------------


def test_cdn_refresh_runs_after_first_delay_then_daily_and_survives_errors(rig, monkeypatch):
    waits, calls = [], []

    class Stop:
        def wait(self, delay):
            waits.append(delay)
            return len(waits) > 3

    def refresh():
        calls.append(1)
        raise RuntimeError("network")

    monkeypatch.setattr(rig.protector, "refresh_cdn_ranges", refresh)
    rig.agent._cdn_loop(Stop())
    assert waits == [3600, 86400, 86400, 86400]
    assert len(calls) == 3


# -- whole sequence -----------------------------------------------------------


def test_log_lines_to_kernel_block_to_sent_event_to_unblock(tmp_path):
    rig = Rig(tmp_path, mode="enforce")

    # Below threshold nothing happens.
    rig.ssh_fails(n=9)
    assert not rig.nft.elems
    assert rig.send()["events"] == []

    # Tenth failure: real engine decides, real enforcer writes, event and block reach central.
    rig.ssh_fails(n=1)
    assert ("port4", IP, 22) in rig.nft.elems
    p = rig.send()
    event = p["events"][0]
    assert (event["rule"], event["ip"], event["action"], event["ports"], event["ttl"], event["simulated"], event["ok"]) \
        == ("ssh_bruteforce", IP, "block_port", [22], 3600, False, True)
    assert SSH_FAIL.split("\n")[0] % IP in event["evidence"]
    assert p["active_blocks"][0]["ip"] == IP and p["active_blocks"][0]["rule"] == "ssh_bruteforce"
    assert rig.send()["events"] == []  # delivered once

    # Central outage: enforcement keeps running, the event waits.
    rig.client.down = True
    rig.ssh_fails("203.0.113.77")
    assert ("port4", "203.0.113.77", 22) in rig.nft.elems
    assert rig.agent.send_once() == 5
    rig.client.down = False

    # Recovery delivers it, with an unblock in the response.
    rig.client.commands = [Command(1, "unblock", {"ip": "203.0.113.77"})]
    assert rig.send()["events"][0]["ip"] == "203.0.113.77"
    rig.agent.tick()
    assert ("port4", "203.0.113.77", 22) not in rig.nft.elems
    assert ("port4", IP, 22) in rig.nft.elems
    assert rig.send()["acked_commands"] == [1]

    # Allowlisting the first IP lifts it and protects it from then on.
    rig.client.commands = [Command(2, "allowlist", {"ips": [IP]})]
    rig.send()
    rig.agent.tick()
    assert not rig.nft.elems
    rig.ssh_fails()
    assert not rig.nft.elems
    assert rig.engine.suppressed["allowlist"] == 1


# -- CLI and process ----------------------------------------------------------


def test_run_without_url_or_key_exits_with_clear_message(monkeypatch, capsys):
    monkeypatch.delenv("NEXUS_URL", raising=False)
    monkeypatch.delenv("NEXUS_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["run"])
    assert "NEXUS_URL" in str(exc.value.code)


def test_run_refuses_plain_http_to_a_remote_central(monkeypatch):
    monkeypatch.setenv("NEXUS_URL", "http://nexus.example.com")
    monkeypatch.setenv("NEXUS_API_KEY", "k")
    monkeypatch.delenv("NEXUS_INSECURE", raising=False)
    with pytest.raises(SystemExit) as exc:
        main([])
    assert "https" in str(exc.value.code)


def test_enroll_prints_identity_as_json(monkeypatch, capsys):
    seen = {}

    def enroll(url, token, hostname, allow_insecure=False):
        seen.update(url=url, token=token, hostname=hostname, insecure=allow_insecure)
        return "web-1", "the-key"

    monkeypatch.setattr(agent_main.Client, "enroll", staticmethod(enroll))
    assert main(["enroll", "--url", "https://c.example", "--token", "tok"]) == 0
    assert json.loads(capsys.readouterr().out) == {"node_id": "web-1", "api_key": "the-key"}
    assert seen["token"] == "tok" and seen["url"] == "https://c.example" and seen["hostname"]
    assert seen["insecure"] is False


def test_enroll_failure_exits_nonzero_without_token(monkeypatch):
    def enroll(*a, **k):
        raise ClientError("enrollment refused", 401)

    monkeypatch.setattr(agent_main.Client, "enroll", staticmethod(enroll))
    with pytest.raises(SystemExit) as exc:
        main(["enroll", "--url", "https://c.example", "--token", "tok-secret"])
    assert "refused" in str(exc.value.code) and "tok-secret" not in str(exc.value.code)


def test_uninstall_tears_down(monkeypatch):
    calls = []
    monkeypatch.setattr(agent_main.shutil, "which", lambda name: "/usr/sbin/nft")
    monkeypatch.setattr(Enforcer, "teardown", lambda self: calls.append(1) or True)
    assert main(["uninstall"]) == 0
    assert calls == [1]
    monkeypatch.setattr(Enforcer, "teardown", lambda self: False)
    assert main(["uninstall"]) == 1


def test_sigterm_exits_cleanly_without_teardown_and_never_logs_the_key(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    trace = tmp_path / "nft-calls"
    nft = bin_dir / "nft"
    nft.write_text('#!/bin/sh\necho "$@" >> %s\nexit 0\n' % trace)
    nft.chmod(0o755)
    env = dict(os.environ, NEXUS_URL="http://127.0.0.1:1", NEXUS_API_KEY="super-secret-key", NEXUS_MAX_MODE="observe",
               NEXUS_STATE_DIR=str(tmp_path / "state"), PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
               PYTHONPATH=os.getcwd())
    proc = subprocess.Popen([sys.executable, "-m", "nexus_agent", "run"], env=env, stderr=subprocess.PIPE, text=True)
    lines = []
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stderr.readline()
        lines.append(line)
        if "agent started" in line:
            break
    assert "agent started" in lines[-1], lines
    time.sleep(7)  # long enough for at least one failed send to be logged
    proc.send_signal(signal.SIGTERM)
    out = proc.stderr.read()
    assert proc.wait(15) == 0
    text = "".join(lines) + out
    assert "super-secret-key" not in text
    assert "central" in text  # the failed send was logged
    assert "delete table" not in (trace.read_text() if trace.exists() else "")


# -- fix round 1 --------------------------------------------------------------


def test_allowlist_not_acked_when_kernel_read_fails_then_lifts_on_redelivery(enforcing):
    enforcing.block()
    enforcing.nft.list_fails = True
    enforcing.agent.handle_command(Command(1, "allowlist", {"ips": [IP]}))
    assert ("port4", IP, 22) in enforcing.nft.elems
    assert enforcing.send()["acked_commands"] == []
    enforcing.nft.list_fails = False
    enforcing.agent.handle_command(Command(1, "allowlist", {"ips": [IP]}))
    assert not enforcing.nft.elems
    assert enforcing.send()["acked_commands"] == [1]


def test_allowlist_not_acked_when_a_removal_fails_and_engine_state_stays(enforcing, monkeypatch):
    enforcing.block()
    forgot = []
    monkeypatch.setattr(enforcing.enforcer, "remove", lambda ip: False)
    monkeypatch.setattr(enforcing.engine, "forget", forgot.append)
    enforcing.agent.handle_command(Command(1, "allowlist", {"ips": [IP]}))
    assert enforcing.send()["acked_commands"] == [] and forgot == []


def test_unblock_not_acked_when_real_kernel_read_fails(enforcing):
    enforcing.block()
    enforcing.nft.list_fails = True
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    assert enforcing.send()["acked_commands"] == []
    enforcing.nft.list_fails = False
    enforcing.agent.handle_command(Command(1, "unblock", {"ip": IP}))
    assert not enforcing.nft.elems


def test_failed_lift_is_reported_and_next_tick_clears_the_block(enforcing, caplog):
    enforcing.block()
    enforcing.nft.flush_fails = True
    enforcing.agent.handle_command(Command(1, "mode", {"mode": "off"}))
    assert enforcing.enforcer.mode == "off" and enforcing.nft.elems
    assert enforcing.send()["config"]["lift_pending"] is True
    enforcing.agent.tick()
    assert enforcing.nft.elems
    enforcing.nft.flush_fails = False
    enforcing.agent.tick()
    assert not enforcing.nft.elems
    assert enforcing.send()["config"]["lift_pending"] is False


def test_old_failed_logins_never_reach_detection(enforcing):
    old = time.strftime("%b %e %H:%M:%S", time.localtime(enforcing.clock() - 3600))
    for _ in range(10):
        enforcing.agent.lines.put("ssh", old + " web01 " + SSH_FAIL % IP)
    enforcing.agent.tick()
    assert not enforcing.nft.elems and not enforcing.agent._events
    assert enforcing.send()["config"]["stale_lines"] == 10


def test_current_timestamped_failed_logins_do_reach_detection(enforcing):
    cur = time.strftime("%b %e %H:%M:%S", time.localtime(enforcing.clock()))
    for _ in range(10):
        enforcing.agent.lines.put("ssh", cur + " web01 " + SSH_FAIL % IP)
    enforcing.agent.tick()
    assert ("port4", IP, 22) in enforcing.nft.elems


def test_old_web_lines_are_dropped_too(rig, monkeypatch):
    fed = []
    monkeypatch.setattr(rig.engine, "feed", lambda e: fed.append(e) or [])
    fmt = '203.0.113.9 - - [%s] "GET /x HTTP/1.1" 404 5 "-" "ua"\n'
    rig.agent.lines.put("web", fmt % time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(rig.clock() - 3600)))
    rig.agent.lines.put("web", fmt % time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(rig.clock())))
    rig.agent.tick()
    assert len(fed) == 1


class Idle:
    def __init__(self, seconds):
        self.seconds = seconds

    def ssh_idle_seconds(self):
        return self.seconds


def test_warns_once_when_ssh_sessions_exist_but_the_source_is_silent(rig, monkeypatch, caplog):
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22), est(22, "198.51.100.7")])
    rig.agent.collectors = Idle(3601)
    for _ in range(3):
        rig.clock.t += 5
        rig.agent.tick()
    assert sum("no line" in r.message for r in caplog.records) == 1


def test_no_silence_warning_without_sessions_or_within_the_hour(rig, monkeypatch, caplog):
    rig.agent.collectors = Idle(99999)
    rig.clock.t += 5
    rig.agent.tick()
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22), est(22, "198.51.100.7")])
    rig.agent.collectors = Idle(3599)
    rig.clock.t += 5
    rig.agent.tick()
    assert "no line" not in caplog.text


ACCEPTED = "sshd[1]: Accepted publickey for root from %s port 4242 ssh2\n"


def test_accepted_line_through_agent_reaches_protector(rig, monkeypatch):
    seen = []
    real = rig.protector.note_ssh_ok
    monkeypatch.setattr(rig.protector, "note_ssh_ok", lambda ip: seen.append(ip) or real(ip))
    rig.agent.lines.put("ssh", ACCEPTED % IP)
    rig.agent.tick()
    assert seen == [IP] and rig.protector.reason(IP) == "recent-ssh"


def test_accepted_line_in_off_mode_feeds_only_the_protector(tmp_path, monkeypatch):
    rig = Rig(tmp_path, mode="off")
    fed = []
    monkeypatch.setattr(rig.engine, "feed", lambda e: fed.append(e) or [])
    rig.agent.lines.put("ssh", ACCEPTED % IP)
    rig.agent.lines.put("ssh", SSH_FAIL % "203.0.113.77")
    rig.agent.tick()
    assert rig.protector.reason(IP) == "recent-ssh"
    assert fed == []


def test_recent_ssh_survives_restart_and_write_is_throttled(tmp_path, monkeypatch):
    rig = Rig(tmp_path)
    writes = []
    real = agent_main.save_state
    monkeypatch.setattr(agent_main, "save_state", lambda *a: writes.append(a) or real(*a))
    rig.agent.lines.put("ssh", ACCEPTED % IP)
    rig.agent.tick()
    assert writes == []  # within the 60s throttle
    rig.clock.t += 60
    rig.agent.tick()
    assert len(writes) == 1
    rig.clock.t += 60
    rig.agent.tick()
    assert len(writes) == 1  # unchanged
    assert Rig(tmp_path).protector.reason(IP) == "recent-ssh"


def test_recent_ssh_past_24h_is_pruned_on_load(tmp_path):
    rig = Rig(tmp_path)
    save_state(tmp_path, "observe", [], [[IP, rig.clock() - 1]])
    assert Rig(tmp_path).protector.reason(IP) is None


def test_first_successful_send_is_written_to_state(rig):
    rig.agent.send_once()
    rig.agent.tick()
    data = json.loads((rig.cfg.state_dir / "state.json").read_text())
    assert data["last_send"] == rig.clock()
    assert data["mode"] == "observe"


def test_failed_send_is_not_written_to_state(rig):
    rig.client.down = True
    rig.agent.send_once()
    rig.agent.tick()
    assert not (rig.cfg.state_dir / "state.json").exists()


def test_last_send_is_refreshed_but_not_on_every_send(rig, monkeypatch):
    writes = []
    monkeypatch.setattr(agent_main, "save_state", lambda *a: writes.append(a) or True)
    for _ in range(5):
        rig.agent.send_once()
        rig.agent.tick()
    assert len(writes) == 1
    rig.clock.t += 61
    rig.agent.send_once()
    rig.agent.tick()
    assert len(writes) == 2 and writes[-1][-1] == rig.clock()


def test_no_state_write_when_nothing_changed(rig):
    rig.clock.t += 120
    rig.agent.tick()
    assert load_state(rig.cfg.state_dir) is None


def test_enforce_waits_for_a_successful_sample(tmp_path, monkeypatch):
    def deny(kind):
        raise psutil.AccessDenied()

    save_state(tmp_path, "enforce", [])
    monkeypatch.setattr(psutil, "net_connections", deny)
    rig = Rig(tmp_path)
    assert rig.enforcer.mode == "observe"
    assert not any("add table" in s for s in rig.nft.scripts())
    assert rig.send()["config"]["enforce_waiting_sample"] is True
    assert load_state(tmp_path)[0] == "enforce"
    rig.clock.t += 5
    rig.agent.tick()
    assert rig.enforcer.mode == "observe"
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22)])
    rig.clock.t += 5
    rig.agent.tick()
    assert rig.enforcer.mode == "enforce"
    assert rig.send()["config"]["enforce_waiting_sample"] is False
    assert any("listening { 22 }" in s for s in rig.nft.scripts())


def test_enforce_command_also_waits_for_a_sample_and_later_mode_cancels(tmp_path, monkeypatch):
    def deny(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", deny)
    rig = Rig(tmp_path)
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    assert rig.enforcer.mode == "observe" and load_state(tmp_path)[0] == "enforce"
    rig.agent.handle_command(Command(2, "mode", {"mode": "observe"}))
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(22)])
    rig.clock.t += 5
    rig.agent.tick()
    assert rig.enforcer.mode == "observe"


def test_spoofable_syn_recv_does_not_count_toward_conn_flood(enforcing, monkeypatch):
    syn = Conn(Addr("198.51.100.1", 80), Addr(IP, 50000), "SYN_RECV")
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [listen(80)] + [syn] * 300)
    enforcing.clock.t += 5
    enforcing.agent.tick()
    assert not enforcing.nft.elems


def test_network_refresh_updates_and_keeps_old_on_empty(rig, monkeypatch):
    monkeypatch.setattr(agent_main, "read_gateways", lambda: ["192.0.2.2"])
    monkeypatch.setattr(agent_main, "read_resolvers", lambda: ["192.0.2.3"])
    monkeypatch.setattr(agent_main, "resolve_host", lambda host: ["192.0.2.1"] if host == "c.example" else [])
    assert rig.agent._refresh_network() is True
    assert rig.protector.reason("192.0.2.1") == "central"
    monkeypatch.setattr(agent_main, "resolve_host", lambda host: [])
    assert rig.agent._refresh_network() is False
    assert rig.protector.reason("192.0.2.1") == "central"


def test_network_loop_retries_empty_sooner_and_survives_errors(rig, monkeypatch):
    results = iter([False, True, RuntimeError("x")])
    waits = []

    class Stop:
        def wait(self, delay):
            waits.append(delay)
            return len(waits) > 3

    def refresh():
        r = next(results)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(rig.agent, "_refresh_network", refresh)
    rig.agent._network_loop(Stop())
    assert waits == [300, 60, 300, 60]


def test_breaker_event_is_not_simulated_in_observe(tmp_path):
    rig = Rig(tmp_path, max_new=1)
    rig.agent._apply([Decision("r", "203.0.113.%d" % n, "block_port", (22,), 3600, "e") for n in (1, 2)])
    breaker = [e for e in rig.agent._events if e["rule"] == "breaker"]
    assert len(breaker) == 1 and breaker[0]["simulated"] is False
    down = [e for e in rig.agent._events if e["rule"] == "r"][1]
    assert down["action"] == "rate_limit" and down["ttl"] == 600 and down["simulated"] is True


def test_real_alert_decision_in_observe_is_not_simulated(rig):
    for port in range(1000, 1020):
        rig.agent.lines.put("scan", scan(IP, port))
    rig.agent.tick()
    e = rig.agent._events[-1]
    assert (e["rule"], e["action"], e["simulated"], e["ok"]) == ("port_scan", "alert", False, True)


def test_failed_downgraded_write_reports_rate_limit(tmp_path, monkeypatch):
    rig = Rig(tmp_path, mode="enforce", max_new=1)
    rig.agent._apply([Decision("r", "203.0.113.1", "block_port", (22,), 3600, "e")])
    real = rig.nft.__call__
    monkeypatch.setattr(rig.enforcer, "_run", lambda argv, input_text=None: (1, "Error: x") if "limit4" in " ".join(argv) else real(argv, input_text))
    rig.agent._apply([Decision("r", "203.0.113.2", "block_port", (22,), 3600, "e")])
    e = [e for e in rig.agent._events if e["rule"] == "r"][-1]
    assert (e["action"], e["ttl"], e["ok"]) == ("rate_limit", 600, False)


def test_clamped_enforce_is_reported_with_reason_and_capability_stays(tmp_path):
    rig = Rig(tmp_path, max_mode="observe")
    rig.agent.handle_command(Command(1, "mode", {"mode": "enforce"}))
    p = rig.send()
    assert p["config"]["enforce_rejected"] is True and p["config"]["enforce_rejected_reason"] == "max_mode"
    assert p["capabilities"]["enforce"] is True
    rig.agent.handle_command(Command(2, "mode", {"mode": "observe"}))
    cfg = rig.send()["config"]
    assert cfg["enforce_rejected"] is False and cfg["enforce_rejected_reason"] is None


def test_persisted_enforce_clamped_at_startup_is_reported(tmp_path):
    save_state(tmp_path, "enforce", [])
    assert Rig(tmp_path, max_mode="observe").send()["config"]["enforce_rejected_reason"] == "max_mode"


def test_send_loop_survives_error(rig, monkeypatch):
    calls = []

    class Stop:
        def wait(self, delay):
            return len(calls) >= 2

    def boom():
        calls.append(1)
        raise RuntimeError("x")

    monkeypatch.setattr(rig.agent, "send_once", boom)
    rig.agent._send_loop(Stop())
    assert len(calls) == 2


def test_dead_send_thread_is_restarted_and_logged(rig, monkeypatch, caplog):
    stop = threading.Event()
    rig.agent.collectors = None
    rig.agent._send_thread = threading.Thread(target=lambda: None)
    rig.agent._send_thread.start()
    rig.agent._send_thread.join()
    rig.agent._check_threads(stop)
    assert rig.agent._send_thread.is_alive()
    assert "send thread" in caplog.text
    stop.set()
    rig.agent._send_thread.join(5)


def test_enroll_prefers_env_token_and_requires_one(monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(agent_main.Client, "enroll",
                        staticmethod(lambda url, token, host, allow_insecure=False: seen.update(t=token) or ("n", "k")))
    monkeypatch.setenv("NEXUS_ENROLL_TOKEN", "env-tok")
    assert main(["enroll", "--url", "https://c.example"]) == 0
    assert seen["t"] == "env-tok"
    assert main(["enroll", "--url", "https://c.example", "--token", "arg-tok"]) == 0
    assert seen["t"] == "env-tok"
    monkeypatch.delenv("NEXUS_ENROLL_TOKEN")
    with pytest.raises(SystemExit) as exc:
        main(["enroll", "--url", "https://c.example"])
    assert "NEXUS_ENROLL_TOKEN" in str(exc.value.code)


def test_uninstall_without_nft_exits_zero_with_message(monkeypatch, capsys):
    monkeypatch.setattr(agent_main.shutil, "which", lambda name: None)
    monkeypatch.setattr(Enforcer, "teardown", lambda self: pytest.fail("no nft to call"))
    assert main(["uninstall"]) == 0
    assert "nft" in capsys.readouterr().out
