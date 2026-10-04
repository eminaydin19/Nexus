import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.defense import ActiveDefender, SafeModeMiddleware, firewall_commands, firewall_setup_commands


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Recorder:
    def __init__(self, code: int = 0):
        self.calls: list[list[str]] = []
        self.code = code

    async def __call__(self, argv):
        self.calls.append(argv)
        return self.code, "boom" if self.code else ""


def make(mode="enforce", runner=None, clock=None, **kwargs):
    events = []

    async def sink(event):
        events.append(event)

    defender = ActiveDefender(
        critical_score=0.85,
        mode=mode,
        firewall=kwargs.pop("firewall", "iptables"),
        block_seconds=300,
        safe_mode_seconds=60,
        allowlist=kwargs.pop("allowlist", ["10.0.0.0/24"]),
        runner=runner or Recorder(),
        clock=clock or FakeClock(),
        on_event=sink,
    )
    return defender, events


def run(coro):
    return asyncio.run(coro)


def test_below_critical_does_nothing():
    defender, events = make()
    run(defender.mitigate("n1", 0.5, "203.0.113.5"))
    assert not defender.safe_mode and not defender.blocked and not events


def test_mode_off_does_nothing():
    defender, events = make(mode="off")
    run(defender.mitigate("n1", 0.99, "203.0.113.5"))
    assert not defender.safe_mode and not events


def test_dry_run_records_but_never_executes():
    runner = Recorder()
    defender, events = make(mode="dry_run", runner=runner)
    run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    assert runner.calls == []
    assert defender.safe_mode
    assert defender.blocked["203.0.113.5"]["simulated"] is True
    assert {e["type"] for e in events} == {"safe_mode", "block"}


def test_enforce_runs_firewall_command():
    runner = Recorder()
    defender, _ = make(runner=runner)
    run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    assert runner.calls == [["iptables", "-I", "INPUT", "1", "-s", "203.0.113.5", "-j", "DROP"]]
    assert defender.blocked["203.0.113.5"]["simulated"] is False


def test_allowlisted_and_loopback_are_never_blocked():
    runner = Recorder()
    defender, events = make(runner=runner)
    run(defender.mitigate("n1", 0.95, "10.0.0.7"))
    run(defender.mitigate("n1", 0.95, "127.0.0.1"))
    assert runner.calls == [] and not defender.blocked
    assert [e["type"] for e in events].count("block_skipped") == 2


def test_failed_command_is_not_tracked_as_blocked():
    defender, events = make(runner=Recorder(code=1))
    run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    assert not defender.blocked
    assert any(e["type"] == "block_failed" and e["ok"] is False for e in events)


def test_same_ip_is_blocked_once():
    runner = Recorder()
    defender, _ = make(runner=runner)
    for _ in range(3):
        run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    assert len(runner.calls) == 1


def test_block_expires_and_is_lifted():
    runner, clock = Recorder(), FakeClock()
    defender, events = make(runner=runner, clock=clock)
    run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    clock.now += 301
    run(defender.sweep_expired())
    assert not defender.blocked
    assert runner.calls[-1] == ["iptables", "-D", "INPUT", "-s", "203.0.113.5", "-j", "DROP"]
    assert events[-1]["type"] == "unblock"


def test_safe_mode_expires():
    clock = FakeClock()
    defender, _ = make(clock=clock)
    run(defender.mitigate("n1", 0.95))
    assert defender.is_safe_mode_active()
    clock.now += 61
    assert not defender.is_safe_mode_active()


def test_manual_unblock_and_shutdown_lift_rules():
    runner = Recorder()
    defender, _ = make(runner=runner)
    run(defender.mitigate("n1", 0.95, "203.0.113.5"))
    run(defender.mitigate("n2", 0.95, "203.0.113.6"))
    assert run(defender.unblock("203.0.113.5")) is True
    assert run(defender.unblock("203.0.113.5")) is False
    run(defender.shutdown())
    assert not defender.blocked


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        ActiveDefender(mode="yolo")


@pytest.mark.parametrize(
    ("backend", "ip", "expected"),
    [
        ("iptables", "203.0.113.5", ["iptables", "-I", "INPUT", "1", "-s", "203.0.113.5", "-j", "DROP"]),
        ("iptables", "2001:db8::1", ["ip6tables", "-I", "INPUT", "1", "-s", "2001:db8::1", "-j", "DROP"]),
        ("nftables", "203.0.113.5", ["nft", "add", "element", "inet", "nexus", "blocked4", "{ 203.0.113.5 }"]),
        ("nftables", "2001:db8::1", ["nft", "add", "element", "inet", "nexus", "blocked6", "{ 2001:db8::1 }"]),
        ("pfctl", "203.0.113.5", ["pfctl", "-t", "nexus_blocked", "-T", "add", "203.0.113.5"]),
    ],
)
def test_firewall_command_construction(backend, ip, expected):
    assert firewall_commands(backend, "block", ip) == [expected]


def test_firewall_commands_reject_non_ip_input():
    with pytest.raises(ValueError):
        firewall_commands("iptables", "block", "1.2.3.4; rm -rf /")


def test_nft_setup_only_for_nftables():
    assert firewall_setup_commands("iptables") == []
    assert firewall_setup_commands("nftables")[0][:3] == ["nft", "add", "table"]


def _app(defender):
    app = FastAPI()
    app.add_middleware(SafeModeMiddleware, defender=defender)

    for path in ("/api/nodes", "/api/ingest", "/api/health", "/api/defense", "/healthz"):
        app.get(path)(lambda: {"ok": True})
    return app


def test_safe_mode_rejects_only_non_essential_api():
    defender, _ = make(clock=FakeClock())
    defender.safe_mode = True
    defender.safe_mode_until = defender._clock() + 60
    # Middleware compares against wall clock for Retry-After only; state comes from the fake clock.
    client = TestClient(_app(defender))
    assert client.get("/api/nodes").status_code == 503
    for path in ("/api/ingest", "/api/health", "/api/defense", "/healthz"):
        assert client.get(path).status_code == 200


def test_normal_mode_passes_everything():
    defender, _ = make()
    assert TestClient(_app(defender)).get("/api/nodes").status_code == 200
