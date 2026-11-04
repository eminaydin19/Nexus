from __future__ import annotations

import json

import pytest

from nexus_agent.enforcer import ApplyResult, Enforcer
from nexus_agent.rules import Decision


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakeRunner:
    def __init__(self, responses=None):
        self.calls, self.inputs, self.responses = [], [], responses or {}

    def __call__(self, argv, input_text=None):
        self.calls.append(list(argv))
        self.inputs.append(input_text)
        for key, resp in self.responses.items():
            if key in " ".join(argv):
                return resp
        return 0, ""


def dec(action="block_port", ip="203.0.113.9", ports=(22,), ttl=3600, rule="ssh_bruteforce"):
    return Decision(rule, ip, action, tuple(ports), ttl, "ev")


def make(mode="enforce", runner=None, **kw):
    clock = Clock()
    runner = runner or FakeRunner()
    return Enforcer(mode, runner, clock, **kw), runner, clock


def table_json(*sets):
    return json.dumps({"nftables": [{"set": {"name": n, "elem": e}} for n, e in sets]})


def test_observe_never_runs_nft():
    enf, runner, _ = make("observe")
    res = enf.apply(dec())
    assert res == ApplyResult(True, True, "observe")
    assert enf.set_mode("observe") and enf.update_listening([22]) is not None
    assert runner.calls == []


def test_off_does_nothing():
    enf, runner, _ = make("off")
    assert enf.apply(dec()) == ApplyResult(False, False, "off")
    assert runner.calls == []


def test_alert_is_noop():
    enf, runner, _ = make("enforce")
    assert enf.apply(dec("alert")) == ApplyResult(True, False, "alert")
    assert runner.calls == []


def test_block_port_argv_exact():
    enf, runner, _ = make()
    res = enf.apply(dec())
    assert res.ok and not res.simulated
    assert ["nft", "add", "element", "inet", "nexus", "port4", "{ 203.0.113.9 . 22 timeout 3600s }"] in runner.calls


def test_block_port_one_element_per_port():
    enf, runner, _ = make()
    enf.apply(dec(ports=(80, 443, 80)))
    assert runner.calls == [["nft", "add", "element", "inet", "nexus", "port4",
                             "{ 203.0.113.9 . 80 timeout 3600s, 203.0.113.9 . 443 timeout 3600s }"]]


def test_block_all_and_rate_limit_argv():
    enf, runner, _ = make()
    enf.apply(dec("block_all", ports=()))
    enf.apply(dec("rate_limit", ip="198.51.100.1", ports=(), ttl=60))
    assert ["nft", "add", "element", "inet", "nexus", "all4", "{ 203.0.113.9 timeout 3600s }"] in runner.calls
    assert ["nft", "add", "element", "inet", "nexus", "limit4", "{ 198.51.100.1 timeout 60s }"] in runner.calls


def test_ipv6_blocked_as_64():
    enf, runner, _ = make()
    enf.apply(dec(ip="2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
    enf.apply(dec("block_all", ip="2001:db8:1:2::5", ports=()))
    assert ["nft", "add", "element", "inet", "nexus", "port6", "{ 2001:db8:1:2:: . 22 timeout 3600s }"] in runner.calls
    assert ["nft", "add", "element", "inet", "nexus", "all6", "{ 2001:db8:1:2:: timeout 3600s }"] in runner.calls


def test_ipv4_mapped_ipv6_uses_v4_set():
    enf, runner, _ = make()
    enf.apply(dec(ip="::ffff:203.0.113.9"))
    assert runner.calls[0][5] == "port4"


@pytest.mark.parametrize("ip", ["", "not-an-ip", "1.2.3", "1.2.3.4/24", "fe80::1%eth0", "1.2.3.4; reboot", " 1.2.3.4"])
def test_invalid_ip_raises_before_exec(ip):
    enf, runner, _ = make()
    with pytest.raises(ValueError):
        enf.apply(dec(ip=ip))
    assert runner.calls == []


@pytest.mark.parametrize("kw", [{"ports": ()}, {"ttl": 0}, {"ttl": -5}, {"ports": (0,)}, {"ports": (70000,)}])
def test_invalid_block_raises(kw):
    enf, runner, _ = make()
    with pytest.raises(ValueError):
        enf.apply(dec(**kw))
    assert runner.calls == []


def test_ttl_clamped_to_one_day():
    enf, runner, _ = make()
    enf.apply(dec(ttl=10**9))
    assert runner.calls[0][-1].endswith("timeout 86400s }")


def test_file_exists_is_success():
    enf, _, _ = make(runner=FakeRunner({"add element": (1, "Error: Could not process rule: File exists")}))
    assert enf.apply(dec()).ok


def test_failure_reported_and_not_counted():
    enf, _, _ = make(runner=FakeRunner({"add element": (1, "Error: boom")}))
    res = enf.apply(dec())
    assert not res.ok and "boom" in res.detail
    assert enf.active() == []


def test_breaker_opens_after_50_in_5m():
    enf, runner, clock = make()
    for i in range(50):
        assert enf.apply(dec(ip="203.0.113.%d" % (i + 1))).detail == ""
    assert not enf.breaker_open
    res = enf.apply(dec(ip="198.51.100.77", ttl=3600))
    assert res.ok and res.detail == "breaker: rate_limit"
    assert enf.breaker_open
    assert runner.calls[-1] == ["nft", "add", "element", "inet", "nexus", "limit4", "{ 198.51.100.77 timeout 600s }"]
    assert not any("198.51.100.77" in " ".join(c) and "port4" in c for c in runner.calls)


def test_breaker_closes_when_window_clears():
    enf, _, clock = make()
    for i in range(51):
        enf.apply(dec(ip="203.0.113.%d" % (i + 1), ttl=60))
    assert enf.breaker_open
    clock.t += 301
    assert not enf.breaker_open
    assert enf.apply(dec(ip="198.51.100.9")).detail == ""


def test_breaker_rate_limit_never_downgraded_or_counted():
    enf, _, _ = make(max_new_per_5m=2)
    for i in range(10):
        assert enf.apply(dec("rate_limit", ip="203.0.113.%d" % (i + 1), ports=())).detail == ""
    assert not enf.breaker_open


def test_breaker_reapplying_same_block_not_new():
    enf, _, _ = make(max_new_per_5m=2)
    for _ in range(5):
        assert enf.apply(dec()).detail == ""


def test_breaker_active_limit():
    enf, _, _ = make(max_active=2)
    enf.apply(dec(ip="203.0.113.1"))
    enf.apply(dec(ip="203.0.113.2"))
    assert enf.apply(dec(ip="203.0.113.3")).detail == "breaker: rate_limit"


def test_breaker_counts_simulated_in_observe():
    enf, runner, _ = make("observe", max_new_per_5m=1)
    enf.apply(dec(ip="203.0.113.1"))
    res = enf.apply(dec(ip="203.0.113.2"))
    assert res.simulated and res.detail == "breaker: rate_limit" and enf.breaker_open
    assert runner.calls == []


def test_observe_active_is_simulated_and_pruned():
    enf, _, clock = make("observe")
    enf.apply(dec(ports=(22, 80), ttl=100))
    enf.apply(dec("block_all", ip="203.0.113.5", ports=(), ttl=500))
    got = {b.ip: b for b in enf.active()}
    assert got["203.0.113.9"].ports == [22, 80] and got["203.0.113.9"].simulated
    assert got["203.0.113.9"].until == clock.t + 100 and got["203.0.113.9"].rule == "ssh_bruteforce"
    clock.t += 200
    assert [b.ip for b in enf.active()] == ["203.0.113.5"]


def test_active_reads_kernel():
    out = table_json(
        ("port4", [{"elem": {"val": {"concat": ["203.0.113.9", 22]}, "timeout": 3600, "expires": 120}},
                   {"elem": {"val": {"concat": ["203.0.113.9", 80]}, "timeout": 3600, "expires": 50}}]),
        ("all6", [{"elem": {"val": "2001:db8:1:2::", "timeout": 60, "expires": 30}}]),
        ("limit4", [{"elem": {"val": "198.51.100.1", "timeout": 60, "expires": 30}}]),
        ("listening", [22, 80]),
        ("all4", [{"elem": {"val": "203.0.113.50", "expires": 0}}]),
    )
    enf, runner, clock = make(runner=FakeRunner({"-j list table": (0, out)}))
    enf.apply(dec())
    got = {b.ip: b for b in enf.active()}
    assert runner.calls[-1] == ["nft", "-j", "list", "table", "inet", "nexus"]
    assert got["203.0.113.9"].ports == [22, 80] and got["203.0.113.9"].until == clock.t + 120
    assert got["203.0.113.9"].rule == "ssh_bruteforce" and not got["203.0.113.9"].simulated
    assert got["2001:db8:1:2::"].rule == "unknown" and got["2001:db8:1:2::"].ports == []
    assert got["198.51.100.1"].until == clock.t + 30
    assert "22" not in got


def test_active_malformed_json_returns_empty(caplog):
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, "{nope")}))
    assert enf.active() == []
    assert "nexus" in caplog.text


def test_active_capped_keeps_longest_lived():
    elems = [{"elem": {"val": "10.%d.%d.1" % (i // 250, i % 250), "expires": i + 1}} for i in range(1200)]
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, table_json(("all4", elems)))}))
    got = enf.active()
    assert len(got) == 1000 and min(b.until for b in got) == 1_000_000.0 + 201


def test_setup_single_atomic_transaction():
    enf, runner, _ = make(runner=FakeRunner({"list chain": (1, "Error: No such file or directory")}))
    assert enf.setup() and enf.capable
    assert runner.calls.count(["nft", "-f", "-"]) == 1
    script = runner.inputs[runner.calls.index(["nft", "-f", "-"])]
    for needle in ["add table inet nexus", "add set inet nexus port4", "ipv4_addr . inet_service",
                   "add chain inet nexus prerouting { type filter hook prerouting priority -150; policy accept; }",
                   "ip saddr . tcp dport @port4 drop", "ip saddr @all4 drop",
                   "ip6 saddr & ffff:ffff:ffff:ffff:: . tcp dport @port6 drop",
                   "ip6 saddr & ffff:ffff:ffff:ffff:: @all6 drop",
                   "ip saddr @limit4 ct state new", "limit rate over 50/second",
                   'log prefix "nexus-scan "', "tcp dport != @listening"]:
        assert needle in script
    assert "flush ruleset" not in script and "interval" not in script


def test_setup_idempotent_skips_rules_when_present():
    present = json.dumps({"nftables": [{"rule": {"chain": "prerouting"}}]})
    enf, runner, _ = make(runner=FakeRunner({"list chain": (0, present)}))
    assert enf.setup()
    script = runner.inputs[runner.calls.index(["nft", "-f", "-"])]
    assert "add set inet nexus port4" in script
    assert "add rule" not in script


def test_setup_nft_missing():
    enf, _, _ = make(runner=FakeRunner({"nft": (127, "")}))
    assert enf.setup() is False and enf.capable is False


def test_setup_seeds_active_count_from_kernel():
    out = table_json(("all4", [{"elem": {"val": "10.0.0.%d" % i, "expires": 99}} for i in range(1, 4)]))
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out), "list chain": (1, "")}), max_active=3)
    enf.setup()
    assert enf.apply(dec()).detail == "breaker: rate_limit"


def test_remove_deletes_from_all_known_sets():
    out = table_json(
        ("port4", [{"elem": {"val": {"concat": ["203.0.113.9", 22]}, "expires": 5}},
                   {"elem": {"val": {"concat": ["203.0.113.9", 80]}, "expires": 5}},
                   {"elem": {"val": {"concat": ["203.0.113.10", 80]}, "expires": 5}}]),
        ("all4", [{"elem": {"val": "203.0.113.9", "expires": 5}}]),
        ("all6", [{"elem": {"val": "2001:db8:1:2::", "expires": 5}}]),
    )
    enf, runner, _ = make(runner=FakeRunner({"-j list table": (0, out)}))
    assert enf.remove("203.0.113.9")
    dels = [c for c in runner.calls if "delete" in c]
    assert sorted(c[-1] for c in dels) == ["{ 203.0.113.9 . 22 }", "{ 203.0.113.9 . 80 }", "{ 203.0.113.9 }"]
    runner.calls.clear()
    assert enf.remove("2001:db8:1:2:9::1")
    assert [c[-2:] for c in runner.calls if "delete" in c] == [["all6", "{ 2001:db8:1:2:: }"]]


def test_remove_absent_is_true_and_failure_false():
    enf, runner, _ = make(runner=FakeRunner({"-j list table": (0, table_json())}))
    assert enf.remove("203.0.113.9") is True
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 5}}]))
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out), "delete element": (1, "Error: boom")}))
    assert enf.remove("203.0.113.9") is False
    out_missing = FakeRunner({"-j list table": (0, out), "delete element": (1, "Error: No such file or directory")})
    assert make(runner=out_missing)[0].remove("203.0.113.9") is True


def test_remove_observe_drops_simulated():
    enf, runner, _ = make("observe")
    enf.apply(dec())
    assert enf.remove("203.0.113.9") and enf.active() == [] and runner.calls == []


def test_remove_invalid_ip_raises():
    enf, _, _ = make()
    with pytest.raises(ValueError):
        enf.remove("bogus")


def test_update_listening_atomic_and_skips_unchanged():
    enf, runner, _ = make()
    assert enf.update_listening([443, 22, 22])
    assert runner.calls == [["nft", "-f", "-"]]
    assert runner.inputs[0] == "flush set inet nexus listening\nadd element inet nexus listening { 22, 443 }\n"
    assert enf.update_listening([22, 443])
    assert len(runner.calls) == 1


def test_update_listening_empty():
    enf, runner, _ = make()
    enf.update_listening([22])
    enf.update_listening([])
    assert runner.inputs[-1] == "flush set inet nexus listening\n"


def test_update_listening_failure_not_cached():
    enf, runner, _ = make(runner=FakeRunner({"-f -": (1, "Error")}))
    assert enf.update_listening([22]) is False
    runner.responses.clear()
    assert enf.update_listening([22]) is True and len(runner.calls) == 2


def test_teardown():
    enf, runner, _ = make()
    assert enf.teardown()
    assert runner.calls == [["nft", "delete", "table", "inet", "nexus"]]
    enf, _, _ = make(runner=FakeRunner({"delete table": (1, "Error: No such file or directory")}))
    assert enf.teardown()
    enf, _, _ = make(runner=FakeRunner({"delete table": (1, "Error: denied")}))
    assert enf.teardown() is False


def test_set_mode():
    enf, runner, _ = make("observe", runner=FakeRunner({"list chain": (1, "")}))
    assert enf.set_mode("enforce") and enf.mode == "enforce" and enf.capable
    n = len(runner.calls)
    assert enf.set_mode("observe") and enf.mode == "observe"
    assert len(runner.calls) == n
    with pytest.raises(ValueError):
        enf.set_mode("block")


def test_set_mode_enforce_failure_stays_observe(caplog):
    enf, _, _ = make("off", runner=FakeRunner({"nft": (127, "")}))
    assert enf.set_mode("enforce") is False
    assert enf.mode == "observe" and "nexus" in caplog.text


def test_default_runner_maps_errors():
    from nexus_agent.enforcer import run_command
    assert run_command(["definitely-not-a-binary-xyz"])[0] == 127
    assert run_command(["sh", "-c", "sleep 5"], timeout=0.2)[0] == 124
    assert run_command(["cat"], "hi") == (0, "hi")
