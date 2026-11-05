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
        hay = " ".join(argv) + " " + (input_text or "")
        for key, resp in self.responses.items():
            if key in hay:
                return resp
        return 0, EMPTY if argv[:3] == ["nft", "-j", "list"] else ""


EMPTY = json.dumps({"nftables": []})
NO_TABLE = (1, "Error: No such file or directory")


def writes(runner):
    return [c for c in runner.calls if "-j" not in c]


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
    assert ["nft", "add", "element", "inet", "nexus", "port4", "{ 203.0.113.9 . 22 timeout 3600s comment \"ssh_bruteforce\" }"] in runner.calls


def test_block_port_one_element_per_port():
    enf, runner, _ = make()
    enf.apply(dec(ports=(80, 443, 80)))
    assert writes(runner) == [["nft", "add", "element", "inet", "nexus", "port4",
                               "{ 203.0.113.9 . 80 timeout 3600s comment \"ssh_bruteforce\", 203.0.113.9 . 443 timeout 3600s comment \"ssh_bruteforce\" }"]]


def test_block_all_and_rate_limit_argv():
    enf, runner, _ = make()
    enf.apply(dec("block_all", ports=()))
    enf.apply(dec("rate_limit", ip="198.51.100.1", ports=(), ttl=60))
    assert ["nft", "add", "element", "inet", "nexus", "all4", "{ 203.0.113.9 timeout 3600s comment \"ssh_bruteforce\" }"] in runner.calls
    assert ["nft", "add", "element", "inet", "nexus", "limit4", "{ 198.51.100.1 timeout 60s comment \"ssh_bruteforce\" }"] in runner.calls


def test_ipv6_blocked_as_64():
    enf, runner, _ = make()
    enf.apply(dec(ip="2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
    enf.apply(dec("block_all", ip="2001:db8:1:2::5", ports=()))
    assert ["nft", "add", "element", "inet", "nexus", "port6", "{ 2001:db8:1:2:: . 22 timeout 3600s comment \"ssh_bruteforce\" }"] in runner.calls
    assert ["nft", "add", "element", "inet", "nexus", "all6", "{ 2001:db8:1:2:: timeout 3600s comment \"ssh_bruteforce\" }"] in runner.calls


def test_ipv4_mapped_ipv6_uses_v4_set():
    enf, runner, _ = make()
    enf.apply(dec(ip="::ffff:203.0.113.9"))
    assert writes(runner)[0][5] == "port4"


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
    assert writes(runner)[0][-1].endswith("timeout 86400s comment \"ssh_bruteforce\" }")


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
    assert writes(runner)[-1] == ["nft", "add", "element", "inet", "nexus", "limit4", "{ 198.51.100.77 timeout 600s comment \"ssh_bruteforce\" }"]
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
    enf, runner, _ = make(runner=FakeRunner({"list chain": NO_TABLE}))
    assert enf.setup() and enf.capable
    assert runner.calls.count(["nft", "-f", "-"]) == 1
    script = runner.inputs[runner.calls.index(["nft", "-f", "-"])]
    for needle in ["add table inet nexus", "add set inet nexus port4", "ipv4_addr . inet_service",
                   "add chain inet nexus prerouting { type filter hook prerouting priority -150; policy accept; }",
                   "ip saddr . tcp dport @port4 drop", "ip saddr @all4 drop",
                   "ip6 saddr & ffff:ffff:ffff:ffff:: . tcp dport @port6 drop",
                   "ip6 saddr & ffff:ffff:ffff:ffff:: @all6 drop",
                   "ip saddr @limit4 ct state new", "limit rate over 100/second", "update @seen4 { ip saddr counter }",
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


@pytest.mark.parametrize("resp", [(124, "timeout"), (1, "Error: Resource busy"), (0, "{garbage"), (0, "[]")])
def test_setup_refuses_when_chain_unreadable(resp):
    enf, runner, _ = make(runner=FakeRunner({"list chain": resp}))
    assert enf.setup() is False and enf.capable is False
    assert ["nft", "-f", "-"] not in runner.calls


def test_setup_adds_rules_when_chain_listing_has_none():
    enf, runner, _ = make(runner=FakeRunner({"list chain": (0, EMPTY)}))
    assert enf.setup()
    assert "add rule" in runner.inputs[runner.calls.index(["nft", "-f", "-"])]


def test_scan_log_rule_only_for_inbound_local_syns():
    enf, runner, _ = make(runner=FakeRunner({"list chain": NO_TABLE}))
    enf.setup()
    script = runner.inputs[runner.calls.index(["nft", "-f", "-"])]
    assert 'fib daddr type local iif != "lo" ct state new tcp flags syn' in script


def test_setup_nft_missing():
    enf, _, _ = make(runner=FakeRunner({"nft": (127, "")}))
    assert enf.setup() is False and enf.capable is False


def test_setup_seeds_active_count_from_kernel():
    out = table_json(("all4", [{"elem": {"val": "10.0.0.%d" % i, "expires": 99}} for i in range(1, 4)]))
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out), "list chain": NO_TABLE}), max_active=3)
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
    assert sorted(runner.inputs[-1].splitlines()) == [
        "delete element inet nexus all4 { 203.0.113.9 }",
        "delete element inet nexus port4 { 203.0.113.9 . 22 }",
        "delete element inet nexus port4 { 203.0.113.9 . 80 }"]
    runner.calls.clear(), runner.inputs.clear()
    assert enf.remove("2001:db8:1:2:9::1")
    assert runner.inputs[-1] == "delete element inet nexus all6 { 2001:db8:1:2:: }\n"


def test_remove_absent_is_true_and_failure_false():
    enf, runner, _ = make(runner=FakeRunner({"-j list table": (0, table_json())}))
    assert enf.remove("203.0.113.9") is True
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 5}}]))
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out), "delete element": (1, "Error: boom")}))
    enf.apply(dec("block_all", ports=()))
    assert enf.remove("203.0.113.9") is False
    assert enf._live  # memory is cleared only after the kernel confirmed
    out_missing = FakeRunner({"-j list table": (0, out), "delete element": (1, "Error: No such file or directory")})
    assert make(runner=out_missing)[0].remove("203.0.113.9") is True


@pytest.mark.parametrize("resp", [NO_TABLE, (127, "")])
def test_remove_missing_table_or_nft_is_success(resp):
    enf, _, _ = make(runner=FakeRunner({"-j list table": resp}))
    assert enf.remove("203.0.113.9") is True


def test_remove_uses_one_transaction():
    out = table_json(("port4", [{"elem": {"val": {"concat": ["203.0.113.9", p]}, "expires": 5}} for p in (22, 80)]))
    enf, runner, _ = make(runner=FakeRunner({"-j list table": (0, out)}))
    assert enf.remove("203.0.113.9")
    assert runner.calls[-1] == ["nft", "-f", "-"]
    assert runner.inputs[-1] == ("delete element inet nexus port4 { 203.0.113.9 . 22 }\n"
                                 "delete element inet nexus port4 { 203.0.113.9 . 80 }\n")


@pytest.mark.parametrize("mode", ["observe", "off"])
def test_remove_reads_kernel_in_every_mode(mode):
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 500}}]))
    enf, runner, _ = make(mode, runner=FakeRunner({"-j list table": (0, out)}))
    assert enf.remove("203.0.113.9")
    assert "delete element inet nexus all4 { 203.0.113.9 }" in runner.inputs[-1]


def test_remove_observe_drops_simulated():
    enf, runner, _ = make("observe")
    enf.apply(dec())
    assert enf.remove("203.0.113.9") and enf.active() == []


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
    enf, runner, _ = make("observe", runner=FakeRunner({"list chain": NO_TABLE}))
    assert enf.set_mode("enforce") and enf.mode == "enforce" and enf.capable
    assert enf.set_mode("observe") and enf.mode == "observe"
    with pytest.raises(ValueError):
        enf.set_mode("block")


@pytest.mark.parametrize("target", ["observe", "off"])
def test_leaving_enforce_flushes_all_block_sets_atomically(target):
    enf, runner, _ = make(runner=FakeRunner({"list chain": NO_TABLE}))
    enf.apply(dec())
    runner.calls.clear(), runner.inputs.clear()
    assert enf.set_mode(target) and enf.mode == target
    assert runner.calls == [["nft", "-f", "-"]]
    for n in ("port4", "port6", "all4", "all6", "limit4", "limit6", "meter4", "meter6"):
        assert "flush set inet nexus %s\n" % n in runner.inputs[0]
    assert "listening" not in runner.inputs[0] and "delete table" not in runner.inputs[0]


def test_leaving_enforce_flush_failure_returns_false_but_changes_mode(caplog):
    enf, _, _ = make(runner=FakeRunner({"flush set": (1, "Error: busy")}))
    assert enf.set_mode("off") is False and enf.mode == "off"
    assert "nexus" in caplog.text


def test_leaving_enforce_with_no_table_is_fine():
    enf, _, _ = make(runner=FakeRunner({"flush set": NO_TABLE}))
    assert enf.set_mode("observe") is True


def test_set_mode_resets_breaker_so_simulated_blocks_do_not_downgrade_real_ones():
    enf, runner, _ = make("observe", runner=FakeRunner({"list chain": NO_TABLE}), max_new_per_5m=2)
    for i in range(3):
        enf.apply(dec(ip="203.0.113.%d" % (i + 1)))
    assert enf.breaker_open
    assert enf.set_mode("enforce")
    assert not enf.breaker_open
    assert enf.apply(dec(ip="203.0.113.50")).detail == ""


def test_set_mode_enforce_failure_stays_observe(caplog):
    enf, _, _ = make("off", runner=FakeRunner({"nft": (127, "")}))
    assert enf.set_mode("enforce") is False
    assert enf.mode == "observe" and "nexus" in caplog.text


def test_default_runner_maps_errors():
    from nexus_agent.enforcer import run_command
    assert run_command(["definitely-not-a-binary-xyz"])[0] == 127
    assert run_command(["sh", "-c", "sleep 5"], timeout=0.2)[0] == 124
    assert run_command(["cat"], "hi") == (0, "hi")


def test_active_rows_have_kind_and_merge_per_ip_and_kind():
    out = table_json(
        ("port4", [{"elem": {"val": {"concat": ["203.0.113.9", p]}, "expires": 50}} for p in (80, 22)]),
        ("all4", [{"elem": {"val": "203.0.113.9", "expires": 50}}]),
        ("limit4", [{"elem": {"val": "198.51.100.1", "expires": 50}}]),
    )
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out)}))
    got = sorted(((b.ip, b.kind, b.ports) for b in enf.active()))
    assert got == [("198.51.100.1", "rate_limit", []), ("203.0.113.9", "block_all", []),
                   ("203.0.113.9", "block_port", [22, 80])]


@pytest.mark.parametrize("mode", ["off", "observe", "enforce"])
def test_active_shows_kernel_rows_in_every_mode(mode):
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 50}}]))
    enf, _, _ = make(mode, runner=FakeRunner({"-j list table": (0, out)}))
    assert [(b.ip, b.simulated) for b in enf.active()] == [("203.0.113.9", False)]


def test_active_observe_adds_simulated():
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 50}}]))
    enf, _, _ = make("observe", runner=FakeRunner({"-j list table": (0, out)}))
    enf.apply(dec(ip="198.51.100.4", ports=(22,)))
    assert sorted((b.ip, b.simulated, b.kind) for b in enf.active()) == [
        ("198.51.100.4", True, "block_port"), ("203.0.113.9", False, "block_all")]


def test_reapply_never_shortens_live_block():
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 80000}}]))
    enf, runner, _ = make(runner=FakeRunner({"-j list set": (0, out)}))
    res = enf.apply(dec("block_all", ports=(), ttl=5))
    assert res.ok and writes(runner) == []


def test_reapply_longer_replaces_atomically():
    out = table_json(("all4", [{"elem": {"val": "203.0.113.9", "expires": 100}}]))
    enf, runner, _ = make(runner=FakeRunner({"-j list set": (0, out)}))
    assert enf.apply(dec("block_all", ports=(), ttl=3600)).ok
    assert writes(runner) == [["nft", "-f", "-"]]
    assert runner.inputs[-1] == ("delete element inet nexus all4 { 203.0.113.9 }\n"
                                 "add element inet nexus all4 { 203.0.113.9 timeout 3600s comment \"ssh_bruteforce\" }\n")


def test_reapply_mixed_ports_only_touches_shorter_ones():
    out = table_json(("port4", [{"elem": {"val": {"concat": ["203.0.113.9", 22]}, "expires": 9000}}]))
    enf, runner, _ = make(runner=FakeRunner({"-j list set": (0, out)}))
    enf.apply(dec(ports=(22, 80), ttl=3600))
    assert writes(runner) == [["nft", "add", "element", "inet", "nexus", "port4", "{ 203.0.113.9 . 80 timeout 3600s comment \"ssh_bruteforce\" }"]]


def test_breaker_downgrade_does_not_shorten_existing_limit():
    out = table_json(("limit4", [{"elem": {"val": "203.0.113.9", "expires": 599}}]))
    enf, runner, _ = make(runner=FakeRunner({"-j list set": (0, out)}), max_new_per_5m=0)
    res = enf.apply(dec(ttl=3600))
    assert res.detail == "breaker: rate_limit" and writes(runner) == []


def test_set_mode_unchanged_is_a_noop_keeping_breaker_state():
    enf, runner, _ = make("observe", max_new_per_5m=1)
    enf.apply(dec(ip="203.0.113.1"))
    enf.apply(dec(ip="203.0.113.2"))
    assert enf.breaker_open
    assert enf.set_mode("observe") is True and enf.breaker_open
    assert runner.calls == []


def test_set_mode_enforce_unchanged_keeps_kernel_and_breaker():
    enf, runner, _ = make("observe", max_new_per_5m=1)
    assert enf.set_mode("enforce")
    enf.apply(dec(ip="203.0.113.1"))
    enf.apply(dec(ip="203.0.113.2"))
    assert enf.breaker_open
    n = len(runner.calls)
    assert enf.set_mode("enforce") is True and enf.breaker_open
    assert len(runner.calls) == n


def test_set_mode_enforce_still_runs_setup_when_not_capable():
    enf, runner, _ = make("enforce")
    assert not enf.capable
    assert enf.set_mode("enforce") is True and enf.capable
    assert any("add table" in (i or "") for i in runner.inputs)


def test_lift_leftovers_flushes_without_enabling():
    enf, runner, _ = make("observe")
    assert enf.lift_leftovers() is True
    assert enf.mode == "observe" and not enf.capable
    script = next(i for i in runner.inputs if i)
    assert all("flush set inet nexus %s\n" % n in script for n in ("port4", "all6", "limit4", "meter6"))
    assert "add " not in script


def test_lift_leftovers_without_nft_or_table_is_fine():
    assert make("observe", FakeRunner({"flush": (127, "")}))[0].lift_leftovers() is True
    assert make("observe", FakeRunner({"flush": NO_TABLE}))[0].lift_leftovers() is True
    assert make("observe", FakeRunner({"flush": (1, "denied")}))[0].lift_leftovers() is False


def test_active_limit_none_returns_everything():
    enf, _, clock = make("observe", max_new_per_5m=10 ** 6, max_active=10 ** 6)
    for n in range(1100):
        enf.apply(dec("block_all", ip="198.18.%d.%d" % (n // 256, n % 256), ports=()))
    assert len(enf.active()) == 1000
    assert len(enf.active(limit=None)) == 1100


def test_failed_lift_stays_pending_until_a_retry_succeeds(caplog):
    enf, _, _ = make(runner=FakeRunner({"flush set": (1, "Error: busy")}))
    assert enf.set_mode("off") is False and enf.lift_pending
    enf.retry_lift()
    assert enf.set_mode("off") is False and enf.lift_pending
    assert sum("cannot lift" in r.message for r in caplog.records) == 1
    enf._run = FakeRunner()
    assert enf.set_mode("off") is True and not enf.lift_pending


def test_retry_lift_clears_and_logs_once(caplog):
    caplog.set_level("INFO", "nexus_agent.enforcer")
    enf, _, _ = make(runner=FakeRunner({"flush set": (1, "Error: busy")}))
    enf.set_mode("observe")
    enf._run = recovered = FakeRunner()
    enf.retry_lift()
    assert not enf.lift_pending
    assert any("flush set" in (i or "") for i in recovered.inputs)
    recovered.calls.clear()
    enf.retry_lift()
    assert recovered.calls == []
    assert sum("lifted" in r.message for r in caplog.records) == 1


def test_failed_startup_lift_is_pending_and_enforce_clears_it():
    enf, _, _ = make("observe", FakeRunner({"flush set": (1, "Error: busy")}))
    assert enf.lift_leftovers() is False and enf.lift_pending
    enf._run = FakeRunner()
    assert enf.set_mode("enforce") and not enf.lift_pending


def test_active_strict_reports_unreadable_kernel():
    enf, _, _ = make("observe", FakeRunner({"list table": (124, "timeout")}))
    assert enf.active() == []
    assert enf.active(limit=None, strict=True) is None


def test_apply_reports_real_ttl_and_detail():
    enf, _, _ = make("observe", max_new_per_5m=1)
    assert enf.apply(dec(ip="203.0.113.1", ttl=90000)).ttl == 86400
    res = enf.apply(dec(ip="203.0.113.2", ttl=3600))
    assert res.detail.startswith("breaker") and res.ttl == 600


def test_failed_downgraded_write_keeps_breaker_in_detail():
    enf, runner, _ = make("enforce", max_new_per_5m=1)
    enf.apply(dec(ip="203.0.113.1"))
    runner.responses["limit4"] = (1, "Error: nope")
    res = enf.apply(dec(ip="203.0.113.2"))
    assert not res.ok and res.detail.startswith("breaker") and res.ttl == 600


def test_rule_survives_a_restart_through_the_element_comment():
    listing = {"nftables": [{"set": {"name": "port4", "elem": [
        {"elem": {"val": {"concat": ["203.0.113.9", 80]}, "expires": 60, "comment": "web_probe"}}]}}]}
    present = json.dumps({"nftables": [{"rule": {"chain": "prerouting"}}]})
    enf, _, _ = make(runner=FakeRunner({"list chain": (0, present), "list table": (0, json.dumps(listing))}))
    assert enf.setup()
    enf.mode = "enforce"
    assert [(b.ip, b.rule, b.ports) for b in enf.active()] == [("203.0.113.9", "web_probe", [80])]


def test_new_connections_reads_counters_and_tolerates_failure():
    seen = {"nftables": [{"set": {"name": "seen4", "elem": [
        {"elem": {"val": "203.0.113.9", "counter": {"packets": 42, "bytes": 2000}, "expires": 50}}]}}]}
    enf, _, _ = make(mode="enforce", runner=FakeRunner({"list set inet nexus seen4": (0, json.dumps(seen)),
                                                       "list set inet nexus seen6": (1, "Error")}))
    assert enf.new_connections() == {"203.0.113.9": 42}
    enf.mode = "observe"
    assert enf.new_connections() == {}



def test_active_survives_concat_element_without_timeout():
    out = table_json(
        ("port4", [{"concat": ["203.0.113.8", 22]}]),
        ("all4", [{"elem": {"val": "203.0.113.50", "timeout": 60, "expires": 30}}]),
    )
    enf, _, _ = make(runner=FakeRunner({"-j list table": (0, out)}))
    assert "203.0.113.50" in {b.ip for b in enf.active()}
