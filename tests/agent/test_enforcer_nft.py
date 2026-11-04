"""Integration tests against the real kernel. Run with: scripts/test.sh --nft

Guarded by NEXUS_NFT_TESTS so a developer running pytest as root on a real host never touches its firewall.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from nexus_agent.enforcer import Enforcer, run_command
from nexus_agent.rules import Decision

pytestmark = pytest.mark.nft

if not os.environ.get("NEXUS_NFT_TESTS") or not shutil.which("nft") or not shutil.which("ip"):
    pytest.skip("real nft integration tests need scripts/test.sh --nft", allow_module_level=True)

SRV, CLI = "nxsrv", "nxcli"
SRV4, CLI4, CLI4B = "10.9.0.1", "10.9.0.2", "10.9.0.3"
SRV6, CLI6, CLI6B, CLI6C = "2001:db8:9:1::1", "2001:db8:9:1::2", "2001:db8:9:1::99", "2001:db8:7:7::2"

SERVER = """
import select, socket, sys
socks = []
for port in map(int, sys.argv[1:]):
    for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        try:
            s = socket.socket(fam)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if fam == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((addr, port)); s.listen(512); socks.append(s)
        except OSError:
            pass
print("ready", flush=True)
while True:
    for s in select.select(socks, [], [])[0]:
        s.accept()[0].close()
"""
CLIENT = """
import socket, sys
dst, port, src = sys.argv[1:4]
s = socket.socket(socket.AF_INET6 if ":" in dst else socket.AF_INET)
s.settimeout(1)
s.bind((src, 0))
s.connect((dst, int(port)))
"""
FLOOD = """
import socket, sys, time
src, dst, other = sys.argv[1:4]
socks = []
for _ in range(200):
    s = socket.socket(); s.setblocking(False); s.bind((src, 0)); s.connect_ex((dst, 8080)); socks.append(s)
try:
    o = socket.socket(); o.settimeout(0.5); o.bind((other, 0)); o.connect((dst, 8080)); other_ok = True
except OSError:
    other_ok = False
time.sleep(1.5)
n = 0
for s in socks:
    try:
        s.getpeername(); n += 1
    except OSError:
        pass
print(n, other_ok)
"""


def sh(*argv, input_text=None):
    return subprocess.run(list(argv), input=input_text, capture_output=True, text=True)


def ns_run(ns, *argv, input_text=None):
    return sh("ip", "netns", "exec", ns, *argv, input_text=input_text)


class Net:
    def __init__(self):
        self.server = None
        self.ipv6 = True

    def runner(self, argv, input_text=None):
        return run_command(["ip", "netns", "exec", SRV] + list(argv), input_text)

    def enforcer(self, mode="enforce", **kw):
        return Enforcer(mode, self.runner, time.time, **kw)

    def connect(self, dst, port, src):
        return ns_run(CLI, sys.executable, "-c", CLIENT, dst, str(port), src).returncode == 0

    def nft(self, *args):
        return ns_run(SRV, "nft", *args)

    def start_server(self, *ports):
        self.server = subprocess.Popen(["ip", "netns", "exec", SRV, sys.executable, "-c", SERVER] + [str(p) for p in ports],
                                       stdout=subprocess.PIPE, text=True)
        assert self.server.stdout.readline().strip() == "ready"


@pytest.fixture
def net():
    n = Net()
    for ns in (SRV, CLI):
        sh("ip", "netns", "del", ns)
    if sh("ip", "netns", "add", SRV).returncode or sh("ip", "netns", "add", CLI).returncode:
        pytest.skip("cannot create network namespaces (need SYS_ADMIN)")
    try:
        cmds = [
            ["ip", "link", "add", "nxv0", "netns", SRV, "type", "veth", "peer", "name", "nxv1", "netns", CLI],
            ["ip", "-n", SRV, "link", "set", "lo", "up"], ["ip", "-n", CLI, "link", "set", "lo", "up"],
            ["ip", "-n", SRV, "link", "set", "nxv0", "up"], ["ip", "-n", CLI, "link", "set", "nxv1", "up"],
            ["ip", "-n", SRV, "addr", "add", SRV4 + "/24", "dev", "nxv0"],
            ["ip", "-n", CLI, "addr", "add", CLI4 + "/24", "dev", "nxv1"],
            ["ip", "-n", CLI, "addr", "add", CLI4B + "/24", "dev", "nxv1"],
        ]
        for c in cmds:
            r = sh(*c)
            assert r.returncode == 0, (c, r.stderr)
        v6 = [
            ["ip", "-n", SRV, "addr", "add", SRV6 + "/64", "dev", "nxv0", "nodad"],
            ["ip", "-n", CLI, "addr", "add", CLI6 + "/64", "dev", "nxv1", "nodad"],
            ["ip", "-n", CLI, "addr", "add", CLI6B + "/64", "dev", "nxv1", "nodad"],
            ["ip", "-n", SRV, "addr", "add", "2001:db8:7:7::1/64", "dev", "nxv0", "nodad"],
            ["ip", "-n", CLI, "addr", "add", CLI6C + "/64", "dev", "nxv1", "nodad"],
        ]
        n.ipv6 = all(sh(*c).returncode == 0 for c in v6)
        yield n
    finally:
        if n.server:
            n.server.kill()
            n.server.wait()
        for ns in (SRV, CLI):
            sh("ip", "netns", "del", ns)


def dec(action="block_port", ip=CLI4, ports=(22,), ttl=3600):
    return Decision("test_rule", ip, action, tuple(ports), ttl, "ev")


def test_empty_sets_change_nothing(net):
    net.start_server(22, 8080)
    enf = net.enforcer()
    assert enf.setup() and enf.capable
    assert net.connect(SRV4, 22, CLI4) and net.connect(SRV4, 8080, CLI4)
    assert enf.update_listening([])
    assert net.connect(SRV4, 22, CLI4)


def test_block_expires_in_kernel(net):
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec("block_all", ports=(), ttl=2)).ok
    assert [b.ip for b in enf.active()] == [CLI4]
    time.sleep(3)
    assert enf.active() == []


def test_port_scope_really_scoped(net):
    net.start_server(22, 8080)
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec(ports=(22,))).ok
    assert not net.connect(SRV4, 22, CLI4)
    assert net.connect(SRV4, 8080, CLI4)
    assert net.connect(SRV4, 22, CLI4B)


def test_block_all_and_remove(net):
    net.start_server(22, 8080)
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec("block_all", ports=())).ok
    assert not net.connect(SRV4, 8080, CLI4) and net.connect(SRV4, 8080, CLI4B)
    assert enf.remove(CLI4)
    assert net.connect(SRV4, 8080, CLI4) and enf.active() == []


def test_remove_port_block(net):
    net.start_server(22)
    enf = net.enforcer()
    assert enf.setup()
    enf.apply(dec(ports=(22, 80)))
    assert enf.remove(CLI4) and enf.active() == [] and net.connect(SRV4, 22, CLI4)


def test_restart_keeps_blocks(net):
    net.start_server(22, 8080)
    first = net.enforcer()
    assert first.setup()
    first.apply(dec(ports=(22, 80), ttl=600))
    before = net.nft("-j", "list", "chain", "inet", "nexus", "prerouting").stdout
    second = net.enforcer()
    assert second.setup()
    got = second.active()
    assert [(b.ip, b.ports, b.rule) for b in got] == [(CLI4, [22, 80], "unknown")]
    assert not net.connect(SRV4, 22, CLI4)
    after = net.nft("-j", "list", "chain", "inet", "nexus", "prerouting").stdout
    assert len(json.loads(after)["nftables"]) == len(json.loads(before)["nftables"])
    assert second.apply(dec(ip="10.9.0.9")).ok  # still usable after restart


def test_breaker_state_seeded_after_restart(net):
    first = net.enforcer()
    first.setup()
    first.apply(dec("block_all", ports=()))
    second = net.enforcer(max_active=1)
    second.setup()
    assert second.apply(dec("block_all", ip="10.9.0.9", ports=())).detail == "breaker: rate_limit"


def test_teardown_removes_table(net):
    enf = net.enforcer()
    assert enf.setup()
    assert net.nft("list", "table", "inet", "nexus").returncode == 0
    assert enf.teardown()
    assert net.nft("list", "table", "inet", "nexus").returncode != 0
    assert enf.teardown()


def test_ipv6_block_covers_whole_64(net):
    if not net.ipv6:
        pytest.skip("ipv6 unavailable in this namespace")
    net.start_server(22, 8080)
    enf = net.enforcer()
    assert enf.setup()
    assert net.connect(SRV6, 22, CLI6B)
    assert enf.apply(dec(ip=CLI6, ports=(22,))).ok
    assert not net.connect(SRV6, 22, CLI6B) and not net.connect(SRV6, 22, CLI6)
    assert net.connect(SRV6, 8080, CLI6B)
    assert net.connect("2001:db8:7:7::1", 22, CLI6C)
    assert enf.apply(dec("block_all", ip=CLI6, ports=())).ok
    assert not net.connect(SRV6, 8080, CLI6B) and net.connect("2001:db8:7:7::1", 8080, CLI6C)


def test_block_applies_before_dnat(net):
    net.start_server(9090)
    r = ns_run(SRV, "nft", "-f", "-", input_text=(
        "add table ip nxnat\n"
        "add chain ip nxnat pre { type nat hook prerouting priority -100; policy accept; }\n"
        "add rule ip nxnat pre tcp dport 2222 dnat to %s:9090\n" % SRV4))
    if r.returncode:
        pytest.skip("nat not available: " + r.stderr.strip())
    enf = net.enforcer()
    assert enf.setup()
    assert net.connect(SRV4, 2222, CLI4)
    assert enf.apply(dec(ports=(9090,))).ok
    assert net.connect(SRV4, 2222, CLI4)  # the rule sees the published port, not the DNAT target
    assert enf.apply(dec(ports=(2222,))).ok
    assert not net.connect(SRV4, 2222, CLI4)


def test_unrelated_table_untouched(net):
    ns_run(SRV, "nft", "-f", "-", input_text=(
        "add table inet other\nadd set inet other s { type ipv4_addr; elements = { 192.0.2.1 }; }\n"
        "add chain inet other c { type filter hook input priority 0; policy accept; }\n"
        "add rule inet other c ip saddr @s drop\n"))
    snap = net.nft("-j", "list", "table", "inet", "other").stdout
    assert json.loads(snap)["nftables"]
    enf = net.enforcer()
    assert enf.setup() and enf.apply(dec()).ok and enf.remove(CLI4) and enf.teardown()
    assert net.nft("-j", "list", "table", "inet", "other").stdout == snap


def test_update_listening_and_scan_log_rule_load(net):
    enf = net.enforcer()
    assert enf.setup()
    assert enf.update_listening([22, 8080]) and enf.update_listening([8080]) and enf.update_listening([])
    out = net.nft("list", "set", "inet", "nexus", "listening").stdout
    assert "elements" not in out
    assert enf.update_listening([443])
    assert "443" in net.nft("list", "set", "inet", "nexus", "listening").stdout


def test_rate_limit_is_per_ip_and_not_a_block(net):
    net.start_server(8080)
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec("rate_limit", ports=())).ok
    assert enf.apply(dec("rate_limit", ip=CLI4B, ports=())).ok
    assert net.connect(SRV4, 8080, CLI4)
    out = ns_run(CLI, sys.executable, "-c", FLOOD, CLI4, SRV4, CLI4B).stdout.split()
    # a shared limit would starve the second address while the first one floods
    assert 0 < int(out[0]) < 100 and out[1] == "True"


def left(enf, ip):
    return {(b.ip, b.kind): b.until - time.time() for b in enf.active()}[(ip, "block_all")]


def test_leaving_enforce_really_lifts_blocks(net):
    net.start_server(22, 8080)
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec("block_all", ports=())).ok
    assert not net.connect(SRV4, 8080, CLI4)
    assert enf.set_mode("observe")
    assert net.connect(SRV4, 8080, CLI4) and enf.active() == []
    assert enf.set_mode("enforce")
    assert enf.apply(dec("block_all", ports=())).ok and not net.connect(SRV4, 8080, CLI4)
    assert enf.set_mode("off")
    assert net.connect(SRV4, 8080, CLI4)


def test_remove_lifts_kernel_block_even_when_not_enforcing(net):
    net.start_server(8080)
    first = net.enforcer()
    assert first.setup() and first.apply(dec("block_all", ports=())).ok
    for mode in ("observe", "off"):
        other = net.enforcer(mode)
        assert [b.ip for b in other.active()] == [CLI4]
        assert not net.connect(SRV4, 8080, CLI4)
        assert other.remove(CLI4)
        assert net.connect(SRV4, 8080, CLI4)
        first.apply(dec("block_all", ports=()))


def test_remove_without_table_is_success(net):
    enf = net.enforcer("observe")
    assert enf.remove(CLI4) is True and enf.active() == []


def test_reapply_never_shortens_and_extends_when_longer(net):
    enf = net.enforcer()
    assert enf.setup()
    enf.apply(dec("block_all", ports=(), ttl=86400))
    enf.apply(dec("block_all", ports=(), ttl=5))
    assert left(enf, CLI4) > 86000
    enf.remove(CLI4)
    enf.apply(dec("block_all", ports=(), ttl=30))
    enf.apply(dec("block_all", ports=(), ttl=3600))
    assert 3500 < left(enf, CLI4) <= 3600
    enf.apply(dec(ports=(22, 80), ttl=100))
    enf.apply(dec(ports=(22, 80, 443), ttl=300))
    ports = {b.kind: b for b in enf.active()}["block_port"]
    assert ports.ports == [22, 80, 443] and 200 < ports.until - time.time() <= 300


def test_breaker_downgrade_keeps_longer_limit(net):
    enf = net.enforcer(max_new_per_5m=0)
    assert enf.setup()
    enf.apply(dec("rate_limit", ports=(), ttl=3000))
    assert enf.apply(dec(ttl=3600)).detail == "breaker: rate_limit"
    row = [b for b in enf.active() if b.kind == "rate_limit"][0]
    assert row.until - time.time() > 2900


def test_active_kinds_and_merged_ports(net):
    enf = net.enforcer()
    assert enf.setup()
    enf.apply(dec(ports=(22, 80)))
    enf.apply(dec("block_all", ports=()))
    enf.apply(dec("rate_limit", ports=()))
    assert sorted((b.kind, b.ports) for b in enf.active()) == [
        ("block_all", []), ("block_port", [22, 80]), ("rate_limit", [])]


def test_setup_refuses_to_duplicate_rules_when_listing_fails(net):
    enf = net.enforcer()
    assert enf.setup()
    n = len(json.loads(net.nft("-j", "list", "chain", "inet", "nexus", "prerouting").stdout)["nftables"])

    def flaky(argv, input_text=None):
        if "chain" in argv:
            return 124, "timeout"
        return net.runner(argv, input_text)
    assert Enforcer("enforce", flaky, time.time).setup() is False
    assert len(json.loads(net.nft("-j", "list", "chain", "inet", "nexus", "prerouting").stdout)["nftables"]) == n


def scan_logged(net, action):
    ns_run(SRV, "nft", "-f", "-", input_text=(
        "add table inet nxtrace\n"
        "add chain inet nxtrace pre { type filter hook prerouting priority -300; policy accept; }\n"
        "add rule inet nxtrace pre tcp dport 8080 meta nftrace set 1\n"))
    mon = subprocess.Popen(["ip", "netns", "exec", SRV, "nft", "monitor", "trace"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(0.5)
        action()
        time.sleep(0.5)
    finally:
        mon.terminate()
    return "nexus-scan" in mon.communicate()[0]


def test_scan_log_rule_inbound_only(net):
    net.start_server(8080)
    ns_run(SRV, "sysctl", "-qw", "net.ipv4.ip_forward=1")
    sh("ip", "-n", CLI, "route", "add", "10.77.0.0/24", "via", SRV4)
    enf = net.enforcer()
    assert enf.setup()
    assert scan_logged(net, lambda: net.connect(SRV4, 8080, CLI4))
    assert not scan_logged(net, lambda: net.connect("10.77.0.5", 8080, CLI4))
    assert not scan_logged(net, lambda: ns_run(SRV, sys.executable, "-c", CLIENT, "127.0.0.1", "8080", "127.0.0.1"))
    assert enf.update_listening([8080])
    assert not scan_logged(net, lambda: net.connect(SRV4, 8080, CLI4))


def test_lift_leftovers_clears_a_previous_runs_blocks_without_enabling(net):
    net.start_server(8080)
    first = net.enforcer()
    assert first.setup()
    assert first.apply(dec("block_all", ports=())).ok
    assert not net.connect(SRV4, 8080, CLI4)
    second = net.enforcer("observe")
    assert second.lift_leftovers()
    assert second.mode == "observe" and not second.capable
    assert net.connect(SRV4, 8080, CLI4)


def test_failed_lift_retried_after_nft_recovers_really_lifts(net):
    net.start_server(8080)
    enf = net.enforcer()
    assert enf.setup()
    assert enf.apply(dec("block_all", ports=())).ok
    real = enf._run
    enf._run = lambda argv, input_text=None: (1, "Error: busy") if "flush set" in (input_text or "") else real(argv, input_text)
    assert enf.set_mode("off") is False and enf.lift_pending
    assert not net.connect(SRV4, 8080, CLI4)
    enf._run = real
    enf.retry_lift()
    assert not enf.lift_pending
    assert net.connect(SRV4, 8080, CLI4)
