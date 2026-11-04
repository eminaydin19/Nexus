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
