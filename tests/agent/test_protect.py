from __future__ import annotations

import socket
import sys
import types

import pytest

from nexus_agent import protect
from nexus_agent.parsers import LogEvent
from nexus_agent.protect import Protector


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class FakeResolver:
    def __init__(self, ptr=None, fwd=None, delay=0.0):
        self.ptr, self.fwd, self.delay, self.calls = ptr or {}, fwd or {}, delay, 0

    def gethostbyaddr(self, ip):
        self.calls += 1
        if self.delay:
            import time
            time.sleep(self.delay)
        if ip not in self.ptr:
            raise socket.herror()
        return (self.ptr[ip], [], [ip])

    def getaddrinfo(self, host, port):
        if host not in self.fwd:
            raise socket.gaierror()
        return [(socket.AF_INET, 0, 0, "", (a, 0)) for a in self.fwd[host]]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def p(clock):
    return Protector(["198.18.0.0/24", "bogus"], "192.0.2.50", "192.0.2.1", ["192.0.2.53"], clock)


def web(ip, status=200):
    return LogEvent("web", ip, 0.0, method="GET", path="/", status=status)


@pytest.mark.parametrize("ip,why", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("10.0.0.1", "private"),
    ("192.168.1.1", "private"), ("172.16.5.5", "private"), ("fd00::1", "private"),
    ("0.0.0.0", "private"), ("100.64.0.1", "cgnat"), ("fe80::1", "link-local"),
    ("169.254.1.1", "link-local"), ("224.0.0.1", "multicast"), ("ff02::1", "multicast"),
    ("not-an-ip", "invalid"), ("", "invalid"), ("::ffff:10.0.0.1", "private"),
])
def test_special_ranges_protected(p, ip, why):
    assert p.reason(ip) == why


def test_test_net_is_public_like(p):
    for ip in ("203.0.113.5", "198.51.100.7", "192.0.2.9"):
        assert p.reason(ip) is None


def test_allowlist_and_invalid_entries_skipped(p):
    assert p.reason("198.18.0.9") == "allowlist"
    assert p.reason("198.18.1.9") is None
    p.set_allowlist(["203.0.113.9", 5, None, "x/y"])
    assert p.reason("203.0.113.9") == "allowlist"
    assert p.reason("198.18.0.9") is None


def test_central_gateway_resolver(p):
    assert p.reason("192.0.2.50") == "central"
    assert p.reason("192.0.2.1") == "gateway"
    assert p.reason("192.0.2.53") == "resolver"


def test_central_ip_forms(clock):
    assert Protector([], None, None, [], clock).reason("192.0.2.50") is None
    assert Protector([], ["192.0.2.50", "192.0.2.51"], None, [], clock).reason("192.0.2.51") == "central"


def test_cloudflare_protected(p):
    assert p.reason("104.16.0.1") == "cdn"
    assert p.is_cdn("104.16.0.1")
    assert p.reason("2606:4700::1") == "cdn"
    assert not p.is_cdn("203.0.113.5")


def test_cloudfront_ipv4_and_ipv6(p):
    assert p._cdn_ranges["cloudfront"], "needs shipped ranges"
    import ipaddress
    v4 = next(n for n in p._cdn_ranges["cloudfront"] if ":" not in n)
    v6 = next(n for n in p._cdn_ranges["cloudfront"] if ":" in n)
    assert p.is_cdn(str(next(ipaddress.ip_network(v4).hosts())))
    assert p.is_cdn(str(ipaddress.ip_network(v6)[1]))


def test_active_ssh_protected(p):
    p.set_active_ssh(["203.0.113.1"])
    assert p.reason("203.0.113.1") == "active-ssh"
    p.set_active_ssh([])
    assert p.reason("203.0.113.1") is None


def test_ssh_success_protected_for_24h(p, clock):
    p.note_ssh_ok("203.0.113.2")
    clock.t += 23 * 3600
    assert p.reason("203.0.113.2") == "recent-ssh"
    clock.t += 2 * 3600
    assert p.reason("203.0.113.2") is None


def test_trusted_after_20_ok_requests(p):
    ip = "203.0.113.3"
    for _ in range(19):
        p.note_web(web(ip, 302))
    assert p.threshold_multiplier(ip) == 1
    p.note_web(web(ip, 200))
    assert p.threshold_multiplier(ip) == 3


def test_errors_do_not_build_trust(p):
    for _ in range(30):
        p.note_web(web("203.0.113.3", 404))
    assert p.threshold_multiplier("203.0.113.3") == 1


def test_trust_expires(p, clock):
    for _ in range(20):
        p.note_web(web("203.0.113.3"))
    clock.t += 3601
    assert p.threshold_multiplier("203.0.113.3") == 1


def test_probe_removes_trust_for_an_hour(p, clock):
    ip = "203.0.113.4"
    for _ in range(20):
        p.note_web(web(ip))
    p.note_probe(ip)
    assert p.threshold_multiplier(ip) == 1
    clock.t += 1800
    for _ in range(25):
        p.note_web(web(ip))
    assert p.threshold_multiplier(ip) == 1
    clock.t += 1801
    for _ in range(20):
        p.note_web(web(ip))
    assert p.threshold_multiplier(ip) == 3


def test_login_ok_trusts_then_probe_clears(p, clock):
    p.note_login_ok("203.0.113.5")
    assert p.threshold_multiplier("203.0.113.5") == 3
    p.note_probe("203.0.113.5")
    assert p.threshold_multiplier("203.0.113.5") == 1
    clock.t += 3601
    assert p.threshold_multiplier("203.0.113.5") == 1


def test_trust_table_bounded(p, monkeypatch):
    monkeypatch.setattr(protect, "MAX_TRUST_IPS", 50)
    for i in range(80):
        p.note_web(web("203.0.113.%d" % i))
    assert len(p._trust) == 50


def test_invalid_ip_inputs_never_raise(p):
    p.note_ssh_ok("zzz")
    p.note_probe("zzz")
    p.note_login_ok("zzz")
    p.note_web(web("zzz"))
    assert p.threshold_multiplier("zzz") == 1
    assert p.verify_bot("zzz", "Googlebot") is False


GOOD = "66.249.66.1"
UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def test_googlebot_forward_confirmed_only(clock):
    r = FakeResolver({GOOD: "crawl-66-249-66-1.googlebot.com"}, {"crawl-66-249-66-1.googlebot.com": [GOOD]})
    p = Protector([], None, None, [], clock, resolver=r)
    assert p.verify_bot(GOOD, UA) is True
    assert p.reason(GOOD) is None


def test_fake_rdns_rejected(clock):
    r = FakeResolver({"203.0.113.9": "evil.googlebot.com.attacker.net"}, {"evil.googlebot.com.attacker.net": ["203.0.113.9"]})
    assert Protector([], None, None, [], clock, resolver=r).verify_bot("203.0.113.9", UA) is False


def test_forward_mismatch_rejected(clock):
    r = FakeResolver({"203.0.113.9": "x.googlebot.com"}, {"x.googlebot.com": ["66.249.66.1"]})
    assert Protector([], None, None, [], clock, resolver=r).verify_bot("203.0.113.9", UA) is False


def test_bing_and_other_agents(clock):
    r = FakeResolver({"40.77.167.1": "msnbot-40-77-167-1.search.msn.com"}, {"msnbot-40-77-167-1.search.msn.com": ["40.77.167.1"]})
    p = Protector([], None, None, [], clock, resolver=r)
    assert p.verify_bot("40.77.167.1", "Mozilla/5.0 (compatible; bingbot/2.0)") is True
    assert p.verify_bot("40.77.167.1", "curl/8") is False
    assert p.verify_bot("40.77.167.1", None) is False


def test_bot_result_cached_one_hour(clock):
    r = FakeResolver({GOOD: "a.googlebot.com"}, {"a.googlebot.com": [GOOD]})
    p = Protector([], None, None, [], clock, resolver=r)
    p.verify_bot(GOOD, UA)
    p.verify_bot(GOOD, UA)
    assert r.calls == 1
    clock.t += 3601
    p.verify_bot(GOOD, UA)
    assert r.calls == 2


def test_slow_resolver_times_out(clock, monkeypatch):
    monkeypatch.setattr(protect, "DNS_TIMEOUT", 0.1)
    r = FakeResolver({GOOD: "a.googlebot.com"}, {"a.googlebot.com": [GOOD]}, delay=1.0)
    assert Protector([], None, None, [], clock, resolver=r).verify_bot(GOOD, UA) is False


def fake_requests(monkeypatch, responses):
    class Resp:
        def __init__(self, body):
            self.body = body
            self.content = b"x"

        def raise_for_status(self):
            if self.body is None:
                raise RuntimeError("boom")

        @property
        def text(self):
            return self.body

        def json(self):
            import json
            return json.loads(self.body)

    def get(url, timeout):
        assert timeout == 10
        return Resp(responses[url])

    monkeypatch.setitem(sys.modules, "requests", types.SimpleNamespace(get=get))


def good_responses():
    import json
    v4 = "\n".join("10.%d.0.0/16" % i for i in range(6))
    v6 = "\n".join("2001:db8:%d::/48" % i for i in range(6))
    return {
        "https://www.cloudflare.com/ips-v4": v4,
        "https://www.cloudflare.com/ips-v6": v6,
        "https://api.fastly.com/public-ip-list": json.dumps({"addresses": ["203.0.113.0/28"] * 3 + ["198.51.100.0/28"] * 3, "ipv6_addresses": []}),
        "https://ip-ranges.amazonaws.com/ip-ranges.json": json.dumps({
            "prefixes": [{"ip_prefix": "198.18.%d.0/24" % i, "service": "CLOUDFRONT"} for i in range(6)]
            + [{"ip_prefix": "9.9.9.0/24", "service": "EC2"}],
            "ipv6_prefixes": [],
        }),
    }


def test_cdn_refresh_success_replaces(p, monkeypatch):
    fake_requests(monkeypatch, good_responses())
    assert p.refresh_cdn_ranges() is True
    assert p.reason("198.18.3.3") == "cdn"
    assert p.reason("9.9.9.9") is None
    assert p.reason("104.16.0.1") is None


def test_cdn_refresh_failure_keeps_list(p, monkeypatch):
    r = good_responses()
    r["https://api.fastly.com/public-ip-list"] = None
    fake_requests(monkeypatch, r)
    assert p.refresh_cdn_ranges() is False
    assert p.reason("104.16.0.1") == "cdn"


@pytest.mark.parametrize("url,bad", [
    ("https://www.cloudflare.com/ips-v4", "garbage\n1.2.3.4/99"),
    ("https://api.fastly.com/public-ip-list", '{"addresses": ["1.0.0.0/8"], "ipv6_addresses": []}'),
    ("https://ip-ranges.amazonaws.com/ip-ranges.json", '{"prefixes": [], "ipv6_prefixes": []}'),
])
def test_cdn_refresh_rejects_invalid_or_tiny(p, monkeypatch, url, bad):
    r = good_responses()
    r[url] = bad
    fake_requests(monkeypatch, r)
    assert p.refresh_cdn_ranges() is False
    assert p.reason("104.16.0.1") == "cdn"


def test_cdn_refresh_without_requests_returns_false(p, monkeypatch):
    monkeypatch.setitem(sys.modules, "requests", None)
    assert p.refresh_cdn_ranges() is False
