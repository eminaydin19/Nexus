from __future__ import annotations

import time

import pytest

from nexus_agent import rules
from nexus_agent.parsers import LogEvent
from nexus_agent.protect import Protector
from nexus_agent.rules import RuleConfig, RuleEngine

IP = "203.0.113.9"
CF = "104.16.0.1"


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t


def mk(cfg=None, **kw):
    clock = Clock()
    prot = Protector(clock=clock, **kw)
    return RuleEngine(cfg or RuleConfig(), prot, clock), clock, prot


def ssh_fail(ip=IP):
    return LogEvent("ssh_fail", ip, 0, raw="sshd: Failed password from %s" % ip)


def web(path, status=404, method="GET", ip=IP, ua=None):
    return LogEvent("web", ip, 0, method, path, status, '%s "%s %s" %d' % (ip, method, path, status), ua)


def feed_n(eng, make, n):
    out = []
    for i in range(n):
        out = eng.feed(make(i))
    return out


def all_decisions(eng, make, n):
    got = []
    for i in range(n):
        got += eng.feed(make(i))
    return got


def probe(i):
    return web("/.env" if i == 0 else "/phpmyadmin" if i == 1 else ["/pma", "/myadmin", "/wso.php", "/c99.php", "/shell.php",
               "/r57.php", "/backup.sql", "/db.sql", "/dump.sql", "/server-status"][i - 2])


def test_probe_fixture_has_distinct_listed_paths():
    assert len({probe(i).path for i in range(10)}) == 10


def test_ssh_9_fails_no_block():
    eng, _, _ = mk()
    assert all_decisions(eng, lambda i: ssh_fail(), 9) == []


def test_ssh_10_fails_blocks_ssh_port_only():
    eng, _, _ = mk()
    got = all_decisions(eng, lambda i: ssh_fail(), 10)
    assert len(got) == 1
    d = got[0]
    assert (d.rule, d.ip, d.action, d.ports, d.ttl) == ("ssh_bruteforce", IP, "block_port", (22,), 3600)
    assert d.evidence.count("\n") == 2 and len(d.evidence) <= 500


def test_evidence_cut_to_500():
    eng, _, _ = mk()
    ev = lambda i: LogEvent("ssh_fail", IP, 0, raw="x" * 300)
    assert len(all_decisions(eng, ev, 10)[0].evidence) == 500


def test_web_login_30_fails_blocks_web_ports_15m():
    eng, _, _ = mk()
    mkev = lambda i: web("/login", 401, "POST")
    assert all_decisions(eng, mkev, 29) == []
    d = eng.feed(mkev(0))[0]
    assert (d.rule, d.action, d.ports, d.ttl) == ("web_login_bruteforce", "block_port", (80, 443), 900)


@pytest.mark.parametrize("path,method,status,counts", [
    ("/login?x=1", "POST", 403, True),
    ("/login/", "POST", 401, True),
    ("/Login", "POST", 401, False),
    ("/login", "GET", 401, False),
    ("/login", "POST", 200, False),
    ("/login", "POST", 302, False),
    ("/wp-login.php", "POST", 200, True),
    ("/wp-login.php", "POST", 401, True),
    ("/wp-login.php", "POST", 302, False),
    ("/login", "POST", 500, False),
    ("/other", "POST", 401, False),
])
def test_login_matching(path, method, status, counts):
    eng, _, _ = mk(RuleConfig(web_login_threshold=2))
    got = all_decisions(eng, lambda i: web(path, status, method), 2)
    assert bool(got) is counts


def test_web_probe_10_distinct_paths_30m():
    eng, _, _ = mk()
    assert all_decisions(eng, probe, 9) == []
    d = eng.feed(probe(9))[0]
    assert (d.rule, d.action, d.ports, d.ttl) == ("web_probe", "block_port", (80, 443), 1800)


def test_same_probe_path_100_times_no_block():
    eng, _, _ = mk()
    assert all_decisions(eng, lambda i: web("/.env"), 100) == []


def test_probe_path_case_insensitive_and_query_ignored():
    eng, _, _ = mk(RuleConfig(probe_threshold=2))
    assert all_decisions(eng, lambda i: web(["/.ENV?a=1", "/PhpMyAdmin"][i]), 2)


def test_probe_with_200_status_not_counted_and_no_note_probe():
    eng, _, prot = mk()
    calls = []
    prot.note_probe = calls.append
    assert all_decisions(eng, lambda i: web(probe(i).path, 200), 10) == []
    assert all_decisions(eng, lambda i: web(probe(i).path, 302), 10) == []
    assert calls == []
    eng.feed(web("/.env"))
    assert calls == [IP]


def test_web_exploit_3_distinct_patterns_1h():
    eng, _, _ = mk()
    paths = ["/a?q=1 union select 2", "/a?q=%27+or+1=1", "/x/../../y"]
    assert all_decisions(eng, lambda i: web(paths[i], 200), 2) == []
    d = eng.feed(web(paths[2], 200))[0]
    assert (d.rule, d.action, d.ports, d.ttl) == ("web_exploit", "block_port", (80, 443), 3600)


def test_exploit_same_pattern_repeated_no_block():
    eng, _, _ = mk()
    assert all_decisions(eng, lambda i: web("/x/../y"), 50) == []


@pytest.mark.parametrize("path", [
    "/a?q=1+UNION+SELECT+2", "/a?q=1/**/union/**/select/**/2", "/a?id=1'%20or%201=1", '/a?id=1" or 1=1',
    "/files/../../x", "/files/%2e%2e/x", "/files/%252e%252e/x", "/a?f=/etc/passwd", "/a?f=%2Fetc%2Fpasswd",
    "/a?c=x;cat+/x", "/a?c=$(id)", "/a?j=${jndi:ldap://x/a}", "/a?f=/proc/self/environ", "/a?x=%22onerror=alert(1)", "/a?x=base64_decode(abc)", "/a?c=%3Cscript%3Ealert(1)", "/a?x=%zz%3Cscript",
])
def test_each_exploit_pattern_matches(path):
    assert len(rules.exploit_hits(path)) >= 1


@pytest.mark.parametrize("path", [
    "/products?q=select+a+shirt", "/blog/union-select-committee", "/a?q=union", "/search?q=or+1",
    "/docs/etc/passwords", "/img/a..b.png", "/a?s=scripting", "/a?c=cat+food", "/a?x=onerrors", "/a?q=base64+decode", "/a?x=$HOME", "/a?q=%7Bjndi%7D",
])
def test_benign_urls_clean(path):
    assert rules.exploit_hits(path) == ()


def test_exploit_decode_limited_and_tolerant():
    assert rules.exploit_hits("/a?x=%25%25%25") == ()
    assert rules.exploit_hits("/a?x=%E0%A4%A<script") != ()
    assert rules.exploit_hits("/a?x=%25252e%25252e") == (3,)  # decode stops at two layers; the literal %2e%2e still matches


def test_patterns_linear_on_16kb():
    bad = ["union" + " " * 16000, "'" + " " * 16000, "' " * 8000, "../" * 5000, "%2e" * 5000, ";" + " " * 16000, "<" * 16000,
           "/etc/" * 3000, "union/*" + "a" * 16000, "$" * 16000]
    t = time.time()
    for s in bad:
        rules.exploit_hits("/a?" + s[:16000])
    assert time.time() - t < 1.0


def scan(eng, ip=IP, first=1000, n=20):
    got = []
    for p in range(first, first + n):
        got += eng.feed_scan(ip, p)
    return got


def test_spoof_style_scan_alone_only_alerts():
    eng, _, _ = mk()
    assert scan(eng, n=19) == []
    d = eng.feed_scan(IP, 1019)[0]
    assert (d.rule, d.action, d.ports, d.ttl) == ("port_scan", "alert", (), 0)
    assert scan(eng, n=20)[0].action == "alert"  # alerts again, no offense escalation, never a block
    assert eng._offense == {}


def test_scan_plus_ssh_fail_blocks_all_ports_15m():
    eng, _, _ = mk()
    eng.feed(ssh_fail())
    d = scan(eng)[0]
    assert (d.rule, d.action, d.ports, d.ttl) == ("port_scan", "block_all", (), 900)


@pytest.mark.parametrize("bad", [
    lambda: web("/.env"), lambda: web("/a?<script"), lambda: web("/login", 401, "POST"),
])
def test_scan_plus_other_handshake_evidence_blocks(bad):
    eng, _, _ = mk()
    eng.feed(bad())
    assert scan(eng)[0].action == "block_all"


def test_scan_bad_activity_must_be_in_current_window():
    eng, clock, _ = mk()
    eng.feed(ssh_fail())
    clock.t += 301
    assert scan(eng)[0].action == "alert"


def test_trusted_ip_scan_plus_bad_activity_only_alerts():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    eng.feed(ssh_fail())
    assert scan(eng)[0].action == "alert"


def test_trusted_ip_scan_plus_probe_hit_only_alerts():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    eng.feed(web("/.env"))  # the probe voids trust, but the hit was seen while trusted
    assert prot.threshold_multiplier(IP) == 1
    assert scan(eng)[0].action == "alert"


def test_protected_ip_scan_emits_nothing():
    eng, _, _ = mk(allowlist=["198.18.0.0/24"])
    assert scan(eng, "198.18.0.9") == []
    assert eng.suppressed["allowlist"] == 1


def test_port_scan_window_60s_and_distinct():
    eng, clock, _ = mk()
    for p in range(1000, 1019):
        eng.feed_scan(IP, p)
        eng.feed_scan(IP, p)
    clock.t += 61
    assert eng.feed_scan(IP, 2000) == []
    assert eng.feed_scan(IP, 1000) == []


def test_port_scan_threshold_not_tripled_for_trusted():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    assert len(scan(eng)) == 1


def test_conn_flood_rate_limits_not_blocks():
    eng, _, _ = mk()
    assert eng.feed_connections({IP: 199}, 0) == []
    d = eng.feed_connections({IP: 200}, 0)[0]
    assert (d.rule, d.action, d.ttl, d.ip) == ("conn_flood", "rate_limit", 600, IP)


def test_conn_flood_once_while_active_then_escalates():
    eng, clock, _ = mk()
    assert len(eng.feed_connections({IP: 500}, 0)) == 1
    assert eng.feed_connections({IP: 500}, 0) == []
    clock.t += 601
    assert eng.feed_connections({IP: 500}, 0)[0].ttl == 1200


def test_conn_flood_protected_and_cdn_ips_accepted_silently():
    eng, _, _ = mk(allowlist=["198.18.0.0/24"])
    assert eng.feed_connections({"198.18.0.5": 900, CF: 900, "127.0.0.1": 900}, 0) == []
    assert eng.suppressed["allowlist"] == 1 and eng.suppressed["cdn"] == 1 and eng.suppressed["loopback"] == 1
    eng.feed_connections({"198.18.0.5": 900}, 0)
    assert eng.suppressed["allowlist"] == 1  # same ongoing episode counted once
    eng.feed_connections({}, 0)
    eng.feed_connections({"198.18.0.5": 900}, 0)
    assert eng.suppressed["allowlist"] == 2


def test_conn_flood_trust_multiplier():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    assert eng.feed_connections({IP: 599}, 0) == []
    assert len(eng.feed_connections({IP: 600}, 0)) == 1


def test_distributed_flood_alert_only():
    eng, _, _ = mk()
    d = eng.feed_connections({}, 501)[0]
    assert (d.rule, d.ip, d.action, d.ports, d.ttl) == ("distributed_flood", "0.0.0.0", "alert", (), 0)
    assert eng.feed_connections({}, 500) == []


def test_distributed_flood_spike_vs_average_compare_before_update():
    eng, clock, _ = mk()
    for _ in range(5):
        assert eng.feed_connections({"198.51.100.%d" % i: 1 for i in range(100)}, 10) == []
    spike = {"198.51.100.%d" % (i % 200): 40 for i in range(200)}  # 8000 connections
    d = eng.feed_connections(spike, 10)
    assert len(d) == 1 and d[0].rule == "distributed_flood"
    assert eng.feed_connections(spike, 10) == []  # at most once per 600 s
    clock.t += 601
    assert len(eng.feed_connections(spike, 10)) == 1


def test_distributed_flood_needs_over_1000_total():
    eng, _, _ = mk()
    eng.feed_connections({IP: 1}, 0)
    assert eng.feed_connections({"198.51.100.1": 100}, 0) == []


def test_trusted_ip_web_login_threshold_tripled():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    assert all_decisions(eng, lambda i: web("/login", 401, "POST"), 89) == []
    assert len(eng.feed(web("/login", 401, "POST"))) == 1


def test_ssh_threshold_not_tripled_for_trusted_ip():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    assert prot.threshold_multiplier(IP) == 3
    assert len(all_decisions(eng, lambda i: ssh_fail(), 10)) == 1


def test_single_request_with_three_patterns_does_not_block():
    eng, _, _ = mk()
    url = '/search?q=<script+src="../js/a.js"></script><script>$(function(){})</script>'
    assert len(rules.exploit_hits(url)) >= 3
    assert eng.feed(web(url, 200)) == []


def test_same_patterns_across_two_requests_fire():
    eng, _, _ = mk()
    assert eng.feed(web("/a?<script+src=../x", 200)) == []
    d = eng.feed(web("/a?$(id)", 200))
    assert len(d) == 1 and d[0].rule == "web_exploit"


def test_trusted_multiplier_applies_to_exploit():
    eng, _, prot = mk()
    prot.note_login_ok(IP)
    pats = ["/a?q=1 union select 2", "/a?q=%27+or+1=1", "/x/../y", "/a?%25252e%25252e", "/a?f=/etc/passwd",
            "/a?c=x;cat+y", "/a?c=$(id)", "/a?<script", "/a?${jndi:ldap://x}"]
    assert all_decisions(eng, lambda i: web(pats[i], 200), 8) == []  # untrusted would fire at 3
    assert len(eng.feed(web(pats[8], 200))) == 1


def test_at_least_nine_exploit_patterns_for_trusted_ips():
    assert len(rules._EXPLOIT) >= 9


def test_wp_login_302_feeds_protector_but_other_paths_do_not():
    eng, _, prot = mk()
    eng.feed(web("/login", 302, "POST"))
    eng.feed(web("/admin", 200, "POST"))
    eng.feed(web("/wp-login.php", 200, "POST"))
    assert prot.threshold_multiplier(IP) == 1
    eng.feed(web("/wp-login.php?redirect=/", 302, "POST"))
    assert prot.threshold_multiplier(IP) == 3
    assert all_decisions(eng, lambda i: web("/login", 401, "POST"), 88) == []
    assert len(eng.feed(web("/login", 401, "POST"))) == 1


def test_failed_wp_logins_do_not_undo_probe_trust_reset():
    eng, _, prot = mk()
    eng.feed(web("/.env"))
    eng.feed(web("/wp-login.php", 302, "POST"))
    assert prot.threshold_multiplier(IP) == 1


def test_protected_ip_produces_no_block_and_counts_once_per_crossing():
    eng, _, _ = mk(allowlist=["198.18.0.0/24"])
    assert all_decisions(eng, lambda i: ssh_fail("198.18.0.7"), 10) == []
    assert eng.suppressed["allowlist"] == 1
    all_decisions(eng, lambda i: ssh_fail("198.18.0.7"), 10)
    assert eng.suppressed["allowlist"] == 2


def test_ssh_ok_feeds_protector_so_ip_is_protected():
    eng, _, prot = mk()
    eng.feed(LogEvent("ssh_ok", IP, 0, raw="ok"))
    assert prot.reason(IP) == "recent-ssh"
    assert all_decisions(eng, lambda i: ssh_fail(), 10) == []
    assert eng.suppressed["recent-ssh"] == 1


def test_web_events_feed_protector_trust():
    eng, _, prot = mk()
    for _ in range(20):
        eng.feed(web("/page", 200))
    assert prot.threshold_multiplier(IP) == 3


def test_repeat_offender_ttl_doubles_capped_86400():
    eng, clock, _ = mk()
    ttls = []
    for _ in range(8):
        ttls.append(all_decisions(eng, lambda i: ssh_fail(), 10)[0].ttl)
        clock.t += ttls[-1] + 1
    assert ttls == [3600, 7200, 14400, 28800, 57600, 86400, 86400, 86400]


def test_offense_memory_expires_after_7_days():
    eng, clock, _ = mk()
    all_decisions(eng, lambda i: ssh_fail(), 10)
    clock.t += 7 * 86400 + 1
    assert all_decisions(eng, lambda i: ssh_fail(), 10)[0].ttl == 3600


def test_no_duplicate_decision_while_active():
    eng, clock, _ = mk()
    assert len(all_decisions(eng, lambda i: ssh_fail(), 10)) == 1
    assert all_decisions(eng, lambda i: ssh_fail(), 30) == []
    clock.t += 3601
    assert len(all_decisions(eng, lambda i: ssh_fail(), 10)) == 1


def test_forget_allows_fresh_evaluation():
    eng, _, _ = mk()
    assert len(all_decisions(eng, lambda i: ssh_fail(), 10)) == 1
    eng.feed(ssh_fail())
    eng.forget(IP)
    assert len(all_decisions(eng, lambda i: ssh_fail(), 10)) == 1


def test_window_expiry_300s_and_cleared_after_fire():
    eng, clock, _ = mk()
    all_decisions(eng, lambda i: ssh_fail(), 9)
    clock.t += 301
    assert eng.feed(ssh_fail()) == []
    assert all_decisions(eng, lambda i: ssh_fail(), 8) == []
    assert len(eng.feed(ssh_fail())) == 1


def test_cdn_source_web_rules_alert_only_ssh_still_blocks():
    eng, _, prot = mk()
    assert prot.is_cdn(CF)
    got = all_decisions(eng, lambda i: web("/login", 401, "POST", CF), 30)
    assert [(d.rule, d.action, d.ports, d.ttl) for d in got] == [("web_login_bruteforce", "alert", (), 0)]
    got = all_decisions(eng, lambda i: web(probe(i).path, 404, ip=CF), 10)
    assert got[0].action == "alert" and got[0].ports == () and got[0].ttl == 0
    got = all_decisions(eng, lambda i: ssh_fail(CF), 10)
    assert got == [] and eng.suppressed["cdn"] == 1  # ssh follows normal protection: cdn is protected


def test_behind_cdn_mode_web_alert_ssh_and_scan_normal():
    eng, _, _ = mk()
    eng.set_behind_cdn(True)
    got = all_decisions(eng, lambda i: web(["/a?<script", "/a?f=/etc/passwd", "/a/../b"][i], 200), 3)
    assert [(d.rule, d.action, d.ports, d.ttl) for d in got] == [("web_exploit", "alert", (), 0)]
    assert all_decisions(eng, lambda i: ssh_fail(), 10)[0].action == "block_port"
    assert scan(eng, first=3000)[0].action == "block_all"  # the SSH failures above are the handshake evidence
    eng.set_behind_cdn(False)


def test_verified_bot_suppressed():
    eng, _, prot = mk()
    prot.verify_bot = lambda ip, ua: ua == "Googlebot/2.1"
    got = all_decisions(eng, lambda i: web(probe(i).path, 404, ua="Googlebot/2.1"), 10)
    assert got == [] and eng.suppressed["verified-bot"] == 1


def test_verify_bot_called_only_when_threshold_crossed():
    eng, _, prot = mk()
    calls = []
    prot.verify_bot = lambda ip, ua: calls.append(ua) or False
    all_decisions(eng, lambda i: web(probe(i).path, 404, ua="Googlebot"), 9)
    assert calls == []
    eng.feed(web(probe(9).path, 404, ua="Googlebot"))
    assert calls == ["Googlebot"]


def test_unverified_bot_ua_still_blocked():
    eng, _, _ = mk()
    assert len(all_decisions(eng, lambda i: web(probe(i).path, 404, ua="Googlebot/2.1"), 10)) == 1


def test_memory_cap_evicts_least_recently_seen():
    eng, _, _ = mk(RuleConfig(max_tracked_ips=3))
    for n in range(1, 4):
        eng.feed(ssh_fail("203.0.113.%d" % n))
    eng.feed(ssh_fail("203.0.113.1"))  # refresh
    eng.feed(ssh_fail("203.0.113.4"))  # evicts .2
    assert len(eng._win) == 3
    assert ("ssh_bruteforce", "203.0.113.2") not in eng._win
    assert ("ssh_bruteforce", "203.0.113.1") in eng._win


def test_sweep_every_60s_removes_expired_windows():
    eng, clock, _ = mk()
    eng.feed(ssh_fail())
    clock.t += 301
    eng.feed(ssh_fail("203.0.113.50"))
    assert ("ssh_bruteforce", IP) not in eng._win
    assert ("ssh_bruteforce", "203.0.113.50") in eng._win


def test_sweep_not_run_more_often_than_60s():
    eng, clock, _ = mk()
    eng.feed(ssh_fail("203.0.113.1"))
    clock.t += 59
    eng.feed(ssh_fail("203.0.113.2"))
    last = eng._last_sweep
    clock.t += 1
    eng.feed(ssh_fail("203.0.113.3"))
    assert eng._last_sweep > last


def test_ssh_ports_and_web_ports_configurable():
    eng, _, _ = mk(RuleConfig(ssh_ports=(22, 2222), web_ports=(8080,), web_login_threshold=1))
    assert all_decisions(eng, lambda i: ssh_fail(), 10)[0].ports == (22, 2222)
    assert eng.feed(web("/login", 401, "POST", ip="203.0.113.5"))[0].ports == (8080,)


def test_config_from_env_valid_and_invalid(caplog):
    cfg = RuleConfig.from_env({
        "NEXUS_RULE_SSH_FAIL_THRESHOLD": "5", "NEXUS_RULE_MAX_CONN_PER_IP": "abc", "NEXUS_RULE_PROBE_THRESHOLD": "-3",
        "NEXUS_RULE_WEB_PORTS": "80,8443", "NEXUS_RULE_SSH_PORTS": "99999", "NEXUS_RULE_LOGIN_PATHS": "/signin,/admin",
        "NEXUS_RULE_MAX_TRACKED_IPS": "50",
    })
    assert cfg.ssh_fail_threshold == 5 and cfg.web_ports == (80, 8443) and cfg.max_tracked_ips == 50
    assert cfg.login_paths == ("/signin", "/admin")
    assert cfg.max_conn_per_ip == 200 and cfg.probe_threshold == 10 and cfg.ssh_ports == (22,)
    assert "NEXUS_RULE_MAX_CONN_PER_IP" in caplog.text


def test_defaults_match_spec():
    c = RuleConfig()
    assert (c.ssh_fail_threshold, c.web_login_threshold, c.probe_threshold, c.exploit_threshold, c.scan_ports) == (10, 30, 10, 3, 20)
    assert c.login_paths == ("/login", "/wp-login.php", "/admin", "/api/login")
    assert c.max_tracked_ips == 100000 and c.ssh_ports == (22,) and c.web_ports == (80, 443)


def test_forget_clears_offense_history():
    eng, clock, _ = mk()
    all_decisions(eng, lambda i: ssh_fail(), 10)
    eng.forget(IP)
    assert all_decisions(eng, lambda i: ssh_fail(), 10)[0].ttl == 3600


V6 = ["2001:db8:1:2::%x" % n for n in range(1, 12)]


def test_ipv6_rules_key_on_slash_64():
    eng, _, _ = mk()
    got = []
    for i in range(10):
        got += eng.feed(ssh_fail(V6[i]))
    assert len(got) == 1 and got[0].ip == V6[9]
    assert eng.feed(ssh_fail(V6[10])) == []  # duplicate tracking is per /64 too
    assert eng.feed(ssh_fail("2001:db8:1:3::1")) == []  # another /64 starts fresh


def test_ipv6_offense_history_per_64_and_forget_from_any_address():
    eng, clock, _ = mk()
    for i in range(10):
        eng.feed(ssh_fail(V6[i]))
    clock.t += 3601
    got = []
    for i in range(10):
        got += eng.feed(ssh_fail(V6[i]))
    assert got[0].ttl == 7200
    eng.forget(V6[5])
    got = []
    for i in range(10):
        got += eng.feed(ssh_fail(V6[i]))
    assert len(got) == 1 and got[0].ttl == 3600
