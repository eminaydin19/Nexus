from __future__ import annotations

import dataclasses
import time
from pathlib import Path

import pytest

from nexus_agent.parsers import (
    LogEvent, normalize_ip, parse_ssh_line, parse_web_line, ssh_line_is_stale, web_line_is_stale,
)

FIX = Path(__file__).parent / "fixtures"
NOW = 1_700_000_000.0


def lines(name):
    return (FIX / name).read_text().splitlines()


def test_username_injection_uses_real_ip():
    line = "sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 from 203.0.113.9 port 22 ssh2"
    assert parse_ssh_line(line, 0).ip == "203.0.113.9"


def test_url_injection_ignored():
    line = '198.51.100.7 - - [t] "GET /a?x=1.1.1.1 HTTP/1.1" 404 1 "-" "1.1.1.1"'
    assert parse_web_line(line, 0).ip == "198.51.100.7"


def test_ipv4_mapped_normalized():
    assert normalize_ip("::ffff:203.0.113.5") == "203.0.113.5"


def test_invalid_ip_returns_none():
    assert normalize_ip("999.1.1.1") is None


def test_garbage_line_returns_none():
    assert parse_web_line("\x00\xff" * 5000, 0) is None


def test_accepted_login_is_ssh_ok():
    ev = parse_ssh_line(lines("auth.log")[6], NOW)
    assert (ev.kind, ev.ip) == ("ssh_ok", "192.0.2.10")


@pytest.mark.parametrize("value,expected", [
    ("fe80::1%eth0", "fe80::1"),
    ("2001:DB8:0:0::5", "2001:db8::5"),
    ("203.0.113.5", "203.0.113.5"),
    ("01.1.1.1", None),
    ("1.1.1.1 ", None),
    ("", None),
    ("example.com", None),
    ("١.1.1.1", None),
    (None, None),
    (b"1.1.1.1", None),
    (12, None),
])
def test_normalize_ip_cases(value, expected):
    assert normalize_ip(value) == expected


def test_event_is_frozen():
    ev = parse_ssh_line(lines("auth.log")[0], NOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.ip = "1.1.1.1"


def test_auth_log_fixture():
    got = [parse_ssh_line(l, NOW) for l in lines("auth.log")]
    assert [(e.kind, e.ip) if e else None for e in got] == [
        ("ssh_fail", "203.0.113.9"),
        ("ssh_fail", "203.0.113.9"),
        ("ssh_fail", "198.51.100.23"),
        ("ssh_fail", "198.51.100.23"),
        ("ssh_fail", "203.0.113.9"),
        ("ssh_fail", "2001:db8::5"),
        ("ssh_ok", "192.0.2.10"),
        None, None, None,
    ]
    assert all(e.ts == NOW for e in got if e)


def test_secure_fixture_sshd_session():
    got = [parse_ssh_line(l, NOW) for l in lines("secure")]
    assert [(e.kind, e.ip) if e else None for e in got] == [
        ("ssh_fail", "203.0.113.44"),
        ("ssh_ok", "192.0.2.77"),
        ("ssh_ok", "192.0.2.77"),
        ("ssh_fail", "198.51.100.200"),
        None,
    ]


def test_other_program_with_sshd_text_ignored():
    line = "Nov  4 10:00:01 web1 evil[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
    assert parse_ssh_line(line, 0) is None
    inner = "Nov  4 10:00:01 web1 evil[1]: sshd[1]: Failed password for x from 203.0.113.9 port 22 ssh2"
    assert parse_ssh_line(inner, 0) is None


def test_failed_with_embedded_accepted_stays_fail():
    line = ("sshd[1]: Failed password for invalid user Accepted password for root "
            "from 8.8.8.8 port 1 ssh2 from 203.0.113.9 port 22 ssh2")
    ev = parse_ssh_line(line, 0)
    assert (ev.kind, ev.ip) == ("ssh_fail", "203.0.113.9")


def test_accepted_with_embedded_failed_stays_ok():
    line = ("sshd[1]: Accepted password for Failed password for x from 8.8.8.8 port 1 ssh2 "
            "from 192.0.2.10 port 22 ssh2")
    ev = parse_ssh_line(line, 0)
    assert (ev.kind, ev.ip) == ("ssh_ok", "192.0.2.10")


def test_trailing_text_after_ip_rejected():
    assert parse_ssh_line("sshd[1]: Failed password for x from 203.0.113.9 port 22 ssh2 from 8.8.8.8", 0) is None
    assert parse_ssh_line("sshd[1]: Failed password for x from 203.0.113.9 port 22 ssh2 extra", 0) is None


def test_invalid_ip_in_ssh_line_none():
    assert parse_ssh_line("sshd[1]: Failed password for x from 999.1.1.1 port 22 ssh2", 0) is None
    assert parse_ssh_line("sshd[1]: Failed password for x from evil.example port 22 ssh2", 0) is None


def test_embedded_newline_cannot_forge():
    line = "sshd[1]: Failed password for x\nsshd[1]: Failed password for y from 8.8.8.8 port 1 ssh2"
    assert parse_ssh_line(line, 0) is None


def test_trailing_newline_ok():
    ev = parse_ssh_line("sshd[1]: Failed password for x from 203.0.113.9 port 22 ssh2\n", 0)
    assert ev.ip == "203.0.113.9"


def test_authentication_failure_without_ip_port_ignored():
    assert parse_ssh_line(lines("auth.log")[7], 0) is None


def test_raw_truncated_to_300():
    user = "a" * 1000
    ev = parse_ssh_line(f"sshd[1]: Failed password for {user} from 203.0.113.9 port 22 ssh2", 0)
    assert len(ev.raw) == 300


def test_oversize_line_none():
    pad = "a" * 17000
    assert parse_ssh_line(f"sshd[1]: Failed password for {pad} from 203.0.113.9 port 22 ssh2", 0) is None
    assert parse_web_line(f'203.0.113.9 - - [t] "GET /{pad} HTTP/1.1" 200 1 "-" "-"', 0) is None


def test_non_str_and_odd_chars_do_not_raise():
    for bad in (None, b"x", 5):
        assert parse_ssh_line(bad, 0) is None
        assert parse_web_line(bad, 0) is None
    for odd in ("‮\x07\x1b[31m", "sshd[1]: Failed password for é\x00 from 203.0.113.9 port 22 ssh2"):
        parse_ssh_line(odd, 0)
        parse_web_line(odd, 0)


def test_nginx_fixture():
    got = [parse_web_line(l, NOW) for l in lines("nginx.log")]
    assert [(e.ip, e.method, e.path, e.status) for e in got] == [
        ("203.0.113.50", "GET", "/wp-login.php", 404),
        ("198.51.100.7", "POST", "/login", 401),
        ("2001:db8::99", "GET", "/admin?next=/", 403),
        ("203.0.113.51", None, None, 400),
        ("203.0.113.52", None, None, 408),
        ("192.0.2.1", "GET", "/", 200),
    ]
    assert all(e.kind == "web" and e.ts == NOW for e in got)


def test_apache_fixture_with_escaped_quotes():
    got = [parse_web_line(l, NOW) for l in lines("apache.log")]
    assert got[0].path == "/index.php?id=1%27%20OR%201=1"
    assert got[1].status == 401
    assert got[2].status == 200 and got[2].ip == "192.0.2.2"


def test_web_hostname_first_field_none():
    assert parse_web_line('example.com - - [t] "GET / HTTP/1.1" 200 1 "-" "-"', 0) is None


def test_web_lowercase_method_has_no_path():
    ev = parse_web_line('203.0.113.9 - - [t] "get /x HTTP/1.1" 200 1 "-" "-"', 0)
    assert ev.method is None and ev.path is None and ev.status == 200


def test_ua_cannot_override_status_or_path():
    ua = '" 200 1 "x" "y'
    line = f'203.0.113.9 - - [05/Nov/2026:10:00:00 +0000] "GET /a HTTP/1.1" 404 1 "-" "{ua}"'
    ev = parse_web_line(line, 0)
    assert ev.path == "/a" and ev.status == 404


def test_xff_never_read():
    line = '10.0.0.1 - - [05/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-" "8.8.8.8"'
    ev = parse_web_line(line, 0)
    assert ev.ip == "10.0.0.1"


def test_dataclass_type():
    assert dataclasses.is_dataclass(LogEvent)


def test_web_user_agent_kept_untruncated():
    ua = "Mozilla/5.0 " + "x" * 400
    line = '198.51.100.7 - - [t] "GET /a HTTP/1.1" 200 1 "-" "%s"' % ua
    ev = parse_web_line(line, 0)
    assert ev.user_agent == ua and len(ev.raw) == 300


def test_web_user_agent_absent_is_none():
    assert parse_web_line('198.51.100.7 - - [t] "GET /a HTTP/1.1" 200 1', 0).user_agent is None
    assert parse_web_line('198.51.100.7 - - [t] "GET /a HTTP/1.1" 200 1 "-" "-"', 0).user_agent is None



def _syslog(age):
    return time.strftime("%b %e %H:%M:%S", time.localtime(NOW - age))


def _iso(age, fmt="%Y-%m-%dT%H:%M:%S+0000"):
    return time.strftime(fmt, time.gmtime(NOW - age))


SSH_TAIL = " web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"


@pytest.mark.parametrize("age,stale", [(0, False), (599, False), (601, True), (86400, True), (-3600, False)])
def test_ssh_line_age(age, stale):
    assert ssh_line_is_stale(_syslog(age) + SSH_TAIL, NOW) is stale
    assert ssh_line_is_stale(_iso(age) + SSH_TAIL, NOW) is stale


@pytest.mark.parametrize("fmt", ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.123456+00:00", "%Y-%m-%dT%H:%M:%S+00:00"])
def test_iso_variants(fmt):
    assert ssh_line_is_stale(_iso(3600, fmt) + SSH_TAIL, NOW)
    assert not ssh_line_is_stale(_iso(0, fmt) + SSH_TAIL, NOW)


def test_iso_offset_is_honoured():
    assert not ssh_line_is_stale(time.strftime("%Y-%m-%dT%H:%M:%S+0300", time.gmtime(NOW + 3 * 3600)) + SSH_TAIL, NOW)


def test_syslog_from_last_december_read_in_january_is_stale_not_future():
    jan = time.mktime((2024, 1, 1, 0, 5, 0, 0, 0, -1))
    assert ssh_line_is_stale("Dec 31 23:00:00" + SSH_TAIL, jan)
    assert not ssh_line_is_stale("Dec 31 23:59:00" + SSH_TAIL, jan)


@pytest.mark.parametrize("line", ["sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2", "", "Foo 99 99:99:99 x",
                                  "2026-99-99T99:99:99+0000 web01 sshd[1]: x"])
def test_unparseable_timestamp_counts_as_now(line):
    assert ssh_line_is_stale(line, NOW) is False


@pytest.mark.parametrize("age,stale", [(0, False), (601, True)])
def test_web_line_age(age, stale):
    stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(NOW - age))
    line = '203.0.113.9 - - [%s] "GET / HTTP/1.1" 200 5 "-" "ua"' % stamp
    assert web_line_is_stale(line, NOW) is stale
    assert parse_web_line(line, NOW).status == 200


def test_web_line_without_usable_time_counts_as_now():
    assert web_line_is_stale('203.0.113.9 - - [nope] "GET / HTTP/1.1" 200 5', NOW) is False
    assert web_line_is_stale("junk", NOW) is False


def test_ssh_certificate_login_is_ok_event():
    line = ("Nov  5 10:00:00 h sshd[1]: Accepted publickey for root from 203.0.113.5 port 5000 ssh2: "
            "ED25519-CERT SHA256:abc ID admin@corp (serial 7) CA ED25519 SHA256:def")
    ev = parse_ssh_line(line, 0)
    assert ev.kind == "ssh_ok" and ev.ip == "203.0.113.5"


def test_scope_only_on_ipv6():
    assert normalize_ip("1.1.1.1%junk") is None
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
