from __future__ import annotations

import logging
import os
import stat
import threading
import time
from collections import namedtuple

import psutil
import pytest

from nexus_agent import collectors
from nexus_agent.collectors import (
    FileTail, JournalTail, LineQueue, LogCollectors, SSH_JOURNAL, read_connections, sample_connections,
    sample_metrics, web_peers,
)
from nexus_agent.parsers import MAX_LINE, parse_scan_line, parse_ssh_line

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "laddr raddr status")


def listen(port):
    return Conn(Addr("0.0.0.0", port), (), "LISTEN")


def conn(port, ip, status="ESTABLISHED", rport=50000):
    return Conn(Addr("198.51.100.1", port), Addr(ip, rport), status)


def append(path, data):
    with open(str(path), "ab") as f:
        f.write(data)


def test_tail_starts_at_end(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("old\n")
    t = FileTail(p)
    assert t.read_lines() == []
    append(p, b"new\n")
    assert t.read_lines() == ["new"]


def test_tail_holds_partial_line_until_newline(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTail(p)
    append(p, b"par")
    assert t.read_lines() == []
    append(p, b"tial\nnext")
    assert t.read_lines() == ["partial"]


def test_tail_follows_rename_rotation(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTail(p)
    append(p, b"one\n")
    assert t.read_lines() == ["one"]
    append(p, b"two\n")
    os.rename(str(p), str(tmp_path / "a.log.1"))
    assert t.read_lines() == ["two"]  # written before the rename, picked up while the new file is absent
    append(tmp_path / "a.log.1", b"three\n")  # the daemon keeps writing the old inode until reopened
    append(p, b"four\n")
    assert t.read_lines() == ["three", "four"]
    append(p, b"five\n")
    assert t.read_lines() == ["five"]


def test_tail_follows_copytruncate(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTail(p)
    append(p, b"a long first line\n")
    assert t.read_lines() == ["a long first line"]
    with open(str(p), "wb"):
        pass
    append(p, b"short\n")
    assert t.read_lines() == ["short"]


def test_tail_survives_invalid_utf8_and_missing_file(tmp_path):
    p = tmp_path / "a.log"
    t = FileTail(p, recheck=0)
    assert t.read_lines() == []
    append(p, b"bad \xff\xfe bytes\n")
    assert t.read_lines() == ["bad �� bytes"]


def test_file_created_after_start_is_read_from_its_beginning_on_recheck(tmp_path, caplog):
    now = [0.0]
    p = tmp_path / "a.log"
    with caplog.at_level(logging.INFO, "nexus_agent.collectors"):
        t = FileTail(p, clock=lambda: now[0])
        p.write_text("first\n")
        assert t.read_lines() == []  # not rechecked yet
        now[0] = 59
        assert t.read_lines() == []
        now[0] = 61
        assert t.read_lines() == ["first"]
    assert sum("unavailable" in r.message for r in caplog.records) == 1


def test_unavailable_log_logs_once_across_rechecks(tmp_path, caplog):
    now = [0.0]
    with caplog.at_level(logging.INFO, "nexus_agent.collectors"):
        t = FileTail(tmp_path / "none", clock=lambda: now[0])
        for now[0] in (61, 122, 183):
            t.read_lines()
    assert sum("unavailable" in r.message for r in caplog.records) == 1


def test_tail_skips_whole_overlong_line_so_its_tail_cannot_pose_as_a_line(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTail(p)
    forged = b"sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n"
    append(p, b"x" * (MAX_LINE * 3))
    assert t.read_lines() == []
    append(p, forged + b"good\n")
    assert t.read_lines() == ["good"]


def test_tail_read_is_bounded_per_call(tmp_path, monkeypatch):
    monkeypatch.setattr(collectors, "MAX_READ", 10)
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTail(p)
    append(p, b"aaaa\nbbbb\ncccc\n")
    assert t.read_lines() == ["aaaa", "bbbb"]
    assert t.read_lines() == ["cccc"]


def fake_journal(tmp_path, body):
    script = tmp_path / "journalctl"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_journal_tail_passes_args_restarts_and_stops(tmp_path):
    binary = fake_journal(tmp_path, 'echo "$@"\nprintf "bad \\377\\n"\nprintf "partial"\nexit 1\n')
    lines, stop = [], threading.Event()
    tail = JournalTail(("-k", "-n", "0"), binary=binary, backoff=0.01)
    th = threading.Thread(target=tail.run, args=(lines.append, stop), daemon=True)
    th.start()
    assert wait_for(lambda: len(lines) >= 4)  # two runs prove the restart
    stop.set()
    tail.terminate()
    th.join(5)
    assert not th.is_alive()
    assert lines[:2] == ["-k -n 0\n", "bad �\n"]
    assert not any("partial" in l for l in lines)


def test_journal_tail_survives_missing_binary_and_stops(tmp_path):
    stop = threading.Event()
    tail = JournalTail(("-k",), binary=str(tmp_path / "absent"), backoff=0.01)
    th = threading.Thread(target=tail.run, args=(lambda l: None, stop), daemon=True)
    th.start()
    time.sleep(0.05)
    assert th.is_alive()
    stop.set()
    th.join(5)
    assert not th.is_alive()


def test_journal_tail_drops_overlong_line_whole(tmp_path):
    binary = fake_journal(tmp_path, 'head -c %d /dev/zero | tr "\\0" x\necho " sshd[1]: forged"\necho good\nexec sleep 5\n' % (MAX_LINE * 3))
    lines, stop = [], threading.Event()
    tail = JournalTail((), binary=binary)
    th = threading.Thread(target=tail.run, args=(lines.append, stop), daemon=True)
    th.start()
    assert wait_for(lambda: lines)
    stop.set()
    tail.terminate()
    th.join(5)
    assert lines == ["good\n"]


def test_journal_format_is_accepted_by_ssh_parser():
    # journalctl -u ssh -o short-iso output; -o cat would drop the sshd[pid] header the parser anchors on.
    assert "short-iso" in SSH_JOURNAL and "cat" not in SSH_JOURNAL
    line = "2026-11-04T13:22:11+0300 web01 sshd[1234]: Failed password for root from 203.0.113.9 port 4242 ssh2\n"
    assert parse_ssh_line(line, 0.0).ip == "203.0.113.9"
    new = "2026-11-04T13:22:11+03:00 web01 sshd-session[99]: Invalid user bob from ::ffff:203.0.113.9 port 4242\n"
    assert parse_ssh_line(new, 0.0).ip == "203.0.113.9"


SCAN = ("IN=eth0 OUT= MAC=00:11 SRC=%s DST=198.51.100.1 LEN=44 TOS=0x00 TTL=50 ID=1 PROTO=TCP "
        "SPT=4444 DPT=%s WINDOW=1024 SYN URGP=0")


@pytest.mark.parametrize("head", [
    "nexus-scan ",
    "2026-11-04T13:22:11+0300 web01 kernel: nexus-scan ",
    "Nov  4 13:22:11 web01 kernel: [12345.678901] nexus-scan ",
    "Nov  4 13:22:11 web01 kernel: nexus-scan ",
])
def test_parse_scan_line(head):
    assert parse_scan_line(head + SCAN % ("203.0.113.9", "23")) == ("203.0.113.9", 23)


def test_parse_scan_line_normalizes_mapped_ip():
    assert parse_scan_line("nexus-scan " + SCAN % ("::ffff:203.0.113.9", "23")) == ("203.0.113.9", 23)


@pytest.mark.parametrize("line", [
    "Nov  4 13:22:11 web01 root: nexus-scan " + SCAN % ("203.0.113.9", "23"),  # logger from a local user
    "Nov  4 13:22:11 web01 kernel: audit nexus-scan " + SCAN % ("203.0.113.9", "23"),
    "nexus-scan " + SCAN % ("not-an-ip", "23"),
    "nexus-scan " + SCAN % ("203.0.113.9", "0"),
    "nexus-scan " + SCAN % ("203.0.113.9", "70000"),
    "nexus-scan IN=eth0 SRC=203.0.113.9",
    "nexus-scan IN=eth0 XSRC=203.0.113.9 XDPT=23",
    "nexus-scan " + "x" * MAX_LINE + " SRC=203.0.113.9 DPT=23",
    "",
])
def test_parse_scan_line_rejects(line):
    assert parse_scan_line(line) is None


def test_line_queue_drops_new_lines_and_counts_when_full():
    q = LineQueue(2)
    for n in "abc":
        q.put("ssh", n)
    assert q.dropped == 1
    assert list(q.drain(10)) == [("ssh", "a"), ("ssh", "b")]


def test_line_queue_drain_is_limited_and_lazy():
    q = LineQueue(10)
    for n in "abcd":
        q.put("web", n)
    it = q.drain(3)
    assert next(it) == ("web", "a")
    assert len(list(it)) == 2
    assert list(q.drain(3)) == [("web", "d")]


def make_collectors(q, ssh, web=(), kern="/nonexistent/kern.log", journal=True):
    return LogCollectors(q, ssh_logs=ssh, web_logs=web, kern_log=kern,
                         journalctl="/bin/journalctl" if journal else None)


def test_ssh_file_wins_and_journal_is_not_used(tmp_path):
    (tmp_path / "secure").write_text("")
    (tmp_path / "auth.log").write_text("")
    c = make_collectors(LineQueue(10), (tmp_path / "auth.log", tmp_path / "secure"))
    assert [(s, str(t.path)) for s, t in c.files if s == "ssh"] == [("ssh", str(tmp_path / "auth.log"))]
    assert [s for s, _ in c.journals] == ["scan"]


def test_ssh_journal_used_when_no_file(tmp_path):
    c = make_collectors(LineQueue(10), (tmp_path / "auth.log",))
    assert not [t for s, t in c.files if s == "ssh"]
    assert sorted(s for s, _ in c.journals) == ["scan", "ssh"]


def test_kernel_falls_back_to_file_without_journalctl(tmp_path):
    kern = tmp_path / "kern.log"
    kern.write_text("")
    c = make_collectors(LineQueue(10), (), kern=kern, journal=False)
    assert c.journals == []
    assert [(s, str(t.path)) for s, t in c.files] == [("scan", str(kern))]


def test_without_journal_a_late_ssh_file_is_picked_once(tmp_path):
    a, b = tmp_path / "auth.log", tmp_path / "secure"
    q = LineQueue(10)
    now = [0.0]
    c = LogCollectors(q, ssh_logs=(a, b), web_logs=(), kern_log=tmp_path / "k", journalctl=None, clock=lambda: now[0])
    a.write_text("x\n")
    b.write_text("y\n")
    c.poll_files()
    assert not list(q.drain(10))
    now[0] = 61
    c.poll_files()
    assert list(q.drain(10)) == [("ssh", "x")]


def test_duplicate_web_paths_are_tailed_once_and_tagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("")
    q = LineQueue(10)
    c = make_collectors(q, (), web=(p, str(p)))
    append(p, b"hello\n")
    c.poll_files()
    assert list(q.drain(10)) == [("web", "hello")]


def test_one_failing_tail_does_not_stop_the_others(tmp_path):
    p, r = tmp_path / "a", tmp_path / "b"
    p.write_text("")
    r.write_text("")
    q = LineQueue(10)
    c = make_collectors(q, (), web=(p, r))
    c.files[0][1].read_lines = lambda: 1 / 0
    append(r, b"ok\n")
    c.poll_files()
    assert list(q.drain(10)) == [("web", "ok")]


def test_sample_connections_counts_only_inbound(monkeypatch):
    conns = [
        listen(22), listen(80),
        conn(80, "203.0.113.9"), conn(80, "::ffff:203.0.113.9"),
        conn(80, "203.0.113.10", "SYN_RECV"),
        conn(45000, "93.184.216.34"),  # an outbound call must never look like a flood
        conn(22, "198.51.100.7"),
        conn(22, "198.51.100.8", "TIME_WAIT"),
        Conn(Addr("0.0.0.0", 53), (), "NONE"),
    ]
    monkeypatch.setattr(psutil, "net_connections", lambda kind: conns)
    per_ip, syn_recv, active_ssh, ports = sample_connections((22,))
    assert per_ip == {"203.0.113.9": 2, "203.0.113.10": 1, "198.51.100.7": 1}
    assert syn_recv == 1
    assert active_ssh == {"198.51.100.7"}
    assert ports == {22, 80}


def test_access_denied_is_an_empty_sample(monkeypatch, caplog):
    def deny(kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", deny)
    assert sample_connections((22,)) == ({}, 0, set(), set())
    assert read_connections() == []
    assert "denied" in caplog.text


def test_web_peers_are_distinct_established_remote_ips():
    conns = [listen(443), conn(443, "104.16.0.1"), conn(443, "::ffff:104.16.0.1"),
             conn(443, "104.16.0.2", "SYN_RECV"), conn(8080, "104.16.0.3")]
    assert web_peers((80, 443), conns) == {"104.16.0.1"}


def test_sample_metrics_shape_and_bounds(monkeypatch):
    first = sample_metrics()
    assert set(first) == {"cpu_pct", "memory_pct", "net_kbps"}
    assert all(isinstance(v, float) for v in first.values())
    assert 0 <= first["cpu_pct"] <= 100 and 0 <= first["memory_pct"] <= 100
    # A counter reset (interface recreated) must not produce a negative rate, which ingest would refuse.
    Net = namedtuple("Net", "bytes_sent bytes_recv")
    monkeypatch.setattr(collectors, "_last_net", (time.monotonic() - 1, 10 ** 12))
    monkeypatch.setattr(psutil, "net_io_counters", lambda: Net(0, 0))
    assert sample_metrics()["net_kbps"] == 0.0
    monkeypatch.setattr(psutil, "net_io_counters", lambda: None)
    assert sample_metrics()["net_kbps"] == 0.0
