from __future__ import annotations

import json

import pytest

from nexus_agent.anomaly import load_models
from nexus_agent.parsers import parse_ssh_line
from nexus_agent.protect import Protector
from nexus_agent.rules import RuleConfig, RuleEngine
from scripts.eval_anomaly import _ssh_line, real, wilson
from scripts.export_real_events import build
from scripts.replay import SimClock, blocked, replay

START = 1800000000.0
IP = "203.0.113.5"


def failures(count):
    lines = []
    for i in range(count):
        ts = START + i * 2
        row = {"t": ts, "kind": "failed", "user": "root", "port": 1000 + i}
        lines.append((ts, "ssh", _ssh_line(row, IP)))
    return lines


def test_wilson_known_values():
    assert wilson(8, 10) == pytest.approx((0.4902, 0.9433), abs=1e-3)
    assert wilson(0, 0) == (0.0, 1.0)


def test_replay_agrees_with_feeding_the_engine():
    clock = SimClock()
    engine = RuleEngine(RuleConfig(anomaly_block=1), Protector(allowlist=(), clock=clock), clock, None)
    direct = []
    for ts, _source, line in failures(12):
        clock.now = ts
        direct += engine.feed(parse_ssh_line(line, ts))
    assert direct
    assert [s.decision for s in replay(failures(12), "rules")] == direct


def test_fail2ban_counts_retries_inside_findtime():
    assert IP in blocked(replay(failures(5), "fail2ban", maxretry=5))
    assert IP not in blocked(replay(failures(4), "fail2ban", maxretry=5))
    assert IP not in blocked(replay(failures(5), "fail2ban", maxretry=5, findtime=4))


def test_alert_is_not_a_block():
    assert blocked(replay(failures(4), "rules")) == {}


def test_real_export_format_runs_through_every_system(tmp_path, capsys):
    rows = [{"src": "meta", "jail": {"maxretry": "5", "findtime": "600", "bantime": "600"}}, {"src": "ban", "t": START, "ip": "a"}]
    rows += [{"src": "ssh", "t": START + i, "kind": "invalid", "ip": "a", "user": "u%d" % i, "port": 1000 + i} for i in range(12)]
    rows += [{"src": "ssh", "t": START, "kind": "ok", "ip": "c", "user": "me", "port": 900},
             {"src": "web", "t": START, "ip": "w", "site": "s", "method": "GET", "path": "/p/ab", "status": 200, "exploit": False,
              "ua": "Mozilla/5.0 (ab"}]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows))
    real(path, load_models())
    out = capsys.readouterr().out
    assert "attack_ssh_real" in out and "customer_ssh_login" in out and "customer_web_real" in out
    assert "Addresses: 3" in out


def test_export_payload_compiles_with_the_given_containers():
    payload = build(["web-1"])
    compile(payload, "payload", "exec")
    assert "CONTAINERS = ['web-1']" in payload
