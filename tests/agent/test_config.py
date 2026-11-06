from __future__ import annotations

import json
import os

import pytest

from nexus_agent.config import (
    AgentConfig, load_ssh_ok, load_state, read_gateways, read_resolvers, resolve_host, save_state,
)

BASE = {"NEXUS_URL": "https://c.example", "NEXUS_API_KEY": "k"}


def cfg(tmp_path, sshd="", **env):
    conf = tmp_path / "sshd_config"
    conf.write_text(sshd)
    return AgentConfig.from_env(dict(BASE, **env), sshd_config=str(conf))


def test_defaults(tmp_path):
    c = cfg(tmp_path)
    assert c.max_mode == "enforce"
    assert c.rules.ssh_ports == (22,) and c.rules.web_ports == (80, 443)
    assert str(c.state_dir) == "/var/lib/nexus-agent"
    assert c.allowlist == () and c.web_logs == () and c.allow_insecure is False


@pytest.mark.parametrize("missing", ["NEXUS_URL", "NEXUS_API_KEY"])
def test_missing_url_or_key_is_a_clear_error(missing):
    env = dict(BASE)
    del env[missing]
    with pytest.raises(ValueError, match=missing):
        AgentConfig.from_env(env)


def test_typo_in_max_mode_fails_instead_of_allowing_enforce(tmp_path):
    with pytest.raises(ValueError, match="NEXUS_MAX_MODE"):
        cfg(tmp_path, NEXUS_MAX_MODE="observ")


def test_key_is_not_in_repr(tmp_path):
    assert "key" not in repr(cfg(tmp_path))


def test_env_values(tmp_path):
    c = cfg(tmp_path, NEXUS_MAX_MODE="observe", NEXUS_WEB_LOGS="/a.log, /b.log,", NEXUS_SSH_PORTS="2222",
            NEXUS_WEB_PORTS="8080,8443", NEXUS_STATE_DIR="/tmp/s", NEXUS_ALLOWLIST="192.0.2.1, 198.51.100.0/24",
            NEXUS_INSECURE="1", NEXUS_NODE_ID="web-1", NEXUS_RULE_SSH_FAIL_THRESHOLD="7")
    assert c.max_mode == "observe" and c.node_id == "web-1"
    assert c.web_logs == ("/a.log", "/b.log")
    assert c.rules.ssh_ports == (2222,) and c.rules.web_ports == (8080, 8443)
    assert c.rules.ssh_fail_threshold == 7
    assert str(c.state_dir) == "/tmp/s"
    assert c.allowlist == ("192.0.2.1", "198.51.100.0/24")
    assert c.allow_insecure is True


def test_sshd_config_ports_are_added(tmp_path):
    sshd = "# Port 9999\nPort 2222\n  port 2200 # second\nPortX 1\nPort abc\nPort 70000\n"
    assert cfg(tmp_path, sshd=sshd).rules.ssh_ports == (22, 2200, 2222)
    assert cfg(tmp_path, sshd=sshd, NEXUS_SSH_PORTS="23").rules.ssh_ports == (23, 2200, 2222)


def test_invalid_ports_keep_default(tmp_path, caplog):
    assert cfg(tmp_path, NEXUS_SSH_PORTS="abc,70000").rules.ssh_ports == (22,)
    assert "NEXUS_SSH_PORTS" in caplog.text


def test_read_gateways(tmp_path):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
        "bad line\n"
    )
    assert read_gateways(str(route)) == ["192.168.1.1"]
    assert read_gateways(str(tmp_path / "absent")) == []


def test_read_resolvers(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("# nameserver 9.9.9.9\nnameserver 1.1.1.1\nsearch x\nnameserver   2606:4700::1111\nnameserver\n")
    assert read_resolvers(str(conf)) == ["1.1.1.1", "2606:4700::1111"]
    assert read_resolvers(str(tmp_path / "absent")) == []


def test_resolve_host():
    infos = [(2, 1, 6, "", ("192.0.2.5", 0)), (10, 1, 6, "", ("2001:db8::5", 0, 0, 0)), (2, 2, 17, "", ("192.0.2.5", 0))]
    assert sorted(resolve_host("c.example", getaddrinfo=lambda h, p: infos)) == ["192.0.2.5", "2001:db8::5"]


def test_resolve_host_failure_and_hang_are_guarded():
    def fail(h, p):
        raise OSError("no dns")

    assert resolve_host("c.example", getaddrinfo=fail) == []
    assert resolve_host(None) == []

    import threading
    release = threading.Event()
    assert resolve_host("c.example", timeout=0.01, getaddrinfo=lambda h, p: release.wait(5)) == []
    release.set()


def test_state_roundtrip_is_atomic_and_private(tmp_path):
    d = tmp_path / "new" / "state"
    assert save_state(d, "enforce", ["192.0.2.1"]) is True
    assert load_state(d) == ("enforce", ["192.0.2.1"])
    assert os.listdir(str(d)) == ["state.json"]
    assert (d / "state.json").stat().st_mode & 0o077 == 0


def test_save_failure_leaves_old_state_and_returns_false(tmp_path, monkeypatch, caplog):
    assert save_state(tmp_path, "observe", [])
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("disk full")))
    assert save_state(tmp_path, "enforce", []) is False
    assert "state" in caplog.text
    assert load_state(tmp_path) == ("observe", [])
    assert os.listdir(str(tmp_path)) == ["state.json"]


def test_save_to_unwritable_location_returns_false(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    assert save_state(blocker / "sub", "observe", []) is False


@pytest.mark.parametrize("content", [
    "{not json", "[]", "null", '{"mode": "bogus", "allowlist": []}', '{"mode": "enforce", "allowlist": "x"}',
    '{"mode": "enforce", "allowlist": [1]}', '{"allowlist": []}',
])
def test_corrupt_state_is_ignored(tmp_path, content):
    (tmp_path / "state.json").write_text(content)
    assert load_state(tmp_path) is None


def test_missing_state(tmp_path):
    assert load_state(tmp_path) is None


def test_state_file_format(tmp_path):
    save_state(tmp_path, "off", ["192.0.2.0/24"])
    assert json.loads((tmp_path / "state.json").read_text()) == {"mode": "off", "allowlist": ["192.0.2.0/24"], "ssh_ok": []}


def test_sshd_include_globs_are_followed(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "10-a.conf").write_text("Port 2222\n")
    (d / "20-b.conf").write_text("Include %s\nPort 2200\n" % (tmp_path / "sshd_config"))
    (d / "skip.txt").write_text("Port 9999\n")
    assert cfg(tmp_path, sshd="Include sshd_config.d/*.conf\n").rules.ssh_ports == (22, 2200, 2222)


def test_sshd_absolute_include_with_several_patterns(tmp_path):
    a = tmp_path / "a.conf"
    a.write_text("Port 2201\n")
    b = tmp_path / "b.conf"
    b.write_text("Port 2202\n")
    assert cfg(tmp_path, sshd='include "%s" %s\n' % (a, b)).rules.ssh_ports == (22, 2201, 2202)


def test_ssh_ok_state_roundtrip_and_tolerance(tmp_path):
    save_state(tmp_path, "observe", [], [["203.0.113.9", 5.0]])
    assert load_ssh_ok(tmp_path) == [["203.0.113.9", 5.0]]
    assert load_state(tmp_path) == ("observe", [])
    (tmp_path / "state.json").write_text('{"mode": "observe", "allowlist": [], "ssh_ok": "x"}')
    assert load_ssh_ok(tmp_path) == []
    assert load_state(tmp_path) == ("observe", [])
    (tmp_path / "state.json").write_text("{broken")
    assert load_ssh_ok(tmp_path) == []


def test_state_keeps_last_send_only_when_given(tmp_path):
    save_state(tmp_path, "observe", [], [], 12.5)
    assert json.loads((tmp_path / "state.json").read_text())["last_send"] == 12.5
    assert load_state(tmp_path) == ("observe", [])
    save_state(tmp_path, "observe", [])
    assert "last_send" not in json.loads((tmp_path / "state.json").read_text())
