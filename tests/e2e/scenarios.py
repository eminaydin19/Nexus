"""Attack and customer scenarios against the whole system. Run by tests/e2e/run.sh, inside the runner container.

Every negative check ("not blocked") is followed by a positive control from another source, processed after it,
so a dead agent can never pass a scenario and no fixed sleep is needed to know the agent has read the lines.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import shlex
import subprocess
import time

import pytest
import requests

PROJECT = os.environ["E2E_PROJECT"]
BACKEND = os.environ.get("E2E_BACKEND", "sqlite")
# RED run: everything is up except the agent, so each scenario must fail on its first agent-dependent check.
AGENT_DOWN = os.environ.get("E2E_AGENT_DOWN") == "1"
SCALE = float(os.environ.get("E2E_TIMEOUT_SCALE", "1"))

CENTRAL = "http://203.0.113.10:8000"
AUTH = ("admin", "e2e-dashboard-password")
TARGET, ATTACKER, CUSTOMER, NAT, CDN, SCANNER = (
    "203.0.113.20", "203.0.113.30", "203.0.113.31", "203.0.113.32", "203.0.113.33", "203.0.113.34")
GATEWAY = "203.0.113.1"
SSH_PORT, WEB_PORT = 22, 80
LOAD = "/usr/local/bin/load.py"
AGENT_LOG = "/var/log/nexus-agent.log"
STATE = "/var/lib/nexus-agent/state.json"
PROBES = ["/.env", "/.git/config", "/phpmyadmin", "/wp-config.php", "/backup.sql", "/shell.php", "/server-status",
          "/.aws/credentials", "/adminer.php", "/config.php", "/web.config", "/dump.sql"]
EXPLOITS = ["' OR 1=1 --", "../../../etc/passwd", "1 UNION SELECT password FROM users", "<script>alert(1)</script>",
            "$(cat /etc/shadow)", "${jndi:ldap://x/a}", "/proc/self/environ", "x onerror=alert(1)"]
TOOLS = ("attacker", "customer", "nat_customer", "cdn", "scanner")


# -- plumbing ----------------------------------------------------------------

def container(service: str) -> str:
    return f"{PROJECT}-{service}-1"


def run(service: str, *argv: str, env: dict | None = None, timeout: float = 120, detach: bool = False,
        check: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", "exec"] + (["-d"] if detach else [])
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    r = subprocess.run(cmd + [container(service), *argv], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise AssertionError(f"{service}: {argv} exited {r.returncode}: {r.stdout}{r.stderr}")
    return r


def sh(service: str, script: str, **kw) -> subprocess.CompletedProcess:
    return run(service, "bash", "-c", script, **kw)


def wait(check, timeout: float, what: str, interval: float = 0.5):
    deadline = time.monotonic() + timeout * SCALE
    last = None
    while time.monotonic() < deadline:
        last = check()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout * SCALE:.0f}s: {what} (last: {last!r})")


def metric(name: str, **values) -> None:
    line = json.dumps({"scenario": name, "backend": BACKEND, **values})
    print(f"\nMETRIC {line}", flush=True)
    with open(f"/e2e/out/metrics-{BACKEND}.jsonl", "a") as f:
        f.write(line + "\n")


def api(method: str, path: str, **kw):
    return requests.request(method, CENTRAL + path, auth=AUTH, timeout=20, **kw)


def api_json(method: str, path: str, **kw):
    r = api(method, path, **kw)
    assert r.status_code == 200, f"{method} {path}: {r.status_code} {r.text[:300]}"
    return r.json()


def server() -> dict:
    return next(a for a in api_json("GET", "/api/agents")["agents"] if a["node_id"] == NODE["id"])


def events(since: float, ip: str | None = None, rule: str | None = None) -> list:
    rows = api_json("GET", "/api/events", params={"limit": 500})["events"]
    return [e for e in rows if e["ts"] >= since and (ip is None or e["ip"] == ip) and (rule is None or e["rule"] == rule)]


def panel_block(ip: str) -> list:
    return [b for b in api_json("GET", "/api/blocks")["blocks"] if b["ip"] == ip]


BLOCK_SETS = ("port4", "port6", "all4", "all6", "limit4", "limit6")


def kernel() -> dict:
    """Block set name -> [(addr, port, seconds left)], from the kernel itself. {} when the table does not exist."""
    r = run("target", "nft", "-j", "list", "table", "inet", "nexus")
    if r.returncode:
        assert "No such file" in r.stderr, r.stderr
        return {}
    out: dict = {}
    for item in json.loads(r.stdout)["nftables"]:
        s = item.get("set")
        if not s or s["name"] not in BLOCK_SETS:
            continue
        rows = out.setdefault(s["name"], [])
        for el in s.get("elem", []):
            el = el.get("elem", el) if isinstance(el, dict) else el
            val = el.get("val") if isinstance(el, dict) else el
            addr, port = val["concat"] if isinstance(val, dict) else (val, 0)
            rows.append((addr, port, el.get("expires", 0) if isinstance(el, dict) else 0))
    return out


def rows_for(ip: str) -> dict:
    return {name: [r for r in rows if r[0] == ip] for name, rows in kernel().items() if any(r[0] == ip for r in rows)}


def port_blocked(ip: str, port: int) -> bool:
    return any(r[0] == ip and r[1] == port for r in kernel().get("port4", []))


def all_blocked(ip: str) -> bool:
    return any(r[0] == ip for r in kernel().get("all4", []))


def limited(ip: str) -> bool:
    return any(r[0] == ip for r in kernel().get("limit4", []))


def assert_no_kernel_rows(ip: str) -> None:
    assert not rows_for(ip), f"{ip} has kernel rows: {rows_for(ip)}"


def http(service: str, path: str = "/") -> str:
    """Status code of one real request; 000 means the connection never got through."""
    r = run(service, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--connect-timeout", "2", "--max-time", "4",
            f"http://{TARGET}{path}")
    return r.stdout.strip()


def tcp_open(service: str, port: int) -> bool:
    code = f"import socket; socket.create_connection(({TARGET!r}, {port}), timeout=2)"
    return run(service, "python3", "-c", code, timeout=15).returncode == 0


def ssh(service: str, user: str, password: str, command: str = "true", timeout: float = 15) -> int:
    r = run(service, "timeout", str(timeout), "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
            "-o", "ConnectTimeout=3", "-o", "LogLevel=ERROR", f"{user}@{TARGET}", command, timeout=timeout + 5)
    return r.returncode


def probe(service: str, paths=PROBES) -> None:
    for p in paths:
        http(service, p)


def scanned_until_blocked(service: str, ip: str, timeout: float = 30) -> None:
    probe(service)
    wait(lambda: port_blocked(ip, WEB_PORT), timeout, f"{ip} blocked on the web ports by web_probe")


def failed_password_lines(ip: str) -> int:
    r = sh("target", f"grep -c 'Failed password for .* from {ip} ' /var/log/auth.log")
    return int(r.stdout.strip() or 0)


def ssh_fail_until_blocked(service: str, ip: str, timeout: float = 240) -> int:
    """Failed logins with a real client until the kernel holds the block. sshd's own penalties may delay some."""
    attempts, deadline = 0, time.monotonic() + timeout * SCALE
    while time.monotonic() < deadline:
        if port_blocked(ip, SSH_PORT):
            return attempts
        ssh(service, "customer", "wrong-password")
        attempts += 1
    raise AssertionError(f"{ip} not blocked on ssh after {attempts} failed logins in {timeout * SCALE:.0f}s")


def ssh_failures(service: str, ip: str, count: int, timeout: float = 240) -> None:
    """At least count real Failed password lines from this address, whatever sshd's penalties delay."""
    base, deadline = failed_password_lines(ip), time.monotonic() + timeout
    while failed_password_lines(ip) - base < count:
        assert time.monotonic() < deadline, f"sshd logged too few failures for {ip}"
        ssh(service, "customer", "wrong-password")


class Load:
    def __init__(self, service: str, name: str, *args: str):
        self.service, self.out = service, f"/tmp/{name}.json"
        run(service, "rm", "-f", self.out)
        run(service, "python3", LOAD, "--out", self.out, *args, detach=True, check=True)
        wait(self.read, 10 / SCALE, f"{name} load started", 0.2)

    def read(self):
        r = run(self.service, "cat", self.out)
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout else None

    def totals(self, start: float = 0, end: float = float("inf")) -> dict:
        ok = err = slow = 0
        for sec, (o, e, s) in self.read()["seconds"].items():
            if start <= int(sec) < end:
                ok, err, slow = ok + o, err + e, slow + s
        total = ok + err
        return {"requests": total, "errors": err, "slow": slow,
                "success_pct": round(100.0 * ok / total, 3) if total else None}

    def stop(self) -> dict:
        # Never through a shell: pkill -f would match that shell's own command line.
        run(self.service, "pkill", "-TERM", "-f", "--", f"--out {self.out}")
        wait(lambda: run(self.service, "pgrep", "-f", "--", f"--out {self.out}").returncode != 0, 10 / SCALE, "load stopped", 0.1)
        return self.read()


def customer_load(name: str = "customer") -> Load:
    return Load("customer", name, "--rate", "10")


# -- agent lifecycle ---------------------------------------------------------

NODE: dict = {}


def agent_pid() -> int | None:
    r = run("target", "pgrep", "-f", "nexus_agent run")
    return int(r.stdout.split()[0]) if r.returncode == 0 else None


def stop_agent() -> None:
    run("target", "pkill", "-TERM", "-f", "nexus_agent run")
    wait(lambda: agent_pid() is None, 15 / SCALE, "agent exited on SIGTERM", 0.1)


def start_agent(env: dict | None = None) -> None:
    if AGENT_DOWN:
        return
    merged = {"NEXUS_URL": CENTRAL, "NEXUS_API_KEY": NODE["key"], "NEXUS_INSECURE": "1", **(env or {})}
    run("target", "bash", "-c", f"exec python -m nexus_agent run >>{AGENT_LOG} 2>&1", env=merged, detach=True, check=True)
    wait(agent_pid, 10, "agent process started", 0.1)


def write_state(mode: str) -> None:
    state = json.dumps({"mode": mode, "allowlist": [], "ssh_ok": []})
    sh("target", f"mkdir -p {os.path.dirname(STATE)} && printf %s {shlex.quote(state)} > {STATE}", check=True)


def wait_reported(mode: str, since: float | None = None, timeout: float = 25) -> dict:
    def check():
        s = server()
        fresh = since is None or (s["last_seen"] or 0) > since
        return s if fresh and s["reported_mode"] == mode and not s["pending"] else None

    return wait(check, timeout, f"agent reporting mode {mode} with no pending commands")


def fresh_agent(mode: str = "enforce", env: dict | None = None) -> None:
    """A clean agent as after a new install: no firewall table, no engine memory, no remembered logins."""
    stop_agent()
    run("target", "python", "-m", "nexus_agent", "uninstall", check=True)
    write_state(mode)
    t0 = time.time()
    start_agent(env)
    if not AGENT_DOWN:
        wait_reported(mode, since=t0)


def _healthy() -> bool:
    try:
        return requests.get(CENTRAL + "/healthz", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def central_up() -> None:
    wait(_healthy, 120 / SCALE, "central answering /healthz", 1)


def docker(*argv: str) -> None:
    subprocess.run(["docker", *argv], check=True, capture_output=True, timeout=120)


@pytest.fixture(scope="session", autouse=True)
def enrolled():
    central_up()
    token = api_json("POST", "/api/agents/tokens", json={"name": "e2e target"})["token"]
    env = {"NEXUS_ENROLL_TOKEN": token, "NEXUS_INSECURE": "1"}
    body = json.loads(run("target", "python", "-m", "nexus_agent", "enroll", "--url", CENTRAL, env=env, check=True).stdout)
    NODE.update(id=body["node_id"], key=body["api_key"])
    reused = run("target", "python", "-m", "nexus_agent", "enroll", "--url", CENTRAL, env=env)
    assert reused.returncode != 0, "an enrollment token must work only once"
    yield
    stop_agent()


@pytest.fixture(autouse=True)
def clean():
    for tool in TOOLS:
        run(tool, "pkill", "-f", LOAD)
        run(tool, "pkill", "-x", "sshpass")
        run(tool, "pkill", "-x", "ssh")
        run(tool, "pkill", "-f", "socket.create_connection")
    # A client blocked mid-login can no longer close its connection, so sshd would hold the session until LoginGraceTime.
    run("target", "pkill", "-f", "sshd-session")
    wait(lambda: run("target", "pgrep", "-f", "sshd-session").returncode != 0, 15 / SCALE, "old ssh sessions gone", 0.2)
    # sshd's own per-source penalties would otherwise carry from one scenario into the next.
    sh("target", "pkill -x sshd; sleep 0.2; /usr/sbin/sshd", check=True)
    central_up()
    api_json("PUT", f"/api/agents/{NODE['id']}/allowlist", json=[])
    fresh_agent()
    yield
    docker("start", container("central"))


# -- the attacker range must be blockable, before anything else means anything ---------------------------------------

def test_00_attacker_address_is_not_protected_and_really_gets_blocked():
    code = ("from nexus_agent.protect import Protector;"
            "p = Protector(central_ip='203.0.113.10', gateway=%r);"
            "print([p.reason(i) for i in (%r, %r, %r, %r)], p.reason(%r))" % (GATEWAY, ATTACKER, CUSTOMER, NAT, SCANNER, CDN))
    out = run("target", "python", "-c", code, check=True).stdout.strip()
    assert out == "[None, None, None, None] cdn", out
    assert http("attacker") == "200"
    scanned_until_blocked("attacker", ATTACKER)
    assert http("attacker") == "000", "a kernel row exists but packets still pass"
    metric("attacker_really_blocked", kernel=rows_for(ATTACKER))


# -- the brief's scenarios -------------------------------------------------------------------------------------------

def test_ssh_attacker_blocked_on_22_but_web_still_works():
    base = failed_password_lines(ATTACKER)
    started = time.monotonic()
    attempts = ssh_fail_until_blocked("attacker", ATTACKER)
    lines = failed_password_lines(ATTACKER) - base
    assert not tcp_open("attacker", SSH_PORT), "port 22 is still reachable"
    assert http("attacker") == "200", "ssh block must not touch the web"
    assert not all_blocked(ATTACKER)
    assert ssh("customer", "customer", "customer-pass") == 0, "another address lost ssh"
    event = wait(lambda: events(time.time() - 600, ATTACKER, "ssh_bruteforce"), 15, "central has the event")[0]
    metric("ssh_attacker", client_attempts=attempts, failed_password_lines=lines,
           seconds_to_block=round(time.monotonic() - started, 1), kernel=rows_for(ATTACKER))
    assert lines >= 10, f"blocked after only {lines} real failed logins; the spec's threshold is 10"
    assert event["action"] == "block_port" and event["ports"] == [SSH_PORT] and event["ttl"] == 3600


def test_unauthenticated_ssh_connection_gives_no_immunity():
    """An open port 22 connection used to count as an active session, which exempted its owner from every rule."""
    hold = ("import socket, time\n"
            f"s = [socket.create_connection(({TARGET!r}, {SSH_PORT})) for _ in range(3)]\n"
            "time.sleep(60)")
    run("attacker", "python3", "-c", hold, detach=True, check=True)
    time.sleep(6)  # one sample of the connection table, which nothing outside the agent can observe
    scanned_until_blocked("attacker", ATTACKER)
    assert http("attacker") == "000"
    metric("preauth_no_immunity", kernel=rows_for(ATTACKER))


def test_web_scanner_blocked_customer_sees_zero_errors():
    load = customer_load()
    scanned_until_blocked("scanner", SCANNER)
    assert http("scanner") == "000", "web block must really drop packets"
    assert ssh("scanner", "customer", "customer-pass") == 0, "a web block must leave ssh working"
    assert not all_blocked(SCANNER)
    time.sleep(3)  # customer traffic keeps measuring after the block lands, which no state change can signal
    load.stop()
    stats = load.totals()
    metric("web_scanner_customer_traffic", **stats, kernel=rows_for(SCANNER))
    assert stats["requests"] > 20 and stats["errors"] == 0, stats
    assert http("customer") == "200"
    assert_no_kernel_rows(CUSTOMER)


def test_high_volume_nat_ip_rate_limited_not_blocked():
    """One address past the open-connection limit: slowed, never blocked, nobody behind it hurt, no growing TTL."""
    # This traffic earns web trust, which triples the open-connection limit: 1100 must clear 3 x 300.
    fresh_agent(env={"NEXUS_RULE_TTL_CONN_FLOOD": "8", "NEXUS_RULE_MAX_CONN_PER_IP": "300"})
    started = int(time.time())
    load = Load("nat_customer", "nat-over", "--rate", "20", "--hold", "1100", "--ramp", "25")
    wait(lambda: load.read()["held_open"] >= 1100, 60, "1100 connections held open")
    limit_at = wait(lambda: limited(NAT) and int(time.time()), 30, "a rate limit on the address")
    # Past two expiries, so a doubling TTL would have to show in the events below.
    wait(lambda: len(events(started, NAT, "conn_flood")) >= 3, 90, "conn_flood fired three times")
    assert not port_blocked(NAT, WEB_PORT) and not all_blocked(NAT), "volume alone must never block"
    data = load.stop()
    stats = load.totals(start=limit_at)
    rows = events(started, NAT, "conn_flood")
    ttls = [e["ttl"] for e in rows]
    metric("nat_over_open_limit", during_limit=stats, ttls=ttls, held_lost=data["held_lost"])
    assert {e["action"] for e in rows} == {"rate_limit"}
    assert stats["errors"] == 0, stats
    assert set(ttls) == {8}, f"the slowdown must not grow on steady traffic: {ttls}"


def test_nat_office_250_connections_20_new_per_second_sees_no_limit_and_no_errors():
    t0 = int(time.time())
    fresh_agent(env={"NEXUS_RULE_TTL_CONN_FLOOD": "8"})
    base = Load("nat_customer", "nat-base", "--rate", "20")
    wait(lambda: base.totals()["requests"] >= 300, 40, "before phase at 20 new connections per second")
    before_end = int(time.time())
    hold = Load("nat_customer", "nat-hold", "--hold", "250", "--ramp", "10")
    wait(lambda: hold.read()["held_open"] >= 250, 40, "250 connections held open")
    during_start = int(time.time())
    # Long enough for several samples of the connection table and several expiries of a short TTL.
    wait(lambda: int(time.time()) - during_start >= 45, 60, "during phase", 1)
    during_end = int(time.time())
    seen_limit = limited(NAT)
    held = hold.stop()
    wait(lambda: int(time.time()) - during_end >= 15, 20, "after phase", 1)
    base.stop()
    before, during, after = base.totals(end=before_end), base.totals(during_start, during_end), base.totals(during_end)
    conn_events = events(t0, NAT, "conn_flood")
    metric("nat_office_250", before=before, during=during, after=after, held_open=held["held_open"],
           held_lost=held["held_lost"], limited=seen_limit, ttls=[e["ttl"] for e in conn_events])
    # Control: the same counters do see a flood; otherwise "no limit" above could mean a blind rule.
    flood = Load("attacker", "flood-control", "--rate", "400")
    wait(lambda: limited(ATTACKER), 40, "control: a real flood gets limited")
    flood.stop()
    assert_no_kernel_rows(NAT)
    for phase in (before, during, after):
        assert phase["requests"] > 100 and phase["errors"] == 0, (before, during, after)
    assert held["held_lost"] == 0 and not conn_events, conn_events


def test_true_flood_from_one_ip_is_slowed_and_customer_unharmed():
    t0 = int(time.time())
    fresh_agent()
    load = customer_load()
    keep = Load("attacker", "keep", "--hold", "5")
    flood = Load("attacker", "flood", "--rate", "500")
    limit_at = wait(lambda: limited(ATTACKER) and int(time.time()), 40, "a rate limit on the flooding address")
    wait(lambda: int(time.time()) - limit_at >= 15, 20, "measuring while limited", 1)
    held = keep.read()
    flood.stop()
    keep.stop()
    load.stop()
    before = flood.totals(end=limit_at)
    after = flood.totals(start=limit_at + 3, end=limit_at + 15)
    accepted_before = (before["requests"] - before["errors"]) / max(1, limit_at - t0)
    accepted_after = (after["requests"] - after["errors"]) / 12
    customer = load.totals()
    metric("true_flood", seconds_to_limit=limit_at - t0, accepted_per_sec_before=round(accepted_before),
           accepted_per_sec_while_limited=round(accepted_after), flood_during=after, customer=customer,
           kernel=rows_for(ATTACKER), kept_connections_lost=held["held_lost"])
    assert accepted_after < 150, f"the flood was not slowed: {accepted_after}/s accepted"
    assert not port_blocked(ATTACKER, WEB_PORT) and not all_blocked(ATTACKER), "volume alone must never block"
    assert held["held_lost"] == 0, "a rate limit must not touch established connections"
    assert customer["errors"] == 0, customer


def test_connect_only_flood_is_slowed_too():
    """No request, nothing in any log: the handshake is the only evidence."""
    fresh_agent()
    flood = Load("attacker", "flood-connect", "--rate", "500", "--connect-only")
    wait(lambda: limited(ATTACKER), 40, "a rate limit on the connect-only flood")
    flood.stop()
    metric("connect_only_flood", flood=flood.totals(), kernel=rows_for(ATTACKER))
    assert not port_blocked(ATTACKER, WEB_PORT) and not all_blocked(ATTACKER)


def test_spoofed_syn_flood_cannot_get_the_customer_limited():
    """Half-open SYNs carry a forged source; only completed handshakes may count toward a limit."""
    load = customer_load()
    r = run("attacker", "timeout", "12", "hping3", "-q", "-S", "-a", CUSTOMER, "-p", str(WEB_PORT), "-i", "u2000", TARGET,
            timeout=30)
    sent = (r.stdout + r.stderr).strip().splitlines()[-2:]
    load.stop()
    stats = load.totals()
    flood = Load("attacker", "flood-control", "--rate", "400")
    wait(lambda: limited(ATTACKER), 40, "control: the same address really flooding does get limited")
    flood.stop()
    metric("spoofed_syn_flood", hping3=sent, customer=stats, customer_kernel=rows_for(CUSTOMER))
    assert_no_kernel_rows(CUSTOMER)
    assert stats["errors"] == 0, stats


def test_cdn_source_never_blocked():
    started = time.time()
    probe("cdn")
    for payload in EXPLOITS:
        run("cdn", "curl", "-s", "-o", "/dev/null", "--get", "--data-urlencode", f"q={payload}", f"http://{TARGET}/search")
    scanned_until_blocked("scanner", SCANNER)
    assert_no_kernel_rows(CDN)
    assert http("cdn") == "200"
    rows = wait(lambda: events(started, CDN), 15, "alerts for the CDN address reach central")
    metric("cdn_source", events=[(e["rule"], e["action"]) for e in rows], kernel=rows_for(CDN))
    assert {e["action"] for e in rows} == {"alert"}, rows


def test_block_expires_with_agent_stopped():
    fresh_agent(env={"NEXUS_RULE_TTL_WEB_PROBE": "25"})
    scanned_until_blocked("attacker", ATTACKER)
    assert http("attacker") == "000"
    stop_agent()
    assert port_blocked(ATTACKER, WEB_PORT), "stopping the agent must leave the block in the kernel"
    assert http("attacker") == "000", "the block must still drop packets with no agent running"
    left = max(r[2] for r in rows_for(ATTACKER)["port4"])
    started = time.monotonic()
    wait(lambda: not rows_for(ATTACKER), 40, "the kernel timeout removed the block with no agent running")
    assert agent_pid() is None
    assert http("attacker") == "200"
    metric("block_expiry_no_agent", seconds_left_at_stop=left, gone_after=round(time.monotonic() - started, 1))


def test_blocks_continue_with_central_stopped():
    started = time.time()
    scanned_until_blocked("attacker", ATTACKER)
    docker("stop", container("central"))
    try:
        assert http("attacker") == "000", "an existing block must survive central going down"
        scanned_until_blocked("scanner", SCANNER)  # a new detection, with central unreachable
        assert http("scanner") == "000"
        assert agent_pid(), "the agent must keep running"
    finally:
        docker("start", container("central"))
    central_up()
    rows = wait(lambda: events(started, SCANNER, "web_probe"), 90, "the event queued while central was down arrives")
    metric("central_stopped", event_arrived=rows[0]["action"], kernel=rows_for(SCANNER))
    assert rows[0]["action"] == "block_port" and not rows[0]["simulated"]


def test_panel_unblock_reaches_agent():
    scanned_until_blocked("attacker", ATTACKER)
    assert http("attacker") == "000"
    row = wait(lambda: panel_block(ATTACKER), 15, "panel shows it")[0]
    assert row["kind"] == "block_port" and row["rule"] == "web_probe" and row["evidence"], row
    started = time.monotonic()
    api_json("POST", f"/api/agents/{NODE['id']}/unblock", json={"ip": ATTACKER})
    wait(lambda: not rows_for(ATTACKER), 20, "unblock reaches the kernel")
    assert http("attacker") == "200"
    wait(lambda: not panel_block(ATTACKER), 15, "panel row gone")
    metric("panel_unblock", seconds_to_kernel=round(time.monotonic() - started, 1))


def test_ml_critical_score_no_block():
    post = f"""
import json, time, urllib.request
def post(body):
    req = urllib.request.Request({CENTRAL + '/api/ingest'!r}, json.dumps(body).encode(),
                                 {{'X-API-Key': {NODE['key']!r}, 'Content-Type': 'application/json'}})
    return json.load(urllib.request.urlopen(req, timeout=20))
"""
    seed = post + """
now = time.time()
for i in range(280):
    post({'timestamp': now - (OFFSET + i) * 60, 'cpu_pct': 20 + i % 5, 'memory_pct': 40 + i % 3, 'net_kbps': 100 + i % 7, 'latency_ms': 5 + i % 2})
"""
    # Training needs 500 rows and central allows one address 300 requests a minute, so two addresses send them.
    for service, offset in (("cdn", "0"), ("nat_customer", "280")):
        run(service, "python3", "-c", seed.replace("OFFSET", offset), check=True, timeout=120)
    trained = requests.post(CENTRAL + "/api/retrain", auth=AUTH, timeout=280)
    assert trained.status_code == 200, trained.text
    spike = post + """
answers = []
for _ in range(40):
    answers.append(post({'cpu_pct': 100, 'memory_pct': 100, 'net_kbps': 9e8, 'latency_ms': 9e6})['commands'])
    time.sleep(1)  # central stores one anomaly per 30 s, and only a full window of spikes can score critical
print(json.dumps(answers))
"""
    answered = json.loads(run("scanner", "python3", "-c", spike, check=True, timeout=120).stdout)
    assert all(not c for c in answered), f"a score produced commands: {answered}"
    anomalies = api_json("GET", "/api/anomalies", params={"limit": 50, "node": NODE["id"]})
    rows = anomalies["anomalies"] if isinstance(anomalies, dict) else anomalies
    critical = [a for a in rows if a["severity"] == "critical"]
    assert critical, f"no critical score to test with: {rows[:3]}"
    assert not server()["pending"]
    # The real agent shares this node: a control, then nothing may have appeared for anyone else.
    scanned_until_blocked("scanner", SCANNER)
    table = kernel()
    assert {r[0] for found in table.values() for r in found} == {SCANNER}, table
    assert http("customer") == "200" and http("attacker") == "200"
    metric("ml_critical_no_block", critical_anomalies=len(critical), top_score=critical[0]["scores"]["ensemble"], kernel=table)


# -- customer false positives: none of these may produce a block -----------------------------------------------------

def control_scanner_blocked() -> None:
    scanned_until_blocked("scanner", SCANNER)


def test_customer_mistypes_ssh_password_three_times_then_logs_in():
    started = time.time()
    ssh_failures("customer", CUSTOMER, 3)
    assert wait(lambda: ssh("customer", "customer", "customer-pass") == 0, 90 / SCALE, "login despite sshd penalties", 2)
    control_scanner_blocked()
    assert_no_kernel_rows(CUSTOMER)
    assert tcp_open("customer", SSH_PORT) and http("customer") == "200"
    assert not events(started, CUSTOMER)
    metric("customer_mistypes", failed_password_lines_total=failed_password_lines(CUSTOMER))


def test_admin_with_established_session_failing_from_second_connection_is_not_blocked():
    session = ("pgrep", "-f", "sshd-session: customer")
    run("customer", "sshpass", "-p", "customer-pass", "ssh", "-N", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "PubkeyAuthentication=no", f"customer@{TARGET}", detach=True, check=True)
    wait(lambda: run("target", *session).returncode == 0, 15 / SCALE, "admin session established")
    ssh_failures("customer", CUSTOMER, 14)
    control_scanner_blocked()
    assert_no_kernel_rows(CUSTOMER)
    assert run("target", *session).returncode == 0, "the admin session was cut"
    assert tcp_open("customer", SSH_PORT)
    metric("admin_second_connection", failed_password_lines_total=failed_password_lines(CUSTOMER))


def test_logged_in_customer_visiting_many_pages_is_not_blocked():
    status = run("customer", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-H", "X-Good-Password: 1",
                 f"http://{TARGET}/login").stdout
    assert status == "302"
    r = run("customer", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\n", f"http://{TARGET}/page/[1-400]", timeout=60)
    codes = r.stdout.split()
    assert len(codes) == 400 and set(codes) == {"200"}, set(codes)
    for _ in range(4):  # a slip on the way in
        run("customer", "curl", "-s", "-o", "/dev/null", "-X", "POST", f"http://{TARGET}/login")
    control_scanner_blocked()
    assert_no_kernel_rows(CUSTOMER)
    metric("logged_in_browsing", pages=len(codes))


def test_customer_pasting_code_into_a_search_box_is_not_blocked():
    started = time.time()
    # A developer's forum search: three attack patterns at once, refreshed, then edited and searched again.
    pastes = ['<script>alert(1)</script>'] * 2
    pastes += ['<script>$("#a").load("../api/x")</script>'] * 4
    pastes += ['<script>$("#b").load("../api/y")</script>', '<script>$("#b").load("../api/z")</script>']
    for text in pastes:
        run("customer", "curl", "-s", "-o", "/dev/null", "--get", "--data-urlencode", f"q={text}", f"http://{TARGET}/search",
            check=True)
    # Control: a real injection tool, same rule, same window.
    for i, payload in enumerate(EXPLOITS):
        run("attacker", "curl", "-s", "-o", "/dev/null", "--get", "--data-urlencode", f"id={i}{payload}", f"http://{TARGET}/search")
    wait(lambda: port_blocked(ATTACKER, WEB_PORT), 30, "control: an injection tool gets blocked")
    metric("customer_paste", pasted_searches=len(pastes), customer_kernel=rows_for(CUSTOMER), attacker_kernel=rows_for(ATTACKER))
    assert_no_kernel_rows(CUSTOMER)
    assert http("customer") == "200"
    assert not events(started, CUSTOMER, "web_exploit")


def test_customer_refreshing_a_404_is_not_blocked():
    r = run("customer", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\n", f"http://{TARGET}/no-such-page?[1-300]", timeout=60)
    assert set(r.stdout.split()) == {"404"} and len(r.stdout.split()) == 300
    for _ in range(50):
        http("customer", "/.env")  # a bookmarked scan path refreshed over and over is still one path
    control_scanner_blocked()
    assert_no_kernel_rows(CUSTOMER)
    metric("customer_refreshing_404", refreshes=350)


# -- spoofing and port scans -----------------------------------------------------------------------------------------

def scan_log_count(src: str) -> int:
    return int(sh("target", f"grep -c 'nexus-scan .*SRC={src} ' /var/log/kern.log").stdout.strip() or 0)


def test_spoofed_scan_with_customer_source_is_alert_only():
    started = time.time()
    load = customer_load()
    base = scan_log_count(CUSTOMER)
    send = ("from scapy.all import IP, TCP, send, conf; conf.verb = 0\n"
            f"send([IP(src={CUSTOMER!r}, dst={TARGET!r}) / TCP(sport=40000 + p, dport=30000 + p, flags='S') for p in range(40)], inter=0.03)")
    run("attacker", "python3", "-c", send, check=True)
    wait(lambda: scan_log_count(CUSTOMER) - base >= 25 and 1, 15, "real kernel log lines with the forged source reach kern.log")
    rows = wait(lambda: events(started, CUSTOMER, "port_scan"), 20, "the spoofed scan raises an alert")
    assert {e["action"] for e in rows} == {"alert"}, rows
    assert_no_kernel_rows(CUSTOMER)
    load.stop()
    stats = load.totals()
    metric("spoofed_scan", tool="scapy", kernel_log_lines=scan_log_count(CUSTOMER) - base, events=len(rows), customer=stats)
    assert stats["errors"] == 0, stats


def test_real_scan_alone_alerts_and_scan_plus_probe_blocks_all():
    started = time.time()
    nmap = ("nmap", "-sS", "-Pn", "-n", "--max-retries", "0", "--max-rate", "40", "-p", "31000-31060", TARGET)
    run("scanner", *nmap, check=True, timeout=60)
    rows = wait(lambda: events(started, SCANNER, "port_scan"), 20, "the real scan raises an alert")
    assert {e["action"] for e in rows} == {"alert"}, rows
    assert_no_kernel_rows(SCANNER)
    assert http("scanner") == "200" and tcp_open("scanner", SSH_PORT), "a scan alone must not cost any access"
    assert http("scanner", "/.env") == "404"  # one handshake-proven probe, far below web_probe's own threshold
    run("scanner", *nmap, check=True, timeout=60)
    wait(lambda: all_blocked(SCANNER), 20, "scan plus a proven probe gives block_all")
    assert http("scanner") == "000" and not tcp_open("scanner", SSH_PORT)
    block = wait(lambda: [e for e in events(started, SCANNER, "port_scan") if e["action"] == "block_all"], 15, "event at central")[0]
    assert block["ttl"] == 900
    metric("real_scan", alert_only_events=len(rows), kernel_log_lines=scan_log_count(SCANNER), kernel=rows_for(SCANNER),
           kernel_log_source="rsyslog imkmsg with net.netfilter.nf_log_all_netns=1 on the Docker VM")


# -- panel API with a real agent -------------------------------------------------------------------------------------

def test_panel_mode_block_customer_and_leaving_enforce():
    fresh_agent(mode="observe")
    assert not any(kernel().values()), "observe must hold nothing"
    api_json("PUT", f"/api/agents/{NODE['id']}/mode", json={"mode": "enforce"})
    wait_reported("enforce")
    scanned_until_blocked("attacker", ATTACKER)
    scanned_until_blocked("scanner", SCANNER)
    assert http("attacker") == "000"

    # "This is a customer" lifts the real block, and from then on the address cannot be blocked.
    answer = api_json("POST", "/api/customers", json={"ip": ATTACKER})
    assert answer["status"] == "sent" and answer["sent"] == [NODE["id"]], answer
    wait(lambda: not rows_for(ATTACKER), 20, "the customer's block is lifted in the kernel")
    assert http("attacker") == "200"
    assert server()["allowlist"] == [f"{ATTACKER}/32"]
    wait(lambda: not server()["pending"], 15, "allowlist acknowledged")
    probe("attacker")
    wait(lambda: server()["config"].get("suppressed", {}).get("allowlist"), 20, "agent suppressed a block for the customer")
    assert_no_kernel_rows(ATTACKER)
    assert http("attacker") == "200"
    assert port_blocked(SCANNER, WEB_PORT), "the other block stays"

    # Leaving enforce lifts every block.
    api_json("PUT", f"/api/agents/{NODE['id']}/mode", json={"mode": "observe"})
    wait_reported("observe")
    assert not any(kernel().values()), kernel()
    assert http("scanner") == "200"
    metric("panel_mode_customer", suppressed=server()["config"]["suppressed"])


def test_panel_refuses_enforce_above_max_mode():
    fresh_agent(mode="observe", env={"NEXUS_MAX_MODE": "observe"})
    r = api("PUT", f"/api/agents/{NODE['id']}/mode", json={"mode": "enforce"})
    assert r.status_code == 409 and "max_mode" in r.json()["detail"], r.text
    assert server()["reported_mode"] == "observe" and server()["max_mode"] == "observe"
    # And a state file asking for enforce is clamped too, with the reason reported to the panel.
    stop_agent()
    write_state("enforce")
    t0 = time.time()
    start_agent({"NEXUS_MAX_MODE": "observe"})
    s = wait_reported("observe", since=t0)
    assert s["config"]["enforce_rejected"] and s["config"]["enforce_rejected_reason"] == "max_mode", s["config"]
    attention = api_json("GET", "/api/overview")["attention"]
    assert any(a["type"] == "enforce_rejected" and a["reason"] == "max_mode" for a in attention), attention
    assert not any(kernel().values())
    metric("max_mode_refused", http=r.status_code, detail=r.json()["detail"], attention=attention)


def test_observe_mode_gives_watch_rows_and_no_kernel_elements():
    fresh_agent(mode="observe")
    t0 = time.time()
    probe("attacker")
    rows = wait(lambda: api_json("GET", f"/api/watch/{NODE['id']}")["items"], 20, "watch rows from observe mode")
    row = next(i for i in rows if i["ip"] == ATTACKER)
    assert row["rule"] == "web_probe" and row["action"] == "block_port"
    assert events(t0, ATTACKER, "web_probe")[0]["simulated"] is True
    assert not any(kernel().values()), f"observe wrote to the kernel: {kernel()}"
    assert http("attacker") == "200"
    metric("observe_watch", watch_rows=len(rows), kernel=kernel())


# -- restarts --------------------------------------------------------------------------------------------------------

def test_agent_restart_keeps_kernel_blocks_and_state():
    assert ssh("customer", "customer", "customer-pass") == 0  # a login to remember
    api_json("POST", "/api/customers", json={"ip": NAT})
    wait(lambda: NAT in sh("target", f"cat {STATE}").stdout, 20, "allowlist saved by the agent")
    scanned_until_blocked("attacker", ATTACKER)
    wait(lambda: panel_block(ATTACKER), 15, "on the panel before the restart")
    before = rows_for(ATTACKER)["port4"]
    pid = agent_pid()
    stop_agent()
    t0 = time.time()
    start_agent()
    assert agent_pid() != pid
    s = wait_reported("enforce", since=t0)
    after = rows_for(ATTACKER)["port4"]
    assert {r[:2] for r in after} == {r[:2] for r in before}
    assert max(r[2] for r in after) <= max(r[2] for r in before), "a restart must not extend a block"
    assert http("attacker") == "000"
    state = json.loads(sh("target", f"cat {STATE}").stdout)
    assert state["mode"] == "enforce" and f"{NAT}/32" in state["allowlist"]
    assert CUSTOMER in [i[0] for i in state["ssh_ok"]], state
    row = wait(lambda: panel_block(ATTACKER), 15, "still on the panel")[0]
    metric("agent_restart", before=before, after=after, reported=s["reported_mode"], state_keys=sorted(state), panel_row=row)
    assert row["rule"] == "web_probe", f"the panel lost why this address is blocked: {row}"
    assert row["evidence"], f"the panel lost the evidence: {row}"
    # What the state file protects still protects, in the kernel.
    probe("nat_customer")
    ssh_failures("customer", CUSTOMER, 12)
    scanned_until_blocked("scanner", SCANNER)
    assert_no_kernel_rows(NAT)
    assert_no_kernel_rows(CUSTOMER)


def test_central_restart_loses_nothing():
    scanned_until_blocked("attacker", ATTACKER)
    api_json("POST", "/api/customers", json={"ip": NAT})
    wait(lambda: not server()["pending"], 15, "commands drained")
    wait(lambda: panel_block(ATTACKER), 15, "block on the panel")
    events_before = {e["id"] for e in api_json("GET", "/api/events", params={"limit": 500})["events"]}
    seen = server()
    docker("restart", container("central"))
    central_up()
    t0 = time.time()
    wait(lambda: (server()["last_seen"] or 0) > t0, 60, "the agent's key still works after the restart")
    after = server()
    assert after["allowlist"] == seen["allowlist"] and after["created_at"] == seen["created_at"]
    events_after = {e["id"] for e in api_json("GET", "/api/events", params={"limit": 500})["events"]}
    assert events_before <= events_after, events_before - events_after
    assert panel_block(ATTACKER)
    assert http("attacker") == "000"
    metric("central_restart", events_kept=len(events_before), allowlist=after["allowlist"])


def test_offline_agent_applies_only_the_newest_queued_mode():
    stop_agent()
    ids = [api_json("PUT", f"/api/agents/{NODE['id']}/mode", json={"mode": m})["command_id"] for m in ("off", "enforce", "observe")]
    pending = [c for c in server()["pending"] if c["type"] == "mode"]
    assert [c["id"] for c in pending] == [ids[-1]] and pending[0]["payload"] == {"mode": "observe"}, pending
    t0 = time.time()
    start_agent()
    s = wait_reported("observe", since=t0, timeout=30)
    assert s["config"]["mode"] == "observe" and json.loads(sh("target", f"cat {STATE}").stdout)["mode"] == "observe"
    metric("offline_newest_mode", queued=len(ids), delivered=len(pending), reported=s["reported_mode"])


# -- log flood -------------------------------------------------------------------------------------------------------

FLOOD_LINES = """
import time
t = time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(time.time() - {age}))
line = '{ip} - - [' + t + '] "GET {path} HTTP/1.1" {status} 5 "-" "curl/8"\\n'
with open('/var/log/nginx/access.log', 'a') as f:
    f.write(''.join(line for _ in range({count})))
"""


def flood_log(age: int, ip: str, path: str, status: int, count: int = 50000) -> None:
    run("target", "python", "-c", FLOOD_LINES.format(age=age, ip=ip, path=path, status=status, count=count), check=True)


def rss_kb(pid: int) -> tuple:
    status = run("target", "cat", f"/proc/{pid}/status").stdout
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    return int(fields["VmRSS"].split()[0]), int(fields["VmHWM"].split()[0])


def test_log_flood_of_old_lines_blocks_nobody_and_detection_resumes():
    pid = agent_pid()
    assert pid, "no agent is running"
    load = customer_load()
    rss_before, _ = rss_kb(pid)
    # An hour old and naming the customer on a probe path: read as news, these would block the customer.
    flood_log(3600, CUSTOMER, "/.env", 404)
    flood_end = time.monotonic()
    scanned_until_blocked("scanner", SCANNER, timeout=60)
    resumed = round(time.monotonic() - flood_end, 1)
    # Fresh, benign and just as large.
    flood_log(0, "198.51.100.78", "/page/fresh", 200)
    probe("attacker")
    wait(lambda: port_blocked(ATTACKER, WEB_PORT), 60, "detection after a fresh flood")
    load.stop()
    stats = load.totals()
    assert agent_pid() == pid, "the agent restarted during the flood"
    rss, peak = rss_kb(pid)
    config = wait(lambda: (lambda c: c if c.get("stale_lines", 0) > 0 else None)(server()["config"]), 20, "agent reports stale lines")
    metric("log_flood", lines=100000, rss_before_kb=rss_before, rss_after_kb=rss, peak_kb=peak, stale_lines=config["stale_lines"],
           lines_dropped=config["lines_dropped"], seconds_to_detection_after_flood=resumed, customer=stats)
    assert stats["errors"] == 0, stats
    assert_no_kernel_rows(CUSTOMER)
    assert not rows_for("198.51.100.78")
    assert peak < 200_000, f"agent peaked at {peak} kB"


# -- central under concurrency and hostile fields ----------------------------------------------------------------------

def test_concurrent_customer_posts_lose_nothing():
    wanted = [f"198.18.7.{i}" for i in range(1, 25)]
    with concurrent.futures.ThreadPoolExecutor(12) as pool:
        answers = list(pool.map(lambda ip: api("POST", "/api/customers", json={"ip": ip}), wanted))
    assert [r.status_code for r in answers] == [200] * len(wanted), [r.text for r in answers if r.status_code != 200]
    assert all(r.json()["status"] == "sent" and r.json()["sent"] == [NODE["id"]] for r in answers), [r.json() for r in answers]
    assert sorted(server()["allowlist"]) == sorted(f"{ip}/32" for ip in wanted), server()["allowlist"]
    wait(lambda: not server()["pending"], 30, "every command acknowledged")
    state = json.loads(sh("target", f"cat {STATE}").stdout)
    assert set(state["allowlist"]) == {f"{ip}/32" for ip in wanted}, state["allowlist"]
    metric("concurrent_customers", posts=len(wanted), allowlist=len(server()["allowlist"]), database=BACKEND)


def test_hostile_text_in_an_event_does_not_stall_ingest():
    """Evidence is log text. A byte the database cannot store must not refuse the batch, or every later event is stuck."""
    body = {"cpu_pct": 1, "memory_pct": 1, "net_kbps": 1, "latency_ms": 1,
            "events": [{"rule": "web_probe", "ip": ATTACKER, "action": "alert", "evidence": "nul\x00byte ' -- \U0001f600"}]}
    r = requests.post(CENTRAL + "/api/ingest", json=body, headers={"X-API-Key": NODE["key"]}, timeout=20)
    assert r.status_code == 200, r.text[:300]
    assert events(time.time() - 60, ATTACKER, "web_probe"), "stored"
    assert agent_pid(), "no agent is running"
