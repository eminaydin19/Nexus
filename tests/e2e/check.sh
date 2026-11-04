#!/usr/bin/env bash
# Runs inside a systemd container against a live central. Needs CENTRAL and PASSWORD.
set -uo pipefail

FAILS=0
expect() {
    local what="$1"
    shift
    if "$@"; then
        printf 'ok   %s\n' "$what"
    else
        printf 'FAIL %s\n' "$what"
        FAILS=$((FAILS + 1))
    fi
}
absent() { ! "$@" >/dev/null 2>&1; }
api() { curl -fsS -u "admin:$PASSWORD" -H 'Content-Type: application/json' "$@"; }
new_token() { api -X POST -d '{"name":"e2e"}' "$CENTRAL/api/agents/tokens" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])'; }
script() { curl -fsSL "$CENTRAL/install-agent.sh" -o /root/install-agent.sh; }
installer() { bash /root/install-agent.sh "$@"; }
nothing_left() {
    expect "$1: no install dir" test ! -e /opt/nexus-agent
    expect "$1: no env file" test ! -e /etc/nexus-agent.env
    expect "$1: no unit file" test ! -e /etc/systemd/system/nexus-agent.service
    expect "$1: no user" absent id nexus-agent
    expect "$1: no group" absent getent group nexus-agent
}

this_agent() {
    api "$CENTRAL/api/agents" | python3 -c "
import json, sys
hits = [a for a in json.load(sys.stdin)['agents'] if a['node_id'].startswith('$(hostname)')]
print(json.dumps(hits[-1]) if hits else '{}')"
}
node_count() {
    api "$CENTRAL/api/agents" | python3 -c "
import json, sys
print(sum(a['node_id'].startswith('$(hostname)') for a in json.load(sys.stdin)['agents']))"
}

script
expect "server starts without nft" absent command -v nft

echo "--- refusals before any change"
expect "http without --insecure is refused" absent installer --url "$CENTRAL" --token x
expect "no address is refused" absent installer --token x
nothing_left "after refusals"
expect "packages untouched by a refusal" absent command -v nft

echo "--- bad token rolls back"
output="$(installer --url "$CENTRAL" --insecure --token BAD-TOKEN-VALUE 2>&1)"
status=$?
expect "bad token fails" test "$status" -ne 0
echo "$output" | tail -3
leak() { ! grep -q BAD-TOKEN-VALUE <<<"$output"; }
expect "bad token not printed" leak
nothing_left "after a failed enroll"

echo "--- fresh install with NEXUS_ENROLL_TOKEN"
TOKEN="$(new_token)"
output="$(NEXUS_ENROLL_TOKEN="$TOKEN" installer --url "$CENTRAL" --insecure 2>&1)"
status=$?
echo "$output" | tail -12
expect "install succeeds" test "$status" -eq 0
KEY="$(sed -n 's/^NEXUS_API_KEY=//p' /etc/nexus-agent.env)"
expect "a key was stored" test -n "$KEY"
no_secret() { ! grep -qF -e "$KEY" -e "$TOKEN" <<<"$output"; }
expect "key and token not printed" no_secret
says() { grep -qF "$1" <<<"$output"; }
expect "says observe" says "Mode: observe"
expect "says nothing is blocked" says "no traffic will be blocked until you enable enforce in the panel"
expect "says how to check" says "systemctl status nexus-agent"
expect "env file is 600 root" test "$(stat -c '%a %U' /etc/nexus-agent.env)" = "600 root"
expect "installer brought nft" command -v nft
expect "service is active" systemctl is-active --quiet nexus-agent
not_enabled() { [ "$(systemctl is-enabled nftables 2>/dev/null)" != enabled ]; }
expect "nftables.service was not enabled" not_enabled
expect "the unit passes verification" systemd-analyze verify /etc/systemd/system/nexus-agent.service

echo "--- running as the sandboxed user"
PID="$(systemctl show -p MainPID --value nexus-agent)"
expect "process runs as nexus-agent" test "$(ps -o user= -p "$PID")" = nexus-agent
grep -E '^(CapAmb|CapBnd|NoNewPrivs)' "/proc/$PID/status"
expect "ambient caps are exactly NET_ADMIN and DAC_READ_SEARCH" test "$(sed -n 's/^CapAmb:[[:space:]]*//p' "/proc/$PID/status")" = 0000000000001004
expect "no new privileges" grep -Eq '^NoNewPrivs:[[:space:]]*1' "/proc/$PID/status"

python3 -c 'import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 2222)); s.listen()
c = socket.create_connection(("nexus", 8000)); open("/root/held_port", "w").write(str(c.getsockname()[1]))
time.sleep(240)' &
HOLDER=$!
sleep 1
HELD_PORT="$(cat /root/held_port)"

logger -t nexus-e2e "journal-sentinel-$HELD_PORT"
logger -p authpriv.info -t sshd "auth-sentinel-$HELD_PORT"
# The agent asks journalctl for -u ssh -u sshd, so the sentinel has to come from a unit of that name.
systemd-run --quiet --wait --unit=sshd --service-type=oneshot echo "unit-sentinel-$HELD_PORT"
AUTH_LOG=/var/log/auth.log
[ -e "$AUTH_LOG" ] || AUTH_LOG=/var/log/secure
sleep 2

cat >/opt/nexus-agent/probe.py <<PY
import os, pwd, subprocess, sys
import psutil

fails = []
def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + (" " + str(detail) if detail else ""), flush=True)
    if not ok:
        fails.append(name)

check("runs as nexus-agent", pwd.getpwuid(os.getuid()).pw_name == "nexus-agent", os.getuid())

r = subprocess.run(["nft", "add", "table", "inet", "nexus_probe"], capture_output=True, text=True)
check("nft can create a table", r.returncode == 0, r.stderr)
r = subprocess.run(["nft", "delete", "table", "inet", "nexus_probe"], capture_output=True, text=True)
check("nft can delete a table", r.returncode == 0, r.stderr)

r = subprocess.run(["journalctl", "-t", "nexus-e2e", "--no-pager"], capture_output=True, text=True)
check("journalctl reads the journal", "journal-sentinel-$HELD_PORT" in r.stdout, r.stderr)
r = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager"], capture_output=True, text=True)
check("journalctl reads the sshd unit like the agent does", "unit-sentinel-$HELD_PORT" in r.stdout, r.stderr)

check("$AUTH_LOG is readable", "auth-sentinel-$HELD_PORT" in open("$AUTH_LOG", errors="replace").read())

conns = psutil.net_connections(kind="inet")
held = [c for c in conns if c.laddr and c.laddr.port == $HELD_PORT and c.raddr]
check("psutil sees a root process's remote address", bool(held), held)
listen = [c for c in conns if c.status == "LISTEN" and c.laddr.port == 2222]
check("psutil sees a root process's listener", bool(listen))

state = os.environ.get("STATE_DIRECTORY", "")
check("StateDirectory is set", state == "/var/lib/nexus-agent", state)
open(state + "/probe", "w").write("x")
os.unlink(state + "/probe")
check("state dir is writable", True)
for path in ("/opt/nexus-agent/x", "/etc/x", "/usr/x"):
    try:
        open(path, "w")
        check("sandbox blocks " + path, False)
    except OSError:
        check("sandbox blocks " + path, True)
check("/root is hidden", not os.path.exists("/root/check.sh"))
sys.exit(1 if fails else 0)
PY
sed -e 's|^ExecStart=.*|ExecStart=/opt/nexus-agent/venv/bin/python /opt/nexus-agent/probe.py|' \
    -e 's/^Type=.*/Type=oneshot/' -e '/^Restart/d' /etc/systemd/system/nexus-agent.service \
    >/etc/systemd/system/nexus-probe.service
systemctl daemon-reload
expect "every probe passed under the unit's own sandbox" systemctl start nexus-probe
journalctl -u nexus-probe --no-pager -o cat | grep -E '^(ok|FAIL) '
rm -f /etc/systemd/system/nexus-probe.service /opt/nexus-agent/probe.py
systemctl daemon-reload

echo "--- the real agent talks to central and creates its table in enforce"
wait_for() {
    local i
    for ((i = 0; i < 40; i++)); do
        "$@" && return 0
        sleep 1
    done
    return 1
}
reported_observe() { this_agent | grep -q '"mode": *"observe"'; }
expect "agent reports observe" wait_for reported_observe
expect "no firewall table in observe" absent nft list table inet nexus
NODE="$(this_agent | python3 -c 'import json,sys;print(json.load(sys.stdin)["node_id"])')"
expect "central accepts enforce" api -X PUT -d '{"mode":"enforce"}' -o /dev/null "$CENTRAL/api/agents/$NODE/mode"
table_exists() { nft list table inet nexus >/dev/null 2>&1; }
expect "the agent created inet nexus" wait_for table_exists
state_enforce() { grep -q '"mode": *"enforce"' /var/lib/nexus-agent/state.json 2>/dev/null; }
expect "the agent wrote state.json" wait_for state_enforce
expect "state.json belongs to the agent" test "$(stat -c %U /var/lib/nexus-agent/state.json)" = nexus-agent
journalctl -u nexus-agent -n 8 --no-pager -o cat
nft add table inet customer

echo "--- re-run keeps the key and does not enroll again"
BEFORE="$(sha256sum /etc/nexus-agent.env)"
COUNT="$(node_count)"
touch /opt/nexus-agent/nexus_agent/planted_stale_file
output="$(installer --url "$CENTRAL" --token UNUSED-TOKEN 2>&1)"
status=$?
echo "$output" | tail -8
expect "re-run succeeds" test "$status" -eq 0
expect "env file unchanged" test "$(sha256sum /etc/nexus-agent.env)" = "$BEFORE"
expect "no second enrollment" test "$(node_count)" = "$COUNT"
expect "code was replaced" test ! -e /opt/nexus-agent/nexus_agent/planted_stale_file
expect "reports the kept enforce mode truthfully" says "Mode: enforce"
expect "service active after upgrade" systemctl is-active --quiet nexus-agent
expect "a different central is refused" absent installer --url https://other.example.com
expect "customer table untouched by re-run" nft list table inet customer

echo "--- a service that cannot start is reported"
cp -p /etc/nexus-agent.env /root/env.saved
echo NEXUS_MAX_MODE=broken >>/etc/nexus-agent.env
output="$(installer 2>&1)"
status=$?
expect "failed start exits non-zero" test "$status" -ne 0
expect "journal lines are shown" says "NEXUS_MAX_MODE must be one of"
expect "enrollment survives a failed start" test -n "$(sed -n 's/^NEXUS_API_KEY=//p' /etc/nexus-agent.env)"
no_key_shown() { ! grep -qF "$KEY" <<<"$output"; }
expect "key not in the journal output" no_key_shown
cp -p /root/env.saved /etc/nexus-agent.env
rm -f /root/env.saved

leak_in_journal() { ! journalctl --no-pager | grep -qF -e "$KEY" -e "$TOKEN"; }
expect "key and token never reached the journal" leak_in_journal

echo "--- uninstall while enforcing leaves nothing"
systemctl restart nexus-agent
expect "enforce came back" wait_for table_exists
output="$(installer --uninstall 2>&1)"
status=$?
echo "$output" | tail -3
expect "uninstall succeeds" test "$status" -eq 0
nothing_left "after uninstall"
expect "no state dir" test ! -e /var/lib/nexus-agent
expect "no inet nexus table" absent nft list table inet nexus
sleep 6
expect "the table stays gone" absent nft list table inet nexus
expect "no agent process" absent pgrep -u nexus-agent
expect "systemd no longer knows the unit" test "$(systemctl show -p LoadState --value nexus-agent)" = not-found
expect "customer table survives uninstall" nft list table inet customer
expect "second uninstall is harmless" installer --uninstall

echo "--- uninstall when partly installed"
expect "install again" env NEXUS_ENROLL_TOKEN="$(new_token)" bash /root/install-agent.sh --url "$CENTRAL" --insecure --max-mode observe
expect "max mode written" grep -q '^NEXUS_MAX_MODE=observe$' /etc/nexus-agent.env
rm -rf /opt/nexus-agent/venv
expect "uninstall with the venv gone" installer --uninstall
nothing_left "after a partial uninstall"

kill "$HOLDER" 2>/dev/null
wait "$HOLDER" 2>/dev/null
echo "=== $(. /etc/os-release; echo "$PRETTY_NAME"): $FAILS failures"
[ "$FAILS" -eq 0 ]
