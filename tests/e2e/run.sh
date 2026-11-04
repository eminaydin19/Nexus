#!/usr/bin/env bash
# Real install on real systemd: scripts/test.sh --e2e [base-image ...]
# Needs Docker, privileged containers, and free ports 8000, 80 and 443 on 127.0.0.1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TARGETS=("$@")
[ "${#TARGETS[@]}" -gt 0 ] || TARGETS=(ubuntu:22.04 debian:12)

# Never the product's own project name: down -v below must only ever hit this test's volumes.
export COMPOSE_PROJECT_NAME=nexus-e2e
CHECKOUT="$(mktemp -d "${TMPDIR:-/tmp}/nexus-e2e.XXXXXX")"
CONTAINERS=()
FAILED=()

cleanup() {
    [ "${#CONTAINERS[@]}" -eq 0 ] || docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
    (cd "$CHECKOUT" && docker compose --profile https down -v --remove-orphans >/dev/null 2>&1) || true
    rm -rf "$CHECKOUT"
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
expect() {
    local what="$1"
    shift
    if "$@"; then
        printf 'ok   %s\n' "$what"
    else
        printf 'FAIL %s\n' "$what"
        FAILED+=("$what")
    fi
}

(cd "$REPO" && git ls-files -co --exclude-standard | grep -v '^\.superpowers/' | tar -cf - -T -) | tar -xf - -C "$CHECKOUT"
cd "$CHECKOUT"

step "docker compose config"
expect "config parses without .env" docker compose config -q
expect "config parses with the https profile" docker compose --profile https config -q

step "install.sh without a domain, for real"
./install.sh </dev/null | sed 's/\(Password: \).*/\1<redacted>/'
PASSWORD="$(sed -n 's/^DASHBOARD_PASSWORD=//p' .env)"
API=http://127.0.0.1:8000
expect ".env is mode 600" test "$(python3 -c 'import os,stat;print(oct(stat.S_IMODE(os.stat(".env").st_mode)))')" = 0o600
expect "nexus is published on loopback only" test "$(docker compose port nexus 8000)" = 127.0.0.1:8000
expect "caddy does not run without a domain" test -z "$(docker compose --profile https ps -q caddy)"
expect "dashboard needs the password" test "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/agents")" = 401

hostile() { ! curl -fsS -H 'Host: evil.example' -H 'X-Forwarded-Host: evil.example' "$API/install-agent.sh" | grep -q evil.example; }
expect "hostile Host header never reaches the script" hostile
empty_url() { curl -fsS "$API/install-agent.sh" | grep -q "^EMBEDDED_URL=''$"; }
expect "without PUBLIC_URL the script embeds no address" empty_url

expect "the image has the postgres driver" docker compose exec -T nexus python -c 'import psycopg'

curl -fsS -o agent.tar.gz -D agent.headers "$API/agent.tar.gz"
tar -tzf agent.tar.gz >agent.list
cat agent.list
clean_tar() { ! grep -Ev '^(nexus_agent/|requirements-agent\.txt$)' agent.list && ! grep -E '__pycache__|\.pyc$|\.env' agent.list; }
expect "tarball holds only the agent" clean_tar
expect "tarball has rule data" grep -q '^nexus_agent/data/exploit_patterns.txt$' agent.list
sha_ok() {
    [ "$(python3 -c 'import hashlib;print(hashlib.sha256(open("agent.tar.gz","rb").read()).hexdigest())')" = \
        "$(tr -d '\r' <agent.headers | awk 'tolower($1)=="x-nexus-agent-sha256:"{print $2}')" ]
}
expect "sha256 header matches" sha_ok

NETWORK="${COMPOSE_PROJECT_NAME}_default"
for base in "${TARGETS[@]}"; do
    step "agent on $base"
    name="nexus-e2e-${base//[:.]/-}"
    docker build -q --build-arg "BASE=$base" -f "$REPO/tests/e2e/Dockerfile.systemd" -t "$name" "$REPO/tests/e2e" >/dev/null
    docker rm -f "$name" >/dev/null 2>&1 || true
    CONTAINERS+=("$name")
    docker run -d --name "$name" --hostname "$name" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        --network "$NETWORK" "$name" >/dev/null
    docker exec "$name" bash -c 'for _ in $(seq 60); do s=$(systemctl is-system-running 2>/dev/null); case "$s" in running|degraded) exit 0;; esac; sleep 1; done; echo "systemd state: $s"; exit 1'
    docker cp "$REPO/tests/e2e/check.sh" "$name:/root/check.sh"
    if docker exec -e "PASSWORD=$PASSWORD" -e CENTRAL=http://nexus:8000 "$name" bash /root/check.sh; then
        printf 'ok   %s\n' "$base"
    else
        printf 'FAIL %s\n' "$base"
        FAILED+=("$base")
    fi
done

step "install.sh again keeps secrets and data"
nodes_before="$(curl -fsS -u "admin:$PASSWORD" "$API/api/agents")"
./install.sh </dev/null >rerun.log
expect "password unchanged" test "$(sed -n 's/^DASHBOARD_PASSWORD=//p' .env)" = "$PASSWORD"
expect "password not printed again" bash -c "! grep -qF '$PASSWORD' rerun.log"
expect "enrolled servers survived" test "$(curl -fsS -u "admin:$PASSWORD" "$API/api/agents")" = "$nodes_before"

step "install.sh --domain, for real"
./install.sh --domain nexus.e2e.test </dev/null >domain.log
expect "password still unchanged" test "$(sed -n 's/^DASHBOARD_PASSWORD=//p' .env)" = "$PASSWORD"
# docker compose port prints ":0" for an unpublished port, so ask the container itself.
expect "nexus is no longer published" test "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$(docker compose ps -q nexus)")" = "{}"
redirect() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: nexus.e2e.test' http://127.0.0.1/ | grep -q '^308 https://nexus.e2e.test/'; }
expect "caddy answers on port 80 for the domain" redirect
embedded() { docker compose exec -T nexus python -c "import urllib.request as u; print(u.urlopen(u.Request('http://127.0.0.1:8000/install-agent.sh', headers={'Host':'evil.example'})).read().decode())" | grep -q "^EMBEDDED_URL='https://nexus.e2e.test'$"; }
expect "the script embeds PUBLIC_URL despite a hostile Host" embedded
./install.sh --domain nexus.e2e.test </dev/null >/dev/null
expect "re-run with the domain passes its own port check" test "$?" = 0
expect "enrolled servers survived the switch" test "$(docker compose exec -T nexus python -c "import sqlite3; print(sqlite3.connect('/data/nexus.db').execute('select count(*) from agents').fetchone()[0])")" -ge "${#TARGETS[@]}"

if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\nFAILED: %s\n' "${FAILED[*]}"
    exit 1
fi
printf '\nALL PASSED: %s\n' "${TARGETS[*]}"
