#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TARGETS=("$@")
[ "${#TARGETS[@]}" -gt 0 ] || TARGETS=(ubuntu:22.04 debian:12 ubuntu:20.04+python3.9 almalinux:8+python39)
REFUSAL_TARGETS=(ubuntu:20.04 almalinux:8)

export COMPOSE_PROJECT_NAME=nexus-e2e
CHECKOUT="$(mktemp -d "${TMPDIR:-/tmp}/nexus-e2e.XXXXXX")"
SECOND="$(mktemp -d "${TMPDIR:-/tmp}/nexus-e2e2.XXXXXX")"
SECOND_PROJECT=nexus-e2e2
CONTAINERS=()
FAILED=()

cleanup() {
    [ "${#CONTAINERS[@]}" -eq 0 ] || docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
    (cd "$CHECKOUT" && docker compose --profile https down -v --remove-orphans >/dev/null 2>&1) || true
    (cd "$SECOND" && COMPOSE_PROJECT_NAME="$SECOND_PROJECT" docker compose down -v --remove-orphans >/dev/null 2>&1) || true
    rm -rf "$CHECKOUT" "$SECOND"
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

copy_checkout() { (cd "$REPO" && git ls-files -co --exclude-standard | grep -Ev '^\.(superpowers|omc)/' | tar -cf - -T -) | tar -xf - -C "$1"; }
copy_checkout "$CHECKOUT"
copy_checkout "$SECOND"
cd "$CHECKOUT"

step "docker compose config"
expect "config parses without .env" docker compose config -q
expect "config parses with the https profile" docker compose --profile https config -q
pinned_name() { env -u COMPOSE_PROJECT_NAME docker compose config | grep -q '^name: nexus-defense$'; }
expect "the pinned project name is distinctive" pinned_name

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

step "a second stack in another directory"
FIRST_ID="$(docker compose ps -q nexus)"
if (cd "$SECOND" && ./install.sh </dev/null) >second.log 2>&1; then
    expect "same project name is refused" false
else
    cat second.log
    expect "same project name is refused" true
fi
expect "the refusal names the other directory" grep -qF "$(basename "$CHECKOUT")" second.log
expect "the refused checkout got no .env" test ! -e "$SECOND/.env"
expect "the first stack's container was not replaced" test "$(docker compose ps -q nexus)" = "$FIRST_ID"
if (cd "$SECOND" && COMPOSE_PROJECT_NAME="$SECOND_PROJECT" ./install.sh </dev/null) >second.log 2>&1; then
    expect "another project next to existing data stops" false
else
    cat second.log
    expect "another project next to existing data stops" true
fi
expect "it names the existing volume" grep -q "${COMPOSE_PROJECT_NAME}_nexus-data" second.log
expect "it offers --adopt-empty-data" grep -q -e '--adopt-empty-data' second.log
expect "it wrote no .env" test ! -e "$SECOND/.env"
no_second_volume() { ! docker volume inspect "${SECOND_PROJECT}_nexus-data" >/dev/null 2>&1; }
expect "it created no volume" no_second_volume

NETWORK="${COMPOSE_PROJECT_NAME}_default"
boot() {
    local target="$1" base extra="" name
    base="${target%%+*}"
    [ "$base" = "$target" ] || extra="${target#*+}"
    name="nexus-e2e-${target//[:.+]/-}"
    docker build -q --build-arg "BASE=$base" --build-arg "EXTRA=$extra" -f "$REPO/tests/e2e/Dockerfile.systemd" -t "$name" "$REPO/tests/e2e" >/dev/null
    docker rm -f "$name" >/dev/null 2>&1 || true
    CONTAINERS+=("$name")
    docker run -d --name "$name" --hostname "$name" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        --network "$NETWORK" "$name" >/dev/null
    docker exec "$name" bash -c 'for _ in $(seq 180); do s=$(systemctl is-system-running 2>/dev/null); case "$s" in running|degraded) exit 0;; esac; sleep 1; done; echo "systemd state: $s"; exit 1'
}

for base in "${REFUSAL_TARGETS[@]}"; do
    step "no usable Python on $base"
    boot "$base"
    name="nexus-e2e-${base//[:.+]/-}"
    docker cp "$REPO/install-agent.sh" "$name:/root/install-agent.sh"
    docker exec "$name" python3 --version
    if output="$(docker exec "$name" bash /root/install-agent.sh --url http://nexus:8000 --insecure --token never-used 2>&1)"; then
        expect "$base refuses" false
    else
        printf '%s\n' "$output"
        expect "$base refuses" true
    fi
    case "$base" in
        ubuntu:*) fix="apt install python3.9 python3.9-venv" ;;
        *) fix="dnf install python39" ;;
    esac
    prints_fix() { grep -qF "$fix" <<<"$output"; }
    expect "$base prints the exact fix" prints_fix
    untouched() { docker exec "$name" bash -c '! command -v nft && [ ! -e /opt/nexus-agent ] && [ ! -e /etc/nexus-agent.env ] && ! id nexus-agent' >/dev/null 2>&1; }
    expect "$base changed nothing" untouched
done

for base in "${TARGETS[@]}"; do
    step "agent on $base"
    boot "$base"
    name="nexus-e2e-${base//[:.+]/-}"
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
expect "nexus is no longer published" test "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$(docker compose ps -q nexus)")" = "{}"
redirect() { curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: nexus.e2e.test' http://127.0.0.1/ | grep -q '^308 https://nexus.e2e.test/'; }
expect "caddy answers on port 80 for the domain" redirect
embedded() { docker compose exec -T nexus python -c "import urllib.request as u; print(u.urlopen(u.Request('http://127.0.0.1:8000/install-agent.sh', headers={'Host':'evil.example'})).read().decode())" | grep -q "^EMBEDDED_URL='https://nexus.e2e.test'$"; }
expect "the script embeds PUBLIC_URL despite a hostile Host" embedded
./install.sh --domain nexus.e2e.test </dev/null >/dev/null
expect "re-run with the domain passes its own port check" test "$?" = 0
expect "enrolled servers survived the switch" test "$(docker compose exec -T nexus python -c "import sqlite3; print(sqlite3.connect('/data/nexus.db').execute('select count(*) from agents').fetchone()[0])")" -ge "${#TARGETS[@]}"

step "--adopt-empty-data proceeds and leaves the other stack's data alone"
docker compose --profile https stop >/dev/null 2>&1
(cd "$SECOND" && COMPOSE_PROJECT_NAME="$SECOND_PROJECT" ./install.sh --adopt-empty-data </dev/null) >second.log 2>&1
expect "the second stack came up" test "$?" = 0
SECOND_PASSWORD="$(sed -n 's/^DASHBOARD_PASSWORD=//p' "$SECOND/.env")"
expect "the second stack has its own password" test "$SECOND_PASSWORD" != "$PASSWORD"
expect "the second stack starts empty" test "$(curl -fsS -u "admin:$SECOND_PASSWORD" "$API/api/agents")" = '{"agents":[]}'
(cd "$SECOND" && COMPOSE_PROJECT_NAME="$SECOND_PROJECT" docker compose down -v >/dev/null 2>&1)
docker compose --profile https start >/dev/null 2>&1
survived() { [ "$(docker compose exec -T nexus python -c "import sqlite3; print(sqlite3.connect('/data/nexus.db').execute('select count(*) from agents').fetchone()[0])")" -ge "${#TARGETS[@]}" ]; }
expect "the first stack's data survived the second stack's down -v" survived

if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\nFAILED: %s\n' "${FAILED[*]}"
    exit 1
fi
printf '\nALL PASSED: %s\n' "${TARGETS[*]}"
