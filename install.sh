#!/usr/bin/env bash
# Nexus central installer. Run from a checkout: ./install.sh [--domain nexus.example.com]
# Nothing runs until the last line, and a cut anywhere in that line is a syntax error, so a truncated download changes nothing.

DOMAIN=""
ADMIN_USER="admin"
NEW_PASSWORD=""
LOCAL_COMPOSE="docker-compose.yml:docker-compose.local.yml"
COMPOSE_HINT="Docker Compose 2.24 or newer"

say() { printf '%s\n' "$*"; }
die() {
    printf 'nexus: %s\n' "$*" >&2
    exit 1
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --domain)
                [ "$#" -ge 2 ] || die "--domain needs a value"
                DOMAIN="$2"
                shift 2
                ;;
            -h | --help)
                say "Usage: ./install.sh [--domain nexus.example.com]"
                exit 0
                ;;
            *) die "unknown option: $1" ;;
        esac
    done
}

check_docker() {
    command -v docker >/dev/null 2>&1 || die "Docker is required. Install it first: https://docs.docker.com/engine/install/"
    docker compose version >/dev/null 2>&1 ||
        die "The Docker Compose plugin is required. Install it first: https://docs.docker.com/compose/install/linux/"
    docker info >/dev/null 2>&1 || die "Docker is installed but not reachable. Is it running, and may this user use it?"
    docker compose config -q >/dev/null || die "docker compose rejected the configuration; $COMPOSE_HINT is required"
}

env_get() {
    [ ! -f .env ] || sed -n "s/^$1=//p" .env | tail -n 1
}

env_del() {
    [ -f .env ] || return 0
    grep -v "^$1=" .env >.env.tmp || true
    mv .env.tmp .env
}

env_set() {
    env_del "$1"
    printf '%s=%s\n' "$1" "$2" >>.env
}

env_default() {
    [ -n "$(env_get "$1")" ] || env_set "$1" "$2"
}

resolve_domain() {
    DOMAIN="${DOMAIN:-$(env_get DOMAIN)}"
    if [ -z "$DOMAIN" ] && [ -t 0 ]; then
        printf 'Domain for HTTPS (empty for local access over an SSH tunnel): '
        read -r DOMAIN
    fi
    [ -z "$DOMAIN" ] || [[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] ||
        die "invalid domain: $DOMAIN"
}

port_busy() {
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -ltnH "( sport = :$1 )" 2>/dev/null)" ]
    else
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
    fi
}

check_ports() {
    local port
    # On a re-run those ports belong to our own Caddy.
    [ -z "$(docker compose --profile https ps -q --status running caddy 2>/dev/null)" ] || return 0
    for port in 80 443; do
        ! port_busy "$port" || die "port $port is already in use; Caddy needs ports 80 and 443 for HTTPS"
    done
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets; print(secrets.token_hex(24))'
    else
        die "openssl or python3 is required to generate a password"
    fi
}

write_env() {
    touch .env
    chmod 600 .env
    env_default INGESTION_SOURCE webhook
    env_default DASHBOARD_USER "$ADMIN_USER"
    ADMIN_USER="$(env_get DASHBOARD_USER)"
    if [ -z "$(env_get DASHBOARD_PASSWORD)" ]; then
        NEW_PASSWORD="$(generate_secret)"
        env_set DASHBOARD_PASSWORD "$NEW_PASSWORD"
    fi
    if [ -n "$DOMAIN" ]; then
        env_set DOMAIN "$DOMAIN"
        env_set PUBLIC_URL "https://$DOMAIN"
        env_set TRUST_PROXY_HEADERS true
        env_set COMPOSE_PROFILES https
        env_del COMPOSE_FILE
        env_del HTTP_BIND
    else
        env_del DOMAIN
        env_del PUBLIC_URL
        env_del COMPOSE_PROFILES
        env_set TRUST_PROXY_HEADERS false
        env_set COMPOSE_FILE "$LOCAL_COMPOSE"
        env_set HTTP_BIND 127.0.0.1:8000
    fi
}

start() {
    # Only ever up: down -v or a volume prune would destroy the customer's data on a re-run.
    docker compose up -d --build --wait --wait-timeout 300 ||
        die "the containers did not become healthy; see: docker compose logs nexus (the password is in .env)"
}

report() {
    local base token_cmd agent_cmd
    if [ -n "$DOMAIN" ]; then
        base="https://$DOMAIN"
        agent_cmd="curl -fsSL $base/install-agent.sh | sudo bash -s -- --token <token>"
    else
        base="http://127.0.0.1:8000"
        agent_cmd="curl -fsSL $base/install-agent.sh | sudo bash -s -- --url $base --token <token>"
    fi
    token_cmd="curl -u $ADMIN_USER -X POST -H 'Content-Type: application/json' -d '{\"name\":\"web-1\"}' $base/api/agents/tokens"
    say ""
    say "Nexus is running."
    say ""
    say "Log in:"
    if [ -z "$DOMAIN" ]; then
        say "  This install listens on 127.0.0.1 only. Open a tunnel from your computer:"
        say "    ssh -L 8000:127.0.0.1:8000 <user>@<this-server>"
    else
        say "  Point the DNS record of $DOMAIN at this server first, so Caddy can get a certificate."
    fi
    say "  Address:  $base"
    say "  User:     $ADMIN_USER"
    if [ -n "$NEW_PASSWORD" ]; then
        say "  Password: $NEW_PASSWORD"
        say "  This password is shown only once. It is stored in $PWD/.env (mode 600)."
    else
        say "  Password: unchanged, stored in $PWD/.env"
    fi
    say ""
    say "Add your first server:"
    say "  1. Create a one-time token here (it asks for the password):"
    say "       $token_cmd"
    say "  2. Run this on the server to protect:"
    say "       $agent_cmd"
    if [ -z "$DOMAIN" ]; then
        say "  Without a domain only an agent on this machine can connect. For other servers run: ./install.sh --domain <domain>"
    fi
    say "Agents start in observe mode: no traffic is blocked until you enable enforce in the panel."
}

main() {
    set -euo pipefail
    umask 077
    parse_args "$@"
    cd "$(dirname "${BASH_SOURCE[0]:-.}")"
    [ -f docker-compose.yml ] ||
        die "run this from a Nexus checkout: git clone https://github.com/eminaydin19/Nexus.git && cd Nexus && ./install.sh"
    check_docker
    resolve_domain
    [ -z "$DOMAIN" ] || check_ports
    write_env
    start
    report
}

{ main "$@"; }
