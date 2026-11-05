#!/usr/bin/env bash
# Nexus central installer. Run from a checkout: ./install.sh [--domain nexus.example.com]
# Nothing runs until the last line, and a cut anywhere in that line is a syntax error, so a truncated download changes nothing.

DEFAULT_PROJECT="nexus-defense"
REPO_DIR=""
ENV_FILE=""
PROJECT=""
DOMAIN=""
DOMAIN_GIVEN=0
FIRST_INSTALL=0
ADOPT_EMPTY_DATA=0
ADMIN_USER="admin"
NEW_PASSWORD=""
LOOPBACK_BIND="127.0.0.1:8000"
LOCAL_COMPOSE="docker-compose.yml:docker-compose.local.yml"
COMPOSE_HINT="Docker Compose 2.24 or newer"

say() { printf '%s\n' "$*"; }
warn() { printf 'nexus: %s\n' "$*" >&2; }
die() {
    warn "$*"
    exit 1
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --domain)
                [ "$#" -ge 2 ] || die "--domain needs a value"
                DOMAIN="$2"
                DOMAIN_GIVEN=1
                shift 2
                ;;
            --adopt-empty-data)
                ADOPT_EMPTY_DATA=1
                shift
                ;;
            -h | --help)
                say "Usage: ./install.sh [--domain nexus.example.com] [--adopt-empty-data]"
                exit 0
                ;;
            *) die "unknown option: $1" ;;
        esac
    done
}

# Compose finds its files relative to the directory, so only this subshell ever leaves /.
compose() {
    (cd "$REPO_DIR" && docker compose "$@")
}

check_docker() {
    command -v docker >/dev/null 2>&1 || die "Docker is required. Install it first: https://docs.docker.com/engine/install/"
    compose version >/dev/null 2>&1 ||
        die "The Docker Compose plugin is required. Install it first: https://docs.docker.com/compose/install/linux/"
    docker info >/dev/null 2>&1 || die "Docker is installed but not reachable. Is it running, and may this user use it?"
    compose config -q >/dev/null || die "docker compose rejected the configuration; $COMPOSE_HINT is required"
}

env_get() {
    [ ! -f "$ENV_FILE" ] || sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

env_del() {
    [ -f "$ENV_FILE" ] || return 0
    grep -v "^$1=" "$ENV_FILE" >"$ENV_FILE.tmp" || true
    mv "$ENV_FILE.tmp" "$ENV_FILE"
}

env_set() {
    env_del "$1"
    printf '%s=%s\n' "$1" "$2" >>"$ENV_FILE"
}

env_default() {
    [ -n "$(env_get "$1")" ] || env_set "$1" "$2"
}

resolve_domain() {
    DOMAIN="${DOMAIN:-$(env_get DOMAIN)}"
    if [ -z "$DOMAIN" ] && [ -t 0 ]; then
        printf 'Domain for HTTPS (empty for local access over an SSH tunnel): '
        read -r DOMAIN || die "no answer at the prompt. Run again with --domain <domain>, or press Enter for no domain."
        [ -z "$DOMAIN" ] || DOMAIN_GIVEN=1
    fi
    [ -z "$DOMAIN" ] || [[ "$DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] ||
        die "invalid domain: $DOMAIN"
}

resolve_project() {
    PROJECT="${COMPOSE_PROJECT_NAME:-$(env_get COMPOSE_PROJECT_NAME)}"
    PROJECT="${PROJECT:-$DEFAULT_PROJECT}"
}

# Same project name from another directory: compose would replace those containers and take over their volumes.
check_project_owner() {
    local dir real
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        real="$dir"
        if [ -d "$dir" ]; then
            real="$(cd "$dir" && pwd -P)"
        fi
        [ "$real" = "$REPO_DIR" ] || die "Docker project $PROJECT already runs from $dir. Starting here would replace its containers and use its data. Nothing was changed. Run install.sh in $dir instead, or remove that stack first."
    done < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
        --format '{{.Label "com.docker.compose.project.working_dir"}}')
}

check_data_volume() {
    local others
    [ "$ADOPT_EMPTY_DATA" = 0 ] || return 0
    if docker volume inspect "${PROJECT}_nexus-data" >/dev/null 2>&1; then
        return 0
    fi
    others="$(docker volume ls --format '{{.Name}}' | grep '_nexus-data$' || true)"
    [ -n "$others" ] || return 0
    warn "this install would start with an empty database, because ${PROJECT}_nexus-data does not exist while these do:"
    printf '%s\n' "$others" >&2
    warn "Nothing was changed. Your options:"
    warn "  1. Keep using that data: run install.sh from the checkout that created it."
    warn "  2. Move it: docker volume create ${PROJECT}_nexus-data, copy the old volume's files into it, then run install.sh again."
    warn "  3. Start empty and leave those volumes alone: ./install.sh --adopt-empty-data"
    exit 1
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
    [ -z "$(compose --profile https ps -q --status running caddy 2>/dev/null)" ] || return 0
    for port in 80 443; do
        ! port_busy "$port" || die "port $port is already in use; Caddy needs ports 80 and 443 for HTTPS"
    done
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1 && openssl rand -hex 24 2>/dev/null; then
        return 0
    fi
    command -v python3 >/dev/null 2>&1 || die "openssl or python3 is required to generate a password"
    python3 -I -c 'import secrets; print(secrets.token_hex(24))'
}

bind_is_loopback() {
    case "$1" in
        127.* | localhost:* | "[::1]:"*) return 0 ;;
        *) return 1 ;;
    esac
}

apply_domain_settings() {
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
        env_set HTTP_BIND "$LOOPBACK_BIND"
    fi
}

# A re-run without --domain keeps the operator's choices. It only fills in what the no-domain path cannot do without.
keep_existing_settings() {
    [ -z "$DOMAIN" ] || return 0
    env_default TRUST_PROXY_HEADERS false
    env_default HTTP_BIND "$LOOPBACK_BIND"
    env_default COMPOSE_FILE "$LOCAL_COMPOSE"
    local bind
    bind="$(env_get HTTP_BIND)"
    bind_is_loopback "$bind" ||
        warn "warning: HTTP_BIND=$bind publishes the dashboard and its password over plain http. Use --domain for HTTPS."
}

write_env() {
    [ -f "$ENV_FILE" ] || FIRST_INSTALL=1
    touch "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    env_default INGESTION_SOURCE webhook
    env_default DASHBOARD_USER "$ADMIN_USER"
    ADMIN_USER="$(env_get DASHBOARD_USER)"
    if [ -z "$(env_get DASHBOARD_PASSWORD)" ]; then
        NEW_PASSWORD="$(generate_secret)"
        env_set DASHBOARD_PASSWORD "$NEW_PASSWORD"
    fi
    if [ "$FIRST_INSTALL" = 1 ] || [ "$DOMAIN_GIVEN" = 1 ]; then
        apply_domain_settings
    else
        keep_existing_settings
    fi
}

start() {
    # Only ever up: down -v or a volume prune would destroy the customer's data on a re-run.
    compose up -d --build --wait --wait-timeout 300 ||
        die "the containers did not become healthy; see: docker compose logs nexus. The dashboard password is stored in $ENV_FILE"
}

report() {
    local base bind token_cmd agent_cmd
    if [ -n "$DOMAIN" ]; then
        base="https://$DOMAIN"
        agent_cmd="curl -fsSL $base/install-agent.sh | NEXUS_ENROLL_TOKEN=<token> sudo --preserve-env=NEXUS_ENROLL_TOKEN bash"
    else
        bind="$(env_get HTTP_BIND)"
        if bind_is_loopback "$bind"; then
            base="http://$bind"
        else
            base="http://<this-server>:${bind##*:}"
        fi
        agent_cmd="curl -fsSL $base/install-agent.sh | NEXUS_ENROLL_TOKEN=<token> sudo --preserve-env=NEXUS_ENROLL_TOKEN bash -s -- --url $base"
        bind_is_loopback "$bind" || agent_cmd="$agent_cmd --insecure"
    fi
    token_cmd="curl -u $ADMIN_USER -X POST -H 'Content-Type: application/json' -d '{\"name\":\"web-1\"}' $base/api/agents/tokens"
    say ""
    say "Nexus is running."
    say ""
    say "Log in:"
    if [ -n "$DOMAIN" ]; then
        say "  Point the DNS record of $DOMAIN at this server first, so Caddy can get a certificate."
    elif bind_is_loopback "$bind"; then
        say "  This install listens on 127.0.0.1 only. Open a tunnel from your computer:"
        say "    ssh -L 8000:127.0.0.1:8000 <user>@<this-server>"
    fi
    say "  Address:  $base"
    say "  User:     $ADMIN_USER"
    if [ -n "$NEW_PASSWORD" ]; then
        say "  Password: $NEW_PASSWORD"
        say "  This password is shown only once. It is stored in $ENV_FILE (mode 600)."
    else
        say "  Password: unchanged, stored in $ENV_FILE"
    fi
    say ""
    say "Add your first server:"
    say "  1. Create a one-time token here (it asks for the password):"
    say "       $token_cmd"
    if [ -n "$DOMAIN" ]; then
        say "  2. Run this on the server you want to protect:"
    else
        say "  2. Without a domain, the only agent that can connect is one on this machine. Run this here:"
    fi
    say "       $agent_cmd"
    say "Agents start in observe mode: no traffic is blocked until you enable enforce in the panel."
}

main() {
    set -euo pipefail
    umask 077
    local source_path="${BASH_SOURCE[0]:-.}" source_dir="."
    case "$source_path" in */*) source_dir="${source_path%/*}" ;; esac
    parse_args "$@"
    REPO_DIR="$(cd "$source_dir" && pwd -P)"
    ENV_FILE="$REPO_DIR/.env"
    # Python puts the current directory on sys.path, and this may run as root: a planted secrets.py would run.
    cd /
    [ -f "$REPO_DIR/docker-compose.yml" ] ||
        die "run this from a Nexus checkout: git clone https://github.com/eminaydin19/Nexus.git && cd Nexus && ./install.sh"
    check_docker
    resolve_domain
    resolve_project
    check_project_owner
    check_data_volume
    [ -z "$DOMAIN" ] || check_ports
    write_env
    start
    report
}

{ main "$@"; }
