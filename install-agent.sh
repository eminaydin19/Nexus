#!/usr/bin/env bash
# Nexus agent installer. Served by central at /install-agent.sh.
#   curl -fsSL https://<central>/install-agent.sh | NEXUS_ENROLL_TOKEN=<one-time-token> sudo --preserve-env=NEXUS_ENROLL_TOKEN bash
# Nothing runs until the last line, and a cut anywhere in that line is a syntax error, so a truncated download changes nothing.

EMBEDDED_URL='__NEXUS_PUBLIC_URL__'

SERVICE=nexus-agent
AGENT_USER=nexus-agent
INSTALL_DIR=/opt/nexus-agent
ENV_FILE=/etc/nexus-agent.env
STATE_DIR=/var/lib/nexus-agent
UNIT_FILE=/etc/systemd/system/nexus-agent.service
OS_RELEASE=/etc/os-release
# Marks a user as created here. Anything else named nexus-agent belongs to someone and must stay untouched.
USER_MARKER="Nexus agent (managed)"
PYTHON=python3
REPORT_WAIT=15

TOKEN=""
URL=""
URL_FLAG=""
MAX_MODE=""
INSECURE=""
UNINSTALL=""
RE_ENROLL=""
ENROLLED=""
HAD_KEY=""
REPORTING=0
STARTED_AT=0
WORKDIR=""
ROLLBACK=0
CREATED_USER=0

say() { printf '%s\n' "$*"; }
warn() { printf 'nexus-agent: %s\n' "$*" >&2; }
die() {
    warn "$*"
    exit 1
}

usage() {
    say "Usage: install-agent.sh --token <token> [--url <central-url>] [--max-mode off|observe|enforce] [--insecure] [--re-enroll]"
    say "       install-agent.sh --uninstall"
    say "NEXUS_ENROLL_TOKEN is preferred over --token, which other local users can see in ps."
}

parse_args() {
    TOKEN="${NEXUS_ENROLL_TOKEN:-}"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --token | --url | --max-mode)
                [ "$#" -ge 2 ] || die "$1 needs a value"
                case "$1" in
                    --token) TOKEN="${NEXUS_ENROLL_TOKEN:-$2}" ;;
                    --url) URL_FLAG="$2" ;;
                    --max-mode) MAX_MODE="$2" ;;
                esac
                shift 2
                ;;
            --insecure) INSECURE=1 && shift ;;
            --uninstall) UNINSTALL=1 && shift ;;
            --re-enroll) RE_ENROLL=1 && shift ;;
            -h | --help) usage && exit 0 ;;
            *) die "unknown option: $1" ;;
        esac
    done
    case "$MAX_MODE" in
        "" | off | observe | enforce) ;;
        *) die "--max-mode must be off, observe or enforce" ;;
    esac
}

require_root() {
    [ "$(id -u)" = 0 ] || die "this installer must run as root (use sudo)"
}

require_systemd() {
    if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
        die "systemd is required, and it is not running on this system"
    fi
}

python_fix() {
    local release=""
    # shellcheck disable=SC1090  # the path is the system's os-release
    [ ! -r "$OS_RELEASE" ] || release="$(. "$OS_RELEASE" 2>/dev/null && printf '%s|%s|%s' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}")"
    case "$release" in
        ubuntu\|*\|20.04) say "Install it with: apt install python3.9 python3.9-venv" ;;
        rhel\|*\|8* | *rhel*\|8*) say "Install it with: dnf install python39" ;;
        *) say "Install Python 3.9 or newer with your system's package manager" ;;
    esac
}

require_python() {
    local candidate
    for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -I -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
            PYTHON="$candidate"
            return 0
        fi
    done
    die "Python 3.9 or newer is required and was not found. $(python_fix), then run the installer again."
}

require_curl() {
    command -v curl >/dev/null 2>&1 || die "curl is required"
}

passwd_line() {
    getent passwd "$AGENT_USER" 2>/dev/null || true
}

user_is_ours() {
    [ "$(passwd_line | cut -d: -f5)" = "$USER_MARKER" ]
}

check_existing_user() {
    [ -z "$(passwd_line)" ] || user_is_ours ||
        die "a user named $AGENT_USER already exists and this installer did not create it. Nothing was changed. Rename that user, then run the installer again."
}

# shellcheck disable=SC2016  # the Python source must reach python3 unexpanded
NORMALIZE_URL_PY='
import ipaddress, re, sys
from urllib.parse import urlsplit

def refuse(why):
    sys.exit("nexus-agent: " + why)

raw, insecure = sys.argv[1], sys.argv[2] == "1"
if not re.fullmatch(r"[A-Za-z0-9._~:/\[\]%-]+", raw):
    refuse("the central URL has invalid characters")
try:
    parts = urlsplit(raw)
    parts.port
except ValueError:
    refuse("the central URL has an invalid host or port")
if parts.scheme not in ("http", "https") or not parts.hostname:
    refuse("the central URL must look like https://host")
if parts.username or parts.password or parts.query or parts.fragment:
    refuse("the central URL must not contain credentials, a query or a fragment")
try:
    loopback = ipaddress.ip_address(parts.hostname).is_loopback
except ValueError:
    loopback = parts.hostname == "localhost"
if parts.scheme != "https" and not insecure and not loopback:
    refuse("the central URL must use https; only loopback or --insecure may use http")
path = parts.path.rstrip("/")
if path.endswith("/api/ingest"):
    path = path[: -len("/api/ingest")]
print("%s://%s%s" % (parts.scheme, parts.netloc, path))
'

normalize_url() {
    "$PYTHON" -I -c "$NORMALIZE_URL_PY" "$1" "${2:-}"
}

env_value() {
    [ ! -f "$ENV_FILE" ] || sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

# Sets URL, ENROLLED, HAD_KEY and INSECURE. An enrolled host keeps talking to the central that issued its key.
resolve_target() {
    local raw
    case "$EMBEDDED_URL" in __*) EMBEDDED_URL="" ;; esac
    if [ -n "$(env_value NEXUS_API_KEY)" ]; then
        HAD_KEY=1
        raw="$(env_value NEXUS_URL)"
        case "$(env_value NEXUS_INSECURE)" in 1 | true | yes) INSECURE=1 ;; esac
        if [ -z "$RE_ENROLL" ]; then
            ENROLLED=1
            [ -n "$raw" ] || die "$ENV_FILE has a key but no NEXUS_URL; run --uninstall and install again"
            URL="$(normalize_url "$raw" "$INSECURE")" || exit 1
            if [ -n "$URL_FLAG" ] && [ "$(normalize_url "$URL_FLAG" "$INSECURE")" != "$URL" ]; then
                die "this server is enrolled with $URL; to move it, use --re-enroll with a new token, or --uninstall first"
            fi
            return 0
        fi
        raw="${URL_FLAG:-${EMBEDDED_URL:-$raw}}"
    else
        raw="${URL_FLAG:-$EMBEDDED_URL}"
    fi
    [ -n "$raw" ] || die "central did not embed its address; pass --url https://<central>"
    URL="$(normalize_url "$raw" "$INSECURE")" || exit 1
    [ -n "$TOKEN" ] || die "an enrollment token is required: set NEXUS_ENROLL_TOKEN or pass --token"
}

venv_package() {
    case "$1:$PYTHON" in
        dnf:python3) echo python3-libs ;;
        dnf:python3.9) echo python39-libs ;;
        dnf:*) echo "$PYTHON-libs" ;;
        *) echo "$PYTHON-venv" ;;
    esac
}

# Stops before any change on systems without apt or dnf.
ensure_packages() {
    local manager="" missing=()
    if command -v apt-get >/dev/null 2>&1; then
        manager=apt
    elif command -v dnf >/dev/null 2>&1; then
        manager=dnf
    fi
    "$PYTHON" -I -c 'import ensurepip, venv' >/dev/null 2>&1 || missing+=("$(venv_package "$manager")")
    command -v nft >/dev/null 2>&1 || missing+=(nftables)
    [ "${#missing[@]}" -gt 0 ] || return 0
    case "$manager" in
        apt)
            say "Installing ${missing[*]} with apt-get"
            apt-get update -qq </dev/null || die "apt-get update failed"
            # confold keeps a firewall config the operator already has on disk.
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
                -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "${missing[@]}" </dev/null ||
                die "could not install ${missing[*]}"
            ;;
        dnf)
            say "Installing ${missing[*]} with dnf"
            dnf install -y -q "${missing[@]}" </dev/null || die "could not install ${missing[*]}"
            ;;
        *) die "please install these packages and run the installer again: ${missing[*]}" ;;
    esac
}

# shellcheck disable=SC2016  # the Python source must reach python3 unexpanded
EXTRACT_PY='
import hashlib, os, sys, tarfile
from pathlib import PurePosixPath

MAX_BYTES = 50 * 1024 * 1024

def refuse(why):
    sys.exit("nexus-agent: agent package refused: " + why)

path, want, dest = sys.argv[1:4]
with open(path, "rb") as f:
    if hashlib.sha256(f.read()).hexdigest() != want.lower():
        refuse("sha256 mismatch, the download is corrupt")
try:
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        names = set()
        for m in members:
            parts = PurePosixPath(m.name).parts
            if not m.isfile():
                refuse("%r is not a regular file" % m.name)
            if m.name.startswith("/") or ".." in parts or not parts:
                refuse("unsafe path %r" % m.name)
            if parts[0] != "nexus_agent" and m.name != "requirements-agent.txt":
                refuse("unexpected file %r" % m.name)
            names.add(m.name)
        if sum(m.size for m in members) > MAX_BYTES:
            refuse("too large")
        if not {"nexus_agent/__main__.py", "requirements-agent.txt"} <= names:
            refuse("required files are missing")
        for m in members:
            target = os.path.join(dest, m.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(m) as src, open(target, "wb") as out:
                out.write(src.read())
except (tarfile.TarError, OSError, EOFError) as exc:
    refuse(str(exc))
'

verify_and_extract() {
    "$PYTHON" -I -c "$EXTRACT_PY" "$1" "$2" "$3"
}

download_agent() {
    local proto=https sha
    case "$URL" in http://*) proto=http ;; esac
    # No -L: the agent itself never follows redirects, so a redirect here would be a misconfigured URL.
    curl -fsS --proto "=$proto" --connect-timeout 10 --max-time 300 \
        -D "$WORKDIR/headers" -o "$WORKDIR/agent.tar.gz" "$URL/agent.tar.gz" ||
        die "could not download the agent from $URL"
    sha="$(tr -d '\r' <"$WORKDIR/headers" | awk 'tolower($1) == "x-nexus-agent-sha256:" { v = $2 } END { print v }')"
    [ -n "$sha" ] || die "$URL did not send a checksum for the agent package; is this the Nexus central URL?"
    mkdir "$WORKDIR/agent"
    verify_and_extract "$WORKDIR/agent.tar.gz" "$sha" "$WORKDIR/agent" || exit 1
}

install_code() {
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    # A distribution upgrade can leave a venv whose interpreter is gone.
    if ! "$INSTALL_DIR/venv/bin/python" -c '' >/dev/null 2>&1; then
        "$PYTHON" -m venv --clear "$INSTALL_DIR/venv" || die "could not create the virtualenv"
    fi
    "$INSTALL_DIR/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-input \
        -r "$WORKDIR/agent/requirements-agent.txt" || die "could not install the agent's Python packages"
    rm -rf "$INSTALL_DIR/nexus_agent.new"
    cp -R "$WORKDIR/agent/nexus_agent" "$INSTALL_DIR/nexus_agent.new"
    # Whole-directory swap: a leftover __pycache__ could shadow the new sources.
    rm -rf "$INSTALL_DIR/nexus_agent"
    mv "$INSTALL_DIR/nexus_agent.new" "$INSTALL_DIR/nexus_agent"
}

ensure_user() {
    local group
    if [ -z "$(passwd_line)" ]; then
        useradd --system --user-group --no-create-home --home-dir "$STATE_DIR" --comment "$USER_MARKER" \
            --shell "$(command -v nologin || echo /bin/false)" "$AGENT_USER" || die "could not create $AGENT_USER"
        CREATED_USER=1
    fi
    for group in adm systemd-journal; do
        if getent group "$group" >/dev/null; then
            usermod -aG "$group" "$AGENT_USER" || die "could not add $AGENT_USER to $group"
        fi
    done
}

# shellcheck disable=SC2016  # the Python source must reach python3 unexpanded
ENV_FILE_PY='
import json, os, re, sys

url, max_mode, insecure = sys.argv[1:4]
try:
    answer = json.load(sys.stdin)
    node_id, api_key = answer["node_id"], answer["api_key"]
except (ValueError, KeyError, TypeError):
    sys.exit("nexus-agent: central sent an invalid enrollment answer")
for value in (node_id, api_key):
    # Both end up in an EnvironmentFile; a newline could add settings central must not control.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        sys.exit("nexus-agent: central sent an invalid enrollment answer")
print("NEXUS_URL=" + url)
print("NEXUS_API_KEY=" + api_key)
print("NEXUS_NODE_ID=" + node_id)
if max_mode:
    print("NEXUS_MAX_MODE=" + max_mode)
if insecure:
    print("NEXUS_INSECURE=1")
'

enroll_and_write_env() {
    local answer
    # The token goes by environment and the answer stays in a variable: argv is world-readable in ps.
    answer="$(cd "$INSTALL_DIR" && NEXUS_ENROLL_TOKEN="$TOKEN" NEXUS_INSECURE="$INSECURE" \
        "$INSTALL_DIR/venv/bin/python" -m nexus_agent enroll --url "$URL")" ||
        die "enrollment failed; check the token (it works once and expires) and the URL"
    TOKEN=""
    local keep='^(NEXUS_URL|NEXUS_API_KEY|NEXUS_NODE_ID|NEXUS_INSECURE)='
    [ -z "$MAX_MODE" ] || keep='^(NEXUS_URL|NEXUS_API_KEY|NEXUS_NODE_ID|NEXUS_INSECURE|NEXUS_MAX_MODE)='
    (
        umask 077
        printf '%s' "$answer" | "$PYTHON" -I -c "$ENV_FILE_PY" "$URL" "$MAX_MODE" "$INSECURE" >"$ENV_FILE.tmp"
    ) || {
        rm -f "$ENV_FILE.tmp"
        die "could not write $ENV_FILE"
    }
    # A re-enroll keeps the operator's other settings.
    [ ! -f "$ENV_FILE" ] || grep -Ev "$keep" "$ENV_FILE" >>"$ENV_FILE.tmp" || true
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    # The key is on disk now, so a later failure must keep it: the token cannot be used twice.
    ROLLBACK=0
}

update_max_mode() {
    [ -n "$MAX_MODE" ] || return 0
    (
        umask 077
        grep -v '^NEXUS_MAX_MODE=' "$ENV_FILE" >"$ENV_FILE.tmp" || true
        printf 'NEXUS_MAX_MODE=%s\n' "$MAX_MODE" >>"$ENV_FILE.tmp"
    ) || die "could not update $ENV_FILE"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
}

write_unit() {
    cat >"$UNIT_FILE" <<'UNIT'
[Unit]
Description=Nexus defense agent
Documentation=https://github.com/eminaydin19/Nexus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nexus-agent
WorkingDirectory=/opt/nexus-agent
EnvironmentFile=/etc/nexus-agent.env
ExecStart=/opt/nexus-agent/venv/bin/python -m nexus_agent run
StateDirectory=nexus-agent
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT
    chmod 644 "$UNIT_FILE"
}

current_mode() {
    "$PYTHON" -I - "$STATE_DIR/state.json" "$(env_value NEXUS_MAX_MODE)" <<'PY'
import json, sys

MODES = ("off", "observe", "enforce")
try:
    mode = json.load(open(sys.argv[1])).get("mode")
except (OSError, ValueError, AttributeError):
    mode = None
mode = mode if mode in MODES else "observe"
limit = sys.argv[2] if sys.argv[2] in MODES else "enforce"
print(min(mode, limit, key=MODES.index))
PY
}

# Restart=always makes a crashing service look active for a moment, so it has to stay up for a few checks.
wait_for_service() {
    local i stable=0
    for ((i = 0; i < 15; i++)); do
        if systemctl is-active --quiet "$SERVICE"; then
            stable=$((stable + 1))
            [ "$stable" -lt 3 ] || return 0
        else
            stable=0
        fi
        sleep 1
    done
    return 1
}

# shellcheck disable=SC2016  # the Python source must reach python3 unexpanded
LAST_SEND_PY='
import json, sys

try:
    last_send = json.load(open(sys.argv[1])).get("last_send")
except (OSError, ValueError, AttributeError):
    sys.exit(1)
fresh = isinstance(last_send, (int, float)) and not isinstance(last_send, bool) and last_send >= float(sys.argv[2])
sys.exit(0 if fresh else 1)
'

# "Active" only means the process runs. A send since this start is what proves central hears it.
wait_for_report() {
    local i
    REPORTING=0
    for ((i = 0; i < REPORT_WAIT; i++)); do
        if "$PYTHON" -I -c "$LAST_SEND_PY" "$STATE_DIR/state.json" "$STARTED_AT"; then
            REPORTING=1
            return 0
        fi
        sleep 1
    done
}

start_service() {
    systemctl daemon-reload
    systemctl enable --quiet "$SERVICE"
    systemctl restart "$SERVICE" || true
    if ! wait_for_service; then
        warn "the service did not stay active. Last journal lines:"
        journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
        die "fix the cause and run the installer again, or remove the agent with --uninstall"
    fi
}

report() {
    local mode
    mode="$(current_mode)"
    say ""
    if [ "$REPORTING" = 1 ]; then
        say "Nexus agent is active and reporting to $URL"
    else
        say "Service active, not yet reporting to $URL. Watch it with: journalctl -u $SERVICE"
    fi
    say "Mode: $mode"
    case "$mode" in
        observe) say "It is in observe mode: no traffic will be blocked until you enable enforce in the panel." ;;
        off) say "Detection is off: no traffic will be blocked." ;;
        enforce) say "This server was already in enforce mode, so it keeps blocking as before." ;;
    esac
    say "Check it with: systemctl status $SERVICE"
    say "Logs:          journalctl -u $SERVICE"
    say "Remove it with: curl -fsSL $URL/install-agent.sh | sudo bash -s -- --uninstall"
}

remove_user() {
    [ -n "$(passwd_line)" ] || return 0
    if user_is_ours; then
        userdel "$AGENT_USER" 2>/dev/null || warn "could not remove user $AGENT_USER"
    else
        say "Leaving user $AGENT_USER in place: this installer did not create it."
    fi
}

rollback() {
    warn "rolling back this installation"
    rm -rf "$INSTALL_DIR"
    rm -f "$ENV_FILE.tmp"
    [ "$CREATED_USER" = 0 ] || remove_user
}

on_exit() {
    local status=$?
    trap - EXIT
    [ -z "$WORKDIR" ] || rm -rf "$WORKDIR"
    if [ "$status" -ne 0 ] && [ "$ROLLBACK" = 1 ]; then
        rollback
    fi
    exit "$status"
}

uninstall() {
    local status=0
    # Stop first: a running agent in enforce mode would create the table again.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
    if [ -x "$INSTALL_DIR/venv/bin/python" ] && [ -d "$INSTALL_DIR/nexus_agent" ]; then
        (cd "$INSTALL_DIR" && "$INSTALL_DIR/venv/bin/python" -m nexus_agent uninstall) ||
            warn "the agent could not remove its firewall table; trying nft directly"
    fi
    if command -v nft >/dev/null 2>&1 && nft list table inet nexus >/dev/null 2>&1; then
        nft delete table inet nexus || { warn "could not delete nftables table inet nexus" && status=1; }
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --quiet "$SERVICE" 2>/dev/null || true
    fi
    rm -f "$UNIT_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl reset-failed "$SERVICE" 2>/dev/null || true
    fi
    rm -rf "$INSTALL_DIR" "$STATE_DIR"
    rm -f "$ENV_FILE" "$ENV_FILE.tmp"
    remove_user
    say "Nexus agent removed. Revoke this server in the panel if it should not come back."
    return "$status"
}

main() {
    set -euo pipefail
    umask 022
    # Python puts the current directory on sys.path, and this runs as root: a planted venv.py would run.
    cd /
    PATH="$PATH:/usr/sbin:/sbin"
    parse_args "$@"
    require_root
    if [ -n "$UNINSTALL" ]; then
        uninstall
        return
    fi
    require_systemd
    require_python
    check_existing_user
    resolve_target
    require_curl
    if [ -n "$INSECURE" ]; then
        warn "warning: with --insecure the token and the agent key can travel without TLS"
    fi
    ensure_packages

    trap on_exit EXIT
    trap 'exit 130' INT TERM
    WORKDIR="$(mktemp -d)"
    download_agent

    if [ -n "$ENROLLED" ]; then
        say "Already enrolled: keeping the key and upgrading the agent code"
        [ -z "$TOKEN" ] || say "The enrollment token was ignored. To replace the key, run again with --re-enroll."
        chmod 600 "$ENV_FILE"
        install_code
        update_max_mode
    else
        # A failed re-enroll must leave the working install and its key alone.
        [ -n "$HAD_KEY" ] || ROLLBACK=1
        ensure_user
        install_code
        enroll_and_write_env
    fi
    ensure_user
    write_unit
    STARTED_AT="$(date +%s)"
    start_service
    wait_for_report
    report
}

{ main "$@"; }
