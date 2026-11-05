#!/usr/bin/env bash
# Attack and customer scenarios: real central, agent, sshd, nginx, nft, attacks and customers, on SQLite then Postgres.
#   tests/e2e/run.sh                      both databases
#   tests/e2e/run.sh sqlite|postgres      one database
#   tests/e2e/run.sh --red                everything up except the agent; every scenario must fail
#   E2E_SELECT=expr tests/e2e/run.sh ...  passed to pytest -k
#
# Needs Docker. Inside a container's network namespace the kernel drops nft "log" output unless the host sets
# net.netfilter.nf_log_all_netns=1, so this sets it for the run and restores it. It is one kernel-wide setting; on
# Docker Desktop that kernel is its VM, and on a native Linux host it is that host.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJECT=nexus-scenarios
SYSCTL=net.netfilter.nf_log_all_netns
TOOLS_IMAGE=nexus-scenarios-tools
ORIGINAL_SYSCTL=""
RED=""
BACKENDS=()
for arg in "$@"; do
    case "$arg" in
        --red) RED=1 ;;
        sqlite | postgres) BACKENDS+=("$arg") ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
[ "${#BACKENDS[@]}" -gt 0 ] || BACKENDS=(sqlite postgres)

compose() { docker compose -p "$PROJECT" -f "$HERE/docker-compose.e2e.yml" --profile postgres "$@"; }
vm_sysctl() { docker run --rm --net=host --privileged --entrypoint sysctl "$TOOLS_IMAGE" "$@"; }

teardown() {
    # -p above is the only project this can touch; volumes of any other project are out of its reach.
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}

# shellcheck disable=SC2317  # Called by the trap below.
cleanup() {
    teardown
    if [ -n "$ORIGINAL_SYSCTL" ]; then
        vm_sysctl -w "$SYSCTL=$ORIGINAL_SYSCTL" >/dev/null || echo "could not restore $SYSCTL=$ORIGINAL_SYSCTL" >&2
    fi
}
trap cleanup EXIT

mkdir -p "$HERE/.scenario-out"
rm -f "$HERE"/.scenario-out/metrics-*.jsonl
started=$SECONDS
compose build >/dev/null
ORIGINAL_SYSCTL="$(vm_sysctl -n "$SYSCTL")"
vm_sysctl -w "$SYSCTL=1" >/dev/null

status=0
for backend in "${BACKENDS[@]}"; do
    teardown
    printf '\n=== %s\n' "$backend"
    export E2E_DATABASE_URL=""
    if [ "$backend" = postgres ]; then
        # The form .env.example documents for DATABASE_URL.
        export E2E_DATABASE_URL="postgresql+psycopg://nexus:e2e-db-password@postgres/nexus"
        compose up -d postgres
        for _ in $(seq 60); do
            compose exec -T postgres pg_isready -U nexus -d nexus >/dev/null 2>&1 && break
            sleep 1
        done
        compose exec -T postgres pg_isready -U nexus -d nexus
    fi
    compose up -d central target attacker customer nat_customer cdn scanner runner
    env=(-e "E2E_BACKEND=$backend")
    [ -z "$RED" ] || env+=(-e E2E_AGENT_DOWN=1 -e E2E_TIMEOUT_SCALE=0.15)
    select=()
    [ -z "${E2E_SELECT:-}" ] || select=(-k "$E2E_SELECT")
    compose exec -T "${env[@]}" runner python -m pytest /e2e/scenarios.py -p no:cacheprovider -c /dev/null \
        --rootdir=/e2e -v -s --tb=short --durations=0 "${select[@]+"${select[@]}"}" || status=1
done
printf '\nTotal time: %ss\n' "$((SECONDS - started))"
exit "$status"
