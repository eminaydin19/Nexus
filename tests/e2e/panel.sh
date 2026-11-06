#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${PANEL_OUT:-$PWD/.panel-out}"
mkdir -p "$OUT"
BACKEND=nexus-panel-backend

cleanup() { docker rm -f "$BACKEND" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q -f Dockerfile.test -t nexus-test . >/dev/null
docker build -q -t nexus-panel-e2e - <tests/e2e/Dockerfile.panel >/dev/null

run_pass() {
    local pass="$1" xss="$2" public_url="$3"
    shift 3
    cleanup
    docker run -d --name "$BACKEND" --entrypoint sh \
        -v "$PWD":/app:ro -w /app \
        -e PYTHONPATH=/app -e PYTHONDONTWRITEBYTECODE=1 -e DATA_DIR=/tmp/nexus -e DASHBOARD_USER=admin -e DASHBOARD_PASSWORD=panel-test \
        -e RATE_LIMIT_PER_MINUTE=0 -e SEED_XSS="$xss" -e PUBLIC_URL="$public_url" -e SLACK_WEBHOOK_URL= \
        nexus-test -c 'uvicorn backend.main:app --host 127.0.0.1 --port 8000 --log-level warning & python tests/e2e/panel_seed.py' >/dev/null
    for _ in $(seq 1 120); do
        docker exec "$BACKEND" test -f /tmp/seeded 2>/dev/null && break
        docker inspect -f '{{.State.Running}}' "$BACKEND" | grep -q true || { docker logs "$BACKEND"; exit 1; }
        sleep 1
    done
    docker exec "$BACKEND" test -f /tmp/seeded || { docker logs "$BACKEND"; exit 1; }
    docker run --rm --network "container:$BACKEND" \
        -v "$PWD/tests/e2e/panel.spec.mjs":/e2e/panel.spec.mjs:ro -v "$OUT":/out \
        -e PANEL_PASS="$pass" -e PANEL_PUBLIC_URL="$public_url" \
        nexus-panel-e2e npx playwright test panel.spec.mjs --workers=1 --reporter=list --output="/out/results-$pass" "$@"
}

status=0
run_pass clean 0 https://nexus.example "$@" || status=1
run_pass xss 1 "" "$@" || status=1
exit "$status"
