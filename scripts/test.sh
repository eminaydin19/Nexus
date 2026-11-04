#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--nft" ]; then
    shift
    docker build -q -f Dockerfile.nft-test -t nexus-nft-test . >/dev/null
    exec docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -v "$PWD":/app -w /app nexus-nft-test "${@:-tests/agent/test_enforcer_nft.py}"
fi
docker build -q -f Dockerfile.test -t nexus-test . >/dev/null
docker run --rm -v "$PWD":/app -w /app nexus-test "$@"
