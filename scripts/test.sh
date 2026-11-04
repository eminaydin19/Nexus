#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -q -f Dockerfile.test -t nexus-test . >/dev/null
docker run --rm -v "$PWD":/app -w /app nexus-test "$@"
