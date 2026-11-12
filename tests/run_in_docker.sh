#!/usr/bin/env bash
# Runs the test suite inside the Artemis image with throwaway Redis/PostgreSQL.
# Usage: tests/run_in_docker.sh [pytest args...]   (ARTEMIS_BUILD_IMAGE overrides the image)
set -euo pipefail
cd "$(dirname "$0")"
PROJECT=cybercover-incremental-test
cleanup() { docker compose -p "$PROJECT" -f test-stack.compose.yaml down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
if [ "$#" -gt 0 ]; then
    docker compose -p "$PROJECT" -f test-stack.compose.yaml run --rm test \
        python3 -m pytest -p no:cacheprovider "$@"
else
    docker compose -p "$PROJECT" -f test-stack.compose.yaml run --rm test
fi
