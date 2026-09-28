#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-load-test.sh — basic load-generation harness
#
# v8.80 / ARCH-004 — test-depth gap closure. Reference-implementation load
# testing using Python stdlib only (no extra dependencies). Useful for:
#
#   - confirming a deployment serves expected RPS without 5xx
#   - smoking the rate-limiter at the edge (Caddy) + the app
#   - generating sufficient verification volume to exercise the cache
#   - capacity-planning sanity checks before production cutover
#
# Usage:
#     ./scripts/polaris-load-test.sh [target_url] [rps] [duration_seconds]
#
# Examples:
#     ./scripts/polaris-load-test.sh                          # defaults: localhost, 50 rps, 30s
#     ./scripts/polaris-load-test.sh https://polaris.example.com/api/health
#     ./scripts/polaris-load-test.sh http://localhost:5000/api/health 100 60
#
# Sample output:
#     polaris-load-test: http://localhost:5000/api/health @ 50 rps for 30s
#     [10s]  hit 502/502 (status: 200=502, error=0) p50=4.1ms p95=12.4ms p99=22.1ms
#     [20s]  hit 1004/1004 ...
#     [30s]  hit 1506/1506 ...
#     ────────────────────────────────────────
#     total requests:   1506
#     successes:        1506  (100.00%)
#     errors:           0
#     rate-limited:     0
#     p50 / p95 / p99:  4.0ms / 12.1ms / 21.6ms
#     wall-clock:       30.01s   (50.18 req/s)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
LOAD_GEN="${POLARIS_ROOT}/scripts/polaris_load_gen.py"

TARGET="${1:-http://localhost:5000/api/health}"
RPS="${2:-50}"
DURATION="${3:-30}"

# Pick a Python that has urllib (stdlib — works with any 3.x).
PY="python3"
if ! command -v "${PY}" >/dev/null 2>&1; then
    echo "error: python3 not found on PATH" >&2
    exit 2
fi

exec "${PY}" "${LOAD_GEN}" \
    --target "${TARGET}" \
    --rps "${RPS}" \
    --duration "${DURATION}"
