#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-partition-maintenance.sh — premake the event tables' monthly
# partitions ahead of time (roadmap P2.1, v9.245).
#
# The four event tables are monthly range-partitioned; new rows need a
# partition for their month to exist. uc_ensure_event_partitions() premakes
# the current month plus a buffer, idempotently. The deploy calls it on every
# upgrade; this script is the standing monthly job (polaris-partition-
# maintenance.timer) so a deployment that does not upgrade for months still
# stays ahead. A month with no partition is not data loss (the row lands in
# DEFAULT), but it forfeits O(1) detach-based purge for that month.
#
# It runs CALL uc_ensure_event_partitions() against the deployed stack's
# database through the compose postgres service, the same database the deploy
# migrates. POLARIS_MONTHS_AHEAD overrides the buffer (default 3).
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
MONTHS="${POLARIS_MONTHS_AHEAD:-3}"
case "$MONTHS" in ''|*[!0-9]*) echo "POLARIS_MONTHS_AHEAD must be an integer" >&2; exit 2 ;; esac
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml "${COMPOSE_EXTRA[@]}" "$@"); }
echo "polaris-partition-maintenance: ensuring monthly partitions (+${MONTHS} months)…"
compose exec -T postgres psql -U postgres -d polaris -v ON_ERROR_STOP=1 -c "CALL uc_ensure_event_partitions(${MONTHS});"
echo "polaris-partition-maintenance: done."
