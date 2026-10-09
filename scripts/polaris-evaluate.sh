#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-evaluate.sh: judge THIS install and write a report its reader can keep
# (docs/operator/EVALUATE.md). The probes are scripts/polaris-evaluate.py; this reads the
# configuration polaris.service runs with first, as the doctor does, so a run with sudo judges the
# stack the service runs.
#
# Usage:
#   polaris-evaluate.sh                      changes nothing an operator would mind
#   polaris-evaluate.sh --pack FILE --rp-config FILE
#                                            also verifies a credential of yours, offline and as
#                                            your relying party
#   polaris-evaluate.sh --notional --operator NAME --password-file FILE
#                                            on notional data only: issues, verifies, tampers with
#                                            and revokes one credential of its own
# Environment: COMPOSE_PROJECT_NAME and POLARIS_COMPOSE_EXTRA, as the other stack scripts;
#   POLARIS_EVALUATE_URL (default https://$POLARIS_DOMAIN, else https://localhost).
# Exit: 0 no probe failed; 1 a probe failed, and the last line names it; 2 nothing to evaluate.
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "${SCRIPT_DIR}/polaris-env.sh"
exec python3 "${SCRIPT_DIR}/polaris-evaluate.py" "$@"
