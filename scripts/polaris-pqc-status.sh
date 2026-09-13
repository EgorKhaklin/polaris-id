#!/usr/bin/env bash
# ============================================================================
# polaris-pqc-status.sh — operator-facing PQC availability check
#
# v9.24. Reports whether the real ML-DSA-65
# signing path is available + enabled. Honest accounting per the
# v9.24: the headline post-quantum claim should not exceed
# what is operationally true.
#
# Usage:
#     ./scripts/polaris-pqc-status.sh             # status report
#     ./scripts/polaris-pqc-status.sh --smoke     # sign/verify roundtrip
#     ./scripts/polaris-pqc-status.sh --json      # machine-readable
#
# Exit codes:
#     0  available + (if --smoke) roundtrip OK
#     1  available but smoke test failed
#     2  module imports but oqs not present
#     3  module fails to import (Python error)
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"

SMOKE=0
JSON=0
for arg in "$@"; do
    case "${arg}" in
        --smoke) SMOKE=1 ;;
        --json)  JSON=1 ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

cd "${POLARIS_ROOT}"

if [[ "${JSON}" -eq 1 ]]; then
    python3 -c "
import json
import polaris_web.pqc_signing as p
report = p.availability_report()
if ${SMOKE}:
    report['smoke_test'] = p.smoke_test()
print(json.dumps(report, indent=2))
"
    exit 0
fi

python3 - "${SMOKE}" <<'PY'
import sys
import polaris_web.pqc_signing as p

smoke = sys.argv[1] == "1"
r = p.availability_report()

print("polaris-pqc-status:")
print(f"  algorithm:        {r['algorithm']} (FIPS 204)")
print(f"  module imported:  {r['module_imported']}")
print(f"  oqs available:    {r['oqs_available']}")
print(f"  oqs version:      {r['oqs_version']}")
if r['oqs_import_error']:
    print(f"  oqs import error: {r['oqs_import_error']}")
print(f"  flag POLARIS_USE_REAL_PQC: {r['flag_set']}")
print(f"  is enabled:       {r['is_enabled']}")
c = r.get('custody')
if c is None:
    print("  custody:          none (no persistent key; ephemeral dev signing)")
elif 'error' in c:
    print(f"  custody:          ERROR {c['error']}")
else:
    print(f"  custody:          {c['driver']}  key={c['key_id']}  pk-fp={c['public_key_fingerprint']}")
print()
if r['is_enabled']:
    print("  STATE: real PQ signing is ENABLED for new token issuance.")
elif r['oqs_available'] and not r['flag_set']:
    print("  STATE: oqs available but flag not set.")
    print("         Set POLARIS_USE_REAL_PQC=1 to enable for new issuance.")
elif not r['oqs_available']:
    print("  STATE: oqs not importable. The current token_value is a")
    print("         deterministic string (NOT post-quantum signed).")
    print("         To enable real signing:")
    print("           1. Install liboqs (apt-get install liboqs-dev OR build")
    print("              from https://github.com/open-quantum-safe/liboqs)")
    print("           2. pip install oqs")
    print("           3. Set POLARIS_USE_REAL_PQC=1 in env")
    print("           4. Re-run this script to verify")

if smoke:
    print()
    if not r['oqs_available']:
        print("  smoke test: SKIPPED (oqs not available)")
        sys.exit(2)
    print(f"  smoke test: ", end='', flush=True)
    ok = p.smoke_test()
    if ok:
        print("PASS (sign + verify roundtrip OK)")
        sys.exit(0)
    else:
        print("FAIL (smoke test returned False)")
        sys.exit(1)

# Exit code based on availability (without smoke)
if r['oqs_available']:
    sys.exit(0)
else:
    sys.exit(2)
PY
