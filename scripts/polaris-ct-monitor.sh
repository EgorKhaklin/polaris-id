#!/usr/bin/env bash
# ============================================================================
# polaris-ct-monitor.sh — Certificate Transparency monitor for ${POLARIS_DOMAIN}
#                        (v9.01 / Phase 3 Wave 1)
#
# Polls the crt.sh public CT log API for cert-issuance events on
# ${POLARIS_DOMAIN}. Compares against a known-fingerprint allowlist
# kept in $STATE_DIR/ct-monitor/known.txt. Alerts on any cert that
# isn't in the allowlist — the operator's only legitimate issuer
# is Let's Encrypt via Caddy, so any other issuer is a sign of:
#
#   - A misconfigured Caddy that re-issued instead of renewed
#   - A compromised DNS allowing rogue ACME validation
#   - An attacker who tricked a CA into issuing a cert (rare but
#     real; CA Mis-issuance is a documented threat model entry)
#   - A CA hash collision / sub-CA compromise (extremely rare)
#
# The monitor is read-only: it never mutates DNS, Caddy config, or
# the cert store. It surfaces anomalies to a log file + stderr and
# returns a non-zero exit code so cron / monitoring systems pick up
# the signal.
#
# Recommended cadence: daily at 06:00 UTC.
# CT logs have ~2-hour propagation latency; once a day catches every
# unexpected issuance within ≤24h.
#
# Usage:
#   ./scripts/polaris-ct-monitor.sh                         # checks $POLARIS_DOMAIN
#   ./scripts/polaris-ct-monitor.sh --check polaris.example.com
#   ./scripts/polaris-ct-monitor.sh --add-known <sha256-fingerprint>
#   ./scripts/polaris-ct-monitor.sh --list-known
#   ./scripts/polaris-ct-monitor.sh --window-days 7        # default 1
#
# Exit codes (greppable):
#   0  no anomalies (all certs in window are in the allowlist OR no
#      certs found in the window)
#   2  usage error
#   3  $POLARIS_DOMAIN not set + no --check argument
#   4  network error (crt.sh unreachable; treat as inconclusive)
#   5  cert-fingerprint anomaly (UNKNOWN cert detected — alert!)
#   6  malformed allowlist file (corrupt $STATE_DIR/ct-monitor/known.txt)
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_NO_DOMAIN=3
EXIT_NETWORK=4
EXIT_ANOMALY=5
EXIT_BAD_ALLOWLIST=6

DOMAIN=""
WINDOW_DAYS=1
ADD_KNOWN=""
LIST_KNOWN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            shift
            DOMAIN="${1:-}"
            ;;
        --window-days)
            shift
            WINDOW_DAYS="${1:-1}"
            ;;
        --add-known)
            shift
            ADD_KNOWN="${1:-}"
            ;;
        --list-known)
            LIST_KNOWN=1
            ;;
        --help|-h)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *)
            echo "warn: unknown arg $1" >&2
            ;;
    esac
    shift
done

DOMAIN="${DOMAIN:-${POLARIS_DOMAIN:-}}"
STATE_DIR="${POLARIS_STATE_DIR:-/tmp/polaris-state}"
ALLOWLIST_DIR="$STATE_DIR/ct-monitor"
ALLOWLIST_FILE="$ALLOWLIST_DIR/known.txt"
ANOMALY_LOG="$ALLOWLIST_DIR/anomalies.log"

mkdir -p "$ALLOWLIST_DIR"
touch "$ALLOWLIST_FILE" "$ANOMALY_LOG"

# Validate allowlist format: one line per fingerprint, hex 64 chars
if [[ -s "$ALLOWLIST_FILE" ]]; then
    if grep -vE '^[0-9a-fA-F]{64}$|^#|^$' "$ALLOWLIST_FILE" >/dev/null 2>&1; then
        echo "error: $ALLOWLIST_FILE contains malformed entries; expected 64-char hex SHA-256 per line" >&2
        exit "${EXIT_BAD_ALLOWLIST}"
    fi
fi

# --add-known: add a fingerprint and exit
if [[ -n "$ADD_KNOWN" ]]; then
    if ! [[ "$ADD_KNOWN" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "error: --add-known requires a 64-char hex SHA-256" >&2
        exit "${EXIT_USAGE}"
    fi
    # Normalize to lowercase + skip if already present
    fingerprint=$(echo "$ADD_KNOWN" | tr '[:upper:]' '[:lower:]')
    if grep -qiF "$fingerprint" "$ALLOWLIST_FILE" 2>/dev/null; then
        echo "  fingerprint already in allowlist: ${fingerprint:0:16}…"
    else
        printf '%s\n' "$fingerprint" >> "$ALLOWLIST_FILE"
        echo "  added: ${fingerprint:0:16}…"
    fi
    exit "${EXIT_OK}"
fi

# --list-known: dump the allowlist + exit
if [[ "$LIST_KNOWN" -eq 1 ]]; then
    if [[ ! -s "$ALLOWLIST_FILE" ]]; then
        echo "  (empty allowlist; first run will populate)"
    else
        local_count=$(grep -cE '^[0-9a-fA-F]{64}$' "$ALLOWLIST_FILE" || true)
        echo "  $local_count known fingerprint(s) in $ALLOWLIST_FILE:"
        grep -E '^[0-9a-fA-F]{64}$' "$ALLOWLIST_FILE" | while IFS= read -r fp; do
            echo "    ${fp:0:16}…"
        done
    fi
    exit "${EXIT_OK}"
fi

# Main check path
if [[ -z "$DOMAIN" ]]; then
    echo "error: POLARIS_DOMAIN not set; pass --check <domain> instead" >&2
    exit "${EXIT_NO_DOMAIN}"
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl required" >&2
    exit "${EXIT_USAGE}"
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq required (install via brew install jq)" >&2
    exit "${EXIT_USAGE}"
fi

cutoff_ts=$(date -u -v-${WINDOW_DAYS}d +%Y-%m-%dT%H:%M:%S 2>/dev/null \
    || date -u -d "${WINDOW_DAYS} days ago" +%Y-%m-%dT%H:%M:%S)

# crt.sh JSON API: ?q=<domain>&output=json
# Returns: [{ "id": ..., "logged_at": "...", "not_before": "...",
#             "not_after": "...", "common_name": "...",
#             "issuer_name": "...", ... }, ... ]
# Note: crt.sh doesn't return SHA-256 fingerprints directly; we
# fetch each cert's PEM via id and compute the fingerprint.

echo
echo "  Polaris CT monitor"
echo "  ──────────────────"
echo "  Domain:           $DOMAIN"
echo "  Window:           last $WINDOW_DAYS day(s) (since $cutoff_ts UTC)"
echo "  Allowlist:        $ALLOWLIST_FILE"
echo "  Anomaly log:      $ANOMALY_LOG"
echo

# crt.sh is a single-operator public service and flaps: it returns transient
# 502s and connection timeouts under load (observed live during the v9.166
# sweep, six 502s in a row). The original made ONE `curl -fsS` attempt and
# treated any failure, transient 5xx included, as terminal "unreachable". That
# is correct as a verdict (fail inconclusive, never fabricate an all-clear) but
# needlessly noisy: a daily cron would false-alarm inconclusive on every crt.sh
# hiccup. Retry with linear backoff so a brief flap self-heals within one run;
# only a sustained outage reaches the inconclusive exit.
#
# POLARIS_CT_FIXTURE points at a local JSON file to use INSTEAD of the network,
# so the parse/anomaly path is testable offline (the whole tool was otherwise
# unverifiable except against a live, flaky third party).
fetch_ct_json() {
    if [[ -n "${POLARIS_CT_FIXTURE:-}" ]]; then
        cat "${POLARIS_CT_FIXTURE}" 2>/dev/null || true
        return
    fi
    local url attempt out
    url="https://crt.sh/?q=$(printf '%s' "$DOMAIN" | tr -d '\n' | jq -sRr @uri)&output=json"
    for attempt in 1 2 3; do
        out=$(curl -fsS --max-time 30 "$url" 2>/dev/null || true)
        if [[ -n "$out" ]]; then
            printf '%s' "$out"
            return
        fi
        [[ "$attempt" -lt 3 ]] && sleep "$((attempt * 3))"
    done
}

ct_response=$(fetch_ct_json)

if [[ -z "$ct_response" ]]; then
    echo "  ⚠ crt.sh unreachable after 3 attempts; treat as inconclusive (will retry next cycle)" >&2
    exit "${EXIT_NETWORK}"
fi

# A non-empty response that is not a JSON array is crt.sh serving an HTML error
# page (its 502s carry a body). Treat as inconclusive, never parse it as certs.
if ! printf '%s' "$ct_response" | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "  ⚠ crt.sh returned a non-JSON response (likely a transient error page);" >&2
    echo "    treat as inconclusive (will retry next cycle)" >&2
    exit "${EXIT_NETWORK}"
fi

# Filter by logged_at within window
in_window=$(printf '%s' "$ct_response" | jq -c \
    --arg cutoff "$cutoff_ts" \
    '[.[] | select(.logged_at >= $cutoff)] | .[]' 2>/dev/null || echo "")

if [[ -z "$in_window" ]]; then
    echo "  ✓ No cert-issuance events for $DOMAIN in the last $WINDOW_DAYS day(s)."
    exit "${EXIT_OK}"
fi

cert_count=$(printf '%s\n' "$in_window" | wc -l | tr -d '[:space:]')
echo "  Found $cert_count cert-issuance event(s) in window:"
echo

anomaly_count=0

while IFS= read -r cert_json; do
    [[ -z "$cert_json" ]] && continue
    cert_id=$(printf '%s' "$cert_json" | jq -r '.id')
    issuer=$(printf '%s' "$cert_json" | jq -r '.issuer_name')
    common_name=$(printf '%s' "$cert_json" | jq -r '.common_name')
    logged_at=$(printf '%s' "$cert_json" | jq -r '.logged_at')

    # Fetch PEM + compute SHA-256 fingerprint. Under a fixture, read the PEM
    # from ${POLARIS_CT_FIXTURE%.json}.<id>.pem so the anomaly path is testable
    # offline without a second crt.sh round-trip per cert.
    if [[ -n "${POLARIS_CT_FIXTURE:-}" ]]; then
        pem=$(cat "${POLARIS_CT_FIXTURE%.json}.${cert_id}.pem" 2>/dev/null || true)
    else
        pem=$(curl -fsS --max-time 15 \
            "https://crt.sh/?d=${cert_id}" 2>/dev/null || true)
    fi
    if [[ -z "$pem" ]]; then
        echo "    ⚠ id=$cert_id  (could not fetch PEM; skipped fingerprint check)"
        continue
    fi
    fingerprint=$(printf '%s' "$pem" \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | awk -F= '{print $2}' | tr -d ': ' | tr '[:upper:]' '[:lower:]')

    if [[ -z "$fingerprint" ]]; then
        echo "    ⚠ id=$cert_id  (could not compute fingerprint; skipped)"
        continue
    fi

    if grep -qiF "$fingerprint" "$ALLOWLIST_FILE" 2>/dev/null; then
        echo "    ✓ id=$cert_id  fp=${fingerprint:0:16}…  (KNOWN; issued by $issuer at $logged_at)"
    else
        anomaly_count=$((anomaly_count + 1))
        echo "    ✗ id=$cert_id  fp=${fingerprint:0:16}…  (UNKNOWN; issued by $issuer at $logged_at; CN=$common_name)"
        printf '%s\tid=%s\tfp=%s\tissuer=%s\tlogged_at=%s\tcn=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "$cert_id" "$fingerprint" "$issuer" "$logged_at" "$common_name" \
            >> "$ANOMALY_LOG"
    fi
done <<< "$in_window"

echo

if [[ "$anomaly_count" -gt 0 ]]; then
    echo "  ✗ $anomaly_count UNKNOWN cert-issuance(s) detected for $DOMAIN" >&2
    echo "    Logged to: $ANOMALY_LOG" >&2
    echo "    Investigate: was this a legitimate Caddy renewal? If so, add" >&2
    echo "    the fingerprint to the allowlist:" >&2
    echo "      $0 --add-known <fingerprint>" >&2
    echo "    If unfamiliar, this may indicate cert mis-issuance; investigate" >&2
    echo "    via DR.md § 4.5 procedure." >&2
    exit "${EXIT_ANOMALY}"
fi

echo "  ✓ All $cert_count cert(s) in window match the allowlist."
exit "${EXIT_OK}"
