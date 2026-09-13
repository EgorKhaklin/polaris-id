#!/usr/bin/env bash
# ============================================================================
# polaris-generate-recovery-code.sh — printed-mnemonic recovery code for
#                                     solo-admin deployments (v8.97 /
#                                     Position B § IV.3 architect-rec).
#
# Use case: a single-admin deployment cannot use the second-admin pairing
# protocol (polaris-recover-admin.sh) because there is no second admin.
# This script generates a SECRET recovery code that, when held by the
# operator (printed and stored in a safe), can be used to authorize an
# emergency password-login window — the script is itself the "second
# admin" in the protocol.
#
# Mechanism: emits a 16-word BIP-39-style mnemonic AND a SHA-256 digest.
# The mnemonic is meant to be PRINTED and STORED OFFLINE (in a safe,
# not on the same disk as the database). The digest is stored in the
# database AppUser.recovery_code_hash (NULL until the operator commits to
# the code) so the application can verify it without holding the cleartext.
#
# When the operator is locked out, they SSH to the host and run:
#   ./scripts/polaris-recover-admin.sh --target <self> --recovery-code -
# and type the 16 words from the printed copy on stdin (the mnemonic is never
# accepted in argv). --recovery-code replaces --authorizing-user-id: the two
# are mutually exclusive, and an admin cannot authorize their own recovery.
#
# v9.02 closes the v8.97 §V deferred item: --bind-to <username>
# persists the SHA-256 hash into AppUser.recovery_code_hash so that
# polaris-recover-admin.sh --recovery-code <mnemonic> can verify
# the operator's printed copy without requiring a second admin.
#
# Usage:
#   ./scripts/polaris-generate-recovery-code.sh > recovery-code.txt
#       # Print the code; operator stores recovery-code.txt offline,
#       # then deletes from disk. Hash NOT bound to any user.
#
#   ./scripts/polaris-generate-recovery-code.sh --bind-to admin > recovery-code.txt
#       # As above, AND persists SHA-256 into AppUser.recovery_code_hash
#       # so polaris-recover-admin.sh --recovery-code can verify.
#
#   ./scripts/polaris-generate-recovery-code.sh --copy-pasteable
#       # Single-line form, easier to paste into a password manager.
#       # (Hash still bound if --bind-to is also passed.)
#
# Exit codes (greppable):
#   0  success
#   2  usage error
#   3  --bind-to user not found (or not an active admin)
#   4  database call failed (--bind-to path)
#   5  failed to read /dev/urandom (host environment problem)
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_NO_USER=3
EXIT_DB=4
EXIT_RAND=5

COPY_PASTEABLE=0
WORD_COUNT=16
BIND_TO=""             # v9.02: persist hash into AppUser.recovery_code_hash
USE_DOCKER_STACK=0     # v9.02: --target=docker-stack for prod

while [[ $# -gt 0 ]]; do
    case "$1" in
        --copy-pasteable) COPY_PASTEABLE=1 ;;
        --word-count)
            shift
            WORD_COUNT="${1:-16}"
            ;;
        --bind-to)
            shift
            BIND_TO="${1:-}"
            ;;
        --bind-to=*)
            BIND_TO="${1#--bind-to=}"
            ;;
        --target=docker-stack)
            USE_DOCKER_STACK=1
            ;;
        --help|-h)
            sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

if ! [[ "${WORD_COUNT}" =~ ^[0-9]+$ ]] || [[ "${WORD_COUNT}" -lt 12 ]] || [[ "${WORD_COUNT}" -gt 24 ]]; then
    echo "error: --word-count must be 12..24 (default 16)" >&2
    exit "${EXIT_USAGE}"
fi

# v9.02: --bind-to validation — username must match AppUser format
if [[ -n "${BIND_TO}" ]] && ! [[ "${BIND_TO}" =~ ^[a-z0-9._-]{3,50}$ ]]; then
    echo "error: --bind-to <username> must match AppUser username format ([a-z0-9._-]{3,50})" >&2
    exit "${EXIT_USAGE}"
fi

# Minimal BIP-39-style wordlist (a small subset; for a real deployment
# operators may swap in the canonical 2048-word BIP-39 wordlist). The
# entropy comes from /dev/urandom, not from the wordlist size, so a
# smaller list trades only collision-resistance against typos for
# operational simplicity. With 256 words at 16 picks, the entropy is
# log2(256^16) = 128 bits — sufficient for a recovery code that backs
# up the password layer.
WORDLIST=(
    abandon ability able about above absent absorb abstract absurd abuse
    access accident account accuse achieve acid acoustic acquire across
    act action actor actress actual adapt add address adjust admit adult
    advance advice aerobic affair afford afraid again age agent agree
    ahead aim air airport aisle alarm album alcohol alert alien
    all alley allow almost alone alpha already also alter always
    amateur amazing among amount amused analyst anchor ancient anger angle
    angry animal ankle announce annual another answer antenna antique anxiety
    any apart apology appear apple approve april arcade arch arctic
    area arena argue arm armed armor army around arrange arrest
    arrive arrow art artefact artist artwork ask aspect assault asset
    assist assume asthma athlete atom attack attend attitude attract auction
    audit august aunt author auto autumn average avocado avoid awake
    award aware away awesome awful awkward axis baby bachelor bacon
    badge bag balance balcony ball bamboo banana banner bar barely
    bargain barrel base basic basket battle beach bean beauty because
    become beef before begin behave behind believe below belt bench
    benefit best betray better between beyond bicycle bid bike binary
    biology bird birth bitter black blade blame blanket blast bleak
    bless blind blood blossom blouse blue blur blush board boat
    body boil bomb bone bonus book boost border boring borrow
    boss bottom bounce box boy bracket brain brand brass brave
    bread breeze brick bridge brief bright bring brisk broccoli broken
    bronze broom brother brown brush bubble buddy budget buffalo build
    bulb bulk bullet bundle bunker burden burger burst bus business
)

WORDLIST_LEN="${#WORDLIST[@]}"

# Read enough random bytes — 2 bytes per word picked.
need_bytes=$(( WORD_COUNT * 2 ))
if ! random_hex=$(dd if=/dev/urandom bs="${need_bytes}" count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'); then
    echo "error: failed to read /dev/urandom" >&2
    exit "${EXIT_RAND}"
fi
if [[ ${#random_hex} -lt $(( need_bytes * 2 )) ]]; then
    echo "error: insufficient entropy from /dev/urandom" >&2
    exit "${EXIT_RAND}"
fi

words=()
for ((i=0; i<WORD_COUNT; i++)); do
    byte_pair="${random_hex:$((i*4)):4}"
    # Hex → integer → modulo wordlist length
    idx=$(( 16#${byte_pair} % WORDLIST_LEN ))
    words+=("${WORDLIST[idx]}")
done

# Compute SHA-256 of the joined cleartext for verification storage.
joined="${words[*]}"
if command -v sha256sum >/dev/null 2>&1; then
    digest=$(printf '%s' "${joined}" | sha256sum | awk '{print $1}')
else
    digest=$(printf '%s' "${joined}" | shasum -a 256 | awk '{print $1}')
fi

# v9.02: --bind-to <username> persists the SHA-256 hash into
# AppUser.recovery_code_hash. Closes the v8.97 deferred
# in-app verification flow. The cleartext mnemonic is NEVER stored
# server-side; only its hash. The operator keeps the printed copy.
if [[ -n "${BIND_TO}" ]]; then
    run_psql() {
        if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
            local compose_file
            compose_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/polaris_web/docker-compose.prod.yml"
            docker compose -f "${compose_file}" exec -T postgres \
                psql -U postgres -d polaris -tA "$@"
        else
            psql -h "${POLARIS_DB_HOST:-localhost}" \
                 -U "${POLARIS_DB_USER:-postgres}" \
                 -d "${POLARIS_DB_NAME:-polaris}" \
                 -tA "$@"
        fi
    }

    # Verify the user exists + is an active admin (recovery codes are
    # only useful for admin role; operator/auditor roles either don't
    # require WebAuthn or have other recovery paths)
    user_check=$(run_psql -c "
        SELECT user_id FROM AppUser
        WHERE username = '${BIND_TO}'
          AND role = 'admin'
          AND is_active = TRUE
    " 2>/dev/null | tr -d '[:space:]')
    if [[ -z "${user_check}" ]]; then
        echo "error: user '${BIND_TO}' not found, not admin, or inactive" >&2
        echo "       Recovery codes only bind to active admin accounts." >&2
        exit "${EXIT_NO_USER}"
    fi

    # UPDATE in single transaction; the constraint chk_recovery_code_hash_format
    # enforces 64-char lowercase hex
    sql_tmp=$(mktemp)
    cat > "${sql_tmp}" <<SQL
BEGIN;
UPDATE AppUser
   SET recovery_code_hash = '${digest}'
 WHERE username = '${BIND_TO}'
   AND role = 'admin';
COMMIT;
SQL
    if ! run_psql -v ON_ERROR_STOP=1 -f "${sql_tmp}" >/dev/null 2>&1; then
        out=$(run_psql -v ON_ERROR_STOP=1 -f "${sql_tmp}" 2>&1 || true)
        rm -f "${sql_tmp}"
        echo "error: database update failed:" >&2
        echo "${out}" >&2
        exit "${EXIT_DB}"
    fi
    rm -f "${sql_tmp}"

    if [[ "${COPY_PASTEABLE}" -ne 1 ]]; then
        echo "  ✓ recovery code bound to ${BIND_TO} (hash prefix: ${digest:0:16}…)"
        echo "  Operator next steps follow below; print + store + delete from disk."
        echo
    fi
fi

if [[ "${COPY_PASTEABLE}" -eq 1 ]]; then
    printf '%s\n' "${joined}"
    exit "${EXIT_OK}"
fi

cat <<EOF
============================================================================
POLARIS RECOVERY CODE — v8.97
============================================================================

Print this page. Store it in a safe. Delete the file from disk after.
This code will let you authorize an emergency password-login window if
you lose access to your WebAuthn authenticator.

Generated at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Word count:   ${WORD_COUNT}
Entropy:      ~$(( WORD_COUNT * 8 )) bits

Words (separated by single spaces — case-insensitive, retype exactly):

    ${joined}

SHA-256 digest of the words above (for AppUser.recovery_code_hash):

    ${digest}

============================================================================
Operator next steps:

  1. Print this page on real paper. Do NOT email it. Do NOT screenshot it.
  2. Store it in a physical safe distinct from the host hardware.
  3. Delete the file/print buffer/clipboard immediately afterward.

If you lose the printed copy, this code becomes unrecoverable — generate
a new one and replace the AppUser.recovery_code_hash on the host. The
SHA-256 digest is the only thing the server stores; the cleartext words
exist ONLY on your printed copy.
============================================================================
EOF
exit "${EXIT_OK}"
