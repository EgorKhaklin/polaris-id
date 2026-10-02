#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# polaris-gen-api-clients.sh -- generate API clients and a self-contained interactive explorer from the
# single OpenAPI contract (docs/reference/openapi.yaml). "One spec, a typed harness in every
# language." Nothing here is committed: these are build artifacts an integrator regenerates.
#
#   scripts/polaris-gen-api-clients.sh [SPEC] [OUTDIR]
#
# Requires: node + npx (TypeScript client, the explorer); python + pip (Python client);
# java + openapi-generator-cli (optional: Go, Java, C#, Rust, and 50+ more).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="${1:-$HERE/docs/reference/openapi.yaml}"
OUT="${2:-$HERE/build/api-clients}"
mkdir -p "$OUT"
echo ">> spec:   $SPEC"
echo ">> outdir: $OUT"

# A self-contained, offline interactive explorer (no network needed to view the result).
if command -v npx >/dev/null 2>&1; then
  npx -y @redocly/cli@latest build-docs "$SPEC" -o "$OUT/api-explorer.html"
  # TypeScript types (pair with openapi-fetch for a client).
  npx -y openapi-typescript@latest "$SPEC" -o "$OUT/polaris-api.d.ts"
else
  echo ">> (node/npx absent: TypeScript client and the explorer skipped)"
fi

# Python client package.
if command -v openapi-python-client >/dev/null 2>&1; then
  ( cd "$OUT" && openapi-python-client generate --path "$SPEC" --overwrite --meta none )
elif command -v pip >/dev/null 2>&1; then
  echo ">> (pip install openapi-python-client to generate the Python client)"
fi

# Everything else via openapi-generator (needs Java).
if command -v openapi-generator-cli >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
  for g in go java csharp rust; do
    openapi-generator-cli generate -i "$SPEC" -g "$g" -o "$OUT/$g" || true
  done
else
  echo ">> (java + @openapitools/openapi-generator-cli absent: Go/Java/C#/Rust skipped)"
fi

echo ">> done -> $OUT"
