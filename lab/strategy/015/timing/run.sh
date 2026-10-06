#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# run.sh: record 015, lab step 4. Builds falcon_dudect.c against a liboqs install and runs the
# four tests. Usage: OQS=/path/to/liboqs/prefix bash run.sh [scale]   (scale 1 = the published run)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
oqs="${OQS:?set OQS to the liboqs install prefix}"
scale="${1:-1}"
out="$(mktemp -d)/falcon_dudect"
cc -O2 -Wall -I"$oqs/include" "$here/falcon_dudect.c" -L"$oqs/lib" -Wl,-rpath,"$oqs/lib" -loqs -lm -o "$out"
echo "platform: $(uname -sm); cpu: $( (sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2) | sed 's/^ *//')"
"$out" key $((1000000 * scale))
"$out" keypair $((500000 * scale))
"$out" message $((500000 * scale))
PLANT_NS=100 "$out" control $((1000000 * scale))
