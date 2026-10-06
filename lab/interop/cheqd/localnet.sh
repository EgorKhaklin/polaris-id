#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# A one-validator cheqd localnet, in cheqd-node's own image pinned by digest.
#
# The configuration is cheqd-node's localnet recipe (docker/localnet/gen-network-config.sh and
# container-env/validator-0.env at the image's revision, the v4.2.1 tag) for one validator instead
# of four validators, a seed and an observer: the same chain id, node and genesis settings, the
# first validator's published mnemonic, the published test account base_account_1 (the only one of
# the recipe's test accounts funded here), and the image's own entrypoint (node-start), which
# starts cheqd's mock price feed beside the node. The recipe points the price feeder's mexc
# provider at that mock; this points its coinbase provider there too, so the chain needs no outside
# service. Left out: the recipe's debug log level and its IBC fee bypasses (no IBC here).
#
#   localnet.sh up      # a fresh chain; waits for the first block
#   localnet.sh down    # stops it and removes its volume
#
# RPC on 127.0.0.1:$CHEQD_RPC_PORT (26657), REST on 127.0.0.1:$CHEQD_REST_PORT (1317).
set -euo pipefail

IMAGE="${CHEQD_IMAGE:-ghcr.io/cheqd/cheqd-node:4.2.1@sha256:57cd432725f53ad832124dac57c5754d458de5359d78540cc83f879116127d5c}"
NAME="${CHEQD_CONTAINER:-polaris-cheqd-localnet}"
RPC_PORT="${CHEQD_RPC_PORT:-26657}"
REST_PORT="${CHEQD_REST_PORT:-1317}"

down() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm -f "$NAME-home" >/dev/null 2>&1 || true
}

case "${1:-}" in
  down) down; exit 0 ;;
  up) ;;
  *) echo "usage: localnet.sh up|down" >&2; exit 2 ;;
esac

down
for p in "$RPC_PORT" "$REST_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set CHEQD_RPC_PORT / CHEQD_REST_PORT" >&2
    exit 2
  fi
done
# The node's home is a named volume mounted at /home/cheqd, as in cheqd's compose file, so the
# image's user owns it on any host.
docker volume create "$NAME-home" >/dev/null

# gen-network-config.sh's init_node, configure_node and configure_genesis, for validator-0 only.
INIT_LOG="$(mktemp)"
docker run -i --rm -v "$NAME-home":/home/cheqd --entrypoint bash "$IMAGE" -s >"$INIT_LOG" 2>&1 <<'EOF' \
  || { cat "$INIT_LOG" >&2; echo "the localnet's genesis could not be made (above)" >&2; exit 2; }
set -euo pipefail
H=/home/cheqd/.cheqdnode
CHAIN_ID=cheqd
cheqd-noded init validator-0 --chain-id "$CHAIN_ID" --home "$H" 2>/dev/null
APP_TOML="$H/config/app.toml"; CONFIG_TOML="$H/config/config.toml"; GENESIS="$H/config/genesis.json"
sed -i 's/minimum-gas-prices = ""/minimum-gas-prices = "50ncheq"/g' "$APP_TOML"
sed -i 's/enable = false/enable = true/g' "$APP_TOML"
sed -i 's|laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|g' "$CONFIG_TOML"
sed -i 's|addr_book_strict = true|addr_book_strict = false|g' "$CONFIG_TOML"
sed -i 's/timeout_propose = "3s"/timeout_propose = "500ms"/g' "$CONFIG_TOML"
sed -i 's/timeout_prevote = "1s"/timeout_prevote = "500ms"/g' "$CONFIG_TOML"
sed -i 's/timeout_precommit = "1s"/timeout_precommit = "500ms"/g' "$CONFIG_TOML"
sed -i 's/timeout_commit = "5s"/timeout_commit = "500ms"/g' "$CONFIG_TOML"
sed -i 's/"stake"/"ncheq"/' "$GENESIS"
sed -i 's/"voting_period": "172800s"/"voting_period": "12s"/' "$GENESIS"
sed -i 's/"expedited_voting_period": "86400s"/"expedited_voting_period": "10s"/' "$GENESIS"
sed -i 's/"vote_extensions_enable_height"[[:space:]]*:[[:space:]]*"0"/"vote_extensions_enable_height": "2"/' "$GENESIS"
# base_account_1, published with its mnemonic in cheqd-node's localnet scripts: the walk's fee payer.
cheqd-noded genesis add-genesis-account cheqd1rnr5jrt4exl0samwj0yegv99jeskl0hsxmcz96 100001000000000000ncheq --home "$H"
echo "mix around destroy web fever address comfort vendor tank sudden abstract cabin acoustic attitude peasant hospital vendor harsh void current shield couple barrel suspect" \
  | cheqd-noded keys add operator-0 --keyring-backend test --home "$H" --recover
cheqd-noded genesis add-genesis-account operator-0 20000000000000000ncheq --keyring-backend test --home "$H"
cheqd-noded genesis gentx operator-0 1000000000000000ncheq --chain-id "$CHAIN_ID" \
  --node-id "$(cheqd-noded tendermint show-node-id --home "$H")" \
  --pubkey "$(cheqd-noded tendermint show-validator --home "$H")" --keyring-backend test --home "$H"
cheqd-noded genesis collect-gentxs --home "$H"
cheqd-noded genesis validate-genesis --home "$H"
# The price feeder's configuration: cheqd's pricefeeder/price-feeder.toml with its providers
# pointed at the mock feed in the image (gen-network-config.sh repoints mexc; coinbase too here).
cat > "$H/price-feeder.toml" <<'TOML'
gas_adjustment = 1
provider_timeout = "1000000s"

[server]
listen_addr = "0.0.0.0:7171"
read_timeout = "20s"
verbose_cors = true
write_timeout = "20s"

[rpc]
grpc_endpoint = "localhost:9090"
rpc_timeout = "100ms"
tmrpc_endpoint = "http://localhost:26657"

[telemetry]
enable-hostname = true
enable-hostname-label = true
enable-service-label = true
enabled = true
global-labels = [["chain_id", "cheqd"]]
service-name = "price-feeder"
prometheus-retention-time = 100

[[provider_endpoints]]
name = "mexc"
rest = "http://localhost:8080"
websocket = "localhost:8080"

[[provider_endpoints]]
name = "coinbase"
rest = "http://localhost:8080"
websocket = "localhost:8080"
TOML
EOF

# container-env/validator-0.env, and the image's own entrypoint.
docker run -d --name "$NAME" -v "$NAME-home":/home/cheqd \
  -p "127.0.0.1:$RPC_PORT:26657" -p "127.0.0.1:$REST_PORT:1317" \
  -e CHEQD_NODED_API_ENABLE=true -e CHEQD_NODED_MINIMUM_GAS_PRICES=25ncheq \
  -e CHEQD_NODED_MONIKER=validator-0 -e CHEQD_NODED_RPC_LADDR=tcp://0.0.0.0:26657 \
  -e CHEQD_NODED_CONSENSUS_TIMEOUT_COMMIT=500ms -e CHEQD_NODED_CONSENSUS_TIMEOUT_PRECOMMIT=500ms \
  -e CHEQD_NODED_CONSENSUS_TIMEOUT_PREVOTE=500ms -e CHEQD_NODED_CONSENSUS_TIMEOUT_PROPOSE=500ms \
  -e CHEQD_NODED_CREATE_EMPTY_BLOCKS=false \
  --entrypoint node-start "$IMAGE" >/dev/null

for _ in $(seq 1 120); do
  h=$(curl -fsS "http://127.0.0.1:$RPC_PORT/status" 2>/dev/null \
      | sed -n 's/.*"latest_block_height": *"\([0-9]*\)".*/\1/p' || true)
  if [ -n "$h" ] && [ "$h" -ge 1 ] && curl -fsS "http://127.0.0.1:$REST_PORT/cosmos/base/tendermint/v1beta1/node_info" >/dev/null 2>&1; then
    version=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}')
    echo "localnet   cheqd-node $version ($(docker image inspect "$IMAGE" --format '{{.Os}}/{{.Architecture}}')), one validator, chain id cheqd, block $h"
    exit 0
  fi
  sleep 1
done
echo "the localnet did not produce a block in 120 s; docker logs $NAME" >&2
exit 2
