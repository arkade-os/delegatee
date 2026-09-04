#!/usr/bin/env bash
# Initialise, unlock and fund the arkd regtest wallet through the admin API,
# the same sequence arkd's own e2e uses. Idempotent.
set -euo pipefail

ADMIN=${ARKD_ADMIN_URL:-http://localhost:7071}
ARK=${ARKD_URL:-http://localhost:7070}
PASSWORD=${ARKD_WALLET_PASSWORD:-password}
TARGET_BTC=${ARKD_WALLET_BTC:-15}

wait_for() { # url jq-filter expected
  for _ in $(seq 1 120); do
    if curl -sf -m 3 "$1" 2>/dev/null | grep -q "$2"; then return 0; fi
    sleep 2
  done
  echo "timeout waiting for $1 ($2)" >&2
  return 1
}

echo "waiting for arkd admin api..."
wait_for "$ADMIN/v1/admin/wallet/status" '"synced":true'

status=$(curl -sf "$ADMIN/v1/admin/wallet/status")
if ! echo "$status" | grep -q '"initialized":true'; then
  echo "creating wallet..."
  seed=$(curl -sf "$ADMIN/v1/admin/wallet/seed" | sed 's/.*"seed":"\([^"]*\)".*/\1/')
  curl -sf -X POST "$ADMIN/v1/admin/wallet/create" \
    -H 'Content-Type: application/json' -d "{\"seed\":\"$seed\",\"password\":\"$PASSWORD\"}" >/dev/null
fi
if ! echo "$status" | grep -q '"unlocked":true'; then
  echo "unlocking wallet..."
  curl -sf -X POST "$ADMIN/v1/admin/wallet/unlock" \
    -H 'Content-Type: application/json' -d "{\"password\":\"$PASSWORD\"}" >/dev/null
fi
wait_for "$ADMIN/v1/admin/wallet/status" '"unlocked":true'
wait_for "$ARK/v1/info" '"signerPubkey"'

available=$(curl -sf "$ADMIN/v1/admin/wallet/balance" | sed 's/.*"mainAccount":{[^}]*"available":"\{0,1\}\([0-9.]*\).*/\1/')
missing=$(python3 -c "import math; print(max(0, math.ceil($TARGET_BTC - float('${available:-0}'))))")
if [ "$missing" -gt 0 ]; then
  address=$(curl -sf "$ADMIN/v1/admin/wallet/address" | sed 's/.*"address":"\([^"]*\)".*/\1/')
  echo "funding $address with $missing BTC..."
  for _ in $(seq 1 "$missing"); do nigiri faucet "$address" >/dev/null; done
fi
echo "arkd ready"

# the emulator backs off while arkd initialises and may have given up
EMULATOR=${EMULATOR_URL:-http://localhost:7073}
if ! curl -sf -m 3 "$EMULATOR/v1/info" >/dev/null 2>&1; then
  echo "restarting emulator..."
  docker restart emulator >/dev/null
  wait_for "$EMULATOR/v1/info" '"signerPubkey"'
fi
echo "emulator ready"
