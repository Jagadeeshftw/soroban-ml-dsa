#!/usr/bin/env bash
#
# Single-command reviewer demo.
#
#   ./demo.sh
#
# From a clean clone, with no configuration and no funded account, this:
#   1. checks the toolchain
#   2. runs the conformance suites (ACVP, Wycheproof, differential vs fips204)
#   3. creates and funds a throwaway testnet account
#   4. builds and deploys both contracts
#   5. authorises a real testnet transaction with an ML-DSA-65 signature
#   6. reproduces the published cost tables on-network
#
# Everything it prints can be checked independently on a block explorer.
# Testnet only. Costs nothing.

set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RESET"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
die()  { printf '    %s✗ %s%s\n' "$RED" "$1" "$RESET"; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
ID="pq-demo-$$"

# ---------------------------------------------------------------- toolchain
step "1/6  Toolchain"
command -v cargo   >/dev/null || die "cargo not found -- install Rust 1.85+"
command -v stellar >/dev/null || die "stellar CLI not found -- cargo install stellar-cli"
command -v curl    >/dev/null || die "curl not found"
rustup target list --installed 2>/dev/null | grep -qx wasm32v1-none \
  || die "missing target -- run: rustup target add wasm32v1-none"
ok "$(rustc --version)"
ok "$(stellar --version | head -1)"
ok "wasm32v1-none installed"

# ------------------------------------------------------------ conformance
step "2/6  Conformance suites  ${DIM}(no network required)${RESET}"
echo "    pq-core: ACVP + Wycheproof + differential vs fips204 ..."
( cd crates/pq-core && cargo test --all-features --quiet 2>&1 | grep -E "^test result" | sed 's/^/    /' )
echo "    pq-stellar: payload golden vector + safety boundary ..."
( cd crates/pq-stellar && cargo test --quiet 2>&1 | grep -E "^test result" | sed 's/^/    /' )
ok "all suites passed"

# ------------------------------------------------------------------ account
step "3/6  Throwaway testnet account"
stellar keys generate "$ID" --network testnet --overwrite >/dev/null 2>&1
SRC="$(stellar keys address "$ID")"
curl -s -m 60 "https://friendbot.stellar.org/?addr=$SRC" -o /dev/null
sleep 3
ok "funded $SRC"
trap 'stellar keys rm "$ID" >/dev/null 2>&1 || true' EXIT

# ------------------------------------------------------------------- build
step "4/6  Build and deploy contracts"
( cd contracts/pq-verifier && cargo build --release --target wasm32v1-none --quiet )
( cd contracts/pq-account  && cargo build --release --target wasm32v1-none --quiet )
ok "pq-verifier $(stat -f%z contracts/pq-verifier/target/wasm32v1-none/release/pq_verifier.wasm 2>/dev/null \
     || stat -c%s contracts/pq-verifier/target/wasm32v1-none/release/pq_verifier.wasm) bytes"
ok "pq-account  $(stat -f%z contracts/pq-account/target/wasm32v1-none/release/pq_account.wasm 2>/dev/null \
     || stat -c%s contracts/pq-account/target/wasm32v1-none/release/pq_account.wasm) bytes"

VERIFIER=$(stellar contract deploy --wasm contracts/pq-verifier/target/wasm32v1-none/release/pq_verifier.wasm \
             --source "$ID" --network testnet 2>/dev/null | tail -1)
ACCOUNT=$(stellar contract deploy --wasm contracts/pq-account/target/wasm32v1-none/release/pq_account.wasm \
             --source "$ID" --network testnet 2>/dev/null | tail -1)
ok "verifier $VERIFIER"
ok "account  $ACCOUNT"

# ------------------------------------------------------- authorise for real
step "5/6  Authorise a transaction with an ML-DSA-65 signature"
export PQ_SECRET="$(stellar keys show "$ID")"
( cd crates/pq-cli && cargo run --release --quiet --bin authorize -- "$SRC" "$ACCOUNT" init 2>/dev/null \
    | grep -E "storing|SUCCESS|^tx " | sed 's/^/    /' )
AUTH_OUT=$( cd crates/pq-cli && cargo run --release --quiet --bin authorize -- "$SRC" "$ACCOUNT" auth 2>/dev/null )
echo "$AUTH_OUT" | grep -E "signature payload|auth entry|simulated|SUCCESS|^tx |^explorer" | sed 's/^/    /'
TXHASH=$(echo "$AUTH_OUT" | awk '/^tx /{print $2}')

# ---------------------------------------------------------------- benchmark
step "6/6  Reproduce the cost tables on-network"
( cd crates/pq-cli && cargo run --release --quiet --bin bench -- "$SRC" "$VERIFIER" 2>/dev/null )

# ------------------------------------------------------------------ summary
cat <<EOF

$BOLD================================================================$RESET
$BOLD  What just happened$RESET
$BOLD================================================================$RESET

  A Soroban contract account with no Ed25519 signer authorised a real
  testnet transaction using only an ML-DSA-65 (FIPS 204) signature,
  verified on-chain in __check_auth.

  Verify independently:
    https://stellar.expert/explorer/testnet/tx/$TXHASH

  account   $ACCOUNT
  verifier  $VERIFIER

  Scope: the transaction *envelope* is still Ed25519-signed -- protocol 27
  offers no alternative. What is post-quantum is the account's
  authorization (QPP Stage 1).

  Caveat: ml-dsa 0.1.1 is unaudited, as is fips204. No audited pure-Rust
  ML-DSA implementation exists. The conformance and differential testing in
  step 2 is mitigation, not assurance. Testnet only.

  Full figures and method: BENCHMARK.md
$BOLD================================================================$RESET
EOF
