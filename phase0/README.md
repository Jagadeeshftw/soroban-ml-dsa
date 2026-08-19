# Phase 0 probe code

Throwaway investigation code from the initial feasibility work.
This is **not** the SDK — it exists only to produce the measurements in the report.
The real `pq-core` / `pq-stellar` layout described in the MVP plan starts at Milestone 1.

## Layout

| Path | What it is |
|---|---|
| `contract/` | `pq-probe` Soroban contract: in-contract ML-DSA-44/65 verification, key-decode-only, Ed25519 host-fn baseline, and a no-op for VM overhead |
| `account/` | `pq-account` Soroban custom account implementing `__check_auth` with ML-DSA-65 |
| `harness/` | Native runner: local metering-VM benchmarks, the end-to-end custom-account auth test, deterministic vector dumper, and the on-network `simulateTransaction` tool |

## Reproduce

Requires Rust 1.85+ and the `wasm32v1-none` target
(`rustup target add wasm32v1-none`). **Not** `wasm32-unknown-unknown` — see the report.

```sh
# build both contracts
(cd contract && cargo build --release --target wasm32v1-none)
(cd account  && cargo build --release --target wasm32v1-none)

# cost table: ML-DSA-44 / ML-DSA-65 / Ed25519
(cd harness && cargo run --release --bin pq-harness)

# end-to-end: custom account authorised by an ML-DSA-65 signature
(cd harness && cargo run --release --bin account)

# deterministic test vectors as hex (for CLI / RPC use)
(cd harness && cargo run --release --bin vectors -- /tmp/vectors)

# ON-NETWORK measurement against deployed testnet contracts.
# This is the authoritative source for any published figure -- the local
# metering VM under-reports this workload by 4.3% plus a fixed ~2.2M overhead.
(cd harness && cargo run --release --bin simulate -- <SOURCE_G...> <PROBE_C...> <ACCOUNT_C...>)

# SUBMIT a real testnet transaction authorised only by an ML-DSA-65 signature
PQ_SECRET=<S...> (cd harness && cargo run --release --bin submit -- <SOURCE_G...> <ACCOUNT_C...>)
```

`simulate` reports both per-transaction and ledger-level throughput figures.
The ledger-level numbers follow CAP-0063 cluster semantics and are the ones that
matter for the CAP-0087 discussion — see [`../BENCHMARK.md`](../BENCHMARK.md).

Deployed testnet contracts used for these probe measurements:

| Contract | Address |
|---|---|
| `pq-probe` (`opt-level = 3`) | `CDJXS5LYJOFH46NUBXZXMIU2MCSKCFJRVHIH6KX5TMJTJN4FU5NNVE3R` |
| `pq-probe` (`opt-level = "z"`) | `CDZZEURTDIZUNKRW3YL7ZA4XAH27YR5API5HEHX5QBIYE5XG5QRWXUWC` |
| `pq-account` | `CDTEFSSESKZ7G6WFILKGND4NCN3BWGRSPLLU2JTK6ZUHR77QLTGSK73R` |

Both keys are derived from a fixed seed (`[42u8; 32]`), so every number is
deterministic and reproducible.

## Note on `opt-level`

`contract/Cargo.toml` and `account/Cargo.toml` set `opt-level = 3`.
This is load-bearing: `opt-level = "z"` (the common Soroban default) costs
**2.69x more CPU** on-network for the same verification, and 2.01x the fee.
See [`../BENCHMARK.md`](../BENCHMARK.md) and the standalone write-up
[`../writeups/opt-level-and-lattice-crypto-on-soroban.md`](../writeups/opt-level-and-lattice-crypto-on-soroban.md).
