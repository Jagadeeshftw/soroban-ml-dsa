# Post-Quantum Signature SDK for Stellar

**ML-DSA (FIPS 204) signature verification inside a Soroban smart contract —
measured on Stellar testnet.**

A Soroban custom account authorised a real testnet transaction using only an
ML-DSA-65 signature, verified on-chain in `__check_auth`. This measures what that
costs, at both the per-transaction and the network-capacity limit.

> ### Verifiable artifact
>
> **Transaction [`5f62349d0b8faeb61746fe457f461ad7fe4d03044c976163ac14f5b52215f4b9`](https://stellar.expert/explorer/testnet/tx/5f62349d0b8faeb61746fe457f461ad7fe4d03044c976163ac14f5b52215f4b9)**
> — testnet ledger 4,219,543, `successful: true`.
> Account [`CDDE2DU2VR4W2XSHIE62VYAFJ3VNIBDIV3IMGZ3N4MPISCKPW2EIIA3S`](https://stellar.expert/explorer/testnet/contract/CDDE2DU2VR4W2XSHIE62VYAFJ3VNIBDIV3IMGZ3N4MPISCKPW2EIIA3S)
> carries **no Ed25519 signer**; authorization came solely from an ML-DSA-65
> signature checked in `__check_auth`. Contract and client share one
> verification implementation ([`pq-core`](crates/pq-core)).

> ### ⚠️ Two things to read before citing this
>
> **Scope.** What is post-quantum is the *contract account's authorization*
> (QPP Stage 1). The *transaction envelope* is still Ed25519-signed — protocol 27
> offers no alternative; that is what QPP Stage 2 changes in 2027. The correct
> claim is "a quantum-safe Soroban contract account authorising a testnet
> transaction," **not** "a post-quantum Stellar transaction." CAP-0087 draws the
> same distinction.
>
> **Assurance.** [`ml-dsa`](https://crates.io/crates/ml-dsa) 0.1.1 states it has
> never been independently audited; [`fips204`](https://crates.io/crates/fips204)
> carries the same warning. **No audited pure-Rust ML-DSA implementation exists
> today.** Differential testing plus ACVP/Wycheproof is *mitigation, not
> resolution.* Testnet only, not production-ready.

## Results

All figures from `simulateTransaction` against deployed testnet contracts
(protocol 27), `opt-level = 3`. Not a local test host.

### Ledger throughput — the limit that matters

`ledger_max_instructions` = 580,000,000, bounding the critical path across
parallel clusters under [CAP-0063](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0063.md).

| Operation | % of ledger budget per call | per ledger | per second |
|---|---|---|---|
| **ML-DSA-65 in contract** | **13.4%** | **14** | **2.8** |
| ML-DSA-44 in contract | 8.8% | 22 | 4.4 |
| ECDSA secp256r1 host fn | 1.0% | 204 | 40.8 |
| Ed25519 host fn | 0.5% | 390 | 78.0 |

**One in-contract ML-DSA-65 authorization consumes 13.3% of the entire network's
per-ledger compute — about 28x fewer per ledger than an Ed25519-verifying
contract call.** Viable for low-volume, high-value use; not a consumer-scale
mechanism.

## Reproduce

```sh
./demo.sh
```

No configuration and no funded account needed. Checks the toolchain, runs every
conformance suite, creates and funds a throwaway testnet account, deploys both
contracts, authorises a real transaction with an ML-DSA-65 signature, and
reproduces the cost tables on-network — then prints a transaction hash you can
check on any explorer. Testnet only, costs nothing.

Requires Rust 1.85+, the `stellar` CLI, and `rustup target add wasm32v1-none`
(**not** `wasm32-unknown-unknown` — current `soroban-sdk` rejects it).

<details><summary>Or run the pieces individually</summary>


```sh
# the SDK crates
cd crates/pq-core    && cargo test --all-features   # ACVP, Wycheproof, differential
cd ../pq-stellar     && cargo test                  # payload golden vector, safety boundary

# contracts
cd ../../contracts/pq-verifier && cargo build --release --target wasm32v1-none
cd ../pq-account               && cargo build --release --target wasm32v1-none

# on-network cost tables (Milestone 4)
cd ../../crates/pq-cli && cargo run --release --bin bench -- <SOURCE_G...> <VERIFIER_C...>

# authorise a real transaction through pq-stellar
PQ_SECRET=<S...> cargo run --release --bin authorize -- <SOURCE_G...> <ACCOUNT_C...> auth
```
</details>

<details><summary>Phase 0 probe harness (frozen evidence)</summary>

```sh
cd phase0/contract && cargo build --release --target wasm32v1-none
cd ../account      && cargo build --release --target wasm32v1-none
cd ../harness

cargo run --release --bin pq-harness    # local metering VM benchmarks
cargo run --release --bin account       # end-to-end auth, local host

# on-network: per-transaction AND ledger-throughput tables
cargo run --release --bin simulate -- <SOURCE_G...> <PROBE_C...> <ACCOUNT_C...>

# submit a real ML-DSA-authorised transaction
PQ_SECRET=<S...> cargo run --release --bin submit -- <SOURCE_G...> <ACCOUNT_C...>
```
</details>

All key material derives from the fixed seed `[42u8; 32]` — every figure is
deterministic. Deployed contracts are listed in
[BENCHMARK.md](BENCHMARK.md).

## Supporting detail

### Per transaction

| Operation | instructions | % of 400M tx budget | resource fee |
|---|---|---|---|
| ML-DSA-65 in contract | 77,519,116 | 19.4% | 90,837 stroops |
| ML-DSA-44 in contract | 51,025,589 | 12.8% | 64,944 stroops |
| ECDSA secp256r1 host fn | 5,661,133 | 1.4% | 17,147 stroops |
| Ed25519 host function | 2,963,805 | 0.7% | 15,084 stroops |
| no-op (VM baseline) | 2,515,683 | 0.6% | 14,090 stroops |

Net of VM baseline, ML-DSA-65 costs **167x** Ed25519 and **24x** secp256r1.
Full tables, the decode/verify cost split, and the message-length sweep:
[BENCHMARK.md](BENCHMARK.md).
Non-CPU resources are not close to binding — largest is on-wire transaction size
at 4.3%.

### Compiler flags matter more than expected

| | `opt-level = 3` | `opt-level = "z"` |
|---|---|---|
| ML-DSA-65 verify | 77,519,116 (19.4%) | 204,957,239 (51.2%) |
| Contract wasm | 61,457 B | 33,384 B |

**2.64x CPU penalty** for the common Soroban size-optimised default.
→ [Write-up](writeups/opt-level-and-lattice-crypto-on-soroban.md)

## Documents

| Document | What it is |
|---|---|
| [**TECHNICAL-REPORT.md**](TECHNICAL-REPORT.md) | **Start here.** What was built, measured, and found; limitations; relationship to CAP-0087. |
| [**BENCHMARK.md**](BENCHMARK.md) | **Current cost reference.** Ledger throughput, cost split, message-length linearity, secp256r1 baseline. Cite this for figures. |
| [opt-level write-up](writeups/opt-level-and-lattice-crypto-on-soroban.md) | Standalone: the 2.64x compiler-flag finding. |
| [`phase0/`](phase0/) | Probe contracts and measurement harness. |

## Relationship to CAP-0087

[CAP-0087](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md)
(Draft, protocol 29) proposes native Soroban host functions for ML-DSA
verification. It lists cost calibration as TBD and states that guest-side
verification "exceeds reasonable network limits."

**Our measurements support the CAP.** Per transaction the operation fits
comfortably (19.3%), but at network level 14 authorizations per ledger is not a
practical basis for broad wallet authentication — which we read as the substance
of that claim. Using the CAP's own estimate of "a few times an Ed25519
verification," host functions would give roughly 250–300 authorizations per
ledger, an 18–22x improvement.

This project **quantifies CAP-0087; it does not refute it.** In-contract
verification is a bridge to protocol 29 for the low-volume, high-value tier the
QPP names for 2026 — not an alternative to the host functions.

## Status

Phase 0 and 0.5 complete. Milestone 3 (testnet transaction) delivered.
Milestones 1–2 rebuild this properly on a reusable `pq-core` rather than the
Phase 0 probe contracts.
