# Post-Quantum Signature SDK for Stellar

**ML-DSA (FIPS 204) signature verification inside a Soroban smart contract —
measured on Stellar testnet.**

A Soroban custom account authorised a real testnet transaction using only an
ML-DSA-65 signature, verified on-chain in `__check_auth`. This measures what that
costs, at both the per-transaction and the network-capacity limit.

> ### Verifiable artifact
>
> **Transaction [`8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4`](https://stellar.expert/explorer/testnet/tx/8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4)**
> — testnet ledger 4,217,131, `successful: true`.
> Account [`CDTEFSSESKZ7G6WFILKGND4NCN3BWGRSPLLU2JTK6ZUHR77QLTGSK73R`](https://stellar.expert/explorer/testnet/contract/CDTEFSSESKZ7G6WFILKGND4NCN3BWGRSPLLU2JTK6ZUHR77QLTGSK73R)
> carries **no Ed25519 signer**; authorization came solely from an ML-DSA-65
> signature checked in `__check_auth`.

> ### ⚠️ Read this before citing the result
>
> **What is post-quantum:** the *contract account's authorization*. This is
> QPP Stage 1 — a quantum-safe Soroban contract account.
>
> **What is not:** the *transaction envelope*, still signed with Ed25519 because
> protocol 27 offers no alternative. That is what QPP Stage 2 (2027) changes.
>
> The correct claim is **"a quantum-safe Soroban contract account authorising a
> testnet transaction."** Not "a post-quantum Stellar transaction." CAP-0087
> draws the same distinction: it does not make transaction signatures,
> account master keys or the overlay post-quantum.

> ### ⚠️ No audited implementation exists
>
> This uses [`ml-dsa`](https://crates.io/crates/ml-dsa) 0.1.1, which states it
> has never been independently audited. The alternative,
> [`fips204`](https://crates.io/crates/fips204), carries the same warning.
> **There is no audited pure-Rust ML-DSA implementation today.** Differential
> testing plus NIST ACVP and Wycheproof vectors is *mitigation, not resolution.*
> Testnet only. Not production-ready.

## Results

All figures from `simulateTransaction` against deployed testnet contracts
(protocol 27), `opt-level = 3`. Not a local test host.

### Ledger throughput — the limit that matters

`ledger_max_instructions` = 580,000,000, bounding the critical path across
parallel clusters under [CAP-0063](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0063.md).

| Operation | % of ledger budget per call | per ledger | per second |
|---|---|---|---|
| **ML-DSA-65 in contract** | **13.3%** | **14** | **2.8** |
| ML-DSA-44 in contract | 8.8% | 22 | 4.4 |
| Ed25519 via host function | 0.5% | 400 | 80.0 |

**One in-contract ML-DSA-65 authorization consumes 13.3% of the entire network's
per-ledger compute — about 28x fewer per ledger than an Ed25519-verifying
contract call.** Viable for low-volume, high-value use; not a consumer-scale
mechanism.

### Per transaction

| Operation | instructions | % of 400M tx budget | resource fee |
|---|---|---|---|
| ML-DSA-65 in contract | 77,119,386 | 19.3% | 90,557 stroops |
| ML-DSA-44 in contract | 51,138,313 | 12.8% | 65,023 stroops |
| Ed25519 host function | 2,887,282 | 0.7% | 15,031 stroops |
| no-op (VM baseline) | 2,438,881 | 0.6% | 14,037 stroops |

Net of VM baseline, ML-DSA-65 costs **167x** an Ed25519 host-function call.
Non-CPU resources are not close to binding — largest is on-wire transaction size
at 4.3%.

### Compiler flags matter more than expected

| | `opt-level = 3` | `opt-level = "z"` |
|---|---|---|
| ML-DSA-65 verify | 77,119,386 (19.3%) | 207,360,903 (51.8%) |
| Contract wasm | 59,833 B | 32,583 B |

**2.69x CPU penalty** for the common Soroban size-optimised default.
→ [Write-up](writeups/opt-level-and-lattice-crypto-on-soroban.md)

## Reproduce

Requires Rust 1.85+ and `rustup target add wasm32v1-none`
(**not** `wasm32-unknown-unknown` — current `soroban-sdk` rejects it).

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

All key material derives from the fixed seed `[42u8; 32]` — every figure is
deterministic. Deployed contracts are listed in
[the verification report](phase-0.5-verification.md#testnet-artefacts).

## Documents

| Document | What it is |
|---|---|
| [**Phase 0.5 verification**](phase-0.5-verification.md) | **Authoritative measurements.** On-network, ledger analysis, submitted transaction. Cite this. |
| [Phase 0 investigation](phase-0-report.md) | Crate survey, CAP-0087 status, `__check_auth` findings. **Figures and framing superseded** — retained as the record. |
| [MVP plan](Pq-sdk-stellar-mvp-plan.md) | Scope, architecture, milestones, amendment history. |
| [opt-level write-up](writeups/opt-level-and-lattice-crypto-on-soroban.md) | Standalone: the 2.69x compiler-flag finding. |
| [CAP-0087 discussion post](outreach/cap-0087-discussion-post.md) | Draft for the CAP discussion thread. |
| [Library vendoring note](outreach/ml-dsa-library-vendoring-note.md) | `ml-dsa` vs `fips204`, answering CAP-0087's vendoring question. |
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
Phase 0 probe contracts. See the [MVP plan](Pq-sdk-stellar-mvp-plan.md).
