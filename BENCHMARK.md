# Milestone 4 — On-network cost reference

**Date:** 19 August 2026 · **Network:** Stellar testnet, protocol 27
**Contracts:** built on [`pq-core`](crates/pq-core), `opt-level = 3`, `wasm32v1-none`

Every figure is read from the `SorobanTransactionData` the network returns from
`simulateTransaction` against a deployed contract. Not the local metering VM,
which under-reports this workload by ~4.3% and omits a fixed ~2.2M instruction
VM/ledger overhead.

Reproduce: `cargo run --release --bin bench -- <SOURCE_G...> <VERIFIER_C...>`

| Deployed | Address |
|---|---|
| `pq-verifier` | `CCH655J7I7WCNF2SAR4BKY6QAMP45UMYHAFXLMNFJ7NJUXI5LGGQB2GY` |
| `pq-account` | `CDDE2DU2VR4W2XSHIE62VYAFJ3VNIBDIV3IMGZ3N4MPISCKPW2EIIA3S` |

---

## Ledger throughput — the binding constraint

`ledger_max_instructions` = 580,000,000, `ledger_max_dependent_tx_clusters` = 2,
measured close time 5.00 s.

| Operation | instructions | % of ledger | seq/ledger | **per ledger** | per second |
|---|---|---|---|---|---|
| no-op (VM instantiation) | 2,515,683 | 0.4% | 230 | 460 | 92.0 |
| Ed25519 (host fn) | 2,963,805 | 0.5% | 195 | 390 | 78.0 |
| ECDSA secp256r1 (host fn) | 5,661,133 | 1.0% | 102 | 204 | 40.8 |
| ML-DSA-44 decode key only | 20,745,432 | 3.6% | 27 | 54 | 10.8 |
| **ML-DSA-44 verify, in contract** | **51,025,589** | **8.8%** | 11 | **22** | 4.4 |
| ML-DSA-65 decode key only | 32,583,599 | 5.6% | 17 | 34 | 6.8 |
| **ML-DSA-65 verify, in contract** | **77,519,116** | **13.4%** | 7 | **14** | 2.8 |

Under CAP-0063 `ledgerMaxInstructions` bounds the **critical path**:
`sequential(stage)` is the max across its clusters, summed across stages. With
two clusters, one stage of balanced non-conflicting work admits
`2 × floor(580,000,000 / per_tx)`. **`per ledger` is the favourable case;
`seq/ledger` is strictly sequential.** `ledger_max_tx_count` (2,000) is not
binding for any row.

## Per transaction

`tx_max_instructions` = 400,000,000.

| Operation | instructions | % of tx | fee (stroops) | net of no-op |
|---|---|---|---|---|
| no-op (VM instantiation) | 2,515,683 | 0.6% | 14,090 | — |
| Ed25519 (host fn) | 2,963,805 | 0.7% | 15,084 | 448,122 |
| ECDSA secp256r1 (host fn) | 5,661,133 | 1.4% | 17,147 | 3,145,450 |
| ML-DSA-44 verify | 51,025,589 | 12.8% | 64,944 | 48,509,906 |
| ML-DSA-65 verify | 77,519,116 | 19.4% | 90,837 | 75,003,433 |

Net of the VM baseline, in-contract ML-DSA-65 costs **167× Ed25519** and
**24× ECDSA secp256r1**.

The secp256r1 comparison is arguably the more useful one. CAP-0087 cites
[CAP-0051](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0051.md)
as its precedent, and secp256r1 is the closest existing analogue — a
comparatively expensive signature scheme made practical by a host function.
24× is the gap a host implementation would be closing.

## Cost split — mirrors CAP-0087's cost types

CAP-0087 defines `MlDsaNNDecodeVerifyingKey` (constant) and `VerifyMlDsaNNSig`
(linear in message length) as separate metering entries. Measured guest-side
split, net of VM baseline:

| Parameter set | decode / ExpandA | verify proper |
|---|---|---|
| ML-DSA-44 | 18,229,749 (**38%**) | 30,280,157 (62%) |
| ML-DSA-65 | 30,067,916 (**40%**) | 44,935,517 (60%) |

The decode share is large enough to matter. CAP-0087 notes that separating it
"leaves room for a future optimization in which expanded verifying keys are
cached across repeated verifications within a transaction" — on these numbers
that optimisation is worth ~40% of a verification, and ~60% of a *second*
verification in the same transaction under the same key.

## Message-length linearity

CAP-0087 models `VerifyMlDsaNNSig` as linear in message length. Guest-side
ML-DSA-65, net of VM baseline:

| message bytes | instructions | net of no-op | marginal insns/byte |
|---|---|---|---|
| 32 | 77,516,549 | 75,000,866 | — |
| 256 | 77,641,683 | 75,126,000 | 558.6 |
| 1,024 | 77,961,922 | 75,446,239 | 417.0 |
| 4,096 | 79,156,399 | 76,640,716 | 388.8 |
| 8,192 | 80,805,128 | 78,289,445 | 402.5 |

**The linear model holds.** Marginal cost settles at roughly **400 instructions
per byte** and the constant term dominates overwhelmingly at realistic sizes:
going from a 32-byte authorization payload to 8 KiB adds only 4.4%.

## `opt-level`

Both variants built from the **same `pq-core` sources** as everything else on
this page and deployed separately, so these are current-reference figures, not
carried over from the Phase 0 probes.

| | `opt-level = 3` | `opt-level = "z"` | penalty |
|---|---|---|---|
| contract wasm | 61,457 B (46% of limit) | 33,384 B (25%) | — |
| **ML-DSA-65 verify** | **77,519,116 (19.4%)** | **204,957,239 (51.2%)** | **2.64×** |
| ML-DSA-44 verify | 51,025,589 (12.8%) | 124,920,531 (31.2%) | 2.45× |
| no-op (VM instantiation) | 2,515,683 | 1,516,930 | 0.60× |
| resource fee, ML-DSA-65 | 90,837 | 180,044 | 1.98× |

Net of the VM baseline the penalty on the cryptographic work alone is **2.71×**
for ML-DSA-65 and 2.54× for ML-DSA-44.

`opt-level = "z"` genuinely wins on VM instantiation — 1,516,930 against
2,515,683, because there is less wasm to load — then loses ~128M on the
verification. The trade is real; it is simply enormously lopsided here.

Deployed for this comparison: `opt-level = 3`
`CCH655J7I7WCNF2SAR4BKY6QAMP45UMYHAFXLMNFJ7NJUXI5LGGQB2GY`,
`opt-level = "z"` `CCZO6X4AXNVPEKRT4CRV57U2M7QDLZEMHAAS5VHICZAJRKH7WANTGAQC`.

Full detail: [`writeups/opt-level-and-lattice-crypto-on-soroban.md`](writeups/opt-level-and-lattice-crypto-on-soroban.md).

## Note on earlier figures

[`phase-0.5-verification.md`](phase-0.5-verification.md) reports 77,119,386 for
ML-DSA-65 (19.3% / 13.3%). That measured the **Phase 0 probe contracts**, which
inlined `ml-dsa` directly. The contracts here are rebuilt on `pq-core`, so both
the crypto and the contract wrapper differ slightly. The gap is **0.5%** and the
ledger-throughput figures are unchanged (14 / 22).

Numbers on this page are the current reference. The Phase 0.5 report is retained
as the record of what was measured then.

## Standing caveat

`ml-dsa` 0.1.1 is unaudited, as is `fips204`. There is no audited pure-Rust
ML-DSA implementation. Differential testing and conformance vectors are
mitigation, not resolution. Testnet only.
