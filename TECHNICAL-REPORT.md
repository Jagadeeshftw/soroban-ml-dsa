# In-contract ML-DSA on Soroban — technical report

**Jagadeesh B — 19 August 2026**
Repository: https://github.com/Jagadeeshftw/soroban-ml-dsa

---

## Summary

Post-quantum signature verification (ML-DSA, FIPS 204) runs inside a Soroban
smart contract today, on protocol 27, with no protocol change. A contract
account with no Ed25519 signer authorises real testnet transactions using only
an ML-DSA-65 signature checked in `__check_auth`.

The question worth answering was not *whether* but *at what cost*, and the
answer depends entirely on which limit you measure against:

- **Per transaction: comfortable.** 19.4% of `tx_max_instructions`.
- **Per ledger: constrained.** 13.4% of the network's per-ledger compute budget
  *per authorization*. About 14 fit in a ledger, against ~390 Ed25519-verifying
  contract calls.

That second figure is the one that matters, and it is why this work **supports**
[CAP-0087](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md)'s
case for native host functions rather than arguing against it.

> **No audited pure-Rust ML-DSA implementation exists.** `ml-dsa` 0.1.1 and
> `fips204` both state they have never been independently audited. The
> conformance and differential testing described below is **mitigation, not
> assurance.** This work is testnet-only and is not production-ready.

---

## 1. What was built

```
crates/
  pq-core/      scheme-agnostic traits + ML-DSA-44/65   no_std, no alloc, no chain types
  pq-stellar/   Soroban adapter: payload, XDR, auth entries      generic over PqScheme
  pq-cli/       deploy, authorise, benchmark
contracts/
  pq-verifier/  benchmark contract: in-contract ML-DSA vs host-function baselines
  pq-account/   custom account, __check_auth via pq-core
```

Two structural constraints, both enforced by tests rather than convention:

**`pq-core` knows nothing about any chain.** Adapters depend on it, never the
reverse.

**Adding a scheme changes neither the trait layer nor any adapter.**
`schemes/slhdsa_sketch.rs` type-checks a hash-based scheme with a 7,856-byte
signature and a 48-byte seed against the unmodified traits, and the `pq-stellar`
test suite instantiates the entire adapter surface over it. Two decisions carry
that: slice-based encoding (signature sizes span three orders of magnitude
across the standardised schemes) and context as a first-class parameter (FIPS
204 and 205 both define one).

The contract and the client-side adapter share one verification implementation.
A signature the client produces is verified by exactly the code it signed
against.

## 2. Correctness

| Suite | ML-DSA-44 | ML-DSA-65 |
|---|---|---|
| NIST ACVP `sigVer`, external/pure | 15/15 | 15/15 |
| NIST ACVP `keyGen`, seed → pk+sk byte-for-byte | 25/25 | 25/25 |
| Wycheproof | 180/180 | 210/210 |
| Differential vs `fips204`, accept/reject agreement | 188 | 218 |
| Differential vs `fips204`, byte-identical signatures | 256 | 256 |

**Zero disagreements.** Both implementations are driven through FIPS 204's
deterministic variant (`rnd = 0^32`), so agreement is checked as byte-identical
signature output rather than mutual acceptance — the strongest form available
when neither implementation is audited.

Wycheproof coverage includes the cases a plausible-but-wrong verifier accepts:
`InfinityNormViolation` (94), `ZeroPublicKey` (86), `InvalidHintsEncoding` (17),
`InvalidContext` (10).

90 ACVP internal-interface cases and 14 wrong-length cases are **skipped and
counted**, never silently dropped: `ML-DSA.Verify_internal` cannot be replayed
through an external-interface API, and `fips204`'s fixed-width API cannot
express a wrong-length input.

## 3. What was measured

Full tables: [BENCHMARK.md](BENCHMARK.md). Headline, on-network against deployed
contracts:

| Operation | % of ledger budget | per ledger | % of tx budget |
|---|---|---|---|
| **ML-DSA-65 in contract** | **13.4%** | **14** | 19.4% |
| ML-DSA-44 in contract | 8.8% | 22 | 12.8% |
| ECDSA secp256r1 host fn | 1.0% | 204 | 1.4% |
| Ed25519 host fn | 0.5% | 390 | 0.7% |

Net of VM baseline, ML-DSA-65 costs **167× Ed25519** and **24× secp256r1**.

Non-CPU resources are nowhere near binding: `disk_read_bytes` 0, `write_bytes`
72, on-wire transaction 3,824 bytes (2.9% of the limit), stored verifying key a
2,088-byte ledger entry.

## 4. Findings

**The ledger limit is the binding one, and it is not a simple sum.** Under
[CAP-0063](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0063.md),
`ledgerMaxInstructions` bounds the *critical path*: `sequential(stage)` is the
max across its clusters, summed across stages. With two clusters, one stage of
balanced non-conflicting work admits `2 × floor(580,000,000 / per_tx)`. Anyone
computing throughput as a plain division will be wrong by 2×.

**`opt-level = "z"` costs 2.64× CPU for lattice arithmetic.** It is close to a
Soroban default and is the right choice for ordinary contracts, where size binds
and computation is light. For ML-DSA it moves verification from 19.4% to 51.2%
of the transaction budget to save 28 KB of a budget with 70 KB spare. Any
guest-side benchmark taken on an inherited profile measures roughly double the
achievable cost. → [write-up](writeups/opt-level-and-lattice-crypto-on-soroban.md)

**Soroban requires `wasm32v1-none`.** Current `soroban-sdk` rejects
`wasm32-unknown-unknown` outright — it enables reference-types and multi-value,
which the environment does not support.

**Key decode is 40% of verification.** CAP-0087 separates
`MlDsa65DecodeVerifyingKey` from `VerifyMlDsa65Sig` and mentions caching
expanded keys as a future optimisation. On these numbers that optimisation is
worth ~40% of a verification, and ~60% of a second verification under the same
key in one transaction.

**The linear message-length model holds.** Marginal cost settles around 400
instructions per byte, with the constant term dominating so heavily that going
from a 32-byte authorization payload to 8 KiB adds 4.4%.

**Local measurement under-reports.** The Soroban test host under-counts this
workload by 4.3% and omits a fixed ~2.2M instruction VM/ledger overhead the
network charges on every call. Every figure here comes from
`simulateTransaction` against a deployed contract.

## 5. Limitations

**No audited implementation.** Stated above; it is the most important
limitation and cannot be engineered away.

**`SigningKey::from_bytes` is trusted-input only.** `ml-dsa`'s `from_expanded`
does not validate its input and its own documentation says it can panic on a
malicious expanded signing key, which `no_std` cannot catch. `pq-stellar` never
calls it — a test scans the crate's own source and fails if that changes,
verified non-vacuous by injecting a violation. The *verification* path, the one
consuming attacker-controlled bytes, touches none of this.

**The expanded secret-key encoding uses a deprecated API.** It is what ACVP's
keyGen vectors specify, so dropping it loses conformance; `ml-dsa` may remove
it.

**Testnet only.** Follows from the first limitation.

**Not measured:** ML-DSA-87, key rotation cost, multi-signature accounts, and
the host functions themselves (they do not exist publicly).

## 6. Relationship to CAP-0087

CAP-0087 (Draft, `min_supported_protocol: 29`) proposes native host functions
for exactly this operation and lists cost calibration as TBD. Testnet runs
protocol 27.

Its Motivation states that guest-side verification "exceeds reasonable network
limits". Measured against `tx_max_instructions` that does not hold; measured
against `ledger_max_instructions` it substantially does, and the wording says
*network*. **We take the second reading and consider the claim supported.**

Using the CAP's own estimate of "a few times an Ed25519 verification", host
functions would give roughly 250–300 authorizations per ledger — an 18–22×
improvement. That is a projection from their estimate, not a measurement.

In-contract verification is a **bridge to protocol 29 for the low-volume,
high-value tier** — the enterprise custody case the QPP names for 2026 — not an
alternative to the host functions.

These measurements were posted to the CAP-0087 discussion thread on 19 August
2026:
[discussion #1915](https://github.com/stellar/stellar-protocol/discussions/1915#discussioncomment-18076058).

## 7. Reproducing

```sh
git clone https://github.com/Jagadeeshftw/soroban-ml-dsa && cd soroban-ml-dsa
./demo.sh
```

No configuration, no funded account. The script checks the toolchain, runs every
conformance suite, creates and funds a throwaway testnet account, deploys both
contracts, authorises a real transaction with an ML-DSA-65 signature, and
reproduces the cost tables on-network. It prints a transaction hash that can be
checked on any block explorer.

Verified from a clean clone on 19 August 2026: the freshly deployed contracts
reproduced every published figure exactly.

## 8. Precision about the claim

What is post-quantum is the **contract account's authorization** — QPP Stage 1.
The transaction *envelope* is still Ed25519-signed, because protocol 27 offers
no alternative; that is what QPP Stage 2 changes in 2027. CAP-0087 makes the
same distinction: it does not make transaction signatures, account master keys,
or the overlay post-quantum.

The correct claim is *"a quantum-safe Soroban contract account authorising a
testnet transaction"* — not *"a post-quantum Stellar transaction"*.
