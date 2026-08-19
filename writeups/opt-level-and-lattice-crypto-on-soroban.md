# `opt-level = "z"` costs 2.7x CPU for lattice cryptography on Soroban

**Jagadeesh B — 19 August 2026**

If you are compiling a Soroban smart contract that does post-quantum signature
verification, the optimisation profile you inherited from a template is probably
costing you two-thirds of your CPU budget.

Measured on Stellar testnet, the same ML-DSA-65 verification compiled two ways:

| | `opt-level = 3` | `opt-level = "z"` |
|---|---|---|
| Contract wasm | 59,833 B (46% of the 131,072 limit) | 32,583 B (25%) |
| CPU instructions | **77,119,386** | **207,360,903** |
| Share of the 400M per-transaction budget | **19.3%** | **51.8%** |
| Resource fee | 90,557 stroops | 181,726 stroops |

**2.69x the CPU and 2.01x the fee, to save 27 KB of a size budget that had 71 KB
spare.**

## Background, briefly

Soroban is Stellar's smart contract platform. Contracts compile to wasm, and
every transaction is metered against a CPU instruction budget —
`tx_max_instructions`, currently 400,000,000 on testnet. Exceed it and the
transaction fails; the fee scales with instructions consumed. So instruction
count is the resource that decides both whether a contract call is possible and
what it costs.

ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium) is NIST's primary standardised
post-quantum signature algorithm. Verifying a signature means expanding a matrix
from a seed with SHAKE-128, running number-theoretic transforms, and doing
matrix-vector products over a 23-bit prime field. It is heavy, tight-loop
arithmetic.

## Why the default is wrong here

`opt-level = "z"` — optimise for size — is close to a default in the Soroban
ecosystem. It appears in example contracts, templates and much published
guidance, and for good reason: for typical contracts, wasm size drives
deployment cost and instantiation overhead while the computation per call is
light. Optimising for size is the right instinct **when size is the binding
constraint.**

Lattice cryptography breaks that assumption. Tight arithmetic loops are exactly
the code where `opt-level = 3` earns its keep through unrolling, inlining and
better codegen, and exactly the code `"z"` penalises hardest.

The consequence is a threshold effect rather than a gradual one. At 19.3% of the
transaction budget, verification leaves 80% of the transaction for actual work.
At 51.8% it leaves 48%, and composing it with anything substantial becomes
awkward. **Same source, same crate, same network — one profile line.**

## The tradeoff is real, just lopsided

`"z"` is not simply worse. It genuinely wins on VM instantiation, because there
is less wasm to load and parse:

| | `opt-level = 3` | `opt-level = "z"` |
|---|---|---|
| No-op call (VM instantiation + dispatch) | 2,438,881 | 1,470,150 |

`"z"` saves about 1M instructions on every call and then loses about 130M on the
verification. If your contract is dominated by dispatch rather than computation,
`"z"` may well be right. If it does lattice arithmetic, it is not close.

Net of the VM baseline, the penalty on the cryptographic work alone is **2.76x**.

ML-DSA-44 shows the same pattern: 51,138,313 (12.8% of budget) at `3` versus
126,234,787 (31.6%) at `"z"` — a 2.47x penalty.

## Practical guidance

1. **Pin `opt-level = 3` in any contract doing lattice cryptography,** and record
   why in the manifest so it does not get tidied away later. Contract size is
   unlikely to be your binding constraint — at 59,833 bytes we used 46% of the
   limit.
2. **Do not benchmark Soroban cryptography on an inherited profile.** Measure
   both. A 2.7x swing is large enough to change an architectural decision, and
   large enough to make a feasibility study reach the wrong conclusion.
3. **Measure on-network, not only in the local test host.** The local metering VM
   under-reported this workload by 4.3% and omits a fixed ~2.2M instruction
   VM/ledger overhead the network charges on every call. Use
   `simulateTransaction` against a deployed contract for anything you publish.
4. **Target `wasm32v1-none`.** Current `soroban-sdk` rejects
   `wasm32-unknown-unknown` outright — it enables reference-types and
   multi-value, which the Soroban environment does not support.

## Where the numbers came from

This is a by-product of building a post-quantum signature SDK for Stellar,
testing whether ML-DSA verification can run inside a Soroban contract today.

It can, per transaction. A custom account authorised a
[real testnet transaction][tx] using only an ML-DSA-65 signature verified in
`__check_auth`, with no Ed25519 signer on the account. (The transaction
*envelope* is still Ed25519-signed — the protocol offers nothing else today.
What is post-quantum there is the contract account's authorisation.)

Per *ledger* the picture is tighter, and worth knowing if you are considering
this approach: the network-wide budget is 580,000,000 instructions per ledger,
so one ML-DSA-65 authorisation costs 13.3% of it and roughly 14 fit in a ledger,
against about 400 Ed25519-verifying contract calls. In-contract post-quantum
verification is viable for low-volume, high-value use; it is not a
consumer-scale mechanism.

Native host functions for ML-DSA verification are proposed in
[CAP-0087][cap87], which would remove most of this cost. Until they ship, the
compiler flag is the largest single lever available.

## Caveat on the implementation

These numbers use [`ml-dsa` 0.1.1][mldsa] (RustCrypto). **That crate states it
has never been independently audited, as does the main alternative,
[`fips204`][fips204]. There is currently no audited pure-Rust ML-DSA
implementation.** Differential testing between implementations and conformance
against NIST ACVP and Wycheproof vectors is mitigation, not resolution. Nothing
here should be read as a recommendation to put in-contract ML-DSA verification
in front of real value on mainnet. These measurements are about feasibility and
cost, not production readiness.

## Reproducing

Contracts, harness and the on-network simulation tool are in the project repo.
Both variants are deployed on testnet:

- `opt-level = 3` — `CDJXS5LYJOFH46NUBXZXMIU2MCSKCFJRVHIH6KX5TMJTJN4FU5NNVE3R`
- `opt-level = "z"` — `CDZZEURTDIZUNKRW3YL7ZA4XAH27YR5API5HEHX5QBIYE5XG5QRWXUWC`

Environment: rustc 1.97.1, `soroban-sdk` 27.0.6, testnet protocol 27. All key
material derives from a fixed seed, so every figure is reproducible.

[cap87]: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md
[mldsa]: https://crates.io/crates/ml-dsa
[fips204]: https://crates.io/crates/fips204
[tx]: https://stellar.expert/explorer/testnet/tx/8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4
