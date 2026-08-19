# pq-core

Scheme-agnostic post-quantum signature traits, with **ML-DSA-44** and
**ML-DSA-65** (FIPS 204) behind them.

`no_std`, allocation-free, `#![forbid(unsafe_code)]`, and builds clean for
`wasm32v1-none`.

> ## ⚠️ No audited implementation exists
>
> ML-DSA here is [`ml-dsa`](https://crates.io/crates/ml-dsa) 0.1.1, whose README
> states: *"The implementation contained in this crate has never been
> independently audited! USE AT YOUR OWN RISK!"* The main alternative,
> [`fips204`](https://crates.io/crates/fips204), carries an equivalent warning.
> **There is currently no audited pure-Rust ML-DSA implementation.**
>
> This crate's answer is differential testing against `fips204` plus NIST ACVP
> and Wycheproof conformance vectors. **That is mitigation, not resolution.** It
> lowers the probability that a defect goes unnoticed. It does not establish
> positive assurance, and it is not a substitute for independent review of the
> verification path. Do not put this in front of real value.
>
> This is shared industry state rather than a defect in this approach — Stellar's
> [CAP-0087](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md)
> describes the same difficulty in choosing an implementation to vendor.

## Chain-agnostic by construction

`pq-core` has no dependency on Stellar, Soroban, or any other chain, and must
not acquire one. Chain adapters depend on `pq-core`; never the reverse.

## Design

Four traits, none of which mention a scheme:

| Trait | Role |
|---|---|
| `PqScheme` | Static metadata — name, security category, key/signature/seed lengths — tying the three key types together |
| `PqEncode` | Canonical byte encoding, slice-based |
| `PqVerifier` | `verify(message, context, signature)` |
| `PqSigner` | `sign_into(message, context, out) -> bytes_written` |
| `PqKeypair` | `from_seed(seed)` |

Two decisions carry most of the design weight:

**Slice-based encoding.** Signature sizes across the standardised schemes span
three orders of magnitude — 2,420 bytes for ML-DSA-44 up to 49,856 for
SLH-DSA-256f. Returning owned arrays would force either `alloc` or const-generic
sizes threaded through every caller. Writing into a caller-provided slice keeps
the layer `no_std`, allocation-free, and size-agnostic.

**Context as a first-class parameter.** FIPS 204 and FIPS 205 both define an
external interface taking a 0–255 byte domain-separation string. Baking in an
empty context would have made ML-DSA's external interface unrepresentable and
forced a trait change to add SLH-DSA later.

### Adding a scheme requires no trait change

`schemes/slhdsa_sketch.rs` is a **compile-checked** demonstration. SLH-DSA is
the hardest case for a layer designed around ML-DSA, differing on every axis
that could have been accidentally assumed:

| | ML-DSA-65 | SLH-DSA-SHA2-128s |
|---|---|---|
| family | module-lattice | stateless hash-based |
| signature | 3,309 B | **7,856 B** |
| verifying key | 1,952 B | **32 B** |
| seed | 32 B | **48 B** |

The sketch implements every trait with `unimplemented!()` bodies and type-checks
against the unmodified trait layer. It also instantiates a generic,
adapter-shaped function over both a real ML-DSA parameter set and the sketch,
proving an adapter written against `PqVerifier` needs no change either.

Falcon / FN-DSA is the easier case. The one accommodation already present:
`sign_into` returns the number of bytes written rather than assuming
`SIGNATURE_LEN`, because Falcon signatures are compressed and variable-length.

## Correctness

Run with `cargo test --all-features`. Every suite must pass; there are no
allowed failures and no skipped assertions that hide a disagreement.

### NIST ACVP (FIPS 204)

Source: `usnistgov/ACVP-Server`, `gen-val/json-files/ML-DSA-{sigVer,keyGen}-FIPS204`.

| Suite | ML-DSA-44 | ML-DSA-65 |
|---|---|---|
| `sigVer`, external/pure | 15 / 15 | 15 / 15 |
| `keyGen`, seed → pk+sk byte-for-byte | 25 / 25 | 25 / 25 |

The 45 internal-interface `sigVer` cases per parameter set are **skipped, not
ignored**: `ML-DSA.Verify_internal` cannot be replayed through an external-
interface API by construction. The count is printed by the test.

### Wycheproof

Source: `C2SP/wycheproof`, `testvectors_v1/mldsa_{44,65}_verify_test.json`.

**180 / 180** (ML-DSA-44) and **210 / 210** (ML-DSA-65), covering the cases a
plausible-but-wrong verifier accepts:

| Flag | 44 | 65 |
|---|---|---|
| `InfinityNormViolation` | 42 | 52 |
| `ZeroPublicKey` | 35 | 51 |
| `InvalidHintsEncoding` | 8 | 9 |
| `BoundaryCondition` | 61 | 75 |
| `InvalidContext` | 5 | 5 |
| `IncorrectPublicKeyLength` | 4 | 4 |
| `IncorrectSignatureLength` | 3 | 3 |

### Differential testing vs `fips204`

Two independent codebases written from the same specification. **Any
disagreement is treated as blocking** — the test panics rather than recording a
count.

Both are driven through FIPS 204's deterministic variant (`rnd = 0^32`), so
agreement is checked at the strongest available level: **byte-identical
signatures**, not merely mutual acceptance.

| Check | ML-DSA-44 | ML-DSA-65 |
|---|---|---|
| Accept/reject agreement on ACVP + Wycheproof | 188 cases | 218 cases |
| Byte-identical deterministic signatures | 256 combinations | 256 combinations |
| Cross-verification, both directions | ✓ | ✓ |
| Encoded key material loads in both | ✓ | ✓ |
| Corrupted signature rejected by both | ✓ | ✓ |
| Wrong context rejected by both | ✓ | ✓ |

**Result: zero disagreements.**

Signature combinations are 16 seeds × 4 message sizes (0 B to 4 KiB) × 4 context
values (empty, short, 255-byte boundary, binary).

7 cases per parameter set are **skipped and counted**: `fips204`'s API is
fixed-width, so wrong-length inputs cannot be expressed in it. The test asserts
that *we* reject those before skipping the comparison.

## Known limitations

**The expanded secret-key encoding depends on a deprecated API.**
`PqEncode` for `SigningKey` uses the FIPS 204 expanded `sk` form, because that
is what ACVP's keyGen vectors specify and what other implementations
interoperate on. `ml-dsa` deprecates it in favour of the 32-byte seed, so a
future release may remove it and break ACVP `sk` conformance. Tracked; the seed
path (`PqKeypair::from_seed`) is unaffected.

**`SigningKey::from_bytes` is trusted-input only.** The underlying
`ExpandedSigningKey::from_expanded` does not validate its input and its own
documentation states it can panic on malformed or maliciously generated keys.
This crate is `no_std` and cannot catch that. Use `PqKeypair::from_seed` for
anything crossing a trust boundary.

Note the boundary this does *not* cross: the **verification** path, which is the
one that actually consumes attacker-controlled bytes, touches none of this. It
decodes through validated APIs and is exercised by all 390 Wycheproof cases
including malformed keys and signatures.

## Status

Milestone 1. Off-chain keygen, sign, verify. No chain adapter — `pq-stellar` is
deliberately not part of this crate.
