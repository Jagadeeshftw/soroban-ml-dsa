# pq-stellar

Stellar/Soroban adapter for [`pq-core`](../pq-core): signature payload
construction, XDR encoding, and authorization entries for post-quantum contract
accounts.

> ## ⚠️ Inherits `pq-core`'s assurance caveat
>
> There is no audited pure-Rust ML-DSA implementation. Differential testing and
> conformance vectors are mitigation, not resolution. Testnet only, not
> production-ready. See the [`pq-core` README](../pq-core/README.md).

## Direction of dependency

`pq-stellar` depends on `pq-core`. **Never the reverse.** `pq-core` contains no
Stellar types and must not acquire any.

Every function in `auth` is generic over `pq_core::PqScheme`. No function in
this crate names a concrete scheme, so adding SLH-DSA or Falcon requires no
change here — a claim the test suite checks by instantiating the whole adapter
surface over the SLH-DSA sketch, which has a 7,856-byte signature and a 48-byte
seed.

## What it does

| Module | Contents |
|---|---|
| `payload` | The Soroban authorization signature payload, and network-id derivation |
| `auth` | Signing, verifying, authorization-entry construction, verifying-key encoding, and a stable on-chain `SchemeId` |
| `error` | `StellarError`, wrapping `pq_core::PqError` |

The payload is the part that is easy to get subtly wrong:

```text
SHA-256( XDR( HashIdPreimage::SorobanAuthorization {
    network_id, nonce, signature_expiration_ledger, invocation }))
```

The host binds the network, the nonce, the expiry, and the entire invocation
tree including arguments. A custom account's job is to verify a signature over
those bytes and not to undo any of it.

## Correctness

### The payload vector is validated by the network, not by us

`tests/payload_golden.rs` replays the exact inputs of testnet transaction
[`8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4`](https://stellar.expert/explorer/testnet/tx/8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4)
(ledger 4,217,131), which was authorised by an ML-DSA-65 signature verified in
`__check_auth` and **succeeded**.

Success means the Soroban host computed the same 32-byte payload this crate
does. A one-bit difference would have failed verification and the transaction
would have been rejected. That makes it a regression test against the real host
rather than a self-consistency check.

A companion test asserts that changing *any* bound field — network, nonce,
expiry, invocation — changes the payload. A field that does not is a field an
attacker can vary freely.

### Round-trips, per scheme

For ML-DSA-44 and ML-DSA-65: sign/verify across three context values including
the 255-byte boundary; wrong context rejected; **wrong nonce rejected** (the
replay defence); corrupted signature rejected; the built authorization entry
verifies against its own carried fields; verifying keys survive the encode →
contract-side decode → re-encode round trip.

## Safety boundary, enforced

`pq-core` documents that `SigningKey::from_bytes` is trusted-input only —
`ml-dsa`'s `from_expanded` does not validate its input and can panic on a
malicious expanded signing key, which `no_std` cannot catch.

**This crate is the layer that would expose that to network-supplied bytes, so
it never decodes a signing key.** Signing keys enter only as `&S::SigningKey`
values the caller already holds. The only decode path exposed is
`PqVerifier::from_bytes` — validated, and exercised by all 390 Wycheproof cases.

`tests/safety_boundary.rs` enforces this by scanning the crate's own source and
failing if the boundary is crossed. It is verified to be non-vacuous: injecting
a `<S::SigningKey as PqEncode>::from_bytes` call makes it fail.

```
no_signing_key_decode_path ............ no signing-key decode, no from_expanded
signing_keys_are_only_borrowed ........ &S::SigningKey only
verifying_key_decode_is_the_untrusted_path .. wrong/garbage input handled
```

## Version pinning

`stellar-xdr` is pinned to 27.0.0, the protocol-27 XDR the measurements in this
repository were taken against. Note that 27.0.0 moved the XDR types to the crate
root — the `curr` module from 26.x is gone.

## Status

Milestone 2. Client-side adapter only. The account contract itself lives in
[`phase0/account`](../../phase0/account) and is due a rebuild on `pq-core` — it
currently carries its own inlined ML-DSA path from the Phase 0 probe.
