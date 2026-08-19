//! Adapter round-trips, exercised for every scheme `pq-core` provides.
//!
//! The test bodies are generic over `PqScheme`. That is the point: if adding a
//! scheme required touching the adapter, these would not compile unchanged.

use pq_core::{PqEncode, PqKeypair, PqScheme};
use pq_stellar::auth::{
    build_auth_entry, encode_verifying_key, sign_authorization, verify_authorization, SchemeId,
};
use pq_stellar::{network_id, AuthorizationPayload, TESTNET_PASSPHRASE};
use stellar_xdr::{
    ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, VecM,
};

fn account() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x11u8; 32])))
}

fn payload(nonce: i64) -> AuthorizationPayload {
    AuthorizationPayload {
        network_id: network_id(TESTNET_PASSPHRASE),
        nonce,
        signature_expiration_ledger: 100_000,
        invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: account(),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        },
    }
}

/// Sign -> verify, across contexts, for one scheme.
fn round_trip<S: PqScheme>() {
    let kp = S::Keypair::from_seed(&[3u8; 32]).expect("seed");
    let sk = kp.signing_key();
    let vk = kp.verifying_key();

    for (i, ctx) in [b"".as_slice(), b"pq-stellar-v1".as_slice(), &[0xFFu8; 255]]
        .into_iter()
        .enumerate()
    {
        let p = payload(1000 + i as i64);
        let sig = sign_authorization::<S>(sk, &p, ctx).expect("sign");
        assert_eq!(sig.len(), S::SIGNATURE_LEN, "{}: signature length", S::NAME);

        verify_authorization::<S>(vk, &p, ctx, &sig).expect("verify");

        // A different context must not verify -- domain separation is the
        // whole reason the parameter exists.
        if !ctx.is_empty() {
            assert!(verify_authorization::<S>(vk, &p, b"", &sig).is_err(),
                    "{}: signature verified under the wrong context", S::NAME);
        }

        // A different nonce must not verify -- this is the replay defence.
        let replay = payload(9999);
        assert!(verify_authorization::<S>(vk, &replay, ctx, &sig).is_err(),
                "{}: signature verified against a different nonce", S::NAME);

        // Corrupting any byte must fail.
        let mut bad = sig.clone();
        bad[S::SIGNATURE_LEN / 2] ^= 0x01;
        assert!(verify_authorization::<S>(vk, &p, ctx, &bad).is_err(),
                "{}: corrupted signature accepted", S::NAME);
    }
}

/// The built entry must carry exactly the signature and the fields it was
/// signed over -- a mismatch here is an authorization failure at submit time.
fn entry_is_self_consistent<S: PqScheme>() {
    let kp = S::Keypair::from_seed(&[9u8; 32]).unwrap();
    let p = payload(4242);
    let entry =
        build_auth_entry::<S>(account(), kp.signing_key(), p.clone(), b"").expect("build entry");

    let SorobanCredentials::Address(creds) = &entry.credentials else {
        panic!("expected address credentials");
    };
    assert_eq!(creds.nonce, p.nonce);
    assert_eq!(creds.signature_expiration_ledger, p.signature_expiration_ledger);

    let ScVal::Bytes(sig) = &creds.signature else {
        panic!("expected ScVal::Bytes signature");
    };
    assert_eq!(sig.len(), S::SIGNATURE_LEN);

    // The carried signature must verify against the carried fields.
    verify_authorization::<S>(kp.verifying_key(), &p, b"", sig.as_slice())
        .expect("entry signature does not verify against its own fields");
}

fn verifying_key_encodes<S: PqScheme>() {
    let kp = S::Keypair::from_seed(&[5u8; 32]).unwrap();
    let ScVal::Bytes(b) = encode_verifying_key::<S>(kp.verifying_key()).unwrap() else {
        panic!("expected bytes");
    };
    assert_eq!(b.len(), S::VERIFYING_KEY_LEN);
    // Must survive the round trip a contract performs when reading it back.
    let decoded = S::VerifyingKey::from_bytes(b.as_slice()).expect("contract-side decode");
    let mut re = vec![0u8; S::VERIFYING_KEY_LEN];
    decoded.write_to(&mut re).unwrap();
    assert_eq!(re.as_slice(), b.as_slice());
}

macro_rules! for_scheme {
    ($name:ident, $scheme:path, $id:expr) => {
        #[test]
        fn $name() {
            type S = $scheme;
            round_trip::<S>();
            entry_is_self_consistent::<S>();
            verifying_key_encodes::<S>();
            assert_eq!(SchemeId::of::<S>(), Some($id));
            println!(
                "{}: round-trip, entry consistency, key encoding, scheme id -- all OK",
                <S as PqScheme>::NAME
            );
        }
    };
}

for_scheme!(adapter_mldsa44, pq_core::schemes::mldsa44::Scheme, SchemeId::MlDsa44);
for_scheme!(adapter_mldsa65, pq_core::schemes::mldsa65::Scheme, SchemeId::MlDsa65);

/// The adapter functions must be instantiable for a scheme that did not exist
/// when they were written. This is compile-time only -- the sketch's bodies are
/// `unimplemented!()` -- but compiling is the whole claim.
#[test]
fn adapter_is_generic_over_unimplemented_schemes() {
    #[allow(dead_code)]
    fn _instantiate<S: PqScheme>() {
        let _ = sign_authorization::<S>;
        let _ = build_auth_entry::<S>;
        let _ = encode_verifying_key::<S>;
        let _ = verify_authorization::<S>;
    }
    _instantiate::<pq_core::schemes::mldsa44::Scheme>();
    _instantiate::<pq_core::schemes::mldsa65::Scheme>();
    // A hash-based scheme with a 7,856-byte signature and a 48-byte seed.
    _instantiate::<pq_core::schemes::slhdsa_sketch::Scheme>();
    println!("adapter instantiates for ML-DSA-44, ML-DSA-65, and the SLH-DSA sketch");
}
