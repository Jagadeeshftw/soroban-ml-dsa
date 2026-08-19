//! Golden signature-payload vector, validated by the network rather than by us.
//!
//! The values below are the exact inputs of testnet transaction
//! `8aa95e1a7ffb5937fd82d608335c50ab0b6a8f6566bd674e5351fa52ea3fbcf4`
//! (ledger 4,217,131), which was authorised by an ML-DSA-65 signature verified
//! in `__check_auth` and **succeeded**.
//!
//! Success means the Soroban host computed the same 32-byte payload we did:
//! had our derivation differed by a single bit, verification would have failed
//! and the transaction would have been rejected. That makes this a
//! network-validated regression test for [`AuthorizationPayload`], not a
//! self-consistency check.

use pq_stellar::{network_id, AuthorizationPayload, TESTNET_PASSPHRASE};
use stellar_xdr::{
    ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, VecM,
};

/// `CDTEFSSESKZ7G6WFILKGND4NCN3BWGRSPLLU2JTK6ZUHR77QLTGSK73R`, the pq-account
/// contract, as raw contract-id bytes.
const ACCOUNT_ID: [u8; 32] = [
    0xe6, 0x42, 0xca, 0x44, 0x92, 0xb3, 0xf3, 0x7a, 0xc5, 0x42, 0xd4, 0x66, 0x8f, 0x8d, 0x13, 0x76,
    0x1b, 0x1a, 0x32, 0x7a, 0xd7, 0x4d, 0x26, 0x6a, 0xf6, 0x68, 0x78, 0xff, 0xf0, 0x5c, 0xcd, 0x25,
];

const NONCE: i64 = 4_217_142_651_407;
const EXPIRATION_LEDGER: u32 = 4_218_130;
const EXPECTED_PAYLOAD: &str =
    "6c91ec2abddfcdbd38b8c345f768a32fd73ba0f9bc064a2dbb7a5fc4d0e64927";

fn invocation() -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(ACCOUNT_ID))),
            function_name: ScSymbol("protected".try_into().unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    }
}

#[test]
fn payload_matches_the_one_the_network_accepted() {
    let payload = AuthorizationPayload {
        network_id: network_id(TESTNET_PASSPHRASE),
        nonce: NONCE,
        signature_expiration_ledger: EXPIRATION_LEDGER,
        invocation: invocation(),
    };
    assert_eq!(
        hex::encode(payload.signature_payload().unwrap()),
        EXPECTED_PAYLOAD,
        "signature payload no longer matches the value the Soroban host accepted \
         in testnet tx 8aa95e1a... -- any custom account built on this would fail \
         authorization with no diagnostic"
    );
}

/// Every field must actually change the payload. A field that does not is a
/// field an attacker can vary freely.
#[test]
fn every_bound_field_changes_the_payload() {
    let base = AuthorizationPayload {
        network_id: network_id(TESTNET_PASSPHRASE),
        nonce: NONCE,
        signature_expiration_ledger: EXPIRATION_LEDGER,
        invocation: invocation(),
    };
    let baseline = base.signature_payload().unwrap();

    let mut mainnet = base.clone();
    mainnet.network_id = network_id(pq_stellar::MAINNET_PASSPHRASE);
    assert_ne!(mainnet.signature_payload().unwrap(), baseline, "network not bound");

    let mut other_nonce = base.clone();
    other_nonce.nonce = NONCE + 1;
    assert_ne!(other_nonce.signature_payload().unwrap(), baseline, "nonce not bound");

    let mut other_expiry = base.clone();
    other_expiry.signature_expiration_ledger = EXPIRATION_LEDGER + 1;
    assert_ne!(other_expiry.signature_payload().unwrap(), baseline, "expiry not bound");

    let mut other_fn = base.clone();
    other_fn.invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(ACCOUNT_ID))),
            function_name: ScSymbol("unprotected".try_into().unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    };
    assert_ne!(other_fn.signature_payload().unwrap(), baseline, "invocation not bound");
}
