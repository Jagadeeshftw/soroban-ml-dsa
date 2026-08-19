//! End-to-end: deploy-agnostic authorisation of a pq-account using pq-stellar.
//!
//! The client side here goes entirely through `pq-stellar`, which goes through
//! `pq-core` — the same crate the contract links. If contract and client ever
//! disagreed about encoding, context handling, or the payload derivation, this
//! would fail rather than silently producing an unusable signature.
//!
//! usage: PQ_SECRET=S... authorize <SOURCE_G...> <ACCOUNT_C...> [init|auth]

use pq_cli::*;
use pq_core::{PqKeypair, PqScheme};
use pq_stellar::auth::{build_auth_entry, encode_verifying_key};
use pq_stellar::{network_id, AuthorizationPayload, TESTNET_PASSPHRASE};
use stellar_xdr::{
    InvokeContractArgs, ScSymbol, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, VecM,
};

type S = pq_core::schemes::mldsa65::Scheme;

/// Must match the contract's CONTEXT constant exactly.
const CONTEXT: &[u8] = b"pq-account-v1";
const SEED: [u8; 32] = [42u8; 32];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (source_str, account) = (&args[1], &args[2]);
    let mode = args.get(3).map(String::as_str).unwrap_or("auth");
    let seed = secret_seed(&std::env::var("PQ_SECRET").expect("PQ_SECRET"));
    let source = account_pk(source_str);
    let net = network_id(TESTNET_PASSPHRASE);

    let kp = <S as PqScheme>::Keypair::from_seed(&SEED).unwrap();
    let (seq, latest) = account_state(source);
    println!("source seq {seq}, latest ledger {latest}");

    let (tx, sim) = if mode == "init" {
        // Store the verifying key. Encoding comes from pq-stellar, so the bytes
        // the contract receives are the bytes pq-core produced.
        let vk_scval = encode_verifying_key::<S>(kp.verifying_key()).unwrap();
        println!("storing {}-byte verifying key", <S as PqScheme>::VERIFYING_KEY_LEN);
        let tx = build_tx(source, seq + 1, invoke_op(account, "init", vec![vk_scval], vec![]));
        let sim = simulate(&tx, None).expect("init simulation failed");
        (tx, sim)
    } else {
        // Build the authorisation entirely through pq-stellar.
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract_addr(account),
                function_name: ScSymbol("protected".try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        };
        let payload = AuthorizationPayload {
            network_id: net,
            nonce: (latest as i64) * 1_000_003 + 29,
            signature_expiration_ledger: latest + 1000,
            invocation: invocation.clone(),
        };
        println!(
            "signature payload {}",
            payload.signature_payload().unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>()
        );

        let entry = build_auth_entry::<S>(contract_addr(account), kp.signing_key(), payload, CONTEXT)
            .expect("build_auth_entry");
        println!("auth entry built via pq-stellar, context {:?}", std::str::from_utf8(CONTEXT).unwrap());

        let tx = build_tx(source, seq + 1, invoke_op(account, "protected", vec![], vec![entry]));
        let sim = simulate(&tx, Some("enforce")).expect("auth simulation failed");
        (tx, sim)
    };

    println!(
        "simulated: {} instructions, diskRead {}, write {}, minResourceFee {}",
        sim.instructions, sim.disk_read_bytes, sim.write_bytes, sim.min_fee
    );

    let r = submit(tx, sim, seed, net);
    let status = r["result"]["status"].as_str().unwrap_or("?");
    println!("\n=== {status} ===");
    println!("ledger  {}", r["result"]["ledger"]);
    println!("tx      {}", r["_hash"].as_str().unwrap_or(""));
    println!("explorer https://stellar.expert/explorer/testnet/tx/{}", r["_hash"].as_str().unwrap_or(""));
    assert_eq!(status, "SUCCESS", "transaction did not succeed");
}
