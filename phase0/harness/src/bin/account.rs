use soroban_sdk::xdr::{
    HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScAddress,
    ScSymbol, ScVal, ScBytes, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, VecM, WriteXdr, Hash,
};
use soroban_sdk::{Bytes, Env, IntoVal, Symbol};
use ml_dsa::{MlDsa65, SigningKey, Seed, Keypair};
use ml_dsa::signature::{Signer, Verifier};
use sha2::{Digest, Sha256};

const WASM: &[u8] = include_bytes!("../../../account/target/wasm32v1-none/release/pq_account.wasm");
const TX_MAX_INSN: u64 = 400_000_000;

fn main() {
    let env = Env::default();
    let id = env.register(WASM, ());

    // ---- off-chain key material ----
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from([42u8; 32]));
    let vk = sk.verifying_key();
    let pk_b = Bytes::from_slice(&env, vk.encode().as_slice());

    // init stores the ML-DSA verifying key on the account
    let _: () = env.invoke_contract(&id, &Symbol::new(&env, "init"), (pk_b,).into_val(&env));
    println!("account initialised with ML-DSA-65 verifying key ({} bytes)", vk.encode().as_slice().len());

    // ---- build the real auth entry for `protected()` ----
    let nonce: i64 = 0xCAFE;
    let expiry: u32 = 1000;
    let sc_addr: ScAddress = id.clone().try_into().unwrap();
    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: sc_addr.clone(),
            function_name: ScSymbol("protected".try_into().unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    };

    // signature payload = SHA256(XDR(HashIdPreimage::SorobanAuthorization))
    let network_id: [u8; 32] = env.ledger().network_id().into();
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger: expiry,
        invocation: invocation.clone(),
    });
    let payload: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
    println!("signature payload = {}", hex(&payload));

    // ---- sign the payload with ML-DSA-65, entirely off-chain ----
    let sig = sk.sign(&payload);
    assert!(vk.verify(&payload, &sig).is_ok(), "offchain self-check failed");
    let sig_bytes = sig.encode().as_slice().to_vec();
    println!("ML-DSA-65 signature = {} bytes", sig_bytes.len());

    let entry = SorobanAuthorizationEntry {
        credentials: soroban_sdk::xdr::SorobanCredentials::Address(SorobanAddressCredentials {
            address: sc_addr,
            nonce,
            signature_expiration_ledger: expiry,
            signature: ScVal::Bytes(ScBytes(sig_bytes.clone().try_into().unwrap())),
        }),
        root_invocation: invocation,
    };

    // ---- invoke under real auth; __check_auth runs ML-DSA verification on-chain ----
    env.cost_estimate().budget().reset_unlimited();
    env.set_auths(&[entry.clone()]);
    let r: u32 = env.invoke_contract(&id, &Symbol::new(&env, "protected"), ().into_val(&env));
    let b = env.cost_estimate().budget();
    let cpu = b.cpu_instruction_cost();
    println!("\n=== AUTHORISED CALL SUCCEEDED ===");
    println!("protected() returned  = {}", r);
    println!("total tx cpu_insn     = {}  ({:.1}% of {} budget)", cpu, cpu as f64 / TX_MAX_INSN as f64 * 100.0, TX_MAX_INSN);
    println!("total tx mem_bytes    = {}", b.memory_bytes_cost());
    println!("headroom left         = {} insn", TX_MAX_INSN.saturating_sub(cpu));

    // ---- negative control: tamper the signature, auth must fail ----
    let mut bad = sig_bytes.clone();
    bad[500] ^= 0x01;
    let bad_entry = SorobanAuthorizationEntry {
        credentials: soroban_sdk::xdr::SorobanCredentials::Address(SorobanAddressCredentials {
            address: id.clone().try_into().unwrap(),
            nonce: 0xBEEF,
            signature_expiration_ledger: expiry,
            signature: ScVal::Bytes(ScBytes(bad.try_into().unwrap())),
        }),
        root_invocation: match entry.root_invocation.function {
            SorobanAuthorizedFunction::ContractFn(ref a) => SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(a.clone()),
                sub_invocations: VecM::default(),
            },
            _ => unreachable!(),
        },
    };
    env.set_auths(&[bad_entry]);
    let res: Result<Result<u32, _>, _> =
        env.try_invoke_contract::<u32, soroban_sdk::Error>(&id, &Symbol::new(&env, "protected"), ().into_val(&env));
    match res {
        Err(_) | Ok(Err(_)) => println!("\nnegative control: tampered signature REJECTED (correct)"),
        Ok(Ok(v)) => println!("\n*** SECURITY FAILURE: tampered signature accepted, returned {} ***", v),
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
