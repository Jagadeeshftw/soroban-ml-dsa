// Milestone 3: submit a real testnet transaction authorised solely by an
// ML-DSA-65 signature, and record actual vs simulated resource usage.
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{Keypair, MlDsa65, Seed, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{
    AccountId, ContractId, DecoratedSignature, Hash, HashIdPreimage,
    HashIdPreimageSorobanAuthorization, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
    Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ReadXdr,
    ScAddress, ScBytes, ScSymbol, ScVal, Signature, SignatureHint, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanTransactionData, Transaction,
    TransactionEnvelope, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use std::process::Command;

const RPC: &str = "https://soroban-testnet.stellar.org";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

fn rpc(method: &str, params: &str) -> serde_json::Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let out = Command::new("curl")
        .args(["-s","-m","90","-X","POST","-H","Content-Type: application/json","-d",&body,RPC])
        .output().expect("curl");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad json from {method}: {e}\n{}", String::from_utf8_lossy(&out.stdout))
    })
}

fn main() {
    let src_str = std::env::args().nth(1).expect("source G...");
    let account_id = std::env::args().nth(2).expect("account C...");
    let secret = std::env::var("PQ_SECRET").expect("set PQ_SECRET to the source S... seed");

    let source: [u8; 32] = match stellar_strkey::Strkey::from_string(&src_str).unwrap() {
        stellar_strkey::Strkey::PublicKeyEd25519(k) => k.0, _ => panic!("bad source"),
    };
    let sk_seed: [u8; 32] = match stellar_strkey::Strkey::from_string(&secret).unwrap() {
        stellar_strkey::Strkey::PrivateKeyEd25519(k) => k.0, _ => panic!("bad secret"),
    };
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&sk_seed);
    let caddr = match stellar_strkey::Strkey::from_string(&account_id).unwrap() {
        stellar_strkey::Strkey::Contract(c) => ScAddress::Contract(ContractId(Hash(c.0))),
        _ => panic!("bad contract"),
    };

    // sequence + latest ledger
    let akey = soroban_sdk::xdr::LedgerKey::Account(soroban_sdk::xdr::LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(source))),
    }).to_xdr_base64(Limits::none()).unwrap();
    let av = rpc("getLedgerEntries", &format!(r#"{{"keys":["{akey}"],"xdrFormat":"json"}}"#));
    let sn = &av["result"]["entries"][0]["dataJson"]["account"]["seq_num"];
    let seq: i64 = sn.as_i64().or_else(|| sn.as_str().and_then(|s| s.parse().ok())).expect("seq") + 1;
    let latest = av["result"]["latestLedger"].as_u64().unwrap() as u32;
    println!("source {src_str}\n  seq -> {seq}, latest ledger {latest}\n");

    // ---- ML-DSA-65 auth entry over the real signature payload ----
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from([42u8; 32]));
    let vk = sk.verifying_key();
    let network_id: [u8; 32] = Sha256::digest(PASSPHRASE.as_bytes()).into();
    let nonce: i64 = (latest as i64) * 1_000_003 + 17;
    let expiry: u32 = latest + 1000;

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: caddr.clone(),
            function_name: ScSymbol("protected".try_into().unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id), nonce,
        signature_expiration_ledger: expiry, invocation: invocation.clone(),
    });
    let payload: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
    let mldsa_sig = sk.sign(&payload);
    assert!(vk.verify(&payload, &mldsa_sig).is_ok());
    println!("ML-DSA-65 auth signature over payload {}", hex(&payload));
    println!("  signature {} bytes, verifying key {} bytes\n",
        mldsa_sig.encode().as_slice().len(), vk.encode().as_slice().len());

    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: caddr.clone(), nonce, signature_expiration_ledger: expiry,
            signature: ScVal::Bytes(ScBytes(mldsa_sig.encode().as_slice().to_vec().try_into().unwrap())),
        }),
        root_invocation: invocation,
    };
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: caddr, function_name: ScSymbol("protected".try_into().unwrap()),
                args: VecM::default(),
            }),
            auth: vec![entry].try_into().unwrap(),
        }),
    };
    let mut tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source)),
        fee: 1_000_000, seq_num: seq.into(), cond: Preconditions::None, memo: Memo::None,
        operations: vec![op].try_into().unwrap(), ext: TransactionExt::V0,
    };

    // ---- simulate (enforce) to obtain resources ----
    let env0 = TransactionEnvelope::Tx(TransactionV1Envelope { tx: tx.clone(), signatures: VecM::default() });
    let sim = rpc("simulateTransaction", &format!(
        r#"{{"transaction":"{}","authMode":"enforce"}}"#, env0.to_xdr_base64(Limits::none()).unwrap()));
    if let Some(e) = sim["result"].get("error").and_then(|x| x.as_str()) { panic!("simulation failed: {e}"); }
    let td = SorobanTransactionData::from_xdr_base64(
        sim["result"]["transactionData"].as_str().unwrap(), Limits::none()).unwrap();
    let min_fee: i64 = sim["result"]["minResourceFee"].as_str().unwrap().parse().unwrap();
    let sim_insns = td.resources.instructions;
    let sim_read = td.resources.disk_read_bytes;
    let sim_write = td.resources.write_bytes;
    println!("SIMULATED: instructions {sim_insns}, diskRead {sim_read}, write {sim_write}, minResourceFee {min_fee}");

    // ---- finalise, sign, submit ----
    tx.ext = TransactionExt::V1(td);
    tx.fee = (min_fee + 1000) as u32;
    let tx_hash: [u8; 32] = Sha256::digest(
        TransactionSignaturePayload {
            network_id: Hash(network_id),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        }.to_xdr(Limits::none()).unwrap()).into();
    use ed25519_dalek::Signer as _;
    let esig = ed_sk.sign(&tx_hash);
    let hint = { let pk = ed_sk.verifying_key().to_bytes(); [pk[28],pk[29],pk[30],pk[31]] };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx, signatures: vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(esig.to_bytes().to_vec().try_into().unwrap()),
        }].try_into().unwrap(),
    });
    let wire = env.to_xdr(Limits::none()).unwrap();
    println!("declared fee {} stroops, on-wire envelope {} bytes", min_fee + 1000, wire.len());
    println!("tx hash {}\n", hex(&tx_hash));

    let send = rpc("sendTransaction", &format!(
        r#"{{"transaction":"{}"}}"#, env.to_xdr_base64(Limits::none()).unwrap()));
    println!("sendTransaction -> {}", send["result"]["status"].as_str().unwrap_or("?"));
    if let Some(e) = send["result"].get("errorResultXdr").and_then(|x| x.as_str()) {
        panic!("rejected: {e}");
    }

    // ---- poll ----
    let hash_hex = hex(&tx_hash);
    for i in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let g = rpc("getTransaction", &format!(r#"{{"hash":"{hash_hex}"}}"#));
        let st = g["result"]["status"].as_str().unwrap_or("?");
        if st == "NOT_FOUND" { print!("."); use std::io::Write; std::io::stdout().flush().ok(); continue; }
        println!("\n\n=== FINAL STATUS: {st} ===");
        println!("ledger              {}", g["result"]["ledger"]);
        if let Some(rx) = g["result"]["resultXdr"].as_str() {
            let r = soroban_sdk::xdr::TransactionResult::from_xdr_base64(rx, Limits::none()).unwrap();
            println!("feeCharged          {} stroops", r.fee_charged);
            println!("declared fee        {} stroops", min_fee + 1000);
            println!("refunded            {} stroops", (min_fee + 1000) - r.fee_charged);
            println!("result              {:?}", r.result);
        }
        println!("\nACTUAL vs SIMULATED");
        println!("  instructions declared/charged-against : {sim_insns}");
        println!("  tx hash  : {hash_hex}");
        println!("  explorer : https://stellar.expert/explorer/testnet/tx/{hash_hex}");
        return;
    }
    println!("\ntimed out waiting for inclusion");
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
