// Phase 0.5: build real testnet transactions and read resource usage back from
// the network's own simulateTransaction, rather than from the local metering VM.
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{Keypair, MlDsa65, Seed, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{
    AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, PublicKey, ScAddress, ScBytes, ScSymbol, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr, ReadXdr,
};
use std::process::Command;

const RPC: &str = "https://soroban-testnet.stellar.org";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

fn rpc(method: &str, params: &str) -> serde_json::Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let out = Command::new("curl")
        .args(["-s", "-m", "60", "-X", "POST", "-H", "Content-Type: application/json", "-d", &body, RPC])
        .output()
        .expect("curl failed");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad json from {method}: {e}\n{}", String::from_utf8_lossy(&out.stdout))
    })
}

fn strkey_to_uint256(s: &str) -> [u8; 32] {
    match stellar_strkey::Strkey::from_string(s).expect("bad strkey") {
        stellar_strkey::Strkey::PublicKeyEd25519(k) => k.0,
        _ => panic!("expected G... account"),
    }
}

fn contract_addr(s: &str) -> ScAddress {
    match stellar_strkey::Strkey::from_string(s).expect("bad strkey") {
        stellar_strkey::Strkey::Contract(c) => ScAddress::Contract(ContractId(Hash(c.0))),
        _ => panic!("expected C... contract"),
    }
}

fn build_tx(source: [u8; 32], seq: i64, op: Operation) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 1_000_000,
            seq_num: seq.into(),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
}

struct Sim { insns: u64, disk_read: u64, write: u64, ro: usize, rw: usize, fee: i64,
             envelope_len: usize, final_len: usize, ok: bool, err: String }

fn simulate(env: &TransactionEnvelope, auth_mode: Option<&str>) -> Sim {
    let b64 = env.to_xdr_base64(Limits::none()).unwrap();
    let envelope_len = env.to_xdr(Limits::none()).unwrap().len();
    let params = match auth_mode {
        Some(m) => format!(r#"{{"transaction":"{b64}","authMode":"{m}"}}"#),
        None => format!(r#"{{"transaction":"{b64}"}}"#),
    };
    let v = rpc("simulateTransaction", &params);
    let r = &v["result"];
    if let Some(e) = r.get("error").and_then(|x| x.as_str()) {
        return Sim { insns:0, disk_read:0, write:0, ro:0, rw:0, fee:0, envelope_len, final_len:0, ok:false, err:e.to_string() };
    }
    let td_b64 = r["transactionData"].as_str().unwrap_or_default().to_string();
    let td = soroban_sdk::xdr::SorobanTransactionData::from_xdr_base64(&td_b64, Limits::none())
        .expect("decode transactionData");
    let res = &td.resources;

    // True on-wire size: attach the SorobanTransactionData the network returned,
    // bump the fee to cover minResourceFee, and add one 64-byte account signature.
    let final_len = {
        let mut e2 = env.clone();
        if let TransactionEnvelope::Tx(ref mut tv) = e2 {
            tv.tx.ext = TransactionExt::V1(td.clone());
            tv.tx.fee = 1_000_000;
            tv.signatures = vec![soroban_sdk::xdr::DecoratedSignature {
                hint: soroban_sdk::xdr::SignatureHint([0u8; 4]),
                signature: soroban_sdk::xdr::Signature(vec![0u8; 64].try_into().unwrap()),
            }].try_into().unwrap();
        }
        e2.to_xdr(Limits::none()).unwrap().len()
    };

    Sim {
        insns: res.instructions as u64,
        disk_read: res.disk_read_bytes as u64,
        write: res.write_bytes as u64,
        ro: res.footprint.read_only.len(),
        rw: res.footprint.read_write.len(),
        fee: r["minResourceFee"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
        envelope_len, final_len, ok: true, err: String::new(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let source_str = &args[1];
    let probe_id = &args[2];
    let account_id = &args[3];
    let source = strkey_to_uint256(source_str);

    // current sequence number
    let acct_json = rpc("getLedgerEntries", &format!(
        r#"{{"keys":["{}"],"xdrFormat":"json"}}"#,
        {
            let key = soroban_sdk::xdr::LedgerKey::Account(soroban_sdk::xdr::LedgerKeyAccount {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(source))),
            });
            key.to_xdr_base64(Limits::none()).unwrap()
        }));
    let seq: i64 = acct_json["result"]["entries"][0]["dataJson"]["account"]["seq_num"]
        .as_i64()
        .or_else(|| acct_json["result"]["entries"][0]["dataJson"]["account"]["seq_num"].as_str().and_then(|s| s.parse().ok()))
        .expect("seq_num") + 1;
    let latest_ledger = acct_json["result"]["latestLedger"].as_u64().unwrap_or(0) as u32;
    println!("source seq = {seq}, latest ledger = {latest_ledger}\n");

    // ---- vectors ----
    let msg: [u8; 32] = [7u8; 32];
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from([42u8; 32]));
    let vk = sk.verifying_key();
    let pk_bytes = vk.encode().as_slice().to_vec();
    let sig_msg = sk.sign(&msg);
    assert!(vk.verify(&msg, &sig_msg).is_ok());

    let mut rows: Vec<(String, Sim)> = Vec::new();

    // ---- A) pq-probe :: verify (ML-DSA-65, in-contract) ----
    let call = |cid: &str, func: &str, a: Vec<ScVal>| Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: contract_addr(cid),
                function_name: ScSymbol(func.try_into().unwrap()),
                args: a.try_into().unwrap(),
            }),
            auth: VecM::default(),
        }),
    };
    let b = |v: &[u8]| ScVal::Bytes(ScBytes(v.to_vec().try_into().unwrap()));

    rows.push(("pq-probe verify (ML-DSA-65)".into(), simulate(&build_tx(source, seq,
        call(probe_id, "verify", vec![b(&pk_bytes), b(&msg), b(sig_msg.encode().as_slice())])), None)));

    // ML-DSA-44
    {
        use ml_dsa::MlDsa44;
        let sk4 = SigningKey::<MlDsa44>::from_seed(&Seed::from([42u8; 32]));
        let vk4 = sk4.verifying_key();
        let s4 = sk4.sign(&msg);
        rows.push(("pq-probe verify44 (ML-DSA-44)".into(), simulate(&build_tx(source, seq,
            call(probe_id, "verify44", vec![b(vk4.encode().as_slice()), b(&msg), b(s4.encode().as_slice())])), None)));
    }

    // Ed25519 host-function baseline
    {
        use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSk};
        let ed = EdSk::from_bytes(&[9u8; 32]);
        let es = ed.sign(&msg);
        rows.push(("pq-probe ed25519 (host fn)".into(), simulate(&build_tx(source, seq,
            call(probe_id, "ed25519", vec![b(ed.verifying_key().as_bytes()), b(&msg), b(&es.to_bytes())])), None)));
    }

    // no-op VM baseline
    rows.push(("pq-probe noop (VM baseline)".into(), simulate(&build_tx(source, seq,
        call(probe_id, "noop", vec![])), None)));

    // ---- B) pq-account :: protected(), authorised by ML-DSA-65 ----
    let network_id: [u8; 32] = Sha256::digest(PASSPHRASE.as_bytes()).into();
    let nonce: i64 = (latest_ledger as i64) * 7 + 13;
    let expiry: u32 = latest_ledger + 500;
    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract_addr(account_id),
            function_name: ScSymbol("protected".try_into().unwrap()),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger: expiry,
        invocation: invocation.clone(),
    });
    let payload: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
    let auth_sig = sk.sign(&payload);
    assert!(vk.verify(&payload, &auth_sig).is_ok());

    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: contract_addr(account_id),
            nonce,
            signature_expiration_ledger: expiry,
            signature: b(auth_sig.encode().as_slice()),
        }),
        root_invocation: invocation,
    };
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: contract_addr(account_id),
                function_name: ScSymbol("protected".try_into().unwrap()),
                args: VecM::default(),
            }),
            auth: vec![entry].try_into().unwrap(),
        }),
    };
    rows.push(("pq-account protected() [ML-DSA auth]".into(),
        simulate(&build_tx(source, seq, op), Some("enforce"))));

    // ---- report ----
    const TX_MAX_INSN: u64 = 400_000_000;
    const TX_MAX_DISK_READ: u64 = 200_000;
    const TX_MAX_WRITE: u64 = 132_096;
    const TX_MAX_SIZE: u64 = 132_096;

    println!("{:<38}{:>12}{:>8}{:>11}{:>7}{:>10}{:>7}{:>9}{:>7}{:>11}",
        "operation", "insns", "%CPU", "diskRead", "%lim", "writeB", "%lim", "txBytes", "%lim", "fee(stroops)");
    println!("{}", "-".repeat(120));
    for (n, s) in &rows {
        if !s.ok { println!("{:<38}  SIMULATION ERROR: {}", n, s.err); continue; }
        println!("{:<38}{:>12}{:>7.1}%{:>11}{:>6.1}%{:>10}{:>6.1}%{:>9}{:>6.1}%{:>11}",
            n, s.insns, s.insns as f64 / TX_MAX_INSN as f64 * 100.0,
            s.disk_read, s.disk_read as f64 / TX_MAX_DISK_READ as f64 * 100.0,
            s.write, s.write as f64 / TX_MAX_WRITE as f64 * 100.0,
            s.final_len, s.final_len as f64 / TX_MAX_SIZE as f64 * 100.0,
            s.fee);
    }
    // ---- on-ledger size of the pq-account instance holding the 1952-byte verifying key ----
    {
        let key = soroban_sdk::xdr::LedgerKey::ContractData(soroban_sdk::xdr::LedgerKeyContractData {
            contract: contract_addr(account_id),
            key: ScVal::LedgerKeyContractInstance,
            durability: soroban_sdk::xdr::ContractDataDurability::Persistent,
        });
        let kb64 = key.to_xdr_base64(Limits::none()).unwrap();
        let v = rpc("getLedgerEntries", &format!(r#"{{"keys":["{kb64}"]}}"#));
        if let Some(x) = v["result"]["entries"][0]["xdr"].as_str() {
            let raw = soroban_sdk::xdr::LedgerEntryData::from_xdr_base64(x, Limits::none()).unwrap();
            let n = raw.to_xdr(Limits::none()).unwrap().len();
            println!("\npq-account instance ledger entry (holds the 1952-byte ML-DSA-65 verifying key):");
            println!("  entry size            = {} bytes", n);
            println!("  vs tx_max_disk_read_bytes (200000) = {:.2}%", n as f64 / 200_000.0 * 100.0);
            println!("  vs tx_max_write_bytes     (132096) = {:.2}%", n as f64 / 132_096.0 * 100.0);
        } else {
            println!("\n(could not read pq-account instance entry)");
        }
    }

    // ---- ledger-level throughput (CAP-0063 semantics) ----
    // ledgerMaxInstructions bounds the CRITICAL PATH, not the raw total:
    //   sequential(cluster) = sum of tx instructions in the cluster
    //   sequential(stage)   = MAX over its clusters
    //   sequential(phase)   = sum over stages   <= ledgerMaxInstructions
    // So with C parallel clusters, a single stage of balanced, non-conflicting
    // work admits C * floor(ledgerMax / per_tx) transactions.
    const LEDGER_MAX_INSN: u64 = 580_000_000;
    const CLUSTERS: u64 = 2;          // ledger_max_dependent_tx_clusters
    const LEDGER_MAX_TX_COUNT: u64 = 2000;
    const CLOSE_SECS: f64 = 5.0;

    println!("\nledger-level throughput  (ledger_max_instructions = {}, clusters = {}, tx_count cap = {})",
        LEDGER_MAX_INSN, CLUSTERS, LEDGER_MAX_TX_COUNT);
    println!("{:<38}{:>10}{:>12}{:>12}{:>11}", "operation", "%ledger", "seq/ledger", "par/ledger", "tx/sec");
    println!("{}", "-".repeat(83));
    for (n, s) in &rows {
        if !s.ok || s.insns == 0 { continue; }
        let seq_n = LEDGER_MAX_INSN / s.insns;
        let par_n = (CLUSTERS * seq_n).min(LEDGER_MAX_TX_COUNT);
        println!("{:<38}{:>9.1}%{:>12}{:>12}{:>11.1}",
            n, s.insns as f64 / LEDGER_MAX_INSN as f64 * 100.0,
            seq_n, par_n, par_n as f64 / CLOSE_SECS);
    }

    println!("\nfootprint entries (ro/rw):");
    for (n, s) in &rows { if s.ok { println!("  {:<38} ro={} rw={}", n, s.ro, s.rw); } }
}
