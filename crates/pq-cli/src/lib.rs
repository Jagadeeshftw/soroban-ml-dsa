//! Shared plumbing for the CLI tools: RPC, account state, transaction assembly.
use serde_json::Value;
use std::process::Command;
use stellar_xdr::{
    AccountId, ContractId, DecoratedSignature, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey, ReadXdr, ScAddress, ScSymbol, Signature, SignatureHint, SorobanAuthorizationEntry,
    SorobanTransactionData, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

pub const RPC: &str = "https://soroban-testnet.stellar.org";

pub fn rpc(method: &str, params: &str) -> Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let out = Command::new("curl")
        .args(["-s", "-m", "90", "-X", "POST", "-H", "Content-Type: application/json", "-d", &body, RPC])
        .output()
        .expect("curl");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad json from {method}: {e}\n{}", String::from_utf8_lossy(&out.stdout))
    })
}

pub fn account_pk(strkey: &str) -> [u8; 32] {
    match stellar_strkey::Strkey::from_string(strkey).expect("bad G-strkey") {
        stellar_strkey::Strkey::PublicKeyEd25519(k) => k.0,
        _ => panic!("expected a G... account"),
    }
}

pub fn contract_addr(strkey: &str) -> ScAddress {
    match stellar_strkey::Strkey::from_string(strkey).expect("bad C-strkey") {
        stellar_strkey::Strkey::Contract(c) => ScAddress::Contract(ContractId(Hash(c.0))),
        _ => panic!("expected a C... contract"),
    }
}

/// Current sequence number and latest ledger for a source account.
pub fn account_state(source: [u8; 32]) -> (i64, u32) {
    let key = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(source))),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let v = rpc("getLedgerEntries", &format!(r#"{{"keys":["{key}"],"xdrFormat":"json"}}"#));
    let sn = &v["result"]["entries"][0]["dataJson"]["account"]["seq_num"];
    let seq = sn
        .as_i64()
        .or_else(|| sn.as_str().and_then(|s| s.parse().ok()))
        .expect("seq_num");
    (seq, v["result"]["latestLedger"].as_u64().unwrap() as u32)
}

pub fn invoke_op(
    contract: &str,
    function: &str,
    args: Vec<stellar_xdr::ScVal>,
    auth: Vec<SorobanAuthorizationEntry>,
) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: contract_addr(contract),
                function_name: ScSymbol(function.try_into().unwrap()),
                args: args.try_into().unwrap(),
            }),
            auth: auth.try_into().unwrap(),
        }),
    }
}

pub fn build_tx(source: [u8; 32], seq: i64, op: Operation) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source)),
        fee: 1_000_000,
        seq_num: seq.into(),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into().unwrap(),
        ext: TransactionExt::V0,
    }
}

pub struct SimResult {
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    pub min_fee: i64,
    pub data: SorobanTransactionData,
}

pub fn simulate(tx: &Transaction, auth_mode: Option<&str>) -> Result<SimResult, String> {
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::default(),
    });
    let b64 = env.to_xdr_base64(Limits::none()).unwrap();
    let params = match auth_mode {
        Some(m) => format!(r#"{{"transaction":"{b64}","authMode":"{m}"}}"#),
        None => format!(r#"{{"transaction":"{b64}"}}"#),
    };
    let v = rpc("simulateTransaction", &params);
    if let Some(e) = v["result"].get("error").and_then(|x| x.as_str()) {
        return Err(e.to_string());
    }
    let data = SorobanTransactionData::from_xdr_base64(
        v["result"]["transactionData"].as_str().ok_or("no transactionData")?,
        Limits::none(),
    )
    .map_err(|e| e.to_string())?;
    Ok(SimResult {
        instructions: data.resources.instructions,
        disk_read_bytes: data.resources.disk_read_bytes,
        write_bytes: data.resources.write_bytes,
        min_fee: v["result"]["minResourceFee"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
        data,
    })
}

/// Attach resources, sign the envelope, submit, and poll to completion.
pub fn submit(mut tx: Transaction, sim: SimResult, seed: [u8; 32], network_id: [u8; 32]) -> Value {
    use ed25519_dalek::Signer;
    tx.ext = TransactionExt::V1(sim.data);
    tx.fee = (sim.min_fee + 1000) as u32;

    let payload = TransactionSignaturePayload {
        network_id: Hash(network_id),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(
        payload.to_xdr(Limits::none()).unwrap(),
    )
    .into();

    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let sig = sk.sign(&hash);
    let pk = sk.verifying_key().to_bytes();
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![DecoratedSignature {
            hint: SignatureHint([pk[28], pk[29], pk[30], pk[31]]),
            signature: Signature(sig.to_bytes().to_vec().try_into().unwrap()),
        }]
        .try_into()
        .unwrap(),
    });

    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let send = rpc(
        "sendTransaction",
        &format!(r#"{{"transaction":"{}"}}"#, env.to_xdr_base64(Limits::none()).unwrap()),
    );
    if let Some(e) = send["result"].get("errorResultXdr").and_then(|x| x.as_str()) {
        panic!("rejected: {e}");
    }
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let g = rpc("getTransaction", &format!(r#"{{"hash":"{hex}"}}"#));
        if g["result"]["status"].as_str() != Some("NOT_FOUND") {
            let mut g = g;
            g["_hash"] = Value::String(hex);
            return g;
        }
    }
    panic!("timed out waiting for inclusion");
}

pub fn secret_seed(s: &str) -> [u8; 32] {
    match stellar_strkey::Strkey::from_string(s).expect("bad S-strkey") {
        stellar_strkey::Strkey::PrivateKeyEd25519(k) => k.0,
        _ => panic!("expected an S... secret"),
    }
}
