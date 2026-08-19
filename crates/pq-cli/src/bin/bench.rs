//! Milestone 4: on-network cost harness.
//!
//! Every figure comes from `simulateTransaction` against a deployed contract,
//! never the local metering VM — the local host under-reports this workload by
//! ~4.3% and omits a fixed ~2.2M instruction VM/ledger overhead.
//!
//! usage: bench <SOURCE_G...> <VERIFIER_C...>

use pq_cli::*;
use pq_core::{PqEncode, PqKeypair, PqScheme, PqSigner};
use stellar_xdr::{ScBytes, ScVal};

// Live testnet config (ConfigSettingContractComputeV0 / ContractBandwidthV0).
const TX_MAX_INSN: u64 = 400_000_000;
const LEDGER_MAX_INSN: u64 = 580_000_000;
const CLUSTERS: u64 = 2; // ledger_max_dependent_tx_clusters
const LEDGER_MAX_TX_COUNT: u64 = 2000;
const CLOSE_SECS: f64 = 5.00;

fn b(v: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(v.to_vec().try_into().unwrap()))
}

struct Row {
    label: String,
    insns: u64,
    fee: i64,
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (source_str, verifier) = (&a[1], &a[2]);
    let source = account_pk(source_str);
    let (seq, _) = account_state(source);

    let measure = |label: &str, func: &str, args: Vec<ScVal>| -> Row {
        let tx = build_tx(source, seq + 1, invoke_op(verifier, func, args, vec![]));
        match simulate(&tx, None) {
            Ok(s) => Row { label: label.into(), insns: s.instructions as u64, fee: s.min_fee },
            Err(e) => panic!("{label}: simulation failed: {e}"),
        }
    };

    // ---- vectors -------------------------------------------------------
    let msg32 = [7u8; 32];

    type S65 = pq_core::schemes::mldsa65::Scheme;
    type S44 = pq_core::schemes::mldsa44::Scheme;

    let kp65 = <S65 as PqScheme>::Keypair::from_seed(&[42u8; 32]).unwrap();
    let mut vk65 = vec![0u8; <S65 as PqScheme>::VERIFYING_KEY_LEN];
    kp65.verifying_key().write_to(&mut vk65).unwrap();
    let sign65 = |m: &[u8]| {
        let mut s = vec![0u8; <S65 as PqScheme>::SIGNATURE_LEN];
        kp65.signing_key().sign_into(m, &[], &mut s).unwrap();
        s
    };

    let kp44 = <S44 as PqScheme>::Keypair::from_seed(&[42u8; 32]).unwrap();
    let mut vk44 = vec![0u8; <S44 as PqScheme>::VERIFYING_KEY_LEN];
    kp44.verifying_key().write_to(&mut vk44).unwrap();
    let mut sig44 = vec![0u8; <S44 as PqScheme>::SIGNATURE_LEN];
    kp44.signing_key().sign_into(&msg32, &[], &mut sig44).unwrap();

    use ed25519_dalek::Signer as _;
    let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let ed_sig = ed.sign(&msg32);

    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey as P256Sk};
    use sha2::{Digest, Sha256};
    let p_sk = P256Sk::from_bytes(&[0x11u8; 32].into()).unwrap();
    let digest: [u8; 32] = Sha256::digest(msg32).into();
    let (p_sig, _): (p256::ecdsa::Signature, _) = p_sk.sign_prehash(&digest).unwrap();
    let p_pk = p_sk.verifying_key().to_encoded_point(false);

    // ---- measurements --------------------------------------------------
    let noop = measure("no-op (VM instantiation)", "noop", vec![]);
    let rows = vec![
        Row { label: noop.label.clone(), insns: noop.insns, fee: noop.fee },
        measure("Ed25519 (host fn)", "ed25519",
            vec![b(ed.verifying_key().as_bytes()), b(&msg32), b(&ed_sig.to_bytes())]),
        measure("ECDSA secp256r1 (host fn)", "secp256r1",
            vec![b(p_pk.as_bytes()), b(&msg32), b(&p_sig.to_bytes())]),
        measure("ML-DSA-44 decode key only", "decode44", vec![b(&vk44)]),
        measure("ML-DSA-44 verify (in contract)", "verify44",
            vec![b(&vk44), b(&msg32), b(&sig44)]),
        measure("ML-DSA-65 decode key only", "decode65", vec![b(&vk65)]),
        measure("ML-DSA-65 verify (in contract)", "verify65",
            vec![b(&vk65), b(&msg32), b(&sign65(&msg32))]),
    ];

    // ---- HEADLINE: ledger throughput -----------------------------------
    println!("\n{}", "=".repeat(94));
    println!("LEDGER THROUGHPUT  (ledger_max_instructions = {LEDGER_MAX_INSN}, clusters = {CLUSTERS}, close {CLOSE_SECS:.2}s)");
    println!("{}", "=".repeat(94));
    println!("{:<34}{:>12}{:>10}{:>12}{:>14}{:>10}", "operation", "insns", "%ledger", "seq/ledger", "per ledger", "per sec");
    println!("{}", "-".repeat(94));
    for r in &rows {
        let seq_n = LEDGER_MAX_INSN / r.insns.max(1);
        let par = (CLUSTERS * seq_n).min(LEDGER_MAX_TX_COUNT);
        println!("{:<34}{:>12}{:>9.1}%{:>12}{:>14}{:>10.1}",
            r.label, r.insns, r.insns as f64 / LEDGER_MAX_INSN as f64 * 100.0,
            seq_n, par, par as f64 / CLOSE_SECS);
    }
    println!("\nledger_max_instructions bounds the CRITICAL PATH (CAP-0063): sequential(stage)");
    println!("is the max across its clusters, summed across stages. 'per ledger' assumes two");
    println!("balanced non-conflicting clusters; 'seq/ledger' is the strictly sequential case.");
    println!("ledger_max_tx_count ({LEDGER_MAX_TX_COUNT}) is not binding for any row.");

    // ---- per transaction ------------------------------------------------
    println!("\n{}", "=".repeat(94));
    println!("PER TRANSACTION  (tx_max_instructions = {TX_MAX_INSN})");
    println!("{}", "=".repeat(94));
    println!("{:<34}{:>12}{:>9}{:>14}{:>16}", "operation", "insns", "%tx", "fee(stroops)", "net of no-op");
    println!("{}", "-".repeat(94));
    for r in &rows {
        println!("{:<34}{:>12}{:>8.1}%{:>14}{:>16}",
            r.label, r.insns, r.insns as f64 / TX_MAX_INSN as f64 * 100.0, r.fee,
            r.insns.saturating_sub(noop.insns));
    }
    let net = |i: u64| i.saturating_sub(noop.insns) as f64;
    let find = |s: &str| rows.iter().find(|r| r.label.starts_with(s)).unwrap().insns;
    println!("\nML-DSA-65 vs Ed25519 host fn, net of VM baseline: {:.0}x",
        net(find("ML-DSA-65 verify")) / net(find("Ed25519")));
    println!("ML-DSA-65 vs secp256r1 host fn, net of VM baseline: {:.0}x",
        net(find("ML-DSA-65 verify")) / net(find("ECDSA")));

    // ---- CAP-0087 cost-type split ---------------------------------------
    println!("\n{}", "=".repeat(94));
    println!("COST SPLIT  (mirrors CAP-0087's MlDsaNNDecodeVerifyingKey / VerifyMlDsaNNSig)");
    println!("{}", "=".repeat(94));
    for (set, dec, ver) in [
        ("ML-DSA-44", find("ML-DSA-44 decode"), find("ML-DSA-44 verify")),
        ("ML-DSA-65", find("ML-DSA-65 decode"), find("ML-DSA-65 verify")),
    ] {
        let d = net(dec);
        let total = net(ver);
        println!("  {set}:  decode/ExpandA {:>12.0} ({:.0}%)   verify proper {:>12.0} ({:.0}%)",
            d, d / total * 100.0, total - d, (total - d) / total * 100.0);
    }

    // ---- message-length linearity ---------------------------------------
    println!("\n{}", "=".repeat(94));
    println!("MESSAGE-LENGTH SWEEP, ML-DSA-65  (CAP-0087 models verification as linear in message length)");
    println!("{}", "=".repeat(94));
    println!("{:>10}{:>14}{:>16}{:>18}", "msg bytes", "insns", "net of no-op", "insns per byte");
    println!("{}", "-".repeat(94));
    let mut prev: Option<(usize, f64)> = None;
    for len in [32usize, 256, 1024, 4096, 8192] {
        let m = vec![0x5Au8; len];
        let r = measure(&format!("len {len}"), "verify65", vec![b(&vk65), b(&m), b(&sign65(&m))]);
        let n = net(r.insns);
        let slope = prev.map(|(pl, pn)| (n - pn) / (len - pl) as f64);
        println!("{:>10}{:>14}{:>16.0}{:>18}", len, r.insns, n,
            slope.map(|s| format!("{s:.1}")).unwrap_or_else(|| "-".into()));
        prev = Some((len, n));
    }
    println!("\nA flat marginal cost per byte across the sweep supports the CAP's linear model;");
    println!("the constant term dominates at realistic payload sizes (a 32-byte auth payload).");
}
