use soroban_sdk::{Bytes, Env, IntoVal, Symbol, Val};
use ml_dsa::{MlDsa44, MlDsa65, SigningKey, Seed, Keypair};
use ml_dsa::signature::{Signer, Verifier};

const WASM: &[u8] = include_bytes!("../../contract/target/wasm32v1-none/release/pq_probe.wasm");
const TX_MAX_INSN: u64 = 400_000_000;
const TX_MEM_LIMIT: u64 = 41_943_040;

fn measure(env: &Env, id: &soroban_sdk::Address, f: &str, args: soroban_sdk::Vec<Val>) -> (u64, u64, bool) {
    env.cost_estimate().budget().reset_unlimited();
    let r: bool = env.invoke_contract(id, &Symbol::new(env, f), args);
    let b = env.cost_estimate().budget();
    (b.cpu_instruction_cost(), b.memory_bytes_cost(), r)
}

fn main() {
    let env = Env::default();
    let id = env.register(WASM, ());
    let msg: [u8; 32] = [7u8; 32];
    let msg_b = Bytes::from_slice(&env, &msg);

    // ---------- baseline: VM instantiation + dispatch ----------
    let (cpu_noop, mem_noop, _) = measure(&env, &id, "noop", ().into_val(&env));

    // ---------- ML-DSA-65 ----------
    let sk65 = SigningKey::<MlDsa65>::from_seed(&Seed::from([42u8; 32]));
    let vk65 = sk65.verifying_key();
    let sig65 = sk65.sign(&msg);
    assert!(vk65.verify(&msg, &sig65).is_ok());
    let pk65_b = Bytes::from_slice(&env, vk65.encode().as_slice());
    let sig65_b = Bytes::from_slice(&env, sig65.encode().as_slice());

    let (cpu65, mem65, ok65) = measure(&env, &id, "verify",
        (pk65_b.clone(), msg_b.clone(), sig65_b.clone()).into_val(&env));
    let (cpu65d, _, _) = measure(&env, &id, "decode_only", (pk65_b.clone(),).into_val(&env));

    // failure path: flip a byte in the signature
    let mut bad = sig65.encode().as_slice().to_vec();
    bad[100] ^= 0x01;
    let bad_b = Bytes::from_slice(&env, &bad);
    let (cpu65f, _, ok65f) = measure(&env, &id, "verify",
        (pk65_b.clone(), msg_b.clone(), bad_b).into_val(&env));

    // ---------- ML-DSA-44 ----------
    let sk44 = SigningKey::<MlDsa44>::from_seed(&Seed::from([42u8; 32]));
    let vk44 = sk44.verifying_key();
    let sig44 = sk44.sign(&msg);
    assert!(vk44.verify(&msg, &sig44).is_ok());
    let pk44_b = Bytes::from_slice(&env, vk44.encode().as_slice());
    let sig44_b = Bytes::from_slice(&env, sig44.encode().as_slice());
    let (cpu44, mem44, ok44) = measure(&env, &id, "verify44",
        (pk44_b, msg_b.clone(), sig44_b).into_val(&env));

    // ---------- Ed25519 host function ----------
    use ed25519_dalek::{SigningKey as EdSk, Signer as EdSigner};
    let ed_sk = EdSk::from_bytes(&[9u8; 32]);
    let ed_sig = ed_sk.sign(&msg);
    let (cpu_ed, _, _) = measure(&env, &id, "ed25519",
        (Bytes::from_slice(&env, ed_sk.verifying_key().as_bytes()),
         msg_b.clone(),
         Bytes::from_slice(&env, &ed_sig.to_bytes())).into_val(&env));

    let net = |c: u64| c.saturating_sub(cpu_noop);
    let pct = |c: u64| c as f64 / TX_MAX_INSN as f64 * 100.0;
    let fee = |c: u64| (c as f64 / 10_000.0 * 7.0).ceil() as u64;

    println!("Soroban VM baseline (noop): {} insn, {} mem bytes\n", cpu_noop, mem_noop);
    println!("{:<34}{:>14}{:>14}{:>10}{:>12}", "operation", "cpu_insn", "net_of_vm", "%budget", "fee_stroops");
    println!("{}", "-".repeat(84));
    for (name, c, r) in [
        ("Ed25519 (host fn)", cpu_ed, "ok"),
        ("ML-DSA-44 verify (in-contract)", cpu44, if ok44 {"ok"} else {"FAIL"}),
        ("ML-DSA-65 verify (in-contract)", cpu65, if ok65 {"ok"} else {"FAIL"}),
        ("  \u{2514}\u{2500} key decode / ExpandA only", cpu65d, "ok"),
        ("ML-DSA-65 verify (bad sig)", cpu65f, if !ok65f {"rejected"} else {"LEAK"}),
    ] {
        println!("{:<34}{:>14}{:>14}{:>9.1}%{:>12}   {}", name, c, net(c), pct(c), fee(c), r);
    }
    println!("\nmemory: mldsa65 {} B, mldsa44 {} B  (tx limit {} B -> {:.2}% used)",
        mem65, mem44, TX_MEM_LIMIT, mem65 as f64 / TX_MEM_LIMIT as f64 * 100.0);
    println!("\nkey/sig sizes: ML-DSA-65 pk={} sig={} | ML-DSA-44 pk={} sig={} | Ed25519 pk=32 sig=64",
        vk65.encode().as_slice().len(), sig65.encode().as_slice().len(),
        vk44.encode().as_slice().len(), sig44.encode().as_slice().len());
    println!("\nVERDICT: ML-DSA-65 in-contract uses {:.1}% of the 400M tx budget -> {}",
        pct(cpu65), if cpu65 < TX_MAX_INSN { "FITS" } else { "EXCEEDS" });
    println!("         cost vs Ed25519 host function: {:.0}x", cpu65 as f64 / cpu_ed as f64);
    println!("         key decode is {:.0}% of total verification cost", cpu65d as f64 / cpu65 as f64 * 100.0);
}
