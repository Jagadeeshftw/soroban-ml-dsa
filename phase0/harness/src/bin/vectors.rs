// Dumps the deterministic Phase 0 test vectors as hex, for CLI/RPC use.
use ml_dsa::{MlDsa44, MlDsa65, SigningKey, Seed, Keypair};
use ml_dsa::signature::{Signer, Verifier};
use std::io::Write;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn main() {
    let dir = std::env::args().nth(1).expect("usage: vectors <outdir>");
    let msg: [u8; 32] = [7u8; 32];

    let sk65 = SigningKey::<MlDsa65>::from_seed(&Seed::from([42u8; 32]));
    let vk65 = sk65.verifying_key();
    let sig65 = sk65.sign(&msg);
    assert!(vk65.verify(&msg, &sig65).is_ok());

    let sk44 = SigningKey::<MlDsa44>::from_seed(&Seed::from([42u8; 32]));
    let vk44 = sk44.verifying_key();
    let sig44 = sk44.sign(&msg);
    assert!(vk44.verify(&msg, &sig44).is_ok());

    let out = |n: &str, b: &[u8]| {
        let mut f = std::fs::File::create(format!("{dir}/{n}.hex")).unwrap();
        write!(f, "{}", hex(b)).unwrap();
        println!("{:<12} {:>5} bytes", n, b.len());
    };
    out("msg", &msg);
    out("pk65", vk65.encode().as_slice());
    out("sig65", sig65.encode().as_slice());
    out("pk44", vk44.encode().as_slice());
    out("sig44", sig44.encode().as_slice());

    use ed25519_dalek::{SigningKey as EdSk, Signer as EdSigner};
    let ed = EdSk::from_bytes(&[9u8; 32]);
    out("ed_pk", ed.verifying_key().as_bytes());
    out("ed_sig", &ed.sign(&msg).to_bytes());
}
