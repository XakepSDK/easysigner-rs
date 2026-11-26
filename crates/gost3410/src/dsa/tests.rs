//! Known-answer and cross checks against kzcrypto's original (num-bigint) GOST code and the
//! test keys made with NCA's Kalkan.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

extern crate std;
use std::{format, vec, vec::Vec};

use super::*;
use crate::{CryptoProA, Tc26_256A, Tc26_512A};
use kzcrypto::keys::{PrivateKey, PublicKey as KzPublic};

struct OsRng;
impl kzcrypto::Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> kzcrypto::Result<()> {
        getrandom::fill(buf).map_err(|_| kzcrypto::Error::new("no random numbers"))
    }
}

fn key(name: &str) -> kzcrypto::p12::Key {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    kzcrypto::p12::open(&std::fs::read(path).unwrap(), "Qwerty12", None).unwrap()
}

fn random(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

/// The generator has order q on every curve, and the cofactor check takes it.
fn generator_has_order_q<C: GostCurve>() {
    let g = ProjectivePoint::<C>::generator();
    assert!(
        bool::from((g * -Scalar::<C>::ONE + g).is_identity()),
        "{}",
        C::NAME
    );
    assert!(VerifyingKey::<C>::from_affine(g.to_affine()).is_ok());
}

#[test]
fn generators() {
    generator_has_order_q::<CryptoProA>();
    generator_has_order_q::<Tc26_256A>();
    generator_has_order_q::<Tc26_512A>();
}

/// For one test key: the same public key as kzcrypto derives, and signatures that each
/// implementation accepts from the other.
fn cross_check<C: GostCurve>(file: &str, size: usize) {
    let k = key(file);
    let (curve, d) = match &k.private_key {
        PrivateKey::Gost { curve, d, .. } => (curve, d),
        _ => panic!("{file}: not a GOST key"),
    };
    let sk = SigningKey::<C>::from_nca_bytes(&d.to_bytes_le()).unwrap();

    // public key: ours = the certificate's
    let (x, y) = match k.cert.public_key().unwrap() {
        KzPublic::Gost { x, y, .. } => (x, y),
        _ => panic!("{file}: not a GOST certificate"),
    };
    let mut xy = x.to_bytes_le();
    xy.resize(size, 0);
    let mut yb = y.to_bytes_le();
    yb.resize(size, 0);
    xy.extend(yb);
    let mut out = [0u8; 128];
    assert_eq!(
        sk.verifying_key().to_nca_bytes(&mut out).unwrap(),
        &xy[..],
        "{file}"
    );
    let vk = VerifyingKey::<C>::from_nca_bytes(&xy).unwrap();
    assert_eq!(&vk, sk.verifying_key());

    for _ in 0..8 {
        let hash = random(size);
        // ours -> theirs
        let sig = sk
            .sign_prehash_with_rng(&mut getrandom::SysRng, &hash)
            .unwrap();
        let mut buf = [0u8; 128];
        let nca = sig.to_nca_bytes(&mut buf).unwrap().to_vec();
        assert!(
            curve.verify(&x, &y, &hash, &nca),
            "{file}: kzcrypto rejects ours"
        );
        assert_eq!(Signature::<C>::from_nca_bytes(&nca).unwrap(), sig);
        vk.verify_prehash(&hash, &sig).unwrap();
        // theirs -> ours
        let theirs = curve.sign(d, &hash, size, &mut OsRng).unwrap();
        let theirs = Signature::<C>::from_nca_bytes(&theirs).unwrap();
        vk.verify_prehash(&hash, &theirs).unwrap();
        // standard form round trip
        let mut std_buf = [0u8; 128];
        let std_form = theirs.to_bytes(&mut std_buf).unwrap().to_vec();
        assert_eq!(Signature::<C>::from_bytes(&std_form).unwrap(), theirs);
        // a changed hash or signature fails
        let mut other = hash.clone();
        other[0] ^= 1;
        assert!(vk.verify_prehash(&other, &theirs).is_err());
        let mut bad = nca.clone();
        bad[size + 1] ^= 1;
        if let Ok(bad) = Signature::<C>::from_nca_bytes(&bad) {
            assert!(vk.verify_prehash(&hash, &bad).is_err());
        }
    }
}

#[test]
fn same_as_kzcrypto_gost2004() {
    cross_check::<CryptoProA>("kalkan/alice_gost2004.p12", 32);
    cross_check::<CryptoProA>("keys/bob_gost2004.p12", 32);
}

#[test]
fn same_as_kzcrypto_gost2015_256() {
    cross_check::<Tc26_256A>("keys/alice_gost2015_256.p12", 32);
    cross_check::<Tc26_256A>("keys/bob_gost2015_256.p12", 32);
}

#[test]
fn same_as_kzcrypto_gost2015_512() {
    cross_check::<Tc26_512A>("kalkan/alice_gost2015.p12", 64);
    cross_check::<Tc26_512A>("keys/bob_gost2015.p12", 64);
}

/// The nonce is deterministic in (key, hash, fresh bytes) and changes with each.
#[test]
fn hedged_nonces() {
    let sk = SigningKey::<CryptoProA>::from_nca_bytes(&[7; 32]).unwrap();
    let h = [1u8; 32];
    let a = sk.sign_prehash_with_fresh(&h, &[0; 32]).unwrap();
    assert_eq!(a, sk.sign_prehash_with_fresh(&h, &[0; 32]).unwrap());
    assert_ne!(a, sk.sign_prehash_with_fresh(&h, &[1; 32]).unwrap());
    assert_ne!(a, sk.sign_prehash_with_fresh(&[2; 32], &[0; 32]).unwrap());
    let other = SigningKey::<CryptoProA>::from_nca_bytes(&[8; 32]).unwrap();
    assert_ne!(
        a.r(),
        other.sign_prehash_with_fresh(&h, &[0; 32]).unwrap().r()
    );
}

/// Bad keys, hashes and signatures are errors, never panics.
#[test]
fn rejects_bad_input() {
    assert!(SigningKey::<CryptoProA>::from_nca_bytes(&[0; 32]).is_err());
    assert!(SigningKey::<CryptoProA>::from_nca_bytes(&[0xff; 32]).is_err()); // >= q
    assert!(SigningKey::<CryptoProA>::from_nca_bytes(&[1; 33]).is_err());
    assert!(VerifyingKey::<CryptoProA>::from_nca_bytes(&[1; 64]).is_err()); // not on the curve
    assert!(VerifyingKey::<CryptoProA>::from_nca_bytes(&[1; 10]).is_err());
    assert!(Signature::<CryptoProA>::from_nca_bytes(&[0; 64]).is_err());
    assert!(Signature::<CryptoProA>::from_nca_bytes(&[0xff; 64]).is_err());
    assert!(Signature::<CryptoProA>::from_nca_bytes(&[1; 63]).is_err());
    let sk = SigningKey::<CryptoProA>::from_nca_bytes(&[7; 32]).unwrap();
    assert!(sk.sign_prehash_with_fresh(&[1; 33], &[0; 32]).is_err());
    // a zero hash is signed as e = 1
    let s = sk.sign_prehash_with_fresh(&[0; 32], &[0; 32]).unwrap();
    sk.verifying_key().verify_prehash(&[0; 32], &s).unwrap();
}

/// TC26 256-A has cofactor 4: a point outside the order-q subgroup is not a public key.
#[test]
fn small_subgroup_points_are_refused() {
    use elliptic_curve::group::GroupEncoding as _;
    let _ = ProjectivePoint::<Tc26_256A>::generator().to_bytes();
    // a point of order 4·q or 2·q: search small x for points on the curve, keep one not in
    // the subgroup
    let mut found = false;
    for x in 1u64..400 {
        let mut xb = [0u8; 32];
        xb[..8].copy_from_slice(&x.to_le_bytes());
        for sign in [2u8, 3] {
            let mut sec1 = vec![sign];
            sec1.extend(xb.iter().rev());
            let Ok(pk) = PublicKey::<Tc26_256A>::from_sec1_bytes(&sec1) else {
                continue;
            };
            let p = ProjectivePoint::<Tc26_256A>::from(*pk.as_affine());
            let in_subgroup = bool::from((p * -Scalar::<Tc26_256A>::ONE + p).is_identity());
            if !in_subgroup {
                assert!(VerifyingKey::<Tc26_256A>::from_affine(*pk.as_affine()).is_err());
                found = true;
            }
        }
        if found {
            break;
        }
    }
    assert!(found, "no point outside the subgroup found");
}
