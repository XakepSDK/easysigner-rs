//! Known-answer tests from signatures made by NCA's Kalkan and by kzcrypto's original
//! (num-bigint) GOST code, and checks on random keys.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

extern crate std;
use std::{vec, vec::Vec};

use super::*;
use crate::{CryptoProA, Tc26_256A, Tc26_512A};
use hex_literal::hex;

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

/// A signature someone else made: the key checks it, and fails it for another hash or a
/// changed signature.
fn verifies<C: GostCurve>(public: &[u8], hash: &[u8], sig: &[u8]) {
    let vk = VerifyingKey::<C>::from_nca_bytes(public).unwrap();
    let mut out = [0u8; 128];
    assert_eq!(vk.to_nca_bytes(&mut out).unwrap(), public);
    let s = Signature::<C>::from_nca_bytes(sig).unwrap();
    assert_eq!(s.to_nca_bytes(&mut out).unwrap(), sig);
    vk.verify_prehash(hash, &s).unwrap();
    let mut std_buf = [0u8; 128];
    let std_form = s.to_bytes(&mut std_buf).unwrap().to_vec();
    assert_eq!(Signature::<C>::from_bytes(&std_form).unwrap(), s);

    let mut other = hash.to_vec();
    other[0] ^= 1;
    assert!(vk.verify_prehash(&other, &s).is_err());
    for i in [0, sig.len() / 2] {
        let mut bad = sig.to_vec();
        bad[i] ^= 1;
        if let Ok(bad) = Signature::<C>::from_nca_bytes(&bad) {
            assert!(vk.verify_prehash(hash, &bad).is_err());
        }
    }
}

/// A test key: the public key derived from d, and signatures it makes check.
fn key<C: GostCurve>(d: &[u8], public: &[u8]) {
    let sk = SigningKey::<C>::from_nca_bytes(d).unwrap();
    let mut out = [0u8; 128];
    assert_eq!(sk.verifying_key().to_nca_bytes(&mut out).unwrap(), public);
    assert_eq!(
        sk.verifying_key(),
        &VerifyingKey::<C>::from_nca_bytes(public).unwrap()
    );
    for _ in 0..8 {
        let hash = random(d.len());
        let sig = sk
            .sign_prehash_with_rng(&mut getrandom::SysRng, &hash)
            .unwrap();
        verifies::<C>(public, &hash, sig.to_nca_bytes(&mut out).unwrap());
    }
}

// alice_gost2004 (Kalkan), and a signature Kalkan made (fixtures kalkan/cosigned_gost2004.cms)
const ALICE_2004_D: [u8; 32] =
    hex!("08f178cb3deb22e379ef32944bae77e043fc99b0f0ce6a6441a4fe2bef28665c");
const ALICE_2004: [u8; 64] = hex!(
    "200482f2699ddabdfe04c808731b0dc80969a8e1a3096c4a764198b36077e154"
    "2a09eda33b1411b77dde83e4278029d3ef22ad90812964a29429f010c53aedda"
);

#[test]
fn gost2004() {
    key::<CryptoProA>(&ALICE_2004_D, &ALICE_2004);
    verifies::<CryptoProA>(
        &ALICE_2004,
        &hex!("e801bf07c37474d965a9b6e14940f6529a5d693eb779cd3308809653259d66ab"),
        &hex!(
            "bed300201aabf2aac29f100059515800e32f7e6f05db8f59b0b613b6e14fb939"
            "1f746f3f2e294179e1a61ab4eaf2500c933f9b2a0968455eeafab569cda3c49e"
        ),
    );
    verifies::<CryptoProA>(
        &hex!(
            "29082b03151384d9759e65fb28a5dadc65ceb31b4592e54cc3d9e165be22ff1a"
            "fae1231c100dc5ba51db3fe03e386aa4ab0ec78935023caec08333484d879e9b"
        ),
        &hex!("5c01c61bf98103fed2d5e37b2f1bfe0a929603be0c382aa26087b92561a1484d"),
        &hex!(
            "fec866ecaffbb5f963824cec09d745f2479dc6702360c90c888e386d3d590e17"
            "113ae90a4fa42c78be4da7f9a2a428f866a958d7664e796efed161f13b489f96"
        ),
    );
}

// alice_gost2015_256 (fixtures keys/), and a signature kzcrypto's original code made
const ALICE_256_D: [u8; 32] =
    hex!("874649f9771f5b5db6646f96ee917de1e298de7d764782196548327b542ab924");
const ALICE_256: [u8; 64] = hex!(
    "820490036fe47a6bf8577f829d2b61804edf968a5161b287368788aafa09071c"
    "0a6a5014766c27568ba85228f8ba139bce158fec9415b02aa738b62fc92ebdef"
);

#[test]
fn gost2015_256() {
    key::<Tc26_256A>(&ALICE_256_D, &ALICE_256);
    verifies::<Tc26_256A>(
        &ALICE_256,
        &hex!("0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"),
        &hex!(
            "8f552f4adc09980bf6317058c8363a3f558b76b32fcf26edb572ec8eca1fc30f"
            "7ae77797e584f038e640daa10a703cb6183aea2471e480248d1e0fc6ad93e209"
        ),
    );
}

// alice_gost2015 (Kalkan), and signatures Kalkan made (fixtures kalkan/cosigned_gost2015.cms)
const ALICE_512_D: [u8; 64] = hex!(
    "5f5bb8dc939c393a9f11b9d5a26e54d6acddea5c73d9e28994800f502c7034f2"
    "1e305aca94412faacc9bdd1b660c03dec959d629d07bb92b74b65358f6cb9404"
);
const ALICE_512: [u8; 128] = hex!(
    "679f0cf92c7ec32568ab1c8808de3bed6dff73cb779985f52089ee06b7ab3cdd"
    "27281f73bea6ec0f4d1028fd0a8dfb3e30257e0758b2b867c58bcbbc3b8b1ae0"
    "601f87d8d3f40a990883e12df262e9c5c5b8b3fe063300a1876751c71ee46658"
    "96c081143be0ecd6430fc683829a97366f0c424dddcc4963ef34933229e43dd7"
);

#[test]
fn gost2015_512() {
    key::<Tc26_512A>(&ALICE_512_D, &ALICE_512);
    verifies::<Tc26_512A>(
        &ALICE_512,
        &hex!(
            "6f8835a900675e7be65b621c83c39216ebcc93b3a25d5a914d9a66538b2e0d46"
            "07741a1ec2bf761e5e7ed3c09eca0cb213889ab7a9d9c8afb3e93c02c4d243ad"
        ),
        &hex!(
            "ecc6d311b93ba55d8d7e6dd2d6f15496a28c053465a895aeec8dcb9397114e8c"
            "dcd487aacc0b5c9859298624e090a66dcee11135c2129f4af6a48d0f1652227a"
            "9867249e423138b0f4b4f1de2313542238a4cf19ce69820d1811ab094bd7de95"
            "6cc8f2a92e5173a8b1102c4b495047f569a7452bfe4b6f5e2d39ab830eccbfc0"
        ),
    );
    verifies::<Tc26_512A>(
        &hex!(
            "1fb4964197ee7c5e8459822eea68b72847747c1851e1379a0cb9d97c30f86560"
            "eedc92c8ca0951ca7b42d1683f805c5aa973c357c3f4d9229f777f2ad39c03d8"
            "6a99184fa5bb318177dcbf86bb3a92916f314676f5bef23ed095ce9da46d2b31"
            "93f39e23ba9460335128a5d88b38be073e052ab42c5f5ca492d5cc15d31105fe"
        ),
        &hex!(
            "b879d5fb8926e4747bfb057f721932062acd35114205d89cd38f4e1ee9b97364"
            "77265f6d7993091a4168b4be343a37cd41d36157ca350d196aa2ecc399e00098"
        ),
        &hex!(
            "b56a44089bb0c41c65318b367fee13598f70c7a163008b33e27a686d5eba1d33"
            "27d982a482d73f8dd6484aa7be2be32c8faf4166c871d375e6a8fca6506c4ae1"
            "48feee9472b95f983532f4c9ed00921df27794bdfdb229fee78d80a95f993ece"
            "3b1a7bcd018340116cb03c145140e3e10b53e798d750198da0066e2f0ce5536f"
        ),
    );
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
