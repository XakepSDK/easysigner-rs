//! Known-answer self-tests, for the start of a certified module and for anyone who wants to
//! know that the build computes what it should: the hashes on standard test vectors, and GOST
//! 34.10 on each of NCA's three curves (checking a signature made elsewhere, and signing with
//! a fixed key and nonce input to a known signature). Opening a GOST key also runs a pairwise
//! check ([`crate::keys::PrivateKey::pairwise_check`]).

use gost3410::signature::hazmat::PrehashVerifier as _;
use gost3410::{CryptoProA, GostCurve, Signature, SigningKey, Tc26_256A, Tc26_512A, VerifyingKey};
use hex_literal::hex;

use crate::gost;
use crate::{Error, Result};

/// Which self-test failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelfTest {
    /// GOST 34.311-95 (GOST R 34.11-94, test parameters).
    Gost34311,
    /// GOST 34.11-2015 (Streebog), 256 bits.
    Streebog256,
    /// GOST 34.11-2015 (Streebog), 512 bits.
    Streebog512,
    Sha1,
    Sha256,
    /// GOST 34.10 on the CryptoPro-A curve (GOST 34.310-2004 keys).
    GostCryptoProA,
    /// GOST 34.10-2015 on the TC26 256-A curve.
    GostTc26_256A,
    /// GOST 34.10-2015 on the TC26 512-A curve.
    GostTc26_512A,
    /// A key opened from a file did not sign and check consistently.
    KeyPair,
}

/// Runs every known-answer test; the first failure is [`Error::SelfTestFailed`].
pub fn self_test() -> Result<()> {
    let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
    hash(
        SelfTest::Gost34311,
        gost::H_GOST34311,
        b"This is message, length=32 bytes",
        &hex!("b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa"),
    )?;
    hash(
        SelfTest::Streebog256,
        gost::H_GOST2015_256,
        m1,
        &hex!("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"),
    )?;
    hash(
        SelfTest::Streebog512,
        gost::H_GOST2015_512,
        m1,
        &hex!(
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
            "00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
        ),
    )?;
    hash(
        SelfTest::Sha1,
        gost::H_SHA1,
        b"abc",
        &hex!("a9993e364706816aba3e25717850c26c9cd0d89d"),
    )?;
    hash(
        SelfTest::Sha256,
        gost::H_SHA256,
        b"abc",
        &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    )?;
    // Each curve: a signature made by NCA's Kalkan (CryptoPro-A, 512-A) or by kzcrypto's
    // first, independent GOST code (256-A) checks; and a fixed key signs a fixed hash with fresh
    // bytes all zero to the signature recorded when this test was written.
    curve::<CryptoProA>(
        SelfTest::GostCryptoProA,
        &hex!(
            "200482f2699ddabdfe04c808731b0dc80969a8e1a3096c4a764198b36077e154"
            "2a09eda33b1411b77dde83e4278029d3ef22ad90812964a29429f010c53aedda"
        ),
        &hex!("e801bf07c37474d965a9b6e14940f6529a5d693eb779cd3308809653259d66ab"),
        &hex!(
            "bed300201aabf2aac29f100059515800e32f7e6f05db8f59b0b613b6e14fb939"
            "1f746f3f2e294179e1a61ab4eaf2500c933f9b2a0968455eeafab569cda3c49e"
        ),
        &hex!("08f178cb3deb22e379ef32944bae77e043fc99b0f0ce6a6441a4fe2bef28665c"),
        &hex!(
            "514e4d07093212e26e167429d9328a0c03ea259082b957e529506194bcd7f482"
            "21ab6b7f8827035922476851effda967e2d0d7faaf805df78ad234b5c40b02a0"
        ),
    )?;
    curve::<Tc26_256A>(
        SelfTest::GostTc26_256A,
        &hex!(
            "820490036fe47a6bf8577f829d2b61804edf968a5161b287368788aafa09071c"
            "0a6a5014766c27568ba85228f8ba139bce158fec9415b02aa738b62fc92ebdef"
        ),
        &hex!("0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186"),
        &hex!(
            "8f552f4adc09980bf6317058c8363a3f558b76b32fcf26edb572ec8eca1fc30f"
            "7ae77797e584f038e640daa10a703cb6183aea2471e480248d1e0fc6ad93e209"
        ),
        &hex!("874649f9771f5b5db6646f96ee917de1e298de7d764782196548327b542ab924"),
        &hex!(
            "b5528df27a7d1cad5c754b838573bec1a1226494860a8126e952f08f5c989c39"
            "9cafc7616ade3e9c4b021d9c4ccc2825e534dd5ee6f4a07a141a03aa9e75c020"
        ),
    )?;
    curve::<Tc26_512A>(
        SelfTest::GostTc26_512A,
        &hex!(
            "679f0cf92c7ec32568ab1c8808de3bed6dff73cb779985f52089ee06b7ab3cdd"
            "27281f73bea6ec0f4d1028fd0a8dfb3e30257e0758b2b867c58bcbbc3b8b1ae0"
            "601f87d8d3f40a990883e12df262e9c5c5b8b3fe063300a1876751c71ee46658"
            "96c081143be0ecd6430fc683829a97366f0c424dddcc4963ef34933229e43dd7"
        ),
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
        &hex!(
            "5f5bb8dc939c393a9f11b9d5a26e54d6acddea5c73d9e28994800f502c7034f2"
            "1e305aca94412faacc9bdd1b660c03dec959d629d07bb92b74b65358f6cb9404"
        ),
        &hex!(
            "d130dbe46c4dcd4f32acb64433a6d47a9c63577bc308516c87520d5e5a51d35a"
            "f6087e22671c67cb2ed25a1e1c1230337436b4ca757201c206f18e32c4ba62d6"
            "6544a952a9def3e59ec3f4ca38d3522cb3f5ef37e4fda90bf216e061a2a2c8fb"
            "69a900445b1fd333ddd944956b8b6a25749ba882e4b1f86f1977bb47dc27fca7"
        ),
    )?;
    Ok(())
}

fn hash(t: SelfTest, oid: &str, data: &[u8], want: &[u8]) -> Result<()> {
    match gost::hash(oid, data) {
        Ok(h) if h == want => Ok(()),
        _ => Err(Error::SelfTestFailed(t)),
    }
}

/// `public` checks `sig` over `hash`, and not over another hash; the key `d` gives `public`
/// and signs `hash` with fresh bytes all zero to `kat`, which `public` checks.
fn curve<C: GostCurve>(
    t: SelfTest,
    public: &[u8],
    hash: &[u8],
    sig: &[u8],
    d: &[u8],
    kat: &[u8],
) -> Result<()> {
    let fail = |_| Error::SelfTestFailed(t);
    let vk = VerifyingKey::<C>::from_nca_bytes(public).map_err(fail)?;
    let s = Signature::<C>::from_nca_bytes(sig).map_err(fail)?;
    vk.verify_prehash(hash, &s).map_err(fail)?;
    let mut other = hash.to_vec();
    if let Some(b) = other.first_mut() {
        *b ^= 1;
    }
    if vk.verify_prehash(&other, &s).is_ok() {
        return Err(Error::SelfTestFailed(t));
    }

    let sk = SigningKey::<C>::from_nca_bytes(d).map_err(fail)?;
    if sk.verifying_key() != &vk {
        return Err(Error::SelfTestFailed(t));
    }
    let h = [0x11u8; 64];
    let h = h.get(..hash.len()).ok_or(Error::SelfTestFailed(t))?;
    let mine = sk.sign_prehash_with_fresh(h, &[0; 32]).map_err(fail)?;
    let mut out = [0u8; 128];
    if mine.to_nca_bytes(&mut out).map_err(fail)? != kat {
        return Err(Error::SelfTestFailed(t));
    }
    vk.verify_prehash(h, &mine).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes() {
        self_test().unwrap();
    }

    #[test]
    fn opened_keys_pass_the_pairwise_check() {
        for name in [
            "alice_gost2004",
            "alice_gost2015",
            "alice_gost2015_256",
            "alice_rsa",
        ] {
            crate::testing::key(name)
                .private_key
                .pairwise_check()
                .unwrap();
        }
    }
}
