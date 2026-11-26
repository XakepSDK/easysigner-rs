//! Kazakhstan's national algorithms (as used by NCA RK), with no NCA code.
//!
//! The KZ standards are profiles of the Russian ones; only the OIDs and byte conventions differ:
//!
//! * GOST 34.311-95 hash (1.2.398.3.10.1.3.1) = GOST R 34.11-94 with the "test" S-box.
//! * GOST 34.11-2015 hash (1.2.398.3.10.1.3.2/3) = GOST R 34.11-2012 (Streebog) 256/512.
//! * GOST 34.310-2004 keys use the CryptoPro-A curve; GOST 34.10-2015 keys the TC26 256-A /
//!   512-A curves. Signatures are the GOST R 34.10 scheme.
//! * Signature value = r || s, each little-endian. Public key = OCTET STRING of X || Y,
//!   little-endian. 2015 private keys are a little-endian OCTET STRING, 2004 keys an INTEGER.
//!
//! The curve arithmetic and the signature scheme are the `gost3410` crate's; this module names
//! the algorithms and computes the digests.
//!
//! These were established by byte-for-byte comparison with NCA's own kalkancrypt, and are
//! checked against Kalkan-made files in tests/fixtures/kalkan and NCA's real CA certificates.

use crate::prelude::*;
use crate::{Error, Result};

pub const SIG_GOST2004: &str = "1.2.398.3.10.1.1.1.2";
pub const SIG_GOST2015_256: &str = "1.2.398.3.10.1.1.2.3.1";
pub const SIG_GOST2015_512: &str = "1.2.398.3.10.1.1.2.3.2";
pub const KEY_GOST2004: &str = "1.2.398.3.10.1.1.1.1";
pub const KEY_GOST2015_256: &str = "1.2.398.3.10.1.1.2.1";
pub const KEY_GOST2015_512: &str = "1.2.398.3.10.1.1.2.2";
pub const H_GOST34311: &str = "1.2.398.3.10.1.3.1";
pub const H_GOST2015_256: &str = "1.2.398.3.10.1.3.2";
pub const H_GOST2015_512: &str = "1.2.398.3.10.1.3.3";
pub const H_SHA1: &str = "1.3.14.3.2.26";
pub const H_SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const H_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const H_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const H_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SIG_SHA256_RSA: &str = "1.2.840.113549.1.1.11";

/// A KZ GOST key type: its signature algorithm, digest and size (bytes per coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scheme {
    pub key_oid: &'static str,
    pub sig_oid: &'static str,
    pub digest_oid: &'static str,
    pub size: usize,
}

pub const SCHEMES: [Scheme; 3] = [
    Scheme {
        key_oid: KEY_GOST2004,
        sig_oid: SIG_GOST2004,
        digest_oid: H_GOST34311,
        size: 32,
    },
    Scheme {
        key_oid: KEY_GOST2015_256,
        sig_oid: SIG_GOST2015_256,
        digest_oid: H_GOST2015_256,
        size: 32,
    },
    Scheme {
        key_oid: KEY_GOST2015_512,
        sig_oid: SIG_GOST2015_512,
        digest_oid: H_GOST2015_512,
        size: 64,
    },
];

pub fn by_key(oid: &str) -> Option<Scheme> {
    SCHEMES.iter().copied().find(|s| s.key_oid == oid)
}

/// By signature OID (or, leniently, by key OID, which some files name instead).
pub fn by_sig(oid: &str) -> Option<Scheme> {
    SCHEMES
        .iter()
        .copied()
        .find(|s| s.sig_oid == oid || s.key_oid == oid)
}

pub fn is_gost(oid: &str) -> bool {
    by_sig(oid).is_some()
}

// ------------------------------------------------------------------ digests

pub fn hash(oid: &str, data: &[u8]) -> Result<Vec<u8>> {
    use digest::Digest;
    Ok(match oid {
        H_GOST34311 => gost94::Gost94Test::digest(data).to_vec(),
        H_GOST2015_256 => streebog::Streebog256::digest(data).to_vec(),
        H_GOST2015_512 => streebog::Streebog512::digest(data).to_vec(),
        H_SHA1 => sha1::Sha1::digest(data).to_vec(),
        H_SHA224 => sha2::Sha224::digest(data).to_vec(),
        H_SHA256 => sha2::Sha256::digest(data).to_vec(),
        H_SHA384 => sha2::Sha384::digest(data).to_vec(),
        H_SHA512 => sha2::Sha512::digest(data).to_vec(),
        _ => {
            return Err(Error::UnsupportedAlgorithm(oid.into()));
        }
    })
}

/// The length of an `oid` digest, in bytes.
pub fn digest_len(oid: &str) -> Result<usize> {
    Ok(match oid {
        H_GOST34311 | H_GOST2015_256 | H_SHA256 => 32,
        H_GOST2015_512 | H_SHA512 => 64,
        H_SHA1 => 20,
        H_SHA224 => 28,
        H_SHA384 => 48,
        _ => {
            return Err(Error::UnsupportedAlgorithm(oid.into()));
        }
    })
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    <sha2::Sha256 as digest::Digest>::digest(data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        for (oid, len, abc) in [
            (H_SHA1, 20, "a9993e36"),
            (H_SHA224, 28, "23097d22"),
            (H_SHA256, 32, "ba7816bf"),
            (H_SHA384, 48, "cb00753f"),
            (H_SHA512, 64, "ddaf35a1"),
        ] {
            let h = hash(oid, b"abc").unwrap();
            assert_eq!(h.len(), len);
            assert_eq!(digest_len(oid).unwrap(), len);
            let hex: String = h[..4].iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, abc, "{oid}");
        }
        assert!(hash("1.2.3", b"").is_err() && digest_len("1.2.3").is_err());
        assert!(is_gost(KEY_GOST2015_512) && is_gost(SIG_GOST2004));
        assert!(!is_gost(RSA_ENCRYPTION) && !is_gost(H_SHA256));
    }

    #[test]
    fn streebog_known_answer() {
        // GOST R 34.11-2012 example M1 ("012345...") from the standard
        let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
        let h = hash(H_GOST2015_256, m1).unwrap();
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        );
    }
}
