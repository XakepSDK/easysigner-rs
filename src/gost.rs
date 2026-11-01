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
//! These were established by byte-for-byte comparison with NCA's own kalkancrypt, and are
//! checked against Kalkan-made files in tests/fixtures/kalkan and NCA's real CA certificates.

use num_bigint::BigUint;
use num_traits::{One, Zero};

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
        _ => return Err(Error::new(format!("Unsupported digest algorithm {oid}"))),
    })
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash(H_SHA256, data).expect("SHA-256")
}

// ------------------------------------------------------------------ curves

/// A short Weierstrass curve y² = x³ + ax + b over GF(p), base point G of prime order q.
pub struct Curve {
    pub name: &'static str,
    p: BigUint,
    a: BigUint,
    b: BigUint,
    pub q: BigUint,
    gx: BigUint,
    gy: BigUint,
}

fn h(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("curve constant")
}

/// The curve for a KZ parameter-set OID.
pub fn curve(param_set: &str) -> Result<Curve> {
    let p256 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97";
    Ok(match param_set {
        "1.2.398.3.10.1.1.1.1.1" => Curve {
            name: "GostR3410-2001-CryptoPro-A",
            p: h(p256),
            a: h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"),
            b: h("a6"),
            q: h("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"),
            gx: h("1"),
            gy: h("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"),
        },
        "1.2.398.3.10.1.1.2.1.1" => Curve {
            name: "Tc26-Gost-3410-12-256-paramSetA",
            p: h(p256),
            a: h("c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"),
            b: h("295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513"),
            q: h("400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"),
            gx: h("91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28"),
            gy: h("32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"),
        },
        "1.2.398.3.10.1.1.2.2.1" => Curve {
            name: "Tc26-Gost-3410-12-512-paramSetA",
            p: h(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
            ),
            a: h(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
            ),
            b: h(
                "e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
            ),
            q: h(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
            ),
            gx: h("3"),
            gy: h(
                "7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
            ),
        },
        _ => {
            return Err(Error::new(format!(
                "Unsupported GOST curve parameter set {param_set}"
            )));
        }
    })
}

/// A point in Jacobian coordinates (X/Z², Y/Z³); Z = 0 is the point at infinity.
#[derive(Clone)]
struct Jac {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl Curve {
    fn add_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }
    fn sub_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        ((a + &self.p) - b) % &self.p
    }
    fn mul_m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }
    fn inv_m(&self, a: &BigUint) -> BigUint {
        a.modpow(&(&self.p - 2u32), &self.p)
    }

    fn infinity() -> Jac {
        Jac {
            x: BigUint::one(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn double(&self, pt: &Jac) -> Jac {
        if pt.z.is_zero() || pt.y.is_zero() {
            return Self::infinity();
        }
        let yy = self.mul_m(&pt.y, &pt.y);
        let s = self.mul_m(&(BigUint::from(4u32) * &pt.x), &yy);
        let zz = self.mul_m(&pt.z, &pt.z);
        let m = self.add_m(
            &(BigUint::from(3u32) * self.mul_m(&pt.x, &pt.x)),
            &self.mul_m(&self.a, &self.mul_m(&zz, &zz)),
        );
        let x3 = self.sub_m(&self.mul_m(&m, &m), &self.add_m(&s, &s));
        let y4_8 = (BigUint::from(8u32) * self.mul_m(&yy, &yy)) % &self.p;
        let y3 = self.sub_m(&self.mul_m(&m, &self.sub_m(&s, &x3)), &y4_8);
        let z3 = self.mul_m(&(BigUint::from(2u32) * &pt.y), &pt.z);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, p1: &Jac, p2: &Jac) -> Jac {
        if p1.z.is_zero() {
            return p2.clone();
        }
        if p2.z.is_zero() {
            return p1.clone();
        }
        let z1z1 = self.mul_m(&p1.z, &p1.z);
        let z2z2 = self.mul_m(&p2.z, &p2.z);
        let u1 = self.mul_m(&p1.x, &z2z2);
        let u2 = self.mul_m(&p2.x, &z1z1);
        let s1 = self.mul_m(&p1.y, &self.mul_m(&p2.z, &z2z2));
        let s2 = self.mul_m(&p2.y, &self.mul_m(&p1.z, &z1z1));
        if u1 == u2 {
            return if s1 == s2 {
                self.double(p1)
            } else {
                Self::infinity()
            };
        }
        let hh = self.sub_m(&u2, &u1);
        let r = self.sub_m(&s2, &s1);
        let h2 = self.mul_m(&hh, &hh);
        let h3 = self.mul_m(&h2, &hh);
        let u1h2 = self.mul_m(&u1, &h2);
        let x3 = self.sub_m(
            &self.sub_m(&self.mul_m(&r, &r), &h3),
            &self.add_m(&u1h2, &u1h2),
        );
        let y3 = self.sub_m(
            &self.mul_m(&r, &self.sub_m(&u1h2, &x3)),
            &self.mul_m(&s1, &h3),
        );
        let z3 = self.mul_m(&hh, &self.mul_m(&p1.z, &p2.z));
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// k·P with a fixed sequence of operations per bit (a ladder).
    fn mul(&self, k: &BigUint, p: &Jac) -> Jac {
        let mut r0 = Self::infinity();
        let mut r1 = p.clone();
        for i in (0..self.q.bits().max(k.bits())).rev() {
            if k.bit(i) {
                r0 = self.add(&r0, &r1);
                r1 = self.double(&r1);
            } else {
                r1 = self.add(&r0, &r1);
                r0 = self.double(&r0);
            }
        }
        r0
    }

    fn affine(&self, p: &Jac) -> Option<(BigUint, BigUint)> {
        if p.z.is_zero() {
            return None;
        }
        let zi = self.inv_m(&p.z);
        let zi2 = self.mul_m(&zi, &zi);
        Some((
            self.mul_m(&p.x, &zi2),
            self.mul_m(&p.y, &self.mul_m(&zi2, &zi)),
        ))
    }

    fn g(&self) -> Jac {
        Jac {
            x: self.gx.clone(),
            y: self.gy.clone(),
            z: BigUint::one(),
        }
    }

    pub fn on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let lhs = self.mul_m(y, y);
        let rhs = self.add_m(
            &self.add_m(&self.mul_m(&self.mul_m(x, x), x), &self.mul_m(&self.a, x)),
            &self.b,
        );
        lhs == rhs
    }

    /// The public point d·G.
    pub fn public(&self, d: &BigUint) -> Option<(BigUint, BigUint)> {
        self.affine(&self.mul(d, &self.g()))
    }

    /// GOST R 34.10 signature of `hash` with private key `d`: r || s, little-endian.
    pub fn sign(&self, d: &BigUint, hash: &[u8], size: usize) -> Result<Vec<u8>> {
        let q = &self.q;
        let mut e = le(hash) % q;
        if e.is_zero() {
            e = BigUint::one();
        }
        loop {
            let k = random_below(q)?;
            let Some((cx, _)) = self.affine(&self.mul(&k, &self.g())) else {
                continue;
            };
            let r = cx % q;
            if r.is_zero() {
                continue;
            }
            let s = (&r * d + &k * &e) % q;
            if s.is_zero() {
                continue;
            }
            let mut out = to_le(&r, size);
            out.extend(to_le(&s, size));
            return Ok(out);
        }
    }

    /// Checks a GOST R 34.10 signature (r || s, little-endian) of `hash` by point (x, y).
    pub fn verify(&self, x: &BigUint, y: &BigUint, hash: &[u8], sig: &[u8]) -> bool {
        if !sig.len().is_multiple_of(2) || sig.is_empty() || !self.on_curve(x, y) {
            return false;
        }
        let q = &self.q;
        let n = sig.len() / 2;
        let r = le(&sig[..n]);
        let s = le(&sig[n..]);
        if r.is_zero() || s.is_zero() || &r >= q || &s >= q {
            return false;
        }
        let mut e = le(hash) % q;
        if e.is_zero() {
            e = BigUint::one();
        }
        let v = e.modpow(&(q - 2u32), q);
        let z1 = (&s * &v) % q;
        let z2 = ((q - &r) * &v) % q;
        let pq = Jac {
            x: x.clone(),
            y: y.clone(),
            z: BigUint::one(),
        };
        let c = self.add(&self.mul(&z1, &self.g()), &self.mul(&z2, &pq));
        match self.affine(&c) {
            Some((cx, _)) => cx % q == r,
            None => false,
        }
    }
}

/// A uniformly random integer in [1, n-1].
pub fn random_below(n: &BigUint) -> Result<BigUint> {
    let len = n.bits().div_ceil(8) as usize + 16;
    let mut buf = vec![0u8; len];
    loop {
        crate::random(&mut buf)?;
        let k = BigUint::from_bytes_be(&buf) % n;
        if !k.is_zero() {
            return Ok(k);
        }
    }
}

// ------------------------------------------------------------------ little-endian helpers

pub fn le(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(b)
}

pub fn to_le(v: &BigUint, size: usize) -> Vec<u8> {
    let mut b = v.to_bytes_le();
    b.resize(size, 0);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_all_curves() {
        for (ps, size) in [
            ("1.2.398.3.10.1.1.1.1.1", 32),
            ("1.2.398.3.10.1.1.2.1.1", 32),
            ("1.2.398.3.10.1.1.2.2.1", 64),
        ] {
            let c = curve(ps).unwrap();
            assert!(c.on_curve(&c.gx, &c.gy), "{}", c.name);
            let d = random_below(&c.q).unwrap();
            let (x, y) = c.public(&d).unwrap();
            let hash = vec![7u8; size];
            let sig = c.sign(&d, &hash, size).unwrap();
            assert!(c.verify(&x, &y, &hash, &sig), "{}", c.name);
            let mut bad = sig.clone();
            bad[0] ^= 1;
            assert!(!c.verify(&x, &y, &hash, &bad));
        }
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
