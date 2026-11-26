//! Public and private keys (KZ GOST and RSA) and the signatures made with them.

use gost3410::signature::hazmat::PrehashVerifier as _;
use gost3410::{CryptoProA, GostCurve, Signature, SigningKey, Tc26_256A, Tc26_512A, VerifyingKey};
use rsa::Pkcs1v15Sign;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::traits::PublicKeyParts;

use crate::der::{self, Tlv};
use crate::gost::{self, Scheme};
use crate::prelude::*;
use crate::{Error, Result, Rng};

pub enum PublicKey {
    Gost(GostPublic),
    Rsa(rsa::PublicKey),
    Other(String),
}

pub enum PrivateKey {
    Gost { key: GostPrivate, scheme: Scheme },
    Rsa(rsa::PrivateKey),
}

/// A GOST public key, on one of NCA's three curves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GostPublic {
    CryptoProA(VerifyingKey<CryptoProA>),
    Tc26_256A(VerifyingKey<Tc26_256A>),
    Tc26_512A(VerifyingKey<Tc26_512A>),
}

/// A GOST private key, on one of NCA's three curves (wiped when dropped).
pub enum GostPrivate {
    CryptoProA(SigningKey<CryptoProA>),
    Tc26_256A(SigningKey<Tc26_256A>),
    Tc26_512A(SigningKey<Tc26_512A>),
}

/// Which of the three curves a parameter-set OID names.
#[derive(Clone, Copy)]
enum GostCurveId {
    CryptoProA,
    Tc26_256A,
    Tc26_512A,
}

fn curve_id(param_set: &str) -> Result<GostCurveId> {
    let named = |oids: &[&str]| oids.contains(&param_set);
    if named(CryptoProA::PARAM_SET_OIDS) {
        Ok(GostCurveId::CryptoProA)
    } else if named(Tc26_256A::PARAM_SET_OIDS) {
        Ok(GostCurveId::Tc26_256A)
    } else if named(Tc26_512A::PARAM_SET_OIDS) {
        Ok(GostCurveId::Tc26_512A)
    } else {
        Err(Error::unsupported(format!(
            "Unsupported GOST curve parameter set {param_set}"
        )))
    }
}

fn gost_verify<C: GostCurve>(k: &VerifyingKey<C>, hash: &[u8], sig: &[u8]) -> bool {
    Signature::<C>::from_nca_bytes(sig).is_ok_and(|s| k.verify_prehash(hash, &s).is_ok())
}

fn gost_sign<C: GostCurve>(k: &SigningKey<C>, hash: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>> {
    let mut fresh = [0u8; 32];
    rng.fill(&mut fresh)?;
    let sig = k
        .sign_prehash_with_fresh(hash, &fresh)
        .map_err(|_| Error::new("GOST signing failed"))?;
    let mut out = [0u8; 128];
    Ok(sig
        .to_nca_bytes(&mut out)
        .map_err(|_| Error::new("GOST signing failed"))?
        .to_vec())
}

impl GostPublic {
    /// From NCA's form: x || y, little-endian.
    fn from_nca_bytes(curve: GostCurveId, xy: &[u8]) -> Result<GostPublic> {
        let bad = |_| Error::malformed("malformed GOST public key");
        Ok(match curve {
            GostCurveId::CryptoProA => {
                GostPublic::CryptoProA(VerifyingKey::from_nca_bytes(xy).map_err(bad)?)
            }
            GostCurveId::Tc26_256A => {
                GostPublic::Tc26_256A(VerifyingKey::from_nca_bytes(xy).map_err(bad)?)
            }
            GostCurveId::Tc26_512A => {
                GostPublic::Tc26_512A(VerifyingKey::from_nca_bytes(xy).map_err(bad)?)
            }
        })
    }

    /// Checks NCA's r || s (little-endian) over a hash.
    pub fn verify_prehash(&self, hash: &[u8], sig: &[u8]) -> bool {
        match self {
            GostPublic::CryptoProA(k) => gost_verify(k, hash, sig),
            GostPublic::Tc26_256A(k) => gost_verify(k, hash, sig),
            GostPublic::Tc26_512A(k) => gost_verify(k, hash, sig),
        }
    }

    /// The curve's name.
    pub fn curve_name(&self) -> &'static str {
        match self {
            GostPublic::CryptoProA(_) => CryptoProA::NAME,
            GostPublic::Tc26_256A(_) => Tc26_256A::NAME,
            GostPublic::Tc26_512A(_) => Tc26_512A::NAME,
        }
    }
}

impl GostPrivate {
    /// From d, little-endian (as long as the curve's field).
    fn from_le(curve: GostCurveId, d: &[u8]) -> Result<GostPrivate> {
        let bad = |_| Error::malformed("malformed GOST private key");
        Ok(match curve {
            GostCurveId::CryptoProA => {
                GostPrivate::CryptoProA(SigningKey::from_nca_bytes(d).map_err(bad)?)
            }
            GostCurveId::Tc26_256A => {
                GostPrivate::Tc26_256A(SigningKey::from_nca_bytes(d).map_err(bad)?)
            }
            GostCurveId::Tc26_512A => {
                GostPrivate::Tc26_512A(SigningKey::from_nca_bytes(d).map_err(bad)?)
            }
        })
    }

    /// NCA's r || s (little-endian) over a hash.
    pub fn sign_prehash(&self, hash: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>> {
        match self {
            GostPrivate::CryptoProA(k) => gost_sign(k, hash, rng),
            GostPrivate::Tc26_256A(k) => gost_sign(k, hash, rng),
            GostPrivate::Tc26_512A(k) => gost_sign(k, hash, rng),
        }
    }

    /// The public key.
    pub fn public(&self) -> GostPublic {
        match self {
            GostPrivate::CryptoProA(k) => GostPublic::CryptoProA(*k.verifying_key()),
            GostPrivate::Tc26_256A(k) => GostPublic::Tc26_256A(*k.verifying_key()),
            GostPrivate::Tc26_512A(k) => GostPublic::Tc26_512A(*k.verifying_key()),
        }
    }
}

fn field_len(curve: GostCurveId) -> usize {
    match curve {
        GostCurveId::Tc26_512A => 64,
        _ => 32,
    }
}

fn param_set(params: Option<&Tlv>) -> Result<String> {
    let p = params.ok_or_else(|| Error::new("GOST key without curve parameters"))?;
    let items = p.items(der::SEQUENCE)?;
    items
        .first()
        .ok_or_else(|| Error::new("GOST key without curve parameters"))?
        .oid()
}

/// AlgorithmIdentifier: (OID, parameters).
pub fn alg_id<'a>(t: &Tlv<'a>) -> Result<(String, Option<Tlv<'a>>)> {
    let k = t.items(der::SEQUENCE)?;
    let oid = k
        .first()
        .ok_or_else(|| Error::malformed("malformed ASN.1: empty AlgorithmIdentifier"))?
        .oid()?;
    Ok((oid, k.get(1).copied()))
}

impl PublicKey {
    /// From a SubjectPublicKeyInfo.
    pub fn from_spki(spki: &[u8]) -> Result<PublicKey> {
        let k = der::parse(spki)?.items(der::SEQUENCE)?;
        if k.len() < 2 {
            return Err(Error::malformed("malformed ASN.1: SubjectPublicKeyInfo"));
        }
        let (oid, params) = alg_id(&k[0])?;
        let bits = k[1].bits()?;
        if gost::by_key(&oid).is_some() {
            let curve = curve_id(&param_set(params.as_ref())?)?;
            let xy = der::parse(bits)?.expect(der::OCTET_STRING)?.content;
            return Ok(PublicKey::Gost(GostPublic::from_nca_bytes(curve, xy)?));
        }
        if oid == gost::RSA_ENCRYPTION {
            let k = rsa::PublicKey::from_pkcs1_der(bits)
                .map_err(|e| Error::malformed(format!("malformed RSA public key: {e}")))?;
            return Ok(PublicKey::Rsa(k));
        }
        Ok(PublicKey::Other(oid))
    }

    /// Checks `sig` over `data`. `sig_alg` is the signature algorithm OID; `digest_alg` the
    /// separate digest OID of a CMS signer, used when the signature algorithm names only the key
    /// type (rsaEncryption).
    pub fn verify(
        &self,
        sig_alg: &str,
        digest_alg: Option<&str>,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool> {
        match self {
            PublicKey::Gost(k) => {
                let sc = gost::by_sig(sig_alg)
                    .ok_or_else(|| Error::new(format!("Key does not match {sig_alg}")))?;
                let h = gost::hash(sc.digest_oid, data)?;
                Ok(k.verify_prehash(&h, sig))
            }
            PublicKey::Rsa(k) => {
                let digest = rsa_digest(sig_alg, digest_alg)?;
                let h = gost::hash(digest, data)?;
                // DigestInfo with NULL parameters, or without them (both are seen)
                let without_null = der::seq(&[&der::seq(&[&der::oid(digest)]), &der::octets(&h)]);
                Ok([digest_info(digest, &h), without_null]
                    .iter()
                    .any(|di| k.verify(Pkcs1v15Sign::new_unprefixed(), di, sig).is_ok()))
            }
            PublicKey::Other(oid) => Err(Error::unsupported(format!(
                "Unsupported key algorithm {oid}"
            ))),
        }
    }
}

/// The digest of an RSA signature algorithm, or of rsaEncryption + a separate digest.
fn rsa_digest<'a>(sig_alg: &str, digest_alg: Option<&'a str>) -> Result<&'a str> {
    Ok(match sig_alg {
        "1.2.840.113549.1.1.5" => gost::H_SHA1,
        "1.2.840.113549.1.1.14" => gost::H_SHA224,
        "1.2.840.113549.1.1.11" => gost::H_SHA256,
        "1.2.840.113549.1.1.12" => gost::H_SHA384,
        "1.2.840.113549.1.1.13" => gost::H_SHA512,
        gost::RSA_ENCRYPTION => match digest_alg {
            Some(
                d @ (gost::H_SHA1
                | gost::H_SHA224
                | gost::H_SHA256
                | gost::H_SHA384
                | gost::H_SHA512),
            ) => d,
            _ => gost::H_SHA256,
        },
        _ => {
            return Err(Error::new(format!(
                "Unsupported signature algorithm {sig_alg}"
            )));
        }
    })
}

/// PKCS#1 v1.5 DigestInfo prefix + hash.
fn digest_info(digest_oid: &str, h: &[u8]) -> Vec<u8> {
    der::seq(&[&der::alg_null(digest_oid), &der::octets(h)])
}

impl PrivateKey {
    /// From a PKCS#8 PrivateKeyInfo.
    pub fn from_pkcs8(pki: &[u8]) -> Result<PrivateKey> {
        let k = der::parse(pki)?.items(der::SEQUENCE)?;
        if k.len() < 3 {
            return Err(Error::malformed("malformed PrivateKeyInfo"));
        }
        let (oid, params) = alg_id(&k[1])?;
        let key = k[2].expect(der::OCTET_STRING)?.octets()?;
        if let Some(scheme) = gost::by_key(&oid) {
            let curve = curve_id(&param_set(params.as_ref())?)?;
            let v = der::parse(&key)?;
            // d little-endian, as long as the field: 2004 keys are a (big-endian) INTEGER,
            // 2015 keys a little-endian OCTET STRING, either maybe shorter
            let mut d = zeroize::Zeroizing::new(match v.tag {
                der::INTEGER => {
                    let mut be = v.uint()?.to_vec();
                    be.reverse();
                    be
                }
                der::OCTET_STRING => v.octets()?.to_vec(),
                _ => return Err(Error::new("unexpected GOST private key encoding")),
            });
            let n = field_len(curve);
            while d.len() > n && d.last() == Some(&0) {
                d.pop();
            }
            if d.len() > n {
                return Err(Error::malformed("malformed GOST private key"));
            }
            d.resize(n, 0);
            let key = GostPrivate::from_le(curve, &d)?;
            return Ok(PrivateKey::Gost { key, scheme });
        }
        if oid == gost::RSA_ENCRYPTION {
            let k = rsa::PrivateKey::from_pkcs1_der(&key)
                .map_err(|e| Error::malformed(format!("malformed RSA private key: {e}")))?;
            return Ok(PrivateKey::Rsa(k));
        }
        Err(Error::unsupported(format!(
            "Unsupported private key type {oid}"
        )))
    }

    /// The KZ GOST scheme, or None for RSA.
    pub fn scheme(&self) -> Option<Scheme> {
        match self {
            PrivateKey::Gost { scheme, .. } => Some(*scheme),
            PrivateKey::Rsa(_) => None,
        }
    }

    /// Digest OID used with this key: the GOST one, or SHA-256 for RSA (as NCALayer does).
    pub fn digest_oid(&self) -> &'static str {
        self.scheme()
            .map(|s| s.digest_oid)
            .unwrap_or(gost::H_SHA256)
    }

    /// Signature algorithm OID: KZ GOST, or sha256WithRSAEncryption.
    pub fn sig_oid(&self) -> &'static str {
        self.scheme()
            .map(|s| s.sig_oid)
            .unwrap_or(gost::SIG_SHA256_RSA)
    }

    /// Signs `data`. GOST 34.310-2004 keys are refused: NCA no longer issues them and its TSA no
    /// longer stamps them, so they are only for checking old signatures.
    pub fn sign(&self, data: &[u8], rng: &mut dyn Rng) -> Result<Vec<u8>> {
        if let PrivateKey::Gost { scheme, .. } = self
            && scheme.key_oid == gost::KEY_GOST2004
        {
            return Err(Error::unsupported(
                "GOST 34.310-2004 keys can no longer sign; they only check old signatures",
            ));
        }
        let h = gost::hash(self.digest_oid(), data)?;
        match self {
            PrivateKey::Gost { key, .. } => key.sign_prehash(&h, rng),
            // blinded, with the caller's random source
            PrivateKey::Rsa(k) => {
                let mut r = crate::RandCore { rng, failed: None };
                let sig = k
                    .sign_with_rng(
                        &mut r,
                        Pkcs1v15Sign::new_unprefixed(),
                        &digest_info(gost::H_SHA256, &h),
                    )
                    .map_err(|e| Error::new(format!("RSA signing failed: {e}")));
                match r.failed {
                    Some(e) => Err(e),
                    None => sig,
                }
            }
        }
    }

    /// Whether `pub_key` belongs to this private key.
    pub fn matches(&self, pub_key: &PublicKey) -> bool {
        match (self, pub_key) {
            (PrivateKey::Gost { key, .. }, PublicKey::Gost(p)) => &key.public() == p,
            (PrivateKey::Rsa(k), PublicKey::Rsa(p)) => k.n() == p.n() && k.e() == p.e(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing::key;

    /// RSA signatures with each digest, named by the signature algorithm or by rsaEncryption
    /// with a separate digest algorithm (SHA-256 when none is named).
    #[test]
    fn rsa_digests() {
        let k = key("alice_rsa");
        let PrivateKey::Rsa(rsa) = &k.private_key else {
            panic!("not RSA");
        };
        let public = k.cert.public_key().unwrap();
        let data = b"hello";
        let sign = |digest: &str| {
            let h = gost::hash(digest, data).unwrap();
            rsa.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info(digest, &h))
                .unwrap()
        };
        for (sig_alg, digest) in [
            ("1.2.840.113549.1.1.5", gost::H_SHA1),
            ("1.2.840.113549.1.1.14", gost::H_SHA224),
            ("1.2.840.113549.1.1.11", gost::H_SHA256),
            ("1.2.840.113549.1.1.12", gost::H_SHA384),
            ("1.2.840.113549.1.1.13", gost::H_SHA512),
        ] {
            let sig = sign(digest);
            assert!(
                public.verify(sig_alg, None, data, &sig).unwrap(),
                "{sig_alg}"
            );
            assert!(
                public
                    .verify(gost::RSA_ENCRYPTION, Some(digest), data, &sig)
                    .unwrap(),
                "{digest}"
            );
            // another digest named: no match
            let other = if digest == gost::H_SHA1 {
                gost::H_SHA256
            } else {
                gost::H_SHA1
            };
            assert!(
                !public
                    .verify(gost::RSA_ENCRYPTION, Some(other), data, &sig)
                    .unwrap(),
                "{digest}"
            );
        }
        let sig = sign(gost::H_SHA256);
        assert!(
            public
                .verify(gost::RSA_ENCRYPTION, None, data, &sig)
                .unwrap()
        );
        assert!(public.verify("1.2.3", None, data, &sig).is_err());
    }

    /// A random source that fails stops signing with its own error, for both key types.
    #[test]
    fn failing_random_source() {
        struct Broken;
        impl crate::Rng for Broken {
            fn fill(&mut self, _: &mut [u8]) -> Result<()> {
                Err(Error::of(crate::ErrorKind::Random, "broken"))
            }
        }
        for name in ["alice_rsa", "alice_gost2015", "alice_gost2015_256"] {
            let e = key(name).private_key.sign(b"x", &mut Broken).unwrap_err();
            assert_eq!(e.kind, crate::ErrorKind::Random, "{name}");
            let sig = key(name)
                .private_key
                .sign(b"x", &mut crate::testing::OsRng)
                .unwrap();
            assert!(
                key(name)
                    .cert
                    .public_key()
                    .unwrap()
                    .verify(key(name).private_key.sig_oid(), None, b"x", &sig)
                    .unwrap()
            );
        }
    }

    /// GOST 2004 keys only check: signing is refused, checking their old signatures works.
    #[test]
    fn gost2004_checks_only() {
        let k = key("alice_gost2004");
        let e = k
            .private_key
            .sign(b"x", &mut crate::testing::OsRng)
            .unwrap_err();
        assert_eq!(e.kind, crate::ErrorKind::Unsupported);
        assert!(k.private_key.matches(&k.cert.public_key().unwrap()));
    }

    #[test]
    fn key_structures() {
        let k = key("alice_gost2015");
        // short SubjectPublicKeyInfo and PrivateKeyInfo
        let alg = der::alg_null(gost::RSA_ENCRYPTION);
        assert!(PublicKey::from_spki(&der::seq(&[&alg])).is_err());
        assert!(PrivateKey::from_pkcs8(&der::seq(&[&der::small_int(0), &alg])).is_err());
        // another key on the same curve, or on another curve, does not match
        assert!(
            !k.private_key
                .matches(&key("bob_gost2015").cert.public_key().unwrap())
        );
        assert!(
            !k.private_key
                .matches(&key("alice_gost2004").cert.public_key().unwrap())
        );
        assert!(k.private_key.matches(&k.cert.public_key().unwrap()));
    }
}
