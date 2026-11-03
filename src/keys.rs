//! Public and private keys (KZ GOST and RSA) and the signatures made with them.

use num_bigint::BigUint;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use crate::der::{self, Tlv};
use crate::gost::{self, Curve, Scheme};
use crate::{Error, Result};

pub enum PublicKey {
    Gost {
        curve: Curve,
        x: BigUint,
        y: BigUint,
    },
    Rsa(RsaPublicKey),
    Other(String),
}

pub enum PrivateKey {
    Gost {
        curve: Curve,
        scheme: Scheme,
        d: BigUint,
    },
    Rsa(RsaPrivateKey),
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
        .ok_or_else(|| Error::new("malformed ASN.1: empty AlgorithmIdentifier"))?
        .oid()?;
    Ok((oid, k.get(1).copied()))
}

impl PublicKey {
    /// From a SubjectPublicKeyInfo.
    pub fn from_spki(spki: &[u8]) -> Result<PublicKey> {
        let k = der::parse(spki)?.items(der::SEQUENCE)?;
        if k.len() < 2 {
            return Err(Error::new("malformed ASN.1: SubjectPublicKeyInfo"));
        }
        let (oid, params) = alg_id(&k[0])?;
        let bits = k[1].bits()?;
        if gost::by_key(&oid).is_some() {
            let curve = gost::curve(&param_set(params.as_ref())?)?;
            let xy = der::parse(bits)?.expect(der::OCTET_STRING)?.content;
            let n = xy.len() / 2;
            return Ok(PublicKey::Gost {
                curve,
                x: gost::le(&xy[..n]),
                y: gost::le(&xy[n..2 * n]),
            });
        }
        if oid == gost::RSA_ENCRYPTION {
            let k = RsaPublicKey::from_pkcs1_der(bits)
                .map_err(|e| Error::new(format!("malformed RSA public key: {e}")))?;
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
            PublicKey::Gost { curve, x, y } => {
                let sc = gost::by_sig(sig_alg)
                    .ok_or_else(|| Error::new(format!("Key does not match {sig_alg}")))?;
                let h = gost::hash(sc.digest_oid, data)?;
                Ok(curve.verify(x, y, &h, sig))
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
            PublicKey::Other(oid) => Err(Error::new(format!("Unsupported key algorithm {oid}"))),
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
            return Err(Error::new("malformed PrivateKeyInfo"));
        }
        let (oid, params) = alg_id(&k[1])?;
        let key = k[2].expect(der::OCTET_STRING)?.octets()?;
        if let Some(scheme) = gost::by_key(&oid) {
            let curve = gost::curve(&param_set(params.as_ref())?)?;
            let v = der::parse(&key)?;
            let d = match v.tag {
                der::INTEGER => BigUint::from_bytes_be(v.uint()?),
                der::OCTET_STRING => gost::le(&v.octets()?),
                _ => return Err(Error::new("unexpected GOST private key encoding")),
            };
            return Ok(PrivateKey::Gost { curve, scheme, d });
        }
        if oid == gost::RSA_ENCRYPTION {
            let k = RsaPrivateKey::from_pkcs1_der(&key)
                .map_err(|e| Error::new(format!("malformed RSA private key: {e}")))?;
            return Ok(PrivateKey::Rsa(k));
        }
        Err(Error::new(format!("Unsupported private key type {oid}")))
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

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let h = gost::hash(self.digest_oid(), data)?;
        match self {
            PrivateKey::Gost { curve, scheme, d } => curve.sign(d, &h, scheme.size),
            // blinded, with the system's random generator
            PrivateKey::Rsa(k) => k
                .sign_with_rng(
                    &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
                    Pkcs1v15Sign::new_unprefixed(),
                    &digest_info(gost::H_SHA256, &h),
                )
                .map_err(|e| Error::new(format!("RSA signing failed: {e}"))),
        }
    }

    /// Whether `pub_key` belongs to this private key.
    pub fn matches(&self, pub_key: &PublicKey) -> bool {
        match (self, pub_key) {
            (PrivateKey::Gost { curve, d, .. }, PublicKey::Gost { curve: c2, x, y }) => {
                curve.name == c2.name
                    && curve.public(d).is_some_and(|(px, py)| &px == x && &py == y)
            }
            (PrivateKey::Rsa(k), PublicKey::Rsa(p)) => k.n() == p.n() && k.e() == p.e(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> crate::p12::Key {
        let d = std::fs::read(format!(
            "{}/tests/fixtures/keys/{name}.p12",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        crate::p12::open(&d, "Qwerty12", None).unwrap()
    }

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

    #[test]
    fn key_structures() {
        let k = key("alice_gost2015");
        // short SubjectPublicKeyInfo and PrivateKeyInfo
        let alg = der::alg_null(gost::RSA_ENCRYPTION);
        assert!(PublicKey::from_spki(&der::seq(&[&alg])).is_err());
        assert!(PrivateKey::from_pkcs8(&der::seq(&[&der::small_int(0), &alg])).is_err());
        // a point with the same x but another y is another key
        let PublicKey::Gost { curve, x, y } = k.cert.public_key().unwrap() else {
            panic!("not GOST");
        };
        assert!(!k.private_key.matches(&PublicKey::Gost {
            curve,
            x,
            y: y + 1u32,
        }));
        assert!(k.private_key.matches(&k.cert.public_key().unwrap()));
    }
}
