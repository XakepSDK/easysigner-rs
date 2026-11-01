//! Public and private keys (KZ GOST and RSA) and the signatures made with them.

use num_bigint::BigUint;
use num_traits::One;

use crate::der::{self, Tlv};
use crate::gost::{self, Curve, Scheme};
use crate::{Error, Result};

pub enum PublicKey {
    Gost {
        curve: Curve,
        x: BigUint,
        y: BigUint,
    },
    Rsa {
        n: BigUint,
        e: BigUint,
    },
    Other(String),
}

pub enum PrivateKey {
    Gost {
        curve: Curve,
        scheme: Scheme,
        d: BigUint,
    },
    Rsa(RsaPrivate),
}

pub struct RsaPrivate {
    pub n: BigUint,
    e: BigUint,
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
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
            let k = der::parse(bits)?.items(der::SEQUENCE)?;
            if k.len() < 2 {
                return Err(Error::new("malformed RSA public key"));
            }
            return Ok(PublicKey::Rsa {
                n: BigUint::from_bytes_be(k[0].uint()?),
                e: BigUint::from_bytes_be(k[1].uint()?),
            });
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
            PublicKey::Rsa { n, e } => {
                let digest = rsa_digest(sig_alg, digest_alg)?;
                let h = gost::hash(digest, data)?;
                Ok(rsa_verify(n, e, digest, &h, sig))
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

fn rsa_verify(n: &BigUint, e: &BigUint, digest_oid: &str, h: &[u8], sig: &[u8]) -> bool {
    let k = n.bits().div_ceil(8) as usize;
    if sig.len() != k {
        return false;
    }
    let s = BigUint::from_bytes_be(sig);
    if &s >= n {
        return false;
    }
    let mut em = s.modpow(e, n).to_bytes_be();
    while em.len() < k {
        em.insert(0, 0);
    }
    // 00 01 FF..FF 00 DigestInfo
    if em.len() < 11 || em[0] != 0 || em[1] != 1 {
        return false;
    }
    let Some(zero) = em[2..].iter().position(|&b| b != 0xff) else {
        return false;
    };
    if zero < 8 || em[2 + zero] != 0 {
        return false;
    }
    let di = &em[3 + zero..];
    // with NULL parameters, or without them (both are seen)
    let without_null = der::seq(&[&der::seq(&[&der::oid(digest_oid)]), &der::octets(h)]);
    di == digest_info(digest_oid, h).as_slice() || di == without_null.as_slice()
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
            let f = der::parse(&key)?.items(der::SEQUENCE)?;
            if f.len() < 9 {
                return Err(Error::new("malformed RSA private key"));
            }
            let n = |i: usize| -> Result<BigUint> { Ok(BigUint::from_bytes_be(f[i].uint()?)) };
            return Ok(PrivateKey::Rsa(RsaPrivate {
                n: n(1)?,
                e: n(2)?,
                p: n(4)?,
                q: n(5)?,
                dp: n(6)?,
                dq: n(7)?,
                qinv: n(8)?,
            }));
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
            PrivateKey::Rsa(k) => k.sign(gost::H_SHA256, &h),
        }
    }

    /// Whether `pub_key` belongs to this private key.
    pub fn matches(&self, pub_key: &PublicKey) -> bool {
        match (self, pub_key) {
            (PrivateKey::Gost { curve, d, .. }, PublicKey::Gost { curve: c2, x, y }) => {
                curve.name == c2.name
                    && curve.public(d).is_some_and(|(px, py)| &px == x && &py == y)
            }
            (PrivateKey::Rsa(k), PublicKey::Rsa { n, .. }) => &k.n == n,
            _ => false,
        }
    }
}

impl RsaPrivate {
    fn sign(&self, digest_oid: &str, h: &[u8]) -> Result<Vec<u8>> {
        let k = self.n.bits().div_ceil(8) as usize;
        let di = digest_info(digest_oid, h);
        if k < di.len() + 11 {
            return Err(Error::new("RSA key too short"));
        }
        let mut em = vec![0u8, 1];
        em.resize(k - di.len() - 1, 0xff);
        em.push(0);
        em.extend(&di);
        let m = BigUint::from_bytes_be(&em);
        // blinded CRT: s = (m·r^e)^d · r^-1
        let r = gost::random_below(&self.n)?;
        let r_inv = mod_inverse(&r, &self.n).ok_or_else(|| Error::new("RSA blinding failed"))?;
        let mb = (&m * r.modpow(&self.e, &self.n)) % &self.n;
        let s1 = mb.modpow(&self.dp, &self.p);
        let s2 = mb.modpow(&self.dq, &self.q);
        let hh = (&self.qinv * ((&s1 + &self.p) - (&s2 % &self.p))) % &self.p;
        let sb = s2 + hh * &self.q;
        let s = (sb * r_inv) % &self.n;
        // check before releasing (a CRT fault would leak the key)
        if s.modpow(&self.e, &self.n) != m {
            return Err(Error::new("RSA signature self-check failed"));
        }
        let mut out = s.to_bytes_be();
        while out.len() < k {
            out.insert(0, 0);
        }
        Ok(out)
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_integer::Integer;
    let e = BigInt::from(a.clone()).extended_gcd(&BigInt::from(m.clone()));
    if !e.gcd.is_one() {
        return None;
    }
    let mi = BigInt::from(m.clone());
    let x = ((e.x % &mi) + &mi) % &mi;
    x.to_biguint()
}
