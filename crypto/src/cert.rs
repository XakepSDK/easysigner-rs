//! X.509 certificates: the fields kzsigner reads, names, and whether a certificate may sign.

use crate::der::{self, Tlv};
use crate::keys::PublicKey;
use crate::prelude::*;
use crate::text::{Text, tr, trf};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct Cert {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    pub serial: Vec<u8>,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub spki: Vec<u8>,
    pub sig_alg: String,
    pub signature: Vec<u8>,
    /// (OID, value octets)
    pub extensions: Vec<(String, Vec<u8>)>,
}

impl PartialEq for Cert {
    fn eq(&self, o: &Cert) -> bool {
        self.der == o.der
    }
}

pub const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const EKU_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

pub const KU_DIGITAL_SIGNATURE: usize = 0;
pub const KU_NON_REPUDIATION: usize = 1;
pub const ANY_POLICY: &str = "2.5.29.32.0";
pub const KU_KEY_CERT_SIGN: usize = 5;

impl Cert {
    pub fn parse(data: &[u8]) -> Result<Cert> {
        let t = der::parse(data)?;
        Self::from_tlv(&t)
    }

    /// Accepts DER, or Base64 / PEM text.
    pub fn parse_any(data: &[u8]) -> Result<Cert> {
        Self::parse(&crate::cms::normalize(data))
    }

    pub fn from_tlv(t: &Tlv) -> Result<Cert> {
        let f = || Error::new("Unreadable certificate: malformed ASN.1");
        let top = t.items(der::SEQUENCE)?;
        if top.len() < 3 {
            return Err(f());
        }
        let tbs = top[0].items(der::SEQUENCE)?;
        let mut i = 0;
        if tbs.first().is_some_and(|x| x.tag == der::ctx(0)) {
            i = 1;
        }
        if tbs.len() < i + 6 {
            return Err(f());
        }
        let validity = tbs[i + 3].items(der::SEQUENCE)?;
        if validity.len() < 2 {
            return Err(f());
        }
        let mut extensions = Vec::new();
        for x in &tbs[i + 6..] {
            if x.tag == der::ctx(3) {
                for e in x.inner()?.items(der::SEQUENCE)? {
                    let k = e.items(der::SEQUENCE)?;
                    let oid = k.first().ok_or_else(f)?.oid()?;
                    let v = k
                        .last()
                        .ok_or_else(f)?
                        .expect(der::OCTET_STRING)?
                        .octets()?;
                    extensions.push((oid, v));
                }
            }
        }
        Ok(Cert {
            der: t.raw.to_vec(),
            tbs: top[0].raw.to_vec(),
            serial: tbs[i].uint()?.to_vec(),
            issuer: tbs[i + 2].raw.to_vec(),
            subject: tbs[i + 4].raw.to_vec(),
            not_before: validity[0].time()?,
            not_after: validity[1].time()?,
            spki: tbs[i + 5].raw.to_vec(),
            sig_alg: crate::keys::alg_id(&top[1])?.0,
            signature: top[2].bits()?.to_vec(),
            extensions,
        })
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(&self.spki)
    }

    pub fn key_alg(&self) -> String {
        der::parse(&self.spki)
            .and_then(|t| t.items(der::SEQUENCE))
            .and_then(|k| crate::keys::alg_id(&k[0]).map(|a| a.0))
            .unwrap_or_default()
    }

    /// The public key BIT STRING contents (for OCSP key hashes).
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        let k = der::parse(&self.spki)?.items(der::SEQUENCE)?;
        Ok(k.get(1)
            .ok_or_else(|| Error::new("malformed SubjectPublicKeyInfo"))?
            .bits()?
            .to_vec())
    }

    pub fn valid_on(&self, ms: i64) -> bool {
        // from notBefore through notAfter, inclusive (RFC 5280 4.1.2.5)
        ms >= self.not_before && ms <= self.not_after
    }

    pub fn self_issued(&self) -> bool {
        names_equal(&self.subject, &self.issuer)
    }

    /// Whether `issuer`'s key made this certificate's signature.
    pub fn signed_by(&self, issuer: &Cert) -> bool {
        issuer
            .public_key()
            .and_then(|k| k.verify(&self.sig_alg, None, &self.tbs, &self.signature))
            .unwrap_or(false)
    }

    fn extension(&self, oid: &str) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v.as_slice())
    }

    /// The subject key identifier extension's value.
    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        let v = self.extension("2.5.29.14")?;
        der::parse(v)
            .ok()?
            .expect(der::OCTET_STRING)
            .ok()?
            .octets()
            .ok()
    }

    /// Key usage bits, or None without the extension.
    pub fn key_usage(&self) -> Option<Vec<bool>> {
        let v = self.extension("2.5.29.15")?;
        let t = der::parse(v).ok()?;
        let c = t.expect(der::BIT_STRING).ok()?.content;
        let bits = c.get(1..)?;
        Some(
            (0..9)
                .map(|i| bits.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0))
                .collect(),
        )
    }

    pub fn extended_key_usage(&self) -> Vec<String> {
        let Some(v) = self.extension("2.5.29.37") else {
            return vec![];
        };
        der::parse(v)
            .and_then(|t| t.items(der::SEQUENCE))
            .map(|k| k.iter().filter_map(|o| o.oid().ok()).collect())
            .unwrap_or_default()
    }

    /// The policy OIDs in the certificate policies extension: None without the extension,
    /// Some(Err) when it can't be read.
    pub fn policies(&self) -> Option<Result<Vec<String>>> {
        let v = self.extension("2.5.29.32")?;
        Some(
            der::parse(v)
                .and_then(|t| t.items(der::SEQUENCE))
                .and_then(|t| {
                    t.iter()
                        .map(|p| {
                            p.items(der::SEQUENCE)?
                                .first()
                                .ok_or_else(|| Error::new("empty PolicyInformation"))?
                                .oid()
                        })
                        .collect()
                }),
        )
    }

    pub fn has_eku(&self, oid: &str) -> bool {
        self.extended_key_usage().iter().any(|o| o == oid)
    }

    /// Basic constraints cA flag (false without the extension).
    pub fn is_ca(&self) -> bool {
        let Some(v) = self.extension("2.5.29.19") else {
            return false;
        };
        der::parse(v)
            .and_then(|t| t.items(der::SEQUENCE))
            .map(|k| {
                k.first()
                    .is_some_and(|b| b.tag == der::BOOLEAN && b.boolean().unwrap_or(false))
            })
            .unwrap_or(false)
    }

    /// Whether key usage allows signing certificates (true without the extension).
    pub fn may_sign_certs(&self) -> bool {
        self.key_usage().is_none_or(|k| k[KU_KEY_CERT_SIGN])
    }

    pub fn serial_hex(&self) -> String {
        let s: String = self.serial.iter().map(|b| format!("{b:02x}")).collect();
        let t = s.trim_start_matches('0');
        if t.is_empty() { "0".into() } else { t.into() }
    }

    pub fn subject_rdns(&self) -> Vec<(String, String)> {
        rdns(&self.subject)
    }

    pub fn cn(&self) -> String {
        cn(&self.subject)
    }
}

// ------------------------------------------------------------------ names

fn label(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SURNAME",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.15" => "BUSINESSCATEGORY",
        "2.5.4.42" => "G",
        "1.2.840.113549.1.9.1" => "E",
        o => o,
    }
}

fn atvs(name: &[u8]) -> Vec<(String, Tlv<'_>)> {
    let mut out = Vec::new();
    let Ok(rdns) = der::parse(name).and_then(|t| t.items(der::SEQUENCE)) else {
        return out;
    };
    for rdn in rdns {
        for atv in rdn.children().unwrap_or_default() {
            if let Ok(k) = atv.items(der::SEQUENCE)
                && k.len() >= 2
                && let Ok(oid) = k[0].oid()
            {
                out.push((oid, k[1]));
            }
        }
    }
    out
}

fn value_text(v: &Tlv) -> String {
    v.text().unwrap_or_else(|| {
        let h: String = v.raw.iter().map(|b| format!("{b:02x}")).collect();
        format!("#{h}")
    })
}

/// Name attributes by short label, in order; repeated attributes (e.g. several OU) are joined.
pub fn rdns(name: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (oid, v) in atvs(name) {
        let l = label(&oid).to_string();
        let val = value_text(&v);
        match out.iter_mut().find(|(k, _)| *k == l) {
            Some((_, old)) => {
                old.push_str(", ");
                old.push_str(&val);
            }
            None => out.push((l, val)),
        }
    }
    out
}

pub fn get<'a>(m: &'a [(String, String)], k: &str) -> Option<&'a str> {
    m.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

pub fn dn(name: &[u8]) -> String {
    rdns(name)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn cn(name: &[u8]) -> String {
    let r = rdns(name);
    get(&r, "CN")
        .map(str::to_string)
        .unwrap_or_else(|| dn(name))
}

/// Name equality, ignoring string types, case and extra spaces (as Bouncy Castle's X500Name).
pub fn names_equal(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let norm = |n: &[u8]| -> Vec<(String, String)> {
        atvs(n)
            .iter()
            .map(|(o, v)| {
                let t = value_text(v).to_lowercase();
                (
                    o.clone(),
                    t.split_whitespace().collect::<Vec<_>>().join(" "),
                )
            })
            .collect()
    };
    let (x, y) = (norm(a), norm(b));
    !x.is_empty() && x == y
}

// ------------------------------------------------------------------ may it sign

/// Why `c` may not sign documents under its CA's rules (Order 500/НҚ p.16.4): a CA key, key
/// usage without digitalSignature and nonRepudiation, a timestamp or OCSP service key, or (when
/// its CA `issuer` was found) certificate policies outside the CA's. Only the direct issuer's
/// policies count: NCA's issuing CAs have policies outside their root's. A CA without a
/// policies extension, or with anyPolicy, sets no rule on policies. None when it may.
pub fn may_not_sign(c: &Cert, issuer: Option<&Cert>) -> Option<Text> {
    if c.is_ca() {
        return Some(tr("The certificate belongs to a certification authority, not to a person or organization.").into());
    }
    if c.key_usage()
        .is_some_and(|k| !k[KU_DIGITAL_SIGNATURE] && !k[KU_NON_REPUDIATION])
    {
        return Some(tr("The certificate's key usage does not allow signing.").into());
    }
    if c.has_eku(EKU_TIME_STAMPING) || c.has_eku(EKU_OCSP_SIGNING) {
        return Some(
            tr("The certificate belongs to a timestamp or OCSP service, not to a person or organization.")
                .into(),
        );
    }
    let allowed = match issuer?.policies()? {
        Ok(a) => a,
        Err(_) => return Some(tr("The CA certificate's policies can't be read.").into()),
    };
    if allowed.iter().any(|p| p == ANY_POLICY) {
        return None;
    }
    let under = |p: &String| {
        p == ANY_POLICY
            || allowed.iter().any(|a| {
                p == a
                    || p.strip_prefix(a.as_str())
                        .is_some_and(|r| r.starts_with('.'))
            })
    };
    match c.policies() {
        Some(Ok(own)) if own.iter().any(under) => None,
        Some(Ok(own)) if !own.is_empty() => Some(trf(
            "The certificate's policy ({}) is not one of its CA's policies ({}).",
            &[&own.join(", "), &allowed.join(", ")],
        )),
        Some(Err(_)) => Some(tr("The certificate's policies can't be read.").into()),
        _ => Some(trf(
            "The certificate names no certificate policy, but its CA issues under {}.",
            &[&allowed.join(", ")],
        )),
    }
}

