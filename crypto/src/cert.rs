//! X.509 certificates: the fields kzsigner reads, names, and whether a certificate may sign.

use ::der::asn1::Any;
use ::der::{Decode, Encode, Tag, Tagged};
use x509_cert::ext::pkix::{
    BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};

use crate::der::Tlv;
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

/// An INTEGER's content without leading zero bytes (one zero for zero).
fn strip_zeros(mut b: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = b
        && !rest.is_empty()
    {
        b = rest;
    }
    b
}

impl Cert {
    pub fn parse(data: &[u8]) -> Result<Cert> {
        Self::from_der(data)
    }

    /// Accepts DER, or Base64 / PEM text.
    pub fn parse_any(data: &[u8]) -> Result<Cert> {
        Self::parse(&crate::cms::normalize(data))
    }

    pub fn from_tlv(t: &Tlv) -> Result<Cert> {
        Self::parse(t.raw)
    }

    /// From DER, read by `x509-cert`. Its `Raw` profile: CAs, NCA's among them, issue serial
    /// numbers RFC 5280 forbids (negative, or longer than 20 bytes), and the fields are kept
    /// exactly as encoded.
    fn from_der(data: &[u8]) -> Result<Cert> {
        use x509_cert::der::{Decode, Encode};
        let f = |_| Error::malformed("Unreadable certificate: malformed ASN.1");
        let c =
            x509_cert::certificate::CertificateInner::<x509_cert::certificate::Raw>::from_der(data)
                .map_err(f)?;
        let tbs = c.tbs_certificate();
        let ms = |t: &x509_cert::time::Time| -> Result<i64> {
            i64::try_from(t.to_unix_duration().as_millis())
                .map_err(|_| Error::malformed("Unreadable certificate: malformed ASN.1"))
        };
        let mut extensions = Vec::new();
        for e in tbs.extensions().into_iter().flatten() {
            extensions.push((e.extn_id.to_string(), e.extn_value.as_bytes().to_vec()));
        }
        Ok(Cert {
            der: data.to_vec(),
            tbs: tbs.to_der().map_err(f)?,
            serial: strip_zeros(tbs.serial_number().as_bytes()).to_vec(),
            issuer: tbs.issuer().to_der().map_err(f)?,
            subject: tbs.subject().to_der().map_err(f)?,
            not_before: ms(&tbs.validity().not_before)?,
            not_after: ms(&tbs.validity().not_after)?,
            spki: tbs.subject_public_key_info().to_der().map_err(f)?,
            sig_alg: c.signature_algorithm().oid.to_string(),
            signature: c
                .signature()
                .as_bytes()
                .ok_or_else(|| Error::malformed("Unreadable certificate: malformed ASN.1"))?
                .to_vec(),
            extensions,
        })
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(&self.spki)
    }

    fn spki(&self) -> Option<spki::SubjectPublicKeyInfoOwned> {
        spki::SubjectPublicKeyInfoOwned::from_der(&self.spki).ok()
    }

    pub fn key_alg(&self) -> String {
        self.spki()
            .map(|k| k.algorithm.oid.to_string())
            .unwrap_or_default()
    }

    /// The public key BIT STRING contents (for OCSP key hashes).
    pub fn public_key_bits(&self) -> Result<Vec<u8>> {
        self.spki()
            .and_then(|k| k.subject_public_key.as_bytes().map(<[u8]>::to_vec))
            .ok_or_else(|| Error::malformed("malformed SubjectPublicKeyInfo"))
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

    /// An extension's value, read as `T`.
    fn ext<'a, T: Decode<'a>>(&'a self, oid: &str) -> Option<core::result::Result<T, T::Error>> {
        self.extension(oid).map(T::from_der)
    }

    /// The subject key identifier extension's value.
    pub fn subject_key_id(&self) -> Option<Vec<u8>> {
        let id: SubjectKeyIdentifier = self.ext("2.5.29.14")?.ok()?;
        Some(id.0.as_bytes().to_vec())
    }

    /// Key usage bits, or None without the extension.
    pub fn key_usage(&self) -> Option<Vec<bool>> {
        let ku: KeyUsage = self.ext("2.5.29.15")?.ok()?;
        let bits = ku.0.bits();
        Some((0..9).map(|i| bits & (1 << i) != 0).collect())
    }

    pub fn extended_key_usage(&self) -> Vec<String> {
        match self.ext::<ExtendedKeyUsage>("2.5.29.37") {
            Some(Ok(e)) => e.0.iter().map(ToString::to_string).collect(),
            _ => vec![],
        }
    }

    /// The policy OIDs in the certificate policies extension: None without the extension,
    /// Some(Err) when it can't be read.
    pub fn policies(&self) -> Option<Result<Vec<String>>> {
        Some(
            self.ext::<CertificatePolicies>("2.5.29.32")?
                .map(|p| {
                    p.0.iter()
                        .map(|i| i.policy_identifier.to_string())
                        .collect()
                })
                .map_err(|e| Error::malformed(format!("malformed ASN.1: {e}"))),
        )
    }

    pub fn has_eku(&self, oid: &str) -> bool {
        self.extended_key_usage().iter().any(|o| o == oid)
    }

    /// Basic constraints cA flag (false without the extension).
    pub fn is_ca(&self) -> bool {
        matches!(self.ext::<BasicConstraints>("2.5.29.19"), Some(Ok(b)) if b.ca)
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

fn atvs(name: &[u8]) -> Vec<(String, Any)> {
    let Ok(n) = x509_cert::name::Name::from_der(name) else {
        return vec![];
    };
    n.iter()
        .map(|atv| (atv.oid.to_string(), atv.value.clone()))
        .collect()
}

/// A name attribute's text: any of the ASN.1 string types, else `#` and the encoding in hex.
fn value_text(v: &Any) -> String {
    let c = v.value();
    match v.tag() {
        Tag::Utf8String
        | Tag::PrintableString
        | Tag::Ia5String
        | Tag::VisibleString
        | Tag::NumericString => String::from_utf8_lossy(c).into_owned(),
        Tag::TeletexString => c.iter().map(|&b| b as char).collect(),
        Tag::BmpString => {
            let u: Vec<u16> = c
                .chunks(2)
                .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&u)
        }
        // UniversalString
        t if t.is_universal() && t.number().value() == 0x1c => c
            .chunks(4)
            .filter(|&p| p.len() == 4)
            .map(|p| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
            .map(|u| char::from_u32(u).unwrap_or('\u{fffd}'))
            .collect(),
        _ => {
            let h: String = v
                .to_der()
                .unwrap_or_default()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("#{h}")
        }
    }
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
        return Some(tr(
            "The certificate belongs to a certification authority, not to a person or organization.",
        ));
    }
    if c.key_usage()
        .is_some_and(|k| !k[KU_DIGITAL_SIGNATURE] && !k[KU_NON_REPUDIATION])
    {
        return Some(tr("The certificate's key usage does not allow signing."));
    }
    if c.has_eku(EKU_TIME_STAMPING) || c.has_eku(EKU_OCSP_SIGNING) {
        return Some(tr(
            "The certificate belongs to a timestamp or OCSP service, not to a person or organization.",
        ));
    }
    let allowed = match issuer?.policies()? {
        Ok(a) => a,
        Err(_) => return Some(tr("The CA certificate's policies can't be read.")),
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
        Some(Err(_)) => Some(tr("The certificate's policies can't be read.")),
        _ => Some(trf(
            "The certificate names no certificate policy, but its CA issues under {}.",
            &[&allowed.join(", ")],
        )),
    }
}
