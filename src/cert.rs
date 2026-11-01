//! X.509 certificates: the fields kzsigner reads, names for people, purposes, key warnings.

use crate::der::{self, Tlv};
use crate::gost;
use crate::i18n::{tr, trf};
use crate::keys::PublicKey;
use crate::report::SignerReport;
use crate::time;
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

const KU_NON_REPUDIATION: usize = 1;
const KU_KEY_CERT_SIGN: usize = 5;

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
        // Java's Date.before/after: valid from notBefore through notAfter inclusive
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

// ------------------------------------------------------------------ for people

/// Fills the certificate part of a report: who, issuer, serial, validity, purposes.
pub fn describe(sr: &mut SignerReport, c: &Cert) {
    sr.cert_der = Some(c.der.clone());
    sr.subject = rdns(&c.subject);
    sr.subject_dn = Some(dn(&c.subject));
    let issuer_dn = dn(&c.issuer);
    sr.issuer_cn = Some(
        get(&rdns(&c.issuer), "CN")
            .map(str::to_string)
            .unwrap_or_else(|| issuer_dn.clone()),
    );
    sr.issuer_dn = Some(issuer_dn);
    sr.serial_hex = Some(c.serial_hex());
    sr.not_before = Some(c.not_before);
    sr.not_after = Some(c.not_after);
    sr.cert_types = types(c);
    if let Some(iin) = get(&sr.subject, "SERIALNUMBER").and_then(|s| s.strip_prefix("IIN")) {
        let iin = iin.to_string();
        sr.subject.push(("IIN".into(), iin));
    }
    if let Some(bin) = get(&sr.subject, "OU").and_then(|s| s.strip_prefix("BIN")) {
        let bin = bin.to_string();
        sr.subject.push(("BIN".into(), bin));
    }
}

/// Certificate purposes from key usage and extended key usage (NCA's type names).
pub fn types(c: &Cert) -> Vec<String> {
    let mut t = Vec::new();
    if c.key_usage().is_some_and(|k| k[KU_NON_REPUDIATION]) {
        t.push("SIGNATURE".into());
    }
    let eku = c.extended_key_usage();
    for (oid, name) in [
        (EKU_CLIENT_AUTH, "AUTHENTICATION"),
        (EKU_SERVER_AUTH, "SSL"),
        (EKU_OCSP_SIGNING, "OCSP_RESPONSE_SIGNING"),
        (EKU_TIME_STAMPING, "TSP_SIGNING"),
    ] {
        if eku.iter().any(|o| o == oid) {
            t.push(name.into());
        }
    }
    t
}

/// Warnings about a key that is unsuitable for signing documents (e.g. an AUTH key).
pub fn key_warnings(c: &Cert) -> Vec<String> {
    let mut w = Vec::new();
    let now = time::now_ms();
    if now > c.not_after {
        w.push(trf(
            "The certificate expired on {}.",
            &[&time::fmt(Some(c.not_after))],
        ));
    }
    if now < c.not_before {
        w.push(trf(
            "The certificate is not valid until {}.",
            &[&time::fmt(Some(c.not_before))],
        ));
    }
    if c.key_usage().is_some_and(|k| !k[KU_NON_REPUDIATION]) {
        w.push(
            tr("This certificate has no 'non-repudiation' key usage, so it looks like an authentication (AUTH_) key. Documents are normally signed with the signing key (RSA_... / GOSTKNCA_... file); some services will reject this signature.")
                .into(),
        );
    }
    w
}

pub fn alg_name(enc_oid: &str, digest_oid: Option<&str>) -> String {
    match enc_oid {
        gost::SIG_GOST2015_512 | gost::KEY_GOST2015_512 => {
            "GOST 34.10-2015 (512) / GOST 34.11-2015".into()
        }
        gost::SIG_GOST2015_256 | gost::KEY_GOST2015_256 => {
            "GOST 34.10-2015 (256) / GOST 34.11-2015".into()
        }
        gost::SIG_GOST2004 | gost::KEY_GOST2004 => "GOST 34.310-2004 / GOST 34.311-95".into(),
        gost::RSA_ENCRYPTION | gost::SIG_SHA256_RSA => {
            format!("RSA / {}", digest_label(digest_oid))
        }
        o => format!("{o} / {}", digest_label(digest_oid)),
    }
}

/// Algorithm label for a certificate's own key.
pub fn key_alg_name(c: &Cert) -> String {
    let k = c.key_alg();
    if k == gost::RSA_ENCRYPTION {
        "RSA".into()
    } else {
        alg_name(&k, None)
    }
}

pub fn digest_label(oid: Option<&str>) -> String {
    match oid {
        Some(gost::H_SHA256) => "SHA-256".into(),
        Some(gost::H_SHA1) => "SHA-1".into(),
        Some(gost::H_GOST34311) => "GOST 34.311-95".into(),
        Some(gost::H_GOST2015_512) => "GOST 34.11-2015 (512)".into(),
        Some(gost::H_GOST2015_256) => "GOST 34.11-2015 (256)".into(),
        Some(o) => o.into(),
        None => "null".into(),
    }
}
