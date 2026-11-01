//! CMS SignedData (.cms files): reading (DER, BER or Base64/PEM), writing DER, new CAdES-BES
//! signers the way NCALayer makes them, and merging signers (co-signing).

use crate::cert::{self, Cert};
use crate::der::{self, Tlv};
use crate::keys::{PrivateKey, alg_id};
use crate::{Error, Result, gost, time};

pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const ID_DATA: &str = "1.2.840.113549.1.7.1";
pub const ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const ATTR_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const ATTR_SIGNING_CERT: &str = "1.2.840.113549.1.9.16.2.12";
pub const ATTR_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
pub const ATTR_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

#[derive(Clone, Debug)]
pub struct SignedData {
    pub digest_algs: Vec<Vec<u8>>,
    pub content_type: String,
    /// The embedded document; None for a detached signature.
    pub content: Option<Vec<u8>>,
    /// Certificates as encoded in the file.
    pub certs: Vec<Vec<u8>>,
    /// The `[1]` CRLs element, as encoded.
    pub crls: Option<Vec<u8>>,
    pub signers: Vec<SignerInfo>,
}

#[derive(Clone, Debug)]
pub struct SignerInfo {
    version: Vec<u8>,
    /// SignerIdentifier as encoded: IssuerAndSerialNumber or `[0]` SubjectKeyIdentifier.
    pub sid: Vec<u8>,
    digest_alg_raw: Vec<u8>,
    pub digest_alg: String,
    /// The `[0] IMPLICIT` signed attributes, as encoded.
    pub signed_attrs: Option<Vec<u8>>,
    sig_alg_raw: Vec<u8>,
    pub sig_alg: String,
    pub signature: Vec<u8>,
    /// Unsigned attributes, each as encoded.
    pub unsigned_attrs: Vec<Vec<u8>>,
}

/// Accepts DER, or Base64 / PEM text (some tools save CMS as Base64).
pub fn normalize(raw: &[u8]) -> Vec<u8> {
    if raw.first() == Some(&0x30) {
        return raw.to_vec();
    }
    let s = String::from_utf8_lossy(raw);
    let body: String = s
        .lines()
        .filter(|l| !(l.trim_start().starts_with("-----") && l.trim_end().ends_with("-----")))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    match crate::base64_decode(&body) {
        Some(d) if d.first() == Some(&0x30) => d,
        _ => raw.to_vec(),
    }
}

/// Attributes in a SET's content: (type, values as encoded).
pub fn attributes(set_content: &[u8]) -> Vec<(String, Vec<Vec<u8>>)> {
    let mut out = Vec::new();
    let mut rest = set_content;
    while !rest.is_empty() {
        let Ok((a, r)) = der::read(rest) else { break };
        rest = r;
        if let Ok(k) = a.items(der::SEQUENCE)
            && k.len() >= 2
            && let (Ok(oid), Ok(vals)) = (k[0].oid(), k[1].children())
        {
            out.push((oid, vals.iter().map(|v| v.raw.to_vec()).collect()));
        }
    }
    out
}

pub fn attribute(oid: &str, value: &[u8]) -> Vec<u8> {
    der::seq(&[&der::oid(oid), &der::tlv(der::SET, value)])
}

impl SignedData {
    /// The CMS, or None when `raw` is not a signed CMS with at least one signature.
    pub fn try_parse(raw: &[u8]) -> Option<SignedData> {
        Self::parse_inner(&normalize(raw)).ok().filter(|d| !d.signers.is_empty())
    }

    pub fn parse(raw: &[u8]) -> Result<SignedData> {
        Self::parse_inner(&normalize(raw))
            .map_err(|e| Error::new(format!("This file is not a CMS/PKCS#7 signed file ({}).", e.0)))
    }

    /// A ContentInfo with SignedData (also used for timestamp tokens).
    pub fn parse_inner(data: &[u8]) -> Result<SignedData> {
        let (ci, _) = der::read(data)?;
        let ci = ci.items(der::SEQUENCE)?;
        if ci.len() < 2 || ci[0].oid()? != SIGNED_DATA {
            return Err(Error::new("not SignedData"));
        }
        let sd = ci[1].expect(der::ctx(0))?.inner_any()?.items(der::SEQUENCE)?;
        if sd.len() < 4 {
            return Err(Error::new("SignedData too short"));
        }
        let digest_algs = sd[1].items(der::SET)?.iter().map(|a| a.raw.to_vec()).collect();
        let encap = sd[2].items(der::SEQUENCE)?;
        let content_type = encap.first().ok_or_else(|| Error::new("no content type"))?.oid()?;
        let content = match encap.get(1) {
            Some(c) => Some(c.expect(der::ctx(0))?.inner_any()?.octets()?),
            None => None,
        };
        let (mut certs, mut crls, mut signers) = (Vec::new(), None, None);
        for t in &sd[3..] {
            match t.tag {
                0xa0 => certs = t.children()?.iter().map(|c| c.raw.to_vec()).collect(),
                0xa1 => crls = Some(t.raw.to_vec()),
                der::SET => {
                    signers = Some(t.children()?.iter().map(SignerInfo::parse).collect::<Result<Vec<_>>>()?)
                }
                _ => {}
            }
        }
        Ok(SignedData {
            digest_algs,
            content_type,
            content,
            certs,
            crls,
            signers: signers.ok_or_else(|| Error::new("no signerInfos"))?,
        })
    }

    /// The certificates that parse.
    pub fn certificates(&self) -> Vec<Cert> {
        self.certs.iter().filter_map(|c| Cert::parse(c).ok()).collect()
    }

    /// DER-encoded ContentInfo.
    pub fn encode(&self) -> Vec<u8> {
        let v3 = self.content_type != ID_DATA
            || self.signers.iter().any(|s| s.sid.first() == Some(&der::ctx_prim(0)));
        let mut encap = der::oid(&self.content_type);
        if let Some(c) = &self.content {
            encap.extend(der::tlv(der::ctx(0), &der::octets(c)));
        }
        let mut body = der::small_int(if v3 { 3 } else { 1 });
        body.extend(der::set_of(self.digest_algs.clone()));
        body.extend(der::tlv(der::SEQUENCE, &encap));
        if !self.certs.is_empty() {
            body.extend(der::sorted_set(der::ctx(0), &mut self.certs.clone()));
        }
        if let Some(c) = &self.crls {
            body.extend(c);
        }
        body.extend(der::set_of(self.signers.iter().map(SignerInfo::encode).collect()));
        der::seq(&[&der::oid(SIGNED_DATA), &der::tlv(der::ctx(0), &der::tlv(der::SEQUENCE, &body))])
    }

    /// The certificate a signer names, from this file's certificates.
    pub fn signer_cert(&self, si: &SignerInfo) -> Option<Cert> {
        self.certificates().into_iter().find(|c| si.identifies(c))
    }

    /// `self` with the signers and certificates of `other` added.
    pub fn merge(&self, other: &SignedData) -> SignedData {
        let mut out = self.clone();
        out.signers.extend(other.signers.iter().cloned());
        let mut algs: Vec<Vec<u8>> = Vec::new();
        for s in &out.signers {
            if !algs.contains(&s.digest_alg_raw) {
                algs.push(s.digest_alg_raw.clone());
            }
        }
        out.digest_algs = algs;
        for c in &other.certs {
            if !out.certs.contains(c) {
                out.certs.push(c.clone());
            }
        }
        out
    }
}

impl SignerInfo {
    fn parse(t: &Tlv) -> Result<SignerInfo> {
        let k = t.items(der::SEQUENCE)?;
        if k.len() < 5 {
            return Err(Error::new("SignerInfo too short"));
        }
        let mut i = 3;
        let signed_attrs = if k[3].tag == der::ctx(0) {
            i = 4;
            Some(k[3].raw.to_vec())
        } else {
            None
        };
        let short = || Error::new("SignerInfo too short");
        let sig_alg_t = k.get(i).ok_or_else(short)?;
        let sig = k.get(i + 1).ok_or_else(short)?;
        let unsigned_attrs = match k.get(i + 2) {
            Some(u) if u.tag == der::ctx(1) => u.children()?.iter().map(|a| a.raw.to_vec()).collect(),
            _ => vec![],
        };
        Ok(SignerInfo {
            version: k[0].raw.to_vec(),
            sid: k[1].raw.to_vec(),
            digest_alg_raw: k[2].raw.to_vec(),
            digest_alg: alg_id(&k[2])?.0,
            signed_attrs,
            sig_alg_raw: sig_alg_t.raw.to_vec(),
            sig_alg: alg_id(sig_alg_t)?.0,
            signature: sig.expect(der::OCTET_STRING)?.octets()?,
            unsigned_attrs,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = der::cat(&[&self.version, &self.sid, &self.digest_alg_raw]);
        if let Some(a) = &self.signed_attrs {
            b.extend(a);
        }
        b.extend(&self.sig_alg_raw);
        b.extend(der::octets(&self.signature));
        if !self.unsigned_attrs.is_empty() {
            b.extend(der::sorted_set(der::ctx(1), &mut self.unsigned_attrs.clone()));
        }
        der::tlv(der::SEQUENCE, &b)
    }

    pub fn signed(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        match &self.signed_attrs {
            Some(a) => der::parse(a).map(|t| attributes(t.content)).unwrap_or_default(),
            None => vec![],
        }
    }

    pub fn unsigned(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        attributes(&self.unsigned_attrs.concat())
    }

    /// First value of a signed attribute.
    pub fn signed_attr(&self, oid: &str) -> Option<Vec<u8>> {
        self.signed().into_iter().find(|(o, _)| o == oid).and_then(|(_, v)| v.into_iter().next())
    }

    pub fn signing_time(&self) -> Option<i64> {
        let v = self.signed_attr(ATTR_SIGNING_TIME)?;
        der::parse(&v).ok()?.time().ok()
    }

    /// Whether `c` is the certificate this signer names.
    pub fn identifies(&self, c: &Cert) -> bool {
        let Ok(t) = der::parse(&self.sid) else { return false };
        if t.tag == der::ctx_prim(0) {
            return c.subject_key_id().is_some_and(|k| k == t.content);
        }
        let Ok(k) = t.items(der::SEQUENCE) else { return false };
        k.len() == 2
            && cert::names_equal(k[0].raw, &c.issuer)
            && k[1].uint().is_ok_and(|s| s == c.serial.as_slice())
    }

    /// The bytes the signature covers: the signed attributes as a SET, or else the content.
    pub fn signed_bytes<'a>(&self, content: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        match &self.signed_attrs {
            Some(a) => {
                let mut v = a.clone();
                v[0] = der::SET;
                std::borrow::Cow::Owned(v)
            }
            None => std::borrow::Cow::Borrowed(content),
        }
    }

    /// Adds an unsigned attribute (e.g. a signature timestamp).
    pub fn add_unsigned(&mut self, oid: &str, value: &[u8]) {
        self.unsigned_attrs.push(attribute(oid, value));
    }
}

/// A new SignedData with one CAdES-BES signer over `content` (embedded when `attach`).
pub fn sign_once(
    content: &[u8],
    content_type: &str,
    attach: bool,
    key: &PrivateKey,
    cert: &Cert,
) -> Result<SignedData> {
    let digest_oid = key.digest_oid();
    let md = gost::hash(digest_oid, content)?;
    // CAdES-BES signed attributes, the same set NCALayer writes
    let ess = der::seq(&[&der::seq(&[&der::seq(&[&der::octets(&gost::sha256(&cert.der))])])]);
    let mut attrs = vec![
        attribute(ATTR_CONTENT_TYPE, &der::oid(content_type)),
        attribute(ATTR_SIGNING_TIME, &time::encode(time::now_ms())),
        attribute(ATTR_SIGNING_CERT_V2, &ess),
        attribute(ATTR_MESSAGE_DIGEST, &der::octets(&md)),
    ];
    let signed_set = der::sorted_set(der::SET, &mut attrs);
    let signature = key.sign(&signed_set)?;
    let mut signed_attrs = signed_set;
    signed_attrs[0] = der::ctx(0);
    let si = SignerInfo {
        version: der::small_int(1),
        sid: der::seq(&[&cert.issuer, &der::uint(&cert.serial)]),
        digest_alg_raw: der::alg_null(digest_oid),
        digest_alg: digest_oid.to_string(),
        signed_attrs: Some(signed_attrs),
        sig_alg_raw: der::alg_null(key.sig_oid()),
        sig_alg: key.sig_oid().to_string(),
        signature,
        unsigned_attrs: vec![],
    };
    Ok(SignedData {
        digest_algs: vec![si.digest_alg_raw.clone()],
        content_type: content_type.to_string(),
        content: attach.then(|| content.to_vec()),
        certs: vec![cert.der.clone()],
        crls: None,
        signers: vec![si],
    })
}
