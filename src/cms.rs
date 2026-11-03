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
        Self::parse_inner(&normalize(raw))
            .ok()
            .filter(|d| !d.signers.is_empty())
    }

    pub fn parse(raw: &[u8]) -> Result<SignedData> {
        Self::parse_inner(&normalize(raw)).map_err(|e| {
            Error::new(crate::i18n::trf(
                "This file is not a CMS/PKCS#7 signed file ({}).",
                &[&e.0],
            ))
        })
    }

    /// A ContentInfo with SignedData (also used for timestamp tokens).
    pub fn parse_inner(data: &[u8]) -> Result<SignedData> {
        let (ci, _) = der::read(data)?;
        let ci = ci.items(der::SEQUENCE)?;
        if ci.len() < 2 || ci[0].oid()? != SIGNED_DATA {
            return Err(Error::new("not SignedData"));
        }
        let sd = ci[1]
            .expect(der::ctx(0))?
            .inner_any()?
            .items(der::SEQUENCE)?;
        if sd.len() < 4 {
            return Err(Error::new("SignedData too short"));
        }
        let digest_algs = sd[1]
            .items(der::SET)?
            .iter()
            .map(|a| a.raw.to_vec())
            .collect();
        let encap = sd[2].items(der::SEQUENCE)?;
        let content_type = encap
            .first()
            .ok_or_else(|| Error::new("no content type"))?
            .oid()?;
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
                    signers = Some(
                        t.children()?
                            .iter()
                            .map(SignerInfo::parse)
                            .collect::<Result<Vec<_>>>()?,
                    )
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
        self.certs
            .iter()
            .filter_map(|c| Cert::parse(c).ok())
            .collect()
    }

    /// DER-encoded ContentInfo.
    pub fn encode(&self) -> Vec<u8> {
        let v3 = self.content_type != ID_DATA
            || self
                .signers
                .iter()
                .any(|s| s.sid.first() == Some(&der::ctx_prim(0)));
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
        body.extend(der::set_of(
            self.signers.iter().map(SignerInfo::encode).collect(),
        ));
        der::seq(&[
            &der::oid(SIGNED_DATA),
            &der::tlv(der::ctx(0), &der::tlv(der::SEQUENCE, &body)),
        ])
    }

    /// The items of the `crls` field (CertificateList, or `[1]` other revocation info such as
    /// an OCSP answer), each as encoded.
    pub fn crl_items(&self) -> Vec<Vec<u8>> {
        self.crls
            .as_deref()
            .and_then(|c| der::parse(c).ok())
            .and_then(|t| t.children().ok())
            .map(|k| k.iter().map(|i| i.raw.to_vec()).collect())
            .unwrap_or_default()
    }

    /// Adds `items` to the `crls` field, each once.
    pub fn add_crl_items(&mut self, items: &[Vec<u8>]) {
        let mut all = self.crl_items();
        let before = all.len();
        for i in items {
            if !all.contains(i) {
                all.push(i.clone());
            }
        }
        if all.len() != before {
            self.crls = Some(der::sorted_set(der::ctx(1), &mut all));
        }
    }

    /// Adds certificates, each once.
    pub fn add_certs(&mut self, certs: &[Vec<u8>]) {
        for c in certs {
            if !self.certs.contains(c) {
                self.certs.push(c.clone());
            }
        }
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
        out.add_certs(&other.certs);
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
            Some(u) if u.tag == der::ctx(1) => {
                u.children()?.iter().map(|a| a.raw.to_vec()).collect()
            }
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
            b.extend(der::sorted_set(
                der::ctx(1),
                &mut self.unsigned_attrs.clone(),
            ));
        }
        der::tlv(der::SEQUENCE, &b)
    }

    pub fn signed(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        match &self.signed_attrs {
            Some(a) => der::parse(a)
                .map(|t| attributes(t.content))
                .unwrap_or_default(),
            None => vec![],
        }
    }

    pub fn unsigned(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        attributes(&self.unsigned_attrs.concat())
    }

    /// First value of a signed attribute.
    pub fn signed_attr(&self, oid: &str) -> Option<Vec<u8>> {
        self.signed()
            .into_iter()
            .find(|(o, _)| o == oid)
            .and_then(|(_, v)| v.into_iter().next())
    }

    pub fn signing_time(&self) -> Option<i64> {
        let v = self.signed_attr(ATTR_SIGNING_TIME)?;
        der::parse(&v).ok()?.time().ok()
    }

    /// Whether `c` is the certificate this signer names.
    pub fn identifies(&self, c: &Cert) -> bool {
        let Ok(t) = der::parse(&self.sid) else {
            return false;
        };
        if t.tag == der::ctx_prim(0) {
            return c.subject_key_id().is_some_and(|k| k == t.content);
        }
        let Ok(k) = t.items(der::SEQUENCE) else {
            return false;
        };
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

    /// The fields an archive-time-stamp-v3 covers (ETSI EN 319 122-1 5.5.3): version, sid,
    /// digestAlgorithm, signedAttrs, signatureAlgorithm and signature, as encoded.
    pub fn archive_fields(&self) -> Vec<u8> {
        let mut b = der::cat(&[&self.version, &self.sid, &self.digest_alg_raw]);
        if let Some(a) = &self.signed_attrs {
            b.extend(a);
        }
        b.extend(&self.sig_alg_raw);
        b.extend(der::octets(&self.signature));
        b
    }

    /// Each unsigned attribute value with its attribute's type: (type as encoded, value as
    /// encoded).
    pub fn unsigned_values(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for a in &self.unsigned_attrs {
            let Ok(k) = der::parse(a).and_then(|t| t.items(der::SEQUENCE)) else {
                continue;
            };
            if k.len() < 2 {
                continue;
            }
            if let Ok(vals) = k[1].children() {
                for v in vals.iter() {
                    out.push((k[0].raw.to_vec(), v.raw.to_vec()));
                }
            }
        }
        out
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
    sign_once_with(content, content_type, attach, key, cert, true, &[])
}

/// [`sign_once`]; `signing_time`: whether to include the signing-time attribute (PAdES leaves
/// it out and keeps the time in the PDF's signature dictionary instead); `extra`: more signed
/// attributes, as encoded.
pub fn sign_once_with(
    content: &[u8],
    content_type: &str,
    attach: bool,
    key: &PrivateKey,
    cert: &Cert,
    signing_time: bool,
    extra: &[Vec<u8>],
) -> Result<SignedData> {
    let md = gost::hash(key.digest_oid(), content)?;
    let mut sd = sign_digest(&md, content_type, key, cert, signing_time, extra)?;
    if attach {
        sd.content = Some(content.to_vec());
    }
    Ok(sd)
}

/// A detached signature over a document whose hash, made with `key`'s digest algorithm, is
/// `md` (the document itself is never seen).
pub fn sign_digest(
    md: &[u8],
    content_type: &str,
    key: &PrivateKey,
    cert: &Cert,
    signing_time: bool,
    extra: &[Vec<u8>],
) -> Result<SignedData> {
    let digest_oid = key.digest_oid();
    // CAdES-BES signed attributes, the same set NCALayer writes
    let ess = der::seq(&[&der::seq(&[&der::seq(&[&der::octets(&gost::sha256(
        &cert.der,
    ))])])]);
    let mut attrs = vec![
        attribute(ATTR_CONTENT_TYPE, &der::oid(content_type)),
        attribute(ATTR_SIGNING_CERT_V2, &ess),
        attribute(ATTR_MESSAGE_DIGEST, &der::octets(md)),
    ];
    if signing_time {
        attrs.push(attribute(ATTR_SIGNING_TIME, &time::encode(time::now_ms())));
    }
    attrs.extend(extra.iter().cloned());
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
        content: None,
        certs: vec![cert.der.clone()],
        crls: None,
        signers: vec![si],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> crate::p12::Key {
        let d = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/alice_gost2015.p12"
        ))
        .unwrap();
        crate::p12::open(&d, "Qwerty12", None).unwrap()
    }

    fn signed(content_type: &str) -> SignedData {
        let k = key();
        sign_once(b"hello", content_type, true, &k.private_key, &k.cert).unwrap()
    }

    /// The SignedData version (RFC 5652 5.1): 3 for other content than data, or a signer named
    /// by its key identifier; 1 otherwise.
    fn version(d: &SignedData) -> i64 {
        let enc = d.encode();
        let ci = der::parse(&enc).unwrap().items(der::SEQUENCE).unwrap();
        let sd = ci[1].inner().unwrap().items(der::SEQUENCE).unwrap();
        sd[0].small_int().unwrap()
    }

    #[test]
    fn versions_and_signer_ids() {
        let k = key();
        let d = signed(ID_DATA);
        assert_eq!(version(&d), 1);
        assert_eq!(version(&signed(crate::tsp::TST_INFO)), 3);
        // named by subject key identifier
        let mut ski = d.clone();
        ski.signers[0].sid = der::tlv(der::ctx_prim(0), &[1, 2, 3]);
        assert_eq!(version(&ski), 3);
        let mut c = k.cert.clone();
        assert!(!ski.signers[0].identifies(&c));
        c.extensions
            .push(("2.5.29.14".into(), der::octets(&[1, 2, 3])));
        assert!(ski.signers[0].identifies(&c));
        c.extensions.last_mut().unwrap().1 = der::octets(&[1, 2, 4]);
        assert!(!ski.signers[0].identifies(&c));
        assert!(d.signers[0].identifies(&k.cert));
    }

    #[test]
    fn structure() {
        // without certificates: the four required fields
        let mut d = signed(ID_DATA);
        d.certs.clear();
        let back = SignedData::parse_inner(&d.encode()).unwrap();
        assert_eq!(back.signers.len(), 1);
        assert_eq!(back.content.as_deref(), Some(&b"hello"[..]));
        // a signer without signed attributes: its five fields
        let mut d = signed(ID_DATA);
        d.signers[0].signed_attrs = None;
        let back = SignedData::parse_inner(&d.encode()).unwrap();
        assert!(back.signers[0].signed_attrs.is_none());
        assert_eq!(back.signers[0].signature, d.signers[0].signature);

        // not SignedData
        let data = der::seq(&[
            &der::oid(ID_DATA),
            &der::tlv(der::ctx(0), &der::octets(b"x")),
        ]);
        let e = SignedData::parse_inner(&data).err().unwrap();
        assert_eq!(e.0, "not SignedData");
        let bare = der::seq(&[&der::oid(SIGNED_DATA)]);
        assert_eq!(
            SignedData::parse_inner(&bare).err().unwrap().0,
            "not SignedData"
        );

        // unsigned attribute values, by type
        let mut d = signed(ID_DATA);
        d.signers[0].add_unsigned("1.2.3", &der::null());
        let v = d.signers[0].unsigned_values();
        assert_eq!(v, vec![(der::oid("1.2.3"), der::null())]);
    }

    #[test]
    fn revocation_items_and_merging() {
        let mut d = signed(ID_DATA);
        d.add_crl_items(&[]);
        assert!(d.crls.is_none());
        let (a, b) = (der::seq(&[&der::null()]), der::seq(&[&der::boolean(true)]));
        d.add_crl_items(std::slice::from_ref(&a));
        assert_eq!(d.crl_items(), vec![a.clone()]);
        let before = d.crls.clone();
        d.add_crl_items(std::slice::from_ref(&a));
        assert_eq!(d.crls, before);
        d.add_crl_items(&[b.clone(), a.clone()]);
        assert_eq!(d.crl_items().len(), 2);
        assert!(d.crl_items().contains(&b));

        // merged signers keep each digest algorithm once
        let m = d.merge(&signed(ID_DATA));
        assert_eq!(m.signers.len(), 2);
        assert_eq!(m.digest_algs.len(), 1);
        let mut other = signed(ID_DATA);
        other.signers[0].digest_alg_raw = der::alg_null(crate::gost::H_SHA256);
        assert_eq!(d.merge(&other).digest_algs.len(), 2);
    }

    #[test]
    fn base64_and_pem() {
        let der = signed(ID_DATA).encode();
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der);
        assert_eq!(normalize(&der), der);
        let wrapped: String = b64
            .as_bytes()
            .chunks(64)
            .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
            .collect();
        assert_eq!(normalize(wrapped.as_bytes()), der);
        let pem = format!("-----BEGIN CMS-----\n{wrapped}-----END CMS-----\n");
        assert_eq!(normalize(pem.as_bytes()), der);
        // a dashed line that is not a PEM header is kept, and spoils the Base64
        let odd = format!("-----BEGIN CMS\n{wrapped}");
        assert_eq!(normalize(odd.as_bytes()), odd.as_bytes());
        // Base64 of something that is not DER is left as it was
        let text = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello");
        assert_eq!(normalize(text.as_bytes()), text.as_bytes());
    }
}
