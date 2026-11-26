//! CMS SignedData (.cms files): reading (DER, BER or Base64/PEM), writing DER, new CAdES-BES
//! signers the way NCALayer makes them, and merging signers (co-signing).

use ::der::asn1::{Any, Int, ObjectIdentifier, OctetString, OctetStringRef, SetOfVec};
use ::der::{Sequence, Tag, Tagged};
use x509_cert::attr::Attribute;

use crate::asn1::{self, any, ber};
use crate::cert::{self, Cert};
use crate::keys::PrivateKey;
use crate::prelude::*;
use crate::{Error, ErrorKind, Result, Rng, gost, time};

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

/// Each attribute: (type, values as encoded).
fn attributes<'a>(list: impl IntoIterator<Item = &'a Attribute>) -> Vec<(String, Vec<Vec<u8>>)> {
    list.into_iter()
        .map(|a| {
            let vals = a.values.iter().filter_map(|v| asn1::der(v).ok()).collect();
            (a.oid.to_string(), vals)
        })
        .collect()
}

/// An attribute of type `oid` with the one value `value` (as encoded).
pub fn attribute(oid: &str, value: &[u8]) -> Result<Vec<u8>> {
    let values = SetOfVec::try_from(vec![any(value)?]).map_err(asn1::err)?;
    asn1::der(&Attribute {
        oid: asn1::oid(oid)?,
        values,
    })
}

/// SignedData (RFC 5652 5.1) for writing, each part as already encoded.
#[derive(Sequence)]
struct SdOut {
    version: u8,
    digest_algorithms: SetOfVec<Any>,
    encap_content_info: EncapOut,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<SetOfVec<Any>>,
    crls: Option<Any>,
    signer_infos: SetOfVec<Any>,
}

#[derive(Sequence)]
struct EncapOut {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    content: Option<OctetString>,
}

#[derive(Sequence)]
struct ContentInfoOut {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: SdOut,
}

/// SignerInfo (RFC 5652 5.3) for writing, each part as already encoded.
#[derive(Sequence)]
struct SiOut {
    version: Any,
    sid: Any,
    digest_alg: Any,
    signed_attrs: Option<Any>,
    sig_alg: Any,
    signature: OctetString,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    unsigned_attrs: Option<SetOfVec<Any>>,
}

/// IssuerAndSerialNumber (RFC 5652 10.2.4), the issuer's name as encoded.
#[derive(Sequence)]
struct IssuerSerial {
    issuer: Any,
    serial: Int,
}

/// ESSCertIDv2 (RFC 5035) with the default hash (SHA-256) and no issuer and serial, as
/// NCALayer writes it.
#[derive(Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

/// SigningCertificateV2 (RFC 5035) without policies.
#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

fn set(items: &[Vec<u8>]) -> Result<SetOfVec<Any>> {
    let v = items.iter().map(|i| any(i)).collect::<Result<Vec<_>>>()?;
    SetOfVec::try_from(v).map_err(asn1::err)
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
            Error::of(
                ErrorKind::Malformed,
                crate::text::trf("This file is not a CMS/PKCS#7 signed file ({}).", &[&e]),
            )
        })
    }

    /// A ContentInfo with SignedData (also used for timestamp tokens), read by RustCrypto's
    /// `cms` (BER or DER). Each part is kept as its DER encoding.
    pub fn parse_inner(data: &[u8]) -> Result<SignedData> {
        rc::signed_data(data)
    }

    /// The certificates that parse.
    pub fn certificates(&self) -> Vec<Cert> {
        self.certs
            .iter()
            .filter_map(|c| Cert::parse(c).ok())
            .collect()
    }

    /// DER-encoded ContentInfo.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let v3 = self.content_type != ID_DATA
            || self.signers.iter().any(|s| {
                any(&s.sid).is_ok_and(|a| {
                    a.tag()
                        == Tag::ContextSpecific {
                            constructed: false,
                            number: ::der::TagNumber(0),
                        }
                })
            });
        let content = match &self.content {
            Some(c) => Some(OctetString::new(c.as_slice()).map_err(asn1::err)?),
            None => None,
        };
        let signers = self
            .signers
            .iter()
            .map(SignerInfo::encode)
            .collect::<Result<Vec<_>>>()?;
        asn1::der(&ContentInfoOut {
            content_type: asn1::oid(SIGNED_DATA)?,
            content: SdOut {
                version: if v3 { 3 } else { 1 },
                digest_algorithms: set(&self.digest_algs)?,
                encap_content_info: EncapOut {
                    content_type: asn1::oid(&self.content_type)?,
                    content,
                },
                certificates: match self.certs.is_empty() {
                    true => None,
                    false => Some(set(&self.certs)?),
                },
                crls: self.crls.as_deref().map(any).transpose()?,
                signer_infos: set(&signers)?,
            },
        })
    }

    /// The items of the `crls` field (CertificateList, or `[1]` other revocation info such as
    /// an OCSP answer), each as encoded.
    pub fn crl_items(&self) -> Vec<Vec<u8>> {
        let Some(c) = &self.crls else {
            return vec![];
        };
        // [1] IMPLICIT SET OF: read as the SET it stands for
        let mut set = c.clone();
        set[0] = 0x31;
        ber::<SetOfVec<Any>>(&set)
            .map(|s| s.iter().filter_map(|i| asn1::der(i).ok()).collect())
            .unwrap_or_default()
    }

    /// Adds `items` to the `crls` field, each once.
    pub fn add_crl_items(&mut self, items: &[Vec<u8>]) -> Result<()> {
        let mut all = self.crl_items();
        let before = all.len();
        for i in items {
            if !all.contains(i) {
                all.push(i.clone());
            }
        }
        if all.len() != before {
            self.crls = Some(asn1::implicit(1, asn1::der(&set(&all)?)?));
        }
        Ok(())
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

/// Reading with RustCrypto's `cms`.
mod rc {
    use ::cms::content_info::ContentInfo;
    use ::cms::signed_data::{SignedData as Sd, SignerInfo as Si};
    use ::der::asn1::OctetString;

    use super::{SIGNED_DATA, SignedData, SignerInfo};
    use crate::asn1::{ber, der, err as asn1, implicit};
    use crate::prelude::*;
    use crate::{Error, Result};

    pub fn signed_data(data: &[u8]) -> Result<SignedData> {
        let ci: ContentInfo = ber(data).map_err(asn1)?;
        if ci.content_type.to_string() != SIGNED_DATA {
            return Err(Error::new("not SignedData"));
        }
        let sd: Sd = ber(&der(&ci.content)?).map_err(asn1)?;
        let content = match &sd.encap_content_info.econtent {
            Some(c) => Some(
                ber::<OctetString>(&der(c)?)
                    .map_err(asn1)?
                    .into_bytes()
                    .into_vec(),
            ),
            None => None,
        };
        let mut certs = Vec::new();
        for c in sd.certificates.iter().flat_map(|s| s.0.iter()) {
            certs.push(der(c)?);
        }
        let crls = match &sd.crls {
            Some(c) => Some(implicit(1, der(&c.0)?)),
            None => None,
        };
        let mut signers = Vec::new();
        for s in sd.signer_infos.0.iter() {
            signers.push(signer(s)?);
        }
        Ok(SignedData {
            digest_algs: sd
                .digest_algorithms
                .iter()
                .map(der)
                .collect::<Result<_>>()?,
            content_type: sd.encap_content_info.econtent_type.to_string(),
            content,
            certs,
            crls,
            signers,
        })
    }

    fn signer(s: &Si) -> Result<SignerInfo> {
        Ok(SignerInfo {
            version: der(&s.version)?,
            sid: der(&s.sid)?,
            digest_alg_raw: der(&s.digest_alg)?,
            digest_alg: s.digest_alg.oid.to_string(),
            signed_attrs: match &s.signed_attrs {
                Some(a) => Some(implicit(0, der(a)?)),
                None => None,
            },
            sig_alg_raw: der(&s.signature_algorithm)?,
            sig_alg: s.signature_algorithm.oid.to_string(),
            signature: s.signature.as_bytes().to_vec(),
            unsigned_attrs: s
                .unsigned_attrs
                .iter()
                .flat_map(|a| a.iter())
                .map(der)
                .collect::<Result<_>>()?,
        })
    }
}

impl SignerInfo {
    pub fn encode(&self) -> Result<Vec<u8>> {
        asn1::der(&SiOut {
            version: any(&self.version)?,
            sid: any(&self.sid)?,
            digest_alg: any(&self.digest_alg_raw)?,
            signed_attrs: self.signed_attrs.as_deref().map(any).transpose()?,
            sig_alg: any(&self.sig_alg_raw)?,
            signature: OctetString::new(self.signature.as_slice()).map_err(asn1::err)?,
            unsigned_attrs: match self.unsigned_attrs.is_empty() {
                true => None,
                false => Some(set(&self.unsigned_attrs)?),
            },
        })
    }

    pub fn signed(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        match &self.signed_attrs {
            Some(_) => ber::<SetOfVec<Attribute>>(&self.signed_bytes(&[]))
                .map(|s| attributes(s.iter()))
                .unwrap_or_default(),
            None => vec![],
        }
    }

    pub fn unsigned(&self) -> Vec<(String, Vec<Vec<u8>>)> {
        let list: Vec<Attribute> = self
            .unsigned_attrs
            .iter()
            .filter_map(|a| ber(a).ok())
            .collect();
        attributes(&list)
    }

    /// First value of a signed attribute.
    pub fn signed_attr(&self, oid: &str) -> Option<Vec<u8>> {
        self.signed()
            .into_iter()
            .find(|(o, _)| o == oid)
            .and_then(|(_, v)| v.into_iter().next())
    }

    pub fn signing_time(&self) -> Option<i64> {
        let v = any(&self.signed_attr(ATTR_SIGNING_TIME)?).ok()?;
        time::parse_asn1(v.tag(), v.value()).ok()
    }

    /// Whether `c` is the certificate this signer names.
    pub fn identifies(&self, c: &Cert) -> bool {
        let Ok(t) = any(&self.sid) else {
            return false;
        };
        if t.tag()
            == (Tag::ContextSpecific {
                constructed: false,
                number: ::der::TagNumber(0),
            })
        {
            return c.subject_key_id().is_some_and(|k| k == t.value());
        }
        let Ok(k) = ber::<IssuerSerial>(&self.sid) else {
            return false;
        };
        asn1::der(&k.issuer).is_ok_and(|i| cert::names_equal(&i, &c.issuer))
            && asn1::strip_zeros(k.serial.as_bytes()) == c.serial.as_slice()
    }

    /// The bytes the signature covers: the signed attributes as a SET, or else the content.
    pub fn signed_bytes<'a>(&self, content: &'a [u8]) -> alloc::borrow::Cow<'a, [u8]> {
        match &self.signed_attrs {
            Some(a) => {
                let mut v = a.clone();
                v[0] = 0x31; // SET
                alloc::borrow::Cow::Owned(v)
            }
            None => alloc::borrow::Cow::Borrowed(content),
        }
    }

    /// The fields an archive-time-stamp-v3 covers (ETSI EN 319 122-1 5.5.3): version, sid,
    /// digestAlgorithm, signedAttrs, signatureAlgorithm and signature, as encoded.
    pub fn archive_fields(&self) -> Result<Vec<u8>> {
        let mut b = [&self.version[..], &self.sid, &self.digest_alg_raw].concat();
        if let Some(a) = &self.signed_attrs {
            b.extend(a);
        }
        b.extend(&self.sig_alg_raw);
        b.extend(asn1::der(
            &OctetStringRef::new(&self.signature).map_err(asn1::err)?,
        )?);
        Ok(b)
    }

    /// Each unsigned attribute value with its attribute's type: (type as encoded, value as
    /// encoded).
    pub fn unsigned_values(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for a in &self.unsigned_attrs {
            let Ok(a) = ber::<Attribute>(a) else { continue };
            let Ok(t) = asn1::der(&a.oid) else { continue };
            for v in a.values.iter() {
                if let Ok(v) = asn1::der(v) {
                    out.push((t.clone(), v));
                }
            }
        }
        out
    }

    /// Adds an unsigned attribute (e.g. a signature timestamp).
    pub fn add_unsigned(&mut self, oid: &str, value: &[u8]) -> Result<()> {
        self.unsigned_attrs.push(attribute(oid, value)?);
        Ok(())
    }
}

/// A new SignedData with one CAdES-BES signer over `content` (embedded when `attach`), signed
/// at `now` (milliseconds since 1970, UTC).
pub fn sign_once(
    content: &[u8],
    content_type: &str,
    attach: bool,
    key: &PrivateKey,
    cert: &Cert,
    now: i64,
    rng: &mut dyn Rng,
) -> Result<SignedData> {
    sign_once_with(
        content,
        content_type,
        attach,
        key,
        cert,
        Some(now),
        &[],
        rng,
    )
}

/// [`sign_once`]; `signing_time`: the signing-time attribute, or None to leave it out (PAdES
/// keeps the time in the PDF's signature dictionary instead); `extra`: more signed attributes,
/// as encoded.
#[allow(clippy::too_many_arguments)]
pub fn sign_once_with(
    content: &[u8],
    content_type: &str,
    attach: bool,
    key: &PrivateKey,
    cert: &Cert,
    signing_time: Option<i64>,
    extra: &[Vec<u8>],
    rng: &mut dyn Rng,
) -> Result<SignedData> {
    let md = gost::hash(key.digest_oid(), content)?;
    let mut sd = sign_digest(&md, content_type, key, cert, signing_time, extra, rng)?;
    if attach {
        sd.content = Some(content.to_vec());
    }
    Ok(sd)
}

/// A detached signature over a document whose hash, made with `key`'s digest algorithm, is
/// `md` (the document itself is never seen). `signing_time`: as in [`sign_once_with`].
pub fn sign_digest(
    md: &[u8],
    content_type: &str,
    key: &PrivateKey,
    cert: &Cert,
    signing_time: Option<i64>,
    extra: &[Vec<u8>],
    rng: &mut dyn Rng,
) -> Result<SignedData> {
    let ct = asn1::oid(content_type)?;
    let digest_oid = key.digest_oid();
    // CAdES-BES signed attributes, the same set NCALayer writes
    let ess = asn1::der(&SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(gost::sha256(&cert.der).to_vec()).map_err(asn1::err)?,
        }],
    })?;
    let mut attrs = vec![
        attribute(ATTR_CONTENT_TYPE, &asn1::der(&ct)?)?,
        attribute(ATTR_SIGNING_CERT_V2, &ess)?,
        attribute(
            ATTR_MESSAGE_DIGEST,
            &asn1::der(&OctetStringRef::new(md).map_err(asn1::err)?)?,
        )?,
    ];
    if let Some(t) = signing_time {
        attrs.push(attribute(ATTR_SIGNING_TIME, &time::encode(t)?)?);
    }
    attrs.extend(extra.iter().cloned());
    let signed_set = asn1::der(&set(&attrs)?)?;
    let signature = key.sign(&signed_set, rng)?;
    let signed_attrs = asn1::implicit(0, signed_set);
    let si = SignerInfo {
        version: asn1::der(&1u8)?,
        sid: asn1::der(&IssuerSerial {
            issuer: any(&cert.issuer)?,
            serial: asn1::positive(&cert.serial)?,
        })?,
        digest_alg_raw: asn1::alg_null(digest_oid)?,
        digest_alg: digest_oid.to_string(),
        signed_attrs: Some(signed_attrs),
        sig_alg_raw: asn1::alg_null(key.sig_oid())?,
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

    use crate::testing::{OsRng, now_ms};
    use ::der::{Decode, Encode};

    fn octets(b: &[u8]) -> Vec<u8> {
        OctetStringRef::new(b).unwrap().to_der().unwrap()
    }

    fn key() -> crate::p12::Key {
        crate::testing::key("alice_gost2015")
    }

    fn signed(content_type: &str) -> SignedData {
        let k = key();
        sign_once(
            b"hello",
            content_type,
            true,
            &k.private_key,
            &k.cert,
            now_ms(),
            &mut OsRng,
        )
        .unwrap()
    }

    /// The SignedData version (RFC 5652 5.1): 3 for other content than data, or a signer named
    /// by its key identifier; 1 otherwise.
    fn version(d: &SignedData) -> u8 {
        use ::cms::content_info::ContentInfo;
        let ci = ContentInfo::from_der(&d.encode().unwrap()).unwrap();
        let sd: ::cms::signed_data::SignedData = ci.content.decode_as().unwrap();
        sd.version as u8
    }

    #[test]
    fn versions_and_signer_ids() {
        let k = key();
        let d = signed(ID_DATA);
        assert_eq!(version(&d), 1);
        assert_eq!(version(&signed(crate::tsp::TST_INFO)), 3);
        // named by subject key identifier
        let mut ski = d.clone();
        ski.signers[0].sid = vec![0x80, 3, 1, 2, 3];
        assert_eq!(version(&ski), 3);
        let mut c = k.cert.clone();
        assert!(!ski.signers[0].identifies(&c));
        c.extensions.push(("2.5.29.14".into(), octets(&[1, 2, 3])));
        assert!(ski.signers[0].identifies(&c));
        c.extensions.last_mut().unwrap().1 = octets(&[1, 2, 4]);
        assert!(!ski.signers[0].identifies(&c));
        assert!(d.signers[0].identifies(&k.cert));
    }

    #[test]
    fn structure() {
        // without certificates: the four required fields
        let mut d = signed(ID_DATA);
        d.certs.clear();
        let back = SignedData::parse_inner(&d.encode().unwrap()).unwrap();
        assert_eq!(back.signers.len(), 1);
        assert_eq!(back.content.as_deref(), Some(&b"hello"[..]));
        // a signer without signed attributes: its five fields
        let mut d = signed(ID_DATA);
        d.signers[0].signed_attrs = None;
        let back = SignedData::parse_inner(&d.encode().unwrap()).unwrap();
        assert!(back.signers[0].signed_attrs.is_none());
        assert_eq!(back.signers[0].signature, d.signers[0].signature);

        // not SignedData
        let data = ::cms::content_info::ContentInfo {
            content_type: asn1::oid(ID_DATA).unwrap(),
            content: any(&octets(b"x")).unwrap(),
        }
        .to_der()
        .unwrap();
        let e = SignedData::parse_inner(&data).err().unwrap();
        assert_eq!(e.to_string(), "not SignedData");
        let mut bare = vec![0x30, 11];
        bare.extend(asn1::oid(SIGNED_DATA).unwrap().to_der().unwrap());
        assert!(SignedData::parse_inner(&bare).is_err());

        // unsigned attribute values, by type
        let mut d = signed(ID_DATA);
        d.signers[0].add_unsigned("1.2.3", &[5, 0]).unwrap();
        let v = d.signers[0].unsigned_values();
        assert_eq!(v, vec![(vec![6, 2, 0x2a, 3], vec![5, 0])]);
    }

    #[test]
    fn revocation_items_and_merging() {
        let mut d = signed(ID_DATA);
        d.add_crl_items(&[]).unwrap();
        assert!(d.crls.is_none());
        let (a, b) = (vec![0x30, 2, 5, 0], vec![0x30, 3, 1, 1, 0xff]);
        d.add_crl_items(std::slice::from_ref(&a)).unwrap();
        assert_eq!(d.crl_items(), vec![a.clone()]);
        let before = d.crls.clone();
        d.add_crl_items(std::slice::from_ref(&a)).unwrap();
        assert_eq!(d.crls, before);
        d.add_crl_items(&[b.clone(), a.clone()]).unwrap();
        assert_eq!(d.crl_items().len(), 2);
        assert!(d.crl_items().contains(&b));

        // merged signers keep each digest algorithm once
        let m = d.merge(&signed(ID_DATA));
        assert_eq!(m.signers.len(), 2);
        assert_eq!(m.digest_algs.len(), 1);
        let mut other = signed(ID_DATA);
        other.signers[0].digest_alg_raw = asn1::alg_null(crate::gost::H_SHA256).unwrap();
        assert_eq!(d.merge(&other).digest_algs.len(), 2);
    }

    #[test]
    fn base64_and_pem() {
        let der = signed(ID_DATA).encode().unwrap();
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
