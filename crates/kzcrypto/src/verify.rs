//! Checking one signer of a CMS SignedData: its signature, its signed attributes, and the
//! signed reference to its certificate (CAdES signingCertificate / signingCertificateV2).

use ::der::asn1::{Any, ObjectIdentifier, OctetString};
use ::der::{Decode, Tag, Tagged};

use crate::cert::Cert;
use crate::cms::{self, SignerInfo};
use crate::prelude::*;
use crate::{Error, Result, gost};

fn asn1(e: ::der::Error) -> Error {
    Error::Asn1(format!("{e}"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    /// The signature does not verify.
    Invalid,
    /// The document's hash differs from the signed message digest.
    DigestMismatch,
}

/// Checks one signer of SignedData over `content` (of type `content_type`) with `cert`'s key.
pub fn check_signer(
    si: &SignerInfo,
    c: &Cert,
    content: &[u8],
    content_type: &str,
) -> Result<Outcome> {
    if si.signed_attrs.is_some() {
        let ct = si
            .signed_attr(cms::ATTR_CONTENT_TYPE)
            .ok_or(Error::NoContentTypeAttr)?;
        if <ObjectIdentifier>::from_der(&ct).map_err(asn1)?.to_string() != content_type {
            return Err(Error::ContentTypeMismatch);
        }
        let md = si
            .signed_attr(cms::ATTR_MESSAGE_DIGEST)
            .ok_or(Error::NoMessageDigestAttr)?;
        let signed = OctetString::from_der(&md).map_err(asn1)?;
        if gost::hash(&si.digest_alg, content)? != signed.as_bytes() {
            return Ok(Outcome::DigestMismatch);
        }
    }
    let ok = c.public_key()?.verify(
        &si.sig_alg,
        Some(&si.digest_alg),
        &si.signed_bytes(content),
        &si.signature,
    )?;
    Ok(if ok { Outcome::Valid } else { Outcome::Invalid })
}

/// CAdES binds the signer's certificate with a signed hash of it (signingCertificateV2, or the
/// older SHA-1 signingCertificate). When present, it must match the certificate used.
pub fn signing_certificate_matches(si: &SignerInfo, c: &Cert) -> Result<bool> {
    let (v, v2) = match si.signed_attr(cms::ATTR_SIGNING_CERT_V2) {
        Some(v) => (v, true),
        None => match si.signed_attr(cms::ATTR_SIGNING_CERT) {
            Some(v) => (v, false),
            None => return Ok(true),
        },
    };
    // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies? }
    let k: Vec<Any> = Vec::from_der(&v).map_err(asn1)?;
    let Some(ids) = k.first() else {
        return Ok(true);
    };
    let ids: Vec<Any> = ids.decode_as().map_err(asn1)?;
    let Some(id) = ids.first() else {
        return Ok(true);
    };
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash, issuerSerial? };
    // ESSCertID ::= SEQUENCE { certHash (SHA-1), issuerSerial? }
    let f: Vec<Any> = id.decode_as().map_err(asn1)?;
    let (alg, hash) = match (v2, f.first()) {
        (true, Some(a)) if a.tag() == Tag::Sequence => (
            a.decode_as::<spki::AlgorithmIdentifierOwned>()
                .map_err(asn1)?
                .oid
                .to_string(),
            f.get(1),
        ),
        (true, _) => (gost::H_SHA256.to_string(), f.first()),
        (false, _) => (gost::H_SHA1.to_string(), f.first()),
    };
    let hash = hash
        .ok_or_else(|| Error::Asn1("ESSCertID without hash".into()))?
        .decode_as::<OctetString>()
        .map_err(asn1)?;
    let hash = hash.as_bytes();
    Ok(gost::hash(&alg, &c.der)? == hash)
}

/// Whether the signature over `si`'s signed attributes alone holds with `c`'s key, and they
/// name `c` (for a detached signature checked without its document: the attributes carry the
/// document's hash). False without signed attributes.
pub fn signed_attributes_valid(si: &SignerInfo, c: &Cert) -> bool {
    si.signed_attrs.is_some()
        && c.public_key()
            .and_then(|k| {
                k.verify(
                    &si.sig_alg,
                    Some(&si.digest_alg),
                    &si.signed_bytes(&[]),
                    &si.signature,
                )
            })
            .unwrap_or(false)
        && signing_certificate_matches(si, c).unwrap_or(false)
}
