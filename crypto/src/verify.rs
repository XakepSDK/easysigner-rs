//! Checking one signer of a CMS SignedData: its signature, its signed attributes, and the
//! signed reference to its certificate (CAdES signingCertificate / signingCertificateV2).

use crate::cert::Cert;
use crate::cms::{self, SignerInfo};
use crate::der;
use crate::keys::alg_id;
use crate::prelude::*;
use crate::{Error, Result, gost};

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
        let ct = si.signed_attr(cms::ATTR_CONTENT_TYPE).ok_or_else(|| {
            Error::new("The content-type attribute type MUST be present whenever signed attributes are present in signed-data")
        })?;
        if der::parse(&ct)?.oid()? != content_type {
            return Err(Error::new(
                "content-type attribute value does not match eContentType",
            ));
        }
        let md = si.signed_attr(cms::ATTR_MESSAGE_DIGEST).ok_or_else(|| {
            Error::new("the message-digest signed attribute type MUST be present when there are any signed attributes present")
        })?;
        let signed = der::parse(&md)?.expect(der::OCTET_STRING)?.octets()?;
        if gost::hash(&si.digest_alg, content)? != signed {
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
    let k = der::parse(&v)?.items(der::SEQUENCE)?;
    let Some(ids) = k.first() else {
        return Ok(true);
    };
    let ids = ids.items(der::SEQUENCE)?;
    let Some(id) = ids.first() else {
        return Ok(true);
    };
    let f = id.items(der::SEQUENCE)?;
    let (alg, hash) = match (v2, f.first()) {
        (true, Some(a)) if a.tag == der::SEQUENCE => (alg_id(a)?.0, f.get(1)),
        (true, _) => (gost::H_SHA256.to_string(), f.first()),
        (false, _) => (gost::H_SHA1.to_string(), f.first()),
    };
    let hash = hash
        .ok_or_else(|| Error::new("ESS certificate id without hash"))?
        .octets()?;
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
