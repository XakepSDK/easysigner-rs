//! Checks every signature in a .cms: signature, certificate, timestamp, trust, revocation.

use crate::cert::{self, Cert};
use crate::cms::{self, SignedData, SignerInfo};
use crate::der;
use crate::keys::alg_id;
use crate::report::{SignerReport, VerifyReport};
use crate::trust::TrustStore;
use crate::{Error, Result, gost, ocsp, time, tsp};

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    /// The signature does not verify.
    Invalid,
    /// The document's hash differs from the signed message digest.
    DigestMismatch,
}

/// Checks one signer of SignedData over `content` (of type `content_type`) with `cert`'s key.
pub fn check_signer(si: &SignerInfo, c: &Cert, content: &[u8], content_type: &str) -> Result<Outcome> {
    if si.signed_attrs.is_some() {
        let ct = si.signed_attr(cms::ATTR_CONTENT_TYPE).ok_or_else(|| {
            Error::new("The content-type attribute type MUST be present whenever signed attributes are present in signed-data")
        })?;
        if der::parse(&ct)?.oid()? != content_type {
            return Err(Error::new("content-type attribute value does not match eContentType"));
        }
        let md = si.signed_attr(cms::ATTR_MESSAGE_DIGEST).ok_or_else(|| {
            Error::new("the message-digest signed attribute type MUST be present when there are any signed attributes present")
        })?;
        let signed = der::parse(&md)?.expect(der::OCTET_STRING)?.octets()?;
        if gost::hash(&si.digest_alg, content)? != signed {
            return Ok(Outcome::DigestMismatch);
        }
    }
    let ok = c.public_key()?.verify(&si.sig_alg, Some(&si.digest_alg), &si.signed_bytes(content), &si.signature)?;
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
    let Some(ids) = k.first() else { return Ok(true) };
    let ids = ids.items(der::SEQUENCE)?;
    let Some(id) = ids.first() else { return Ok(true) };
    let f = id.items(der::SEQUENCE)?;
    let (alg, hash) = match (v2, f.first()) {
        (true, Some(a)) if a.tag == der::SEQUENCE => (alg_id(a)?.0, f.get(1)),
        (true, _) => (gost::H_SHA256.to_string(), f.first()),
        (false, _) => (gost::H_SHA1.to_string(), f.first()),
    };
    let hash = hash.ok_or_else(|| Error::new("ESS certificate id without hash"))?.octets()?;
    Ok(gost::hash(&alg, &c.der)? == hash)
}

pub fn verify(raw: &[u8], detached_original: Option<&[u8]>, trust: &TrustStore, ocsp_url: Option<&str>) -> Result<VerifyReport> {
    let d = SignedData::parse(raw)?;
    let mut rep = VerifyReport::default();
    let content: Option<Vec<u8>> = if let Some(c) = &d.content {
        rep.has_content = true;
        Some(c.clone())
    } else if let Some(o) = detached_original {
        rep.detached_provided = true;
        Some(o.to_vec())
    } else {
        rep.warnings.push(
            "This is a detached signature (the document is not inside the .cms). Provide the original file to check the signatures against it."
                .into(),
        );
        None
    };
    if let Some(c) = &content {
        rep.content_size = c.len() as u64;
        rep.content_sha256 = Some(crate::hex(&gost::sha256(c)));
    }
    for si in &d.signers {
        rep.signers.push(check_one(&d, si, content.as_deref(), trust, ocsp_url));
    }
    // by time: trusted timestamp if any, else the signer's clock; unknown times last
    rep.signers.sort_by_key(|s| match s.timestamp_time.or(s.signing_time) {
        Some(t) => (0, t),
        None => (1, 0),
    });
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    rep.valid = !rep.signers.is_empty() && rep.signers.iter().all(|s| s.valid);
    if rep.signers.is_empty() {
        rep.warnings.push("The file contains no signatures.".into());
    }
    Ok(rep)
}

fn check_one(d: &SignedData, si: &SignerInfo, content: Option<&[u8]>, trust: &TrustStore, ocsp_url: Option<&str>) -> SignerReport {
    let mut sr = SignerReport {
        signing_time: si.signing_time(),
        algorithm: Some(cert::alg_name(&si.sig_alg, Some(&si.digest_alg))),
        ..Default::default()
    };
    let Some(c) = d.signer_cert(si) else {
        sr.signature_error =
            Some("The signer's certificate is not included in the .cms, so this signature cannot be checked.".into());
        return sr;
    };
    cert::describe(&mut sr, &c);
    match content {
        Some(content) => check_signature(&mut sr, si, &c, content, &d.content_type),
        None => sr.signature_error = Some("Not checked: original document not provided (detached signature).".into()),
    }

    tsp::check(&mut sr, si, trust);
    // only a valid timestamp from a trusted TSA may move the reference time; otherwise a
    // self-made "timestamp" could make an expired or revoked certificate look fine
    let trusted_time = sr.timestamp_ok == Some(true) && sr.timestamp_trusted == Some(true);
    let at = if trusted_time { sr.timestamp_time } else { sr.signing_time }.unwrap_or_else(time::now_ms);
    let valid_at = c.valid_on(at);
    sr.cert_valid_at_signing = Some(valid_at);
    if !valid_at {
        sr.warnings.push(format!("The certificate was not valid at the signing time ({}).", time::fmt(Some(at))));
    }
    if !trusted_time && sr.signing_time.is_some() {
        sr.warnings.push("Signing time comes from the signer's own computer clock (no trusted timestamp).".into());
    }
    let chain = trust.check(&c, at);
    sr.chain_ok = chain.ok;
    sr.chain_status = Some(chain.status);
    sr.chain = chain.path;
    if let Some(url) = ocsp_url {
        sr.ocsp_status = Some(ocsp::check(&c, chain.issuer.as_ref(), url, trust));
    }
    sr.valid = sr.signature_ok
        && sr.chain_ok
        && valid_at
        && sr.timestamp_ok != Some(false)
        && sr.ocsp_status.as_ref().is_none_or(|s| s.starts_with("GOOD"));
    sr
}

fn check_signature(sr: &mut SignerReport, si: &SignerInfo, c: &Cert, content: &[u8], content_type: &str) {
    match check_signer(si, c, content, content_type) {
        Ok(Outcome::Valid) => match signing_certificate_matches(si, c) {
            Ok(true) => sr.signature_ok = true,
            Ok(false) => {
                sr.signature_error = Some(
                    "The signed reference to the signer's certificate does not match the certificate in the file.".into(),
                )
            }
            Err(e) => sr.signature_error = Some(format!("Signature check failed: {e}")),
        },
        Ok(Outcome::Invalid) => {
            sr.signature_error =
                Some("Signature does not match the document (the document or signature was changed).".into())
        }
        Ok(Outcome::DigestMismatch) => {
            sr.signature_error = Some(
                "Signature check failed: the document's content hash does not match the signed hash (the document was changed)."
                    .into(),
            )
        }
        Err(e) => sr.signature_error = Some(format!("Signature check failed: {e}")),
    }
}
