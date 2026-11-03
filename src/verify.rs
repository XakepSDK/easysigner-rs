//! Checks every signature in a .cms: signature, certificate, timestamp, trust, revocation.

use crate::cert::{self, Cert};
use crate::cms::{self, SignedData, SignerInfo};
use crate::der;
use crate::i18n::{tr, trf};
use crate::keys::alg_id;
use crate::ltv::{self, Kept};
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

pub fn verify(
    raw: &[u8],
    detached_original: Option<&[u8]>,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
) -> Result<VerifyReport> {
    verify_with(raw, detached_original, trust, ocsp_url, false, None)
}

/// [`verify`], with validation data kept outside the CMS (a PDF's DSS).
pub fn verify_kept(
    raw: &[u8],
    detached_original: Option<&[u8]>,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
    kept: &Kept,
) -> Result<VerifyReport> {
    verify_with(raw, detached_original, trust, ocsp_url, false, Some(kept))
}

/// [`verify`]; `signature_only`: without the document, still check each signature over its
/// signed attributes (that the signer signed a document with that hash). The report is then
/// never valid, since the document itself was not compared.
pub fn verify_with(
    raw: &[u8],
    detached_original: Option<&[u8]>,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
    signature_only: bool,
    kept: Option<&Kept>,
) -> Result<VerifyReport> {
    let d = SignedData::parse(raw)?;
    let mut rep = VerifyReport::default();
    let content: Option<Vec<u8>> = if let Some(c) = &d.content {
        rep.has_content = true;
        Some(c.clone())
    } else if let Some(o) = detached_original {
        rep.detached_provided = true;
        Some(o.to_vec())
    } else if signature_only {
        rep.warnings.push(
            tr("The document was not compared with the signature: give the signed PDF or the original document to check it.")
                .into(),
        );
        None
    } else {
        rep.warnings.push(
            tr("This is a detached signature (the document is not inside the .cms). Provide the original file to check the signatures against it.")
                .into(),
        );
        None
    };
    if let Some(c) = &content {
        rep.content_size = c.len() as u64;
        rep.content_sha256 = Some(crate::hex(&gost::sha256(c)));
    }
    for si in &d.signers {
        rep.signers.push(check_one(
            &d,
            si,
            content.as_deref(),
            trust,
            ocsp_url,
            signature_only,
            kept,
        ));
    }
    // by time: trusted timestamp if any, else the signer's clock; unknown times last
    rep.signers
        .sort_by_key(|s| match s.trusted_time().or(s.signing_time) {
            Some(t) => (0, t),
            None => (1, 0),
        });
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    rep.valid = !rep.signers.is_empty() && rep.signers.iter().all(|s| s.valid) && content.is_some();
    if rep.signers.is_empty() {
        rep.warnings
            .push(tr("The file contains no signatures.").into());
    }
    Ok(rep)
}

fn check_one(
    d: &SignedData,
    si: &SignerInfo,
    content: Option<&[u8]>,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
    signature_only: bool,
    extra: Option<&Kept>,
) -> SignerReport {
    let mut sr = SignerReport {
        signing_time: si.signing_time(),
        algorithm: Some(cert::alg_name(&si.sig_alg, Some(&si.digest_alg))),
        ..Default::default()
    };
    let Some(c) = d.signer_cert(si) else {
        sr.signature_error =
            Some(tr("The signer's certificate is not included in the .cms, so this signature cannot be checked.").into());
        return sr;
    };
    cert::describe(&mut sr, &c);
    match content {
        Some(content) => check_signature(&mut sr, si, &c, content, &d.content_type),
        None if signature_only => check_signed_attributes(&mut sr, si, &c),
        None => {
            sr.signature_error =
                Some(tr("Not checked: original document not provided (detached signature).").into())
        }
    }

    let tsa_ca = tsp::check(&mut sr, si, trust);
    let cert_check = check_certificate(&mut sr, &c, tsa_ca, trust, ocsp_url);
    let (valid_at, mut ocsp_good) = (cert_check.valid_at, cert_check.ocsp_good);

    let mut kept = Kept::from_cms(d, Some(si));
    if let Some(e) = extra {
        kept.extend(e);
    }
    let kept_found = apply_kept(
        &mut sr,
        &c,
        &kept,
        trust,
        &cert_check,
        ocsp_url,
        &mut ocsp_good,
    );
    sr.archive_timestamps = ltv::check_archives(d, si, content, trust);
    let archives_ok = report_archives(&mut sr);
    sr.level = Some(level(&sr, kept_found));
    sr.valid = sr.signature_ok
        && sr.chain_ok
        && sr.usage_error.is_none()
        && valid_at
        && sr.timestamp_ok != Some(false)
        && ocsp_good
        && archives_ok;
    sr
}

/// What [`check_certificate`] found.
pub struct CertCheck {
    /// The moment the certificates were checked at.
    pub at: i64,
    /// Whether `at` comes from a trusted timestamp.
    pub trusted_time: bool,
    pub valid_at: bool,
    /// The signer's issuer, when the chain was built.
    pub issuer: Option<Cert>,
    /// No online revocation check, or a good answer.
    pub ocsp_good: bool,
}

/// Checks the signer's certificate `c` as Order 500/НҚ p.13-16 and 18-19 ask, at the time of
/// the signature's timestamp (already checked into `sr`; `tsa_ca` from [`tsp::check`]) or now,
/// and records it in `sr`.
pub fn check_certificate(
    sr: &mut SignerReport,
    c: &Cert,
    tsa_ca: Option<Cert>,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
) -> CertCheck {
    // only a valid timestamp from a trusted TSA may set the reference time; otherwise a
    // self-made "timestamp" could make an expired or revoked certificate look fine.
    // Order 500/НҚ p.13-14: with one, the certificates are checked at its time, without one at
    // the moment of checking (the signing time the signer's computer wrote in is only a claim)
    let (at, trusted_time) = reference_time(sr, time::now_ms());
    let valid_at = c.valid_on(at);
    sr.cert_valid_at_signing = Some(valid_at);
    sr.checked_at = Some(at);
    if !valid_at {
        sr.warnings.push(validity_warning(trusted_time, at));
    }
    if !trusted_time && sr.signing_time.is_some() {
        sr.warnings.push(
            tr("Signing time comes from the signer's own computer clock (no trusted timestamp).")
                .into(),
        );
    }
    let chain = trust.check(c, at);
    sr.chain_ok = chain.ok;
    sr.chain_status = Some(chain.status);
    sr.chain = chain.path;
    sr.usage_error = cert::usage_problem(c, chain.issuer.as_ref());
    if let (Some(t), Some(i), true) = (&tsa_ca, &chain.issuer, chain.ok) {
        tsp::same_ca(sr, t, i, trust);
    }
    let mut ocsp_good = true;
    if let Some(url) = ocsp_url {
        let (good, status, answer, source) = revocation(
            c,
            chain.issuer.as_ref(),
            url,
            trust,
            trusted_time.then_some(at),
        );
        sr.revocation_source = source;
        ocsp_good = good;
        sr.ocsp_status = Some(status);
        sr.ocsp_answer = Some(answer);
    }
    CertCheck {
        at,
        trusted_time,
        valid_at,
        issuer: chain.issuer,
        ocsp_good,
    }
}

/// The validation data kept in the signature (B-LT): what it says counts when it was made at
/// the signing time, and stands in for an online check that is off or got no answer. Records
/// it in `sr` and updates `ocsp_good`; returns whether it had an answer for `c`.
pub fn apply_kept(
    sr: &mut SignerReport,
    c: &Cert,
    kept: &Kept,
    trust: &TrustStore,
    check: &CertCheck,
    ocsp_url: Option<&str>,
    ocsp_good: &mut bool,
) -> bool {
    let kept_status = check
        .issuer
        .as_ref()
        .and_then(|i| kept.status(c, i, trust, check.at));
    if let Some(k) = &kept_status
        && sr.ocsp_answer.is_none_or(str::is_empty)
    {
        sr.ocsp_status = Some(trf("{} (answer kept in the signature)", &[&k.status]));
        sr.ocsp_answer = Some(k.answer);
        sr.revocation_source = Some(if k.source == "ocsp" {
            "kept-ocsp"
        } else {
            "kept-crl"
        });
        if !k.fresh {
            sr.warnings
                .push(tr("The kept OCSP answer is older than the signature's timestamp.").into());
        }
        *ocsp_good = if ocsp_url.is_some() {
            k.answer == "good" && k.fresh && check.trusted_time
        } else {
            k.answer != "revoked"
        };
    }
    kept_status.is_some()
}

/// Reports `sr`'s archive timestamps as notes and warnings; false when one is not valid.
pub fn report_archives(sr: &mut SignerReport) -> bool {
    let mut ok = true;
    let archives = std::mem::take(&mut sr.archive_timestamps);
    for a in &archives {
        let tsa = a.tsa.clone().unwrap_or_default();
        if !a.checked {
            sr.notes.push(trf(
                "Archive timestamp of {}: {}",
                &[&time::fmt(a.time), &a.error.clone().unwrap_or_default()],
            ));
        } else if !a.valid {
            ok = false;
            sr.warnings.push(trf(
                "An archive timestamp is not valid: {}",
                &[&a.error.clone().unwrap_or_default()],
            ));
        } else if !a.trusted {
            sr.warnings.push(trf(
                "The archive timestamp authority '{}' is not a trusted NCA RK TSA.",
                &[&tsa],
            ));
        }
    }
    sr.archive_timestamps = archives;
    ok
}

/// The ETSI baseline level a signature reaches: a signature timestamp makes it B-T, kept
/// revocation data for the signer's certificate B-LT, and archive timestamps B-LTA.
pub fn level(sr: &SignerReport, kept_revocation: bool) -> &'static str {
    if sr.timestamp_time.is_none() {
        "B-B"
    } else if !kept_revocation {
        "B-T"
    } else if sr.archive_timestamps.is_empty() {
        "B-LT"
    } else {
        "B-LTA"
    }
}

/// Whether `c` is revoked, by OCSP at `url`, or, when OCSP gives no answer, by the CA's current
/// revocation list (Order 500/НҚ p.18-19): (good, status for people, answer "good", "revoked",
/// "unknown" or "" when there is none, where the answer came from: "ocsp" or "crl").
/// `trusted_at`: the time of the signature's trusted timestamp. A certificate revoked after it
/// still counts as good there (Order 500/НҚ p.14: checked as of the timestamp's time).
pub fn revocation(
    c: &Cert,
    issuer: Option<&Cert>,
    url: &str,
    trust: &TrustStore,
    trusted_at: Option<i64>,
) -> (bool, String, &'static str, Option<&'static str>) {
    let Some(issuer) = issuer else {
        // the revocation list can't be checked without the CA either: say it once
        let (good, status, answer) = ocsp::check(c, None, url, trust);
        return (good, status, answer, None);
    };
    let (good, status, answer, revoked) = match ocsp::fetch(c, issuer, url, trust) {
        Ok(a) => (
            a.good,
            a.status,
            a.cert_status,
            a.revoked_at.zip(a.untrusted_from),
        ),
        Err(e) => (
            false,
            trf("ERROR: could not check OCSP ({})", &[&e]),
            "",
            None,
        ),
    };
    let (good, status, answer, source, revoked) = if !answer.is_empty() {
        (good, status, answer, Some("ocsp"), revoked)
    } else {
        let now = time::now_ms();
        let (good, crl_status, answer, revoked) = match crate::crl::lists(c, now) {
            Ok((base, delta, due)) => {
                let (good, s, a) =
                    crate::crl::evaluate(&base, delta.as_deref(), due, c, issuer, now);
                (good, s, a, ltv::crl_revocation(&base, delta.as_deref(), c))
            }
            Err(e) => (
                false,
                trf("ERROR: could not check the revocation list ({})", &[&e]),
                "",
                None,
            ),
        };
        let status = trf("{} (OCSP: {})", &[&crl_status, &status]);
        (
            good,
            status,
            answer,
            (!answer.is_empty()).then_some("crl"),
            revoked,
        )
    };
    match trusted_at {
        Some(t) if answer == "revoked" => {
            let (answer, status) = ltv::good_if_later(answer, status, revoked, t);
            (answer == "good", status, answer, source)
        }
        _ => (good, status, answer, source),
    }
}

/// Checks the signature over the signed attributes alone, and reports the signed hash.
fn check_signed_attributes(sr: &mut SignerReport, si: &SignerInfo, c: &Cert) {
    let md = si
        .signed_attr(cms::ATTR_MESSAGE_DIGEST)
        .and_then(|v| der::parse(&v).ok()?.octets().ok());
    let ok = si.signed_attrs.is_some()
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
        && signing_certificate_matches(si, c).unwrap_or(false);
    match md {
        Some(md) if ok => {
            sr.signature_ok = true;
            sr.warnings.push(trf(
                "Only the signature was checked, not the document: it signs a document whose {} hash is {}.",
                &[&cert::digest_label(Some(&si.digest_alg)), &crate::hex(&md)],
            ));
        }
        _ => sr.signature_error = Some(
            tr("Signature does not match the document (the document or signature was changed).")
                .into(),
        ),
    }
}

fn check_signature(
    sr: &mut SignerReport,
    si: &SignerInfo,
    c: &Cert,
    content: &[u8],
    content_type: &str,
) {
    match check_signer(si, c, content, content_type) {
        Ok(Outcome::Valid) => match signing_certificate_matches(si, c) {
            Ok(true) => sr.signature_ok = true,
            Ok(false) => {
                sr.signature_error = Some(
                    tr("The signed reference to the signer's certificate does not match the certificate in the file.").into(),
                )
            }
            Err(e) => sr.signature_error = Some(trf("Signature check failed: {}", &[&e])),
        },
        Ok(Outcome::Invalid) => {
            sr.signature_error =
                Some(tr("Signature does not match the document (the document or signature was changed).").into())
        }
        Ok(Outcome::DigestMismatch) => {
            sr.signature_error = Some(
                tr("Signature check failed: the document's content hash does not match the signed hash (the document was changed).")
                    .into(),
            )
        }
        Err(e) => sr.signature_error = Some(trf("Signature check failed: {}", &[&e])),
    }
}

/// The time to check certificates at, and whether a trusted timestamp gave it.
fn reference_time(sr: &SignerReport, now: i64) -> (i64, bool) {
    match sr.trusted_time() {
        Some(t) => (t, true),
        None => (now, false),
    }
}

fn validity_warning(trusted_time: bool, at: i64) -> String {
    if trusted_time {
        trf(
            "The certificate was not valid at the signing time ({}).",
            &[&time::fmt(Some(at))],
        )
    } else {
        trf(
            "The certificate is not valid now ({}), and no trusted timestamp shows that it was valid when the document was signed.",
            &[&time::fmt(Some(at))],
        )
    }
}

#[cfg(test)]
mod reference_time_tests {
    use super::*;

    fn report(ok: Option<bool>, trusted: Option<bool>, ts: Option<i64>) -> SignerReport {
        SignerReport {
            timestamp_ok: ok,
            timestamp_trusted: trusted,
            timestamp_time: ts,
            // the signer's own clock never counts
            signing_time: Some(1_000),
            ..Default::default()
        }
    }

    #[test]
    fn only_a_trusted_timestamp_sets_the_time() {
        let now = 9_000;
        assert_eq!(
            reference_time(&report(Some(true), Some(true), Some(5_000)), now),
            (5_000, true)
        );
        assert_eq!(
            reference_time(&report(Some(true), Some(false), Some(5_000)), now),
            (now, false)
        );
        assert_eq!(
            reference_time(&report(Some(false), Some(true), Some(5_000)), now),
            (now, false)
        );
        assert_eq!(reference_time(&report(None, None, None), now), (now, false));
        // trusted but no time read: the moment of checking, and said so
        assert_eq!(
            reference_time(&report(Some(true), Some(true), None), now),
            (now, false)
        );
    }

    #[test]
    fn the_warning_names_the_right_time() {
        assert!(validity_warning(true, 0).contains("signing time"));
        assert!(validity_warning(false, 0).contains("no trusted timestamp"));
    }
}
