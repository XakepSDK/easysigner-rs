//! Revocation checks against NCA RK's OCSP server: [`kzcrypto::ocsp`] makes the request and
//! checks the answer; this module sends it.

pub use kzcrypto::ocsp::*;

use crate::cert::Cert;
use crate::i18n::{self, tr, trf};
use crate::trust::TrustStore;
use crate::{Result, http, time};

pub const DEFAULT_URL: &str = "http://ocsp.pki.gov.kz";

/// Whether the certificate is known not to be revoked, a status line (in English: starting
/// with GOOD, REVOKED, UNKNOWN or ERROR), and the answer: "good", "revoked", "unknown", or
/// "" when there was none (no issuer, no network, a broken or untrusted response).
pub fn check(
    c: &Cert,
    issuer: Option<&Cert>,
    url: &str,
    trust: &TrustStore,
) -> (bool, String, &'static str) {
    let Some(issuer) = issuer else {
        return (
            false,
            tr("UNKNOWN (issuer certificate not available)").into(),
            "",
        );
    };
    match fetch(c, issuer, url, trust) {
        Ok(a) => (a.good, i18n::text(&a.status), a.cert_status),
        Err(e) => (false, trf("ERROR: could not check OCSP ({})", &[&e]), ""),
    }
}

/// Asks the OCSP server at `url` about `c`, and checks the answer.
pub fn fetch(c: &Cert, issuer: &Cert, url: &str, trust: &TrustStore) -> Result<Answer> {
    let mut nonce = [0u8; 16];
    crate::random(&mut nonce)?;
    let req = request(c, issuer, &nonce)?;
    let body = http::post(url, CONTENT_TYPE, &req, "OCSP server")?;
    Ok(read_fresh(&body, c, issuer, &nonce, trust, time::now_ms())?)
}
