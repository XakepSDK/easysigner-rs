//! Revocation check against NCA RK's OCSP server.

use crate::cert::{self, Cert};
use crate::der::{self, Tlv};
use crate::i18n::{tr, trf};
use crate::keys::alg_id;
use crate::trust::TrustStore;
use crate::{Error, Result, gost, http, time};

pub const DEFAULT_URL: &str = "http://ocsp.pki.gov.kz";
const NONCE: &str = "1.3.6.1.5.5.7.48.1.2";
const BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

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
        Ok(a) => (a.good, a.status, a.cert_status),
        Err(e) => (false, trf("ERROR: could not check OCSP ({})", &[&e]), ""),
    }
}

/// An OCSP answer about one certificate.
pub struct Answer {
    /// Known not to be revoked.
    pub good: bool,
    /// For people (in English: starting with GOOD, REVOKED, UNKNOWN or ERROR).
    pub status: String,
    /// "good", "revoked" or "unknown" (empty on an error).
    pub cert_status: &'static str,
    pub this_update: Option<i64>,
    /// The certificate that signed the response.
    pub responder: Option<Cert>,
    /// The OCSPResponse, as received.
    pub raw: Vec<u8>,
    /// The BasicOCSPResponse inside it (empty on an error), as CAdES revocationValues holds it.
    pub basic: Vec<u8>,
}

impl Answer {
    fn error(status: String, raw: &[u8]) -> Answer {
        Answer {
            good: false,
            status,
            cert_status: "",
            this_update: None,
            responder: None,
            raw: raw.to_vec(),
            basic: vec![],
        }
    }
}

/// An OCSPResponse (successful) around a BasicOCSPResponse.
pub fn wrap_basic(basic: &[u8]) -> Vec<u8> {
    let bytes = der::seq(&[&der::oid(BASIC), &der::octets(basic)]);
    der::seq(&[
        &der::tlv(der::ENUMERATED, &[0]),
        &der::tlv(der::ctx(0), &bytes),
    ])
}

/// The BasicOCSPResponse inside a successful OCSPResponse.
pub fn basic_of(raw: &[u8]) -> Option<Vec<u8>> {
    let resp = der::parse(raw).ok()?.items(der::SEQUENCE).ok()?;
    if resp.first()?.small_int().ok()? != 0 {
        return None;
    }
    let rb = resp.get(1)?.inner().ok()?.items(der::SEQUENCE).ok()?;
    if rb.first()?.oid().ok()? != BASIC {
        return None;
    }
    rb.get(1)?.octets().ok()
}

/// The hash NCALayer uses in OCSP certificate IDs for this issuer's key type.
fn cert_id_hash(issuer: &Cert) -> &'static str {
    let k = issuer.key_alg();
    if k == gost::KEY_GOST2004 {
        gost::H_GOST34311
    } else if gost::is_gost(&k) {
        gost::H_GOST2015_512
    } else {
        gost::H_SHA256
    }
}

/// (issuerNameHash, issuerKeyHash) with `alg`.
fn issuer_hashes(issuer: &Cert, alg: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        gost::hash(alg, &issuer.subject)?,
        gost::hash(alg, &issuer.public_key_bits()?)?,
    ))
}

/// Asks the OCSP server at `url` about `c`, and checks the answer.
pub fn fetch(c: &Cert, issuer: &Cert, url: &str, trust: &TrustStore) -> Result<Answer> {
    let alg = cert_id_hash(issuer);
    let (name_hash, key_hash) = issuer_hashes(issuer, alg)?;
    let cert_id = der::seq(&[
        &der::alg_null(alg),
        &der::octets(&name_hash),
        &der::octets(&key_hash),
        &der::uint(&c.serial),
    ]);
    let mut nonce = [0u8; 16];
    crate::random(&mut nonce)?;
    // RFC 8954: the extension value is the DER of an OCTET STRING holding the nonce
    let nonce_ext = der::seq(&[&der::seq(&[
        &der::oid(NONCE),
        &der::octets(&der::octets(&nonce)),
    ])]);
    let tbs = der::seq(&[
        &der::seq(&[&der::seq(&[&cert_id])]),
        &der::tlv(der::ctx(2), &nonce_ext),
    ]);
    let req = der::seq(&[&tbs]);
    let body = http::post(url, "application/ocsp-request", &req, "OCSP server")?;
    evaluate(&body, c, issuer, Some(&nonce), trust, time::now_ms())
}

/// Checks an OCSP response kept inside a signature (no nonce, and its age is judged by whoever
/// reads it). A delegated responder's certificate is checked at `at`, the time the signature
/// is checked at.
pub fn read_embedded(
    raw: &[u8],
    c: &Cert,
    issuer: &Cert,
    trust: &TrustStore,
    at: i64,
) -> Result<Answer> {
    evaluate(raw, c, issuer, None, trust, at)
}

/// Element `n` of a DER sequence, or an error for a short one.
fn at<'a>(items: &[Tlv<'a>], n: usize) -> Result<Tlv<'a>> {
    items
        .get(n)
        .copied()
        .ok_or_else(|| Error::new("OCSP response is incomplete"))
}

/// `nonce`: the one sent, for a fresh answer; None for a stored one.
fn evaluate(
    body: &[u8],
    c: &Cert,
    issuer: &Cert,
    nonce: Option<&[u8]>,
    trust: &TrustStore,
    responder_at: i64,
) -> Result<Answer> {
    let resp = der::parse(body)?.items(der::SEQUENCE)?;
    let status = resp
        .first()
        .ok_or_else(|| Error::new("empty OCSP response"))?
        .small_int()?;
    if status != 0 {
        return Ok(Answer::error(
            trf("ERROR: OCSP server answered status {}", &[&status]),
            body,
        ));
    }
    let rb = resp
        .get(1)
        .ok_or_else(|| Error::new("OCSP response without content"))?
        .inner()?
        .items(der::SEQUENCE)?;
    if at(&rb, 0)?.oid()? != BASIC {
        return Err(Error::new("not a basic OCSP response"));
    }
    let basic_raw = at(&rb, 1)?.octets()?;
    let basic_der = basic_raw.clone();
    let basic = der::parse(&basic_raw)?.items(der::SEQUENCE)?;
    let tbs_t = at(&basic, 0)?;
    let sig_alg = alg_id(&at(&basic, 1)?)?.0;
    let sig = at(&basic, 2)?.bits()?;
    let certs: Vec<Cert> = match basic.get(3) {
        Some(t) if t.tag == der::ctx(0) => t
            .inner()?
            .children()?
            .iter()
            .filter_map(|c| Cert::from_tlv(c).ok())
            .collect(),
        _ => vec![],
    };
    let responder = match check_responder(
        tbs_t.raw,
        &sig_alg,
        sig,
        &certs,
        issuer,
        trust,
        responder_at,
    ) {
        Ok(r) => r,
        Err(problem) => return Ok(Answer::error(trf("ERROR: {}", &[&problem]), body)),
    };

    let rd = tbs_t.items(der::SEQUENCE)?;
    let mut i = 0;
    if at(&rd, 0)?.tag == der::ctx(0) {
        i = 1; // version
    }
    let responses = at(&rd, i + 2)?.items(der::SEQUENCE)?;
    let mut nonce_ok = false;
    if let Some(nonce) = nonce
        && let Some(ext) = rd.get(i + 3).filter(|t| t.tag == der::ctx(1))
        && let Some(echoed) = extension(ext, NONCE)?
    {
        // accept the RFC form (nested OCTET STRING) and the bare nonce some responders echo
        let nested = der::parse(&echoed)
            .ok()
            .and_then(|t| t.expect(der::OCTET_STRING).ok())
            .map(|t| t.content.to_vec());
        if echoed != nonce && nested.as_deref() != Some(nonce) {
            return Ok(Answer::error(
                tr("ERROR: OCSP response is not for this request (nonce mismatch)").into(),
                body,
            ));
        }
        nonce_ok = true;
    }
    for s in responses {
        let k = s.items(der::SEQUENCE)?;
        let id = at(&k, 0)?.items(der::SEQUENCE)?;
        let id_alg = alg_id(&at(&id, 0)?)?.0;
        if at(&id, 3)?.uint()? != c.serial.as_slice() {
            continue;
        }
        let Ok((nh, kh)) = issuer_hashes(issuer, &id_alg) else {
            continue;
        };
        if at(&id, 1)?.octets()? != nh || at(&id, 2)?.octets()? != kh {
            continue;
        }
        let next_update = k
            .iter()
            .skip(3)
            .find(|t| t.tag == der::ctx(0))
            .map(|t| t.inner().and_then(|x| x.time()))
            .transpose()?;
        let this_update = k.get(2).map(|t| t.time()).transpose()?;
        if nonce.is_some() {
            // Without our nonce echoed back, only freshness shows that the answer is not an old
            // one replayed: it must be within its validity period (nextUpdate), or, without one,
            // made within the last hour.
            let now = time::now_ms();
            let skew = 5 * 60 * 1000;
            let fresh = match next_update {
                Some(n) => n >= now,
                None => nonce_ok || this_update.is_some_and(|t| t >= now - 3600 * 1000),
            };
            if !fresh || this_update.is_some_and(|t| t > now + skew) {
                return Ok(Answer::error(
                    tr("ERROR: OCSP answer is out of date").into(),
                    body,
                ));
            }
        }
        let checked = if nonce.is_some() {
            Some(time::now_ms())
        } else {
            this_update
        };
        let (good, cert_status, status) = match at(&k, 1)?.tag {
            0x80 => (
                true,
                "good",
                trf("GOOD (not revoked, checked {})", &[&time::fmt(checked)]),
            ),
            0xa1 => {
                let when = at(&k, 1)?
                    .children()?
                    .first()
                    .map(|t| t.time())
                    .transpose()?;
                (false, "revoked", trf("REVOKED on {}", &[&time::fmt(when)]))
            }
            _ => (
                false,
                "unknown",
                tr("UNKNOWN (the OCSP server does not know this certificate)").into(),
            ),
        };
        return Ok(Answer {
            good,
            status,
            cert_status,
            this_update,
            responder: Some(responder),
            raw: body.to_vec(),
            basic: basic_der,
        });
    }
    Ok(Answer::error(
        tr("UNKNOWN (no answer for this certificate)").into(),
        body,
    ))
}

fn extension(exts: &Tlv, oid: &str) -> Result<Option<Vec<u8>>> {
    for e in exts.inner()?.items(der::SEQUENCE)? {
        let k = e.items(der::SEQUENCE)?;
        if k[0].oid()? == oid {
            return Ok(Some(
                k.last()
                    .ok_or_else(|| Error::new("bad extension"))?
                    .octets()?,
            ));
        }
    }
    Ok(None)
}

/// The response must be signed by the issuing CA itself, or by a responder certificate that the
/// CA issued for OCSP signing. Returns the signer, or a problem description.
fn check_responder(
    tbs: &[u8],
    sig_alg: &str,
    sig: &[u8],
    certs: &[Cert],
    issuer: &Cert,
    trust: &TrustStore,
    at: i64,
) -> std::result::Result<Cert, String> {
    let candidates = std::iter::once(issuer).chain(certs.iter());
    for c in candidates {
        let signed = c
            .public_key()
            .and_then(|k| k.verify(sig_alg, None, tbs, sig))
            .unwrap_or(false);
        if !signed {
            continue;
        }
        if c == issuer {
            return Ok(c.clone());
        }
        if !cert::names_equal(&c.issuer, &issuer.subject) {
            return Err(tr("OCSP responder was not issued by the certificate's CA").into());
        }
        if !c.has_eku(cert::EKU_OCSP_SIGNING) {
            return Err(tr("OCSP responder certificate is not issued for OCSP signing").into());
        }
        let chain = trust.check(c, at);
        return if chain.ok {
            Ok(c.clone())
        } else {
            Err(trf("OCSP responder is not trusted ({})", &[&chain.status]))
        };
    }
    Err(tr("OCSP response signature is invalid").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short or empty pieces in a stored answer are errors, not crashes.
    #[test]
    fn broken_stored_answers_are_errors() {
        let trust = TrustStore::new(vec![]);
        let (_, d) = crate::trust::BUNDLED_CA[4];
        let ca = Cert::parse_any(d).unwrap();
        let empty = der::seq(&[]);
        let short = der::seq(&[&der::seq(&[]), &der::seq(&[])]);
        for basic in [&empty, &short] {
            assert!(read_embedded(&wrap_basic(basic), &ca, &ca, &trust, 0).is_err());
        }
        assert!(
            read_embedded(
                &der::seq(&[&der::tlv(der::ENUMERATED, &[0])]),
                &ca,
                &ca,
                &trust,
                0
            )
            .is_err()
        );
    }
}
