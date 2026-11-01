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

/// Whether the certificate is known not to be revoked, and a status line (in English: starting
/// with GOOD, REVOKED, UNKNOWN or ERROR).
pub fn check(c: &Cert, issuer: Option<&Cert>, url: &str, trust: &TrustStore) -> (bool, String) {
    let Some(issuer) = issuer else {
        return (
            false,
            tr("UNKNOWN (issuer certificate not available)").into(),
        );
    };
    match check_inner(c, issuer, url, trust) {
        Ok(s) => s,
        Err(e) => (false, trf("ERROR: could not check OCSP ({})", &[&e])),
    }
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

fn check_inner(c: &Cert, issuer: &Cert, url: &str, trust: &TrustStore) -> Result<(bool, String)> {
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

    let resp = der::parse(&body)?.items(der::SEQUENCE)?;
    let status = resp
        .first()
        .ok_or_else(|| Error::new("empty OCSP response"))?
        .small_int()?;
    if status != 0 {
        return Ok((
            false,
            trf("ERROR: OCSP server answered status {}", &[&status]),
        ));
    }
    let rb = resp
        .get(1)
        .ok_or_else(|| Error::new("OCSP response without content"))?
        .inner()?
        .items(der::SEQUENCE)?;
    if rb[0].oid()? != BASIC {
        return Err(Error::new("not a basic OCSP response"));
    }
    let basic_raw = rb[1].octets()?;
    let basic = der::parse(&basic_raw)?.items(der::SEQUENCE)?;
    let tbs_t = basic[0];
    let sig_alg = alg_id(&basic[1])?.0;
    let sig = basic[2].bits()?;
    let certs: Vec<Cert> = match basic.get(3) {
        Some(t) if t.tag == der::ctx(0) => t
            .inner()?
            .children()?
            .iter()
            .filter_map(|c| Cert::from_tlv(c).ok())
            .collect(),
        _ => vec![],
    };
    if let Some(problem) = check_responder(tbs_t.raw, &sig_alg, sig, &certs, issuer, trust) {
        return Ok((false, trf("ERROR: {}", &[&problem])));
    }

    let rd = tbs_t.items(der::SEQUENCE)?;
    let mut i = 0;
    if rd[0].tag == der::ctx(0) {
        i = 1; // version
    }
    let responses = rd[i + 2].items(der::SEQUENCE)?;
    if let Some(ext) = rd.get(i + 3).filter(|t| t.tag == der::ctx(1))
        && let Some(echoed) = extension(ext, NONCE)?
    {
        // accept the RFC form (nested OCTET STRING) and the bare nonce some responders echo
        let nested = der::parse(&echoed)
            .ok()
            .and_then(|t| t.expect(der::OCTET_STRING).ok())
            .map(|t| t.content.to_vec());
        if echoed != nonce && nested.as_deref() != Some(&nonce[..]) {
            return Ok((
                false,
                tr("ERROR: OCSP response is not for this request (nonce mismatch)").into(),
            ));
        }
    }
    for s in responses {
        let k = s.items(der::SEQUENCE)?;
        let id = k[0].items(der::SEQUENCE)?;
        let id_alg = alg_id(&id[0])?.0;
        if id[3].uint()? != c.serial.as_slice() {
            continue;
        }
        let Ok((nh, kh)) = issuer_hashes(issuer, &id_alg) else {
            continue;
        };
        if id[1].octets()? != nh || id[2].octets()? != kh {
            continue;
        }
        let next_update = k[3..]
            .iter()
            .find(|t| t.tag == der::ctx(0))
            .map(|t| t.inner().and_then(|x| x.time()))
            .transpose()?;
        if next_update.is_some_and(|n| n < time::now_ms()) {
            return Ok((false, tr("ERROR: OCSP answer is out of date").into()));
        }
        return Ok(match k[1].tag {
            0x80 => (
                true,
                trf(
                    "GOOD (not revoked, checked {})",
                    &[&time::fmt(Some(time::now_ms()))],
                ),
            ),
            0xa1 => {
                let when = k[1].children()?.first().map(|t| t.time()).transpose()?;
                (false, trf("REVOKED on {}", &[&time::fmt(when)]))
            }
            _ => (
                false,
                tr("UNKNOWN (the OCSP server does not know this certificate)").into(),
            ),
        });
    }
    Ok((false, tr("UNKNOWN (no answer for this certificate)").into()))
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
/// CA issued for OCSP signing. Returns a problem description, or None.
fn check_responder(
    tbs: &[u8],
    sig_alg: &str,
    sig: &[u8],
    certs: &[Cert],
    issuer: &Cert,
    trust: &TrustStore,
) -> Option<String> {
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
            return None;
        }
        if !cert::names_equal(&c.issuer, &issuer.subject) {
            return Some(tr("OCSP responder was not issued by the certificate's CA").into());
        }
        if !c.has_eku(cert::EKU_OCSP_SIGNING) {
            return Some(tr("OCSP responder certificate is not issued for OCSP signing").into());
        }
        let chain = trust.check(c, time::now_ms());
        return if chain.ok {
            None
        } else {
            Some(trf("OCSP responder is not trusted ({})", &[&chain.status]))
        };
    }
    Some(tr("OCSP response signature is invalid").into())
}
