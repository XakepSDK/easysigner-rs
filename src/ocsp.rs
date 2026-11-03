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
    /// When the certificate was revoked, for a "revoked" answer.
    pub revoked_at: Option<i64>,
    /// From when its key is not to be trusted: `revoked_at`, or never ([`i64::MIN`]) when the
    /// reason given is a key compromise.
    pub untrusted_from: Option<i64>,
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
            revoked_at: None,
            untrusted_from: None,
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
    evaluate(&body, c, issuer, Some(&nonce), trust)
}

/// Checks an OCSP response kept inside a signature (no nonce, and its age is judged by whoever
/// reads it). A delegated responder's certificate is checked at the time the answer was made.
pub fn read_embedded(raw: &[u8], c: &Cert, issuer: &Cert, trust: &TrustStore) -> Result<Answer> {
    evaluate(raw, c, issuer, None, trust)
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
    let rd = tbs_t.items(der::SEQUENCE)?;
    let mut i = 0;
    if at(&rd, 0)?.tag == der::ctx(0) {
        i = 1; // version
    }
    // a fresh answer's responder must be valid now; a kept one's when it answered (producedAt)
    let responder_at = match nonce {
        Some(_) => time::now_ms(),
        None => at(&rd, i + 1)?.time()?,
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
        let (mut revoked_at, mut untrusted_from) = (None, None);
        let (good, cert_status, status) = match at(&k, 1)?.tag {
            0x80 => (
                true,
                "good",
                trf("GOOD (not revoked, checked {})", &[&time::fmt(checked)]),
            ),
            0xa1 => {
                let info = at(&k, 1)?.children()?;
                let when = info.first().map(|t| t.time()).transpose()?;
                let compromised = info
                    .iter()
                    .find(|t| t.tag == der::ctx(0))
                    .and_then(|t| t.inner().ok())
                    .is_some_and(|r| crate::crl::is_compromise(&r));
                revoked_at = when;
                untrusted_from = if compromised { Some(i64::MIN) } else { when };
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
            revoked_at,
            untrusted_from,
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
pub(crate) mod tests {
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
            assert!(read_embedded(&wrap_basic(basic), &ca, &ca, &trust).is_err());
        }
        assert!(
            read_embedded(
                &der::seq(&[&der::tlv(der::ENUMERATED, &[0])]),
                &ca,
                &ca,
                &trust
            )
            .is_err()
        );
    }

    pub(crate) fn key(p: &str) -> crate::p12::Key {
        let d =
            std::fs::read(format!("{}/tests/fixtures/{p}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        crate::p12::open(&d, "Qwerty12", None).unwrap()
    }

    /// A certificate for `subject`'s key issued by `by`, with the OCSP signing purpose when
    /// `ocsp`.
    pub(crate) fn issue(by: &crate::p12::Key, subject: &Cert, ocsp: bool) -> Cert {
        let alg = der::alg_null(by.private_key.sig_oid());
        let validity = der::seq(&[
            &time::encode_generalized(by.cert.not_before),
            &time::encode_generalized(by.cert.not_after),
        ]);
        let mut tbs = vec![
            der::tlv(der::ctx(0), &der::small_int(2)),
            der::small_int(99),
            alg.clone(),
            by.cert.subject.clone(),
            validity,
            der::seq(&[&der::set_of(vec![der::seq(&[
                &der::oid("2.5.4.3"),
                &der::tlv(0x0c, b"TEST OCSP RESPONDER"),
            ])])]),
            subject.spki.clone(),
        ];
        if ocsp {
            let eku = der::seq(&[&der::oid(cert::EKU_OCSP_SIGNING)]);
            let ext = der::seq(&[&der::oid("2.5.29.37"), &der::octets(&eku)]);
            tbs.push(der::tlv(der::ctx(3), &der::seq(&[&ext])));
        }
        let refs: Vec<&[u8]> = tbs.iter().map(Vec::as_slice).collect();
        let tbs = der::seq(&refs);
        let sig = by.private_key.sign(&tbs).unwrap();
        Cert::parse(&der::seq(&[&tbs, &alg, &der::bit_string(&sig)])).unwrap()
    }

    /// An answer about `c`.
    pub(crate) struct Reply<'a> {
        pub signer: &'a crate::p12::Key,
        pub certs: Vec<Cert>,
        pub issuer: &'a Cert,
        pub serial: Vec<u8>,
        pub status: Vec<u8>,
        pub this_update: i64,
        pub next_update: Option<i64>,
        pub nonce: Option<Vec<u8>>,
        pub version: bool,
    }

    impl Reply<'_> {
        pub(crate) fn encode(&self) -> Vec<u8> {
            let alg = gost::H_SHA256;
            let (nh, kh) = issuer_hashes(self.issuer, alg).unwrap();
            let cert_id = der::seq(&[
                &der::alg_null(alg),
                &der::octets(&nh),
                &der::octets(&kh),
                &der::uint(&self.serial),
            ]);
            let mut single = vec![
                cert_id,
                self.status.clone(),
                time::encode_generalized(self.this_update),
            ];
            if let Some(n) = self.next_update {
                single.push(der::tlv(der::ctx(0), &time::encode_generalized(n)));
            }
            let refs: Vec<&[u8]> = single.iter().map(Vec::as_slice).collect();
            let mut rd = vec![];
            if self.version {
                rd.push(der::tlv(der::ctx(0), &der::small_int(0)));
            }
            rd.push(der::tlv(der::ctx(1), &self.signer.cert.subject));
            rd.push(time::encode_generalized(self.this_update));
            rd.push(der::seq(&[&der::seq(&refs)]));
            if let Some(n) = &self.nonce {
                let ext = der::seq(&[&der::oid(NONCE), &der::octets(n)]);
                rd.push(der::tlv(der::ctx(1), &der::seq(&[&ext])));
            }
            let refs: Vec<&[u8]> = rd.iter().map(Vec::as_slice).collect();
            let rd = der::seq(&refs);
            let sig = self.signer.private_key.sign(&rd).unwrap();
            let mut basic = vec![
                rd,
                der::alg_null(self.signer.private_key.sig_oid()),
                der::bit_string(&sig),
            ];
            if !self.certs.is_empty() {
                let c: Vec<&[u8]> = self.certs.iter().map(|c| c.der.as_slice()).collect();
                basic.push(der::tlv(der::ctx(0), &der::seq(&c)));
            }
            let refs: Vec<&[u8]> = basic.iter().map(Vec::as_slice).collect();
            wrap_basic(&der::seq(&refs))
        }
    }

    pub(crate) const GOOD: [u8; 2] = [0x80, 0];

    #[test]
    fn answers() {
        let ca = key("ocsp/ca.p12");
        let carol = key("ocsp/carol.p12").cert;
        let trust = TrustStore::new(vec![ca.cert.clone()]);
        let now = time::now_ms();
        let reply = || Reply {
            signer: &ca,
            certs: vec![],
            issuer: &ca.cert,
            serial: carol.serial.clone(),
            status: GOOD.to_vec(),
            this_update: now,
            next_update: Some(now + 3_600_000),
            nonce: None,
            version: false,
        };
        let stored = |r: &Reply| read_embedded(&r.encode(), &carol, &ca.cert, &trust).unwrap();

        let a = stored(&reply());
        assert!(a.good && a.cert_status == "good", "{}", a.status);
        assert!(a.status.starts_with("GOOD"));
        assert_eq!(a.this_update, Some(now / 1000 * 1000));
        assert_eq!(a.responder.as_ref(), Some(&ca.cert));
        assert!(!a.basic.is_empty());
        let a = stored(&Reply {
            version: true,
            ..reply()
        });
        assert!(a.good, "{}", a.status);

        let revoked = der::tlv(der::ctx(1), &time::encode_generalized(now - 86_400_000));
        let a = stored(&Reply {
            status: revoked,
            ..reply()
        });
        assert!(!a.good && a.cert_status == "revoked", "{}", a.status);
        assert_eq!(a.revoked_at, Some((now - 86_400_000) / 1000 * 1000));
        let a = stored(&Reply {
            status: vec![0x82, 0],
            ..reply()
        });
        assert!(!a.good && a.cert_status == "unknown", "{}", a.status);

        // about another certificate, or from a CA in trouble
        let a = stored(&Reply {
            serial: vec![1, 2, 3],
            ..reply()
        });
        assert!(
            !a.good && a.status.contains("no answer for this certificate"),
            "{}",
            a.status
        );
        let r = der::seq(&[&der::tlv(der::ENUMERATED, &[3])]);
        let a = read_embedded(&r, &carol, &ca.cert, &trust).unwrap();
        assert!(!a.good && a.status.contains("status 3"), "{}", a.status);
    }

    #[test]
    fn who_may_answer() {
        let ca = key("ocsp/ca.p12");
        let carol_key = key("ocsp/carol.p12");
        let carol = carol_key.cert.clone();
        let other = key("keys/alice_rsa.p12");
        let trust = TrustStore::new(vec![ca.cert.clone()]);
        let now = time::now_ms();
        let responder = |cert: Cert| crate::p12::Key {
            alias: String::new(),
            private_key: key("keys/alice_rsa.p12").private_key,
            cert,
            chain: vec![],
            other_aliases: vec![],
        };
        let check = |signer: &crate::p12::Key| {
            let r = Reply {
                signer,
                certs: vec![signer.cert.clone()],
                issuer: &ca.cert,
                serial: carol.serial.clone(),
                status: GOOD.to_vec(),
                this_update: now,
                next_update: None,
                nonce: None,
                version: false,
            };
            read_embedded(&r.encode(), &carol, &ca.cert, &trust).unwrap()
        };
        // a responder the CA certified for OCSP signing
        let delegated = responder(issue(&ca, &other.cert, true));
        let a = check(&delegated);
        assert!(a.good, "{}", a.status);
        assert_eq!(a.responder.as_ref(), Some(&delegated.cert));
        // ... not for OCSP signing
        let a = check(&responder(issue(&ca, &other.cert, false)));
        assert!(
            !a.good && a.status.contains("not issued for OCSP signing"),
            "{}",
            a.status
        );
        // ... certified by someone else
        let a = check(&responder(issue(&carol_key, &other.cert, true)));
        assert!(
            !a.good && a.status.contains("not issued by the certificate's CA"),
            "{}",
            a.status
        );
        // ... any key at all
        let a = check(&other);
        assert!(
            !a.good && a.status.contains("not issued by the certificate's CA"),
            "{}",
            a.status
        );
        // a signature that does not hold
        let mut r = Reply {
            signer: &ca,
            certs: vec![],
            issuer: &ca.cert,
            serial: carol.serial.clone(),
            status: GOOD.to_vec(),
            this_update: now,
            next_update: None,
            nonce: None,
            version: false,
        }
        .encode();
        let n = r.len();
        r[n - 1] ^= 1;
        let a = read_embedded(&r, &carol, &ca.cert, &trust).unwrap();
        assert!(
            !a.good && a.status.contains("signature is invalid"),
            "{}",
            a.status
        );
    }

    /// A fresh answer must echo the nonce, or be fresh by its own dates.
    #[test]
    fn fresh_answers() {
        let ca = key("ocsp/ca.p12");
        let carol = key("ocsp/carol.p12").cert;
        let trust = TrustStore::new(vec![ca.cert.clone()]);
        let now = time::now_ms();
        let sent = [7u8; 16];
        let minute = 60_000;
        let fresh = |this_update: i64, next_update: Option<i64>, echo: Option<Vec<u8>>| {
            let r = Reply {
                signer: &ca,
                certs: vec![],
                issuer: &ca.cert,
                serial: carol.serial.clone(),
                status: GOOD.to_vec(),
                this_update,
                next_update,
                nonce: echo,
                version: false,
            };
            evaluate(&r.encode(), &carol, &ca.cert, Some(&sent), &trust).unwrap()
        };
        let nested = der::octets(&sent);
        for (name, a, ok) in [
            (
                "echoed",
                fresh(now - 120 * minute, None, Some(nested.clone())),
                true,
            ),
            (
                "echoed bare",
                fresh(now - 120 * minute, None, Some(sent.to_vec())),
                true,
            ),
            (
                "other nonce",
                fresh(now, None, Some(der::octets(&[8; 16]))),
                false,
            ),
            (
                "valid until later",
                fresh(now - 120 * minute, Some(now + minute), None),
                true,
            ),
            (
                "expired",
                fresh(now - 120 * minute, Some(now - minute), None),
                false,
            ),
            (
                "made 50 minutes ago",
                fresh(now - 50 * minute, None, None),
                true,
            ),
            (
                "made 70 minutes ago",
                fresh(now - 70 * minute, None, None),
                false,
            ),
            (
                "made 4 minutes ahead",
                fresh(now + 4 * minute, Some(now + 60 * minute), None),
                true,
            ),
            (
                "made 6 minutes ahead",
                fresh(now + 6 * minute, Some(now + 60 * minute), None),
                false,
            ),
        ] {
            assert_eq!(a.good, ok, "{name}: {}", a.status);
            if !ok && name != "other nonce" {
                assert!(a.status.contains("out of date"), "{name}: {}", a.status);
            }
        }
        let a = fresh(now, None, Some(der::octets(&[8; 16])));
        assert!(a.status.contains("nonce mismatch"), "{}", a.status);
        // a fresh answer is dated when it was checked, not when it was made
        let a = fresh(now - 2 * 1440 * minute, None, Some(nested));
        assert!(
            a.status
                .contains(&time::fmt(Some(now)).chars().take(10).collect::<String>())
        );
    }

    #[test]
    fn certificate_id_hashes() {
        let ca = |a: &str| {
            Cert::parse(
                &std::fs::read(format!(
                    "{}/tests/fixtures/keys/ca_{a}.cer",
                    env!("CARGO_MANIFEST_DIR")
                ))
                .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(cert_id_hash(&ca("gost2004")), gost::H_GOST34311);
        assert_eq!(cert_id_hash(&ca("gost2015")), gost::H_GOST2015_512);
        assert_eq!(cert_id_hash(&ca("rsa")), gost::H_SHA256);
    }
}
