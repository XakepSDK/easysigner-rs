//! OCSP (RFC 6960): requests about a certificate, and checking the answers (signature,
//! responder, nonce, freshness). The caller sends the request and passes the answer back.

use crate::cert::{self, Cert};
use ::der::asn1::{Any, BitString};
use ::der::{Decode, Encode, Sequence};
use x509_ocsp::{CertStatus as Status, OcspResponse, OcspResponseStatus, ResponseData};

use crate::der;
use crate::prelude::*;
use crate::text::{Text, Time, tr, trf};
use crate::trust::TrustStore;
use crate::{Error, Result, gost};

pub const CONTENT_TYPE: &str = "application/ocsp-request";
const NONCE: &str = "1.3.6.1.5.5.7.48.1.2";
const BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

/// What a CA says about a certificate, by OCSP or in a revocation list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertStatus {
    /// Not revoked.
    Good,
    Revoked,
    /// The CA does not know it (OCSP only).
    Unknown,
}

impl CertStatus {
    /// "good", "revoked" or "unknown".
    pub fn code(self) -> &'static str {
        match self {
            CertStatus::Good => "good",
            CertStatus::Revoked => "revoked",
            CertStatus::Unknown => "unknown",
        }
    }
}

/// An OCSP answer about one certificate.
pub struct Answer {
    /// Known not to be revoked.
    pub good: bool,
    /// For people (in English: starting with GOOD, REVOKED, UNKNOWN or ERROR).
    pub status: Text,
    /// What the server said; None on an error.
    pub cert_status: Option<CertStatus>,
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
    fn error(status: Text, raw: &[u8]) -> Answer {
        Answer {
            good: false,
            status,
            cert_status: None,
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
    let r = OcspResponse::from_der(raw).ok()?;
    let rb = r.response_bytes?;
    (r.response_status == OcspResponseStatus::Successful && rb.response_type.to_string() == BASIC)
        .then(|| rb.response.as_bytes().to_vec())
}

/// BasicOCSPResponse (RFC 6960 4.2.1) from x509-ocsp's parts, with the certificates left as
/// they are: x509-ocsp's own type refuses some serial numbers CAs issue, and [`Cert`] reads
/// them.
#[derive(Sequence)]
struct Basic {
    /// Kept as encoded: the signature covers these bytes, and some responders write the
    /// default version out, which DER re-encoding would drop.
    tbs_response_data: Any,
    signature_algorithm: spki::AlgorithmIdentifierOwned,
    signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    certs: Option<Vec<Any>>,
}

fn asn1(e: ::der::Error) -> Error {
    Error::malformed(format!("malformed ASN.1: {e}"))
}

fn ms(t: &x509_ocsp::OcspGeneralizedTime) -> Result<i64> {
    i64::try_from(t.0.to_unix_duration().as_millis())
        .map_err(|_| Error::malformed("OCSP time out of range"))
}

/// An INTEGER's content without leading zero bytes (one zero for zero), as [`Cert::serial`].
fn strip_zeros(mut b: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = b
        && !rest.is_empty()
    {
        b = rest;
    }
    b
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

/// An OCSP request about `c` (issued by `issuer`) with `nonce` (16 random bytes are usual).
/// Send it with content type [`CONTENT_TYPE`], and check the answer with [`read_fresh`].
pub fn request(c: &Cert, issuer: &Cert, nonce: &[u8]) -> Result<Vec<u8>> {
    let alg = cert_id_hash(issuer);
    let (name_hash, key_hash) = issuer_hashes(issuer, alg)?;
    let cert_id = der::seq(&[
        &der::alg_null(alg),
        &der::octets(&name_hash),
        &der::octets(&key_hash),
        &der::uint(&c.serial),
    ]);
    // RFC 8954: the extension value is the DER of an OCTET STRING holding the nonce
    let nonce_ext = der::seq(&[&der::seq(&[
        &der::oid(NONCE),
        &der::octets(&der::octets(nonce)),
    ])]);
    let tbs = der::seq(&[
        &der::seq(&[&der::seq(&[&cert_id])]),
        &der::tlv(der::ctx(2), &nonce_ext),
    ]);
    Ok(der::seq(&[&tbs]))
}

/// Checks the server's answer to a [`request`] with `nonce`, received at `now` (milliseconds
/// since 1970, UTC).
pub fn read_fresh(
    body: &[u8],
    c: &Cert,
    issuer: &Cert,
    nonce: &[u8],
    trust: &TrustStore,
    now: i64,
) -> Result<Answer> {
    evaluate(body, c, issuer, Some((nonce, now)), trust)
}

/// Checks an OCSP response kept inside a signature (no nonce, and its age is judged by whoever
/// reads it). A delegated responder's certificate is checked at the time the answer was made.
pub fn read_embedded(raw: &[u8], c: &Cert, issuer: &Cert, trust: &TrustStore) -> Result<Answer> {
    evaluate(raw, c, issuer, None, trust)
}

/// `fresh`: the nonce sent and the time now, for a fresh answer; None for a stored one.
fn evaluate(
    body: &[u8],
    c: &Cert,
    issuer: &Cert,
    fresh: Option<(&[u8], i64)>,
    trust: &TrustStore,
) -> Result<Answer> {
    let nonce = fresh.map(|f| f.0);
    let resp = OcspResponse::from_der(body).map_err(asn1)?;
    if resp.response_status != OcspResponseStatus::Successful {
        return Ok(Answer::error(
            trf(
                "ERROR: OCSP server answered status {}",
                &[&(resp.response_status as u8 as i64)],
            ),
            body,
        ));
    }
    let rb = resp
        .response_bytes
        .ok_or_else(|| Error::new("OCSP response without content"))?;
    if rb.response_type.to_string() != BASIC {
        return Err(Error::new("not a basic OCSP response"));
    }
    let basic_der = rb.response.as_bytes().to_vec();
    let basic = Basic::from_der(&basic_der).map_err(asn1)?;
    let tbs = basic.tbs_response_data.to_der().map_err(asn1)?;
    let rd = &ResponseData::from_der(&tbs).map_err(asn1)?;
    let sig_alg = basic.signature_algorithm.oid.to_string();
    let sig = basic
        .signature
        .as_bytes()
        .ok_or_else(|| Error::malformed("OCSP signature is not whole bytes"))?;
    let certs: Vec<Cert> = basic
        .certs
        .iter()
        .flatten()
        .filter_map(|a| a.to_der().ok())
        .filter_map(|d| Cert::parse(&d).ok())
        .collect();
    // a fresh answer's responder must be valid now; a kept one's when it answered (producedAt)
    let responder_at = match fresh {
        Some((_, now)) => now,
        None => ms(&rd.produced_at)?,
    };
    let responder = match check_responder(&tbs, &sig_alg, sig, &certs, issuer, trust, responder_at)
    {
        Ok(r) => r,
        Err(problem) => return Ok(Answer::error(trf("ERROR: {}", &[&problem]), body)),
    };

    let mut nonce_ok = false;
    if let Some(nonce) = nonce
        && let Some(echoed) = rd
            .response_extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id.to_string() == NONCE)
    {
        let echoed = echoed.extn_value.as_bytes();
        // accept the RFC form (nested OCTET STRING) and the bare nonce some responders echo
        let nested = ::der::asn1::OctetString::from_der(echoed).ok();
        if echoed != nonce && nested.as_ref().map(|n| n.as_bytes()) != Some(nonce) {
            return Ok(Answer::error(
                tr("ERROR: OCSP response is not for this request (nonce mismatch)"),
                body,
            ));
        }
        nonce_ok = true;
    }
    for s in &rd.responses {
        let id = &s.cert_id;
        if strip_zeros(id.serial_number.as_bytes()) != c.serial.as_slice() {
            continue;
        }
        let Ok((nh, kh)) = issuer_hashes(issuer, &id.hash_algorithm.oid.to_string()) else {
            continue;
        };
        if id.issuer_name_hash.as_bytes() != nh || id.issuer_key_hash.as_bytes() != kh {
            continue;
        }
        let next_update = s.next_update.as_ref().map(ms).transpose()?;
        let this_update = Some(ms(&s.this_update)?);
        if let Some((_, now)) = fresh {
            // Without our nonce echoed back, only freshness shows that the answer is not an old
            // one replayed: it must be within its validity period (nextUpdate), or, without one,
            // made within the last hour.
            let skew = 5 * 60 * 1000;
            let fresh = match next_update {
                Some(n) => n >= now,
                None => nonce_ok || this_update.is_some_and(|t| t >= now - 3600 * 1000),
            };
            if !fresh || this_update.is_some_and(|t| t > now + skew) {
                return Ok(Answer::error(tr("ERROR: OCSP answer is out of date"), body));
            }
        }
        let checked = match fresh {
            Some((_, now)) => Some(now),
            None => this_update,
        };
        let (mut revoked_at, mut untrusted_from) = (None, None);
        let (good, cert_status, status) = match &s.cert_status {
            Status::Good(_) => (
                true,
                CertStatus::Good,
                trf("GOOD (not revoked, checked {})", &[&Time(checked)]),
            ),
            Status::Revoked(info) => {
                use x509_cert::ext::pkix::CrlReason as R;
                let when = Some(ms(&info.revocation_time)?);
                let compromised = matches!(
                    info.revocation_reason,
                    Some(R::KeyCompromise | R::CaCompromise | R::AaCompromise)
                );
                revoked_at = when;
                untrusted_from = if compromised { Some(i64::MIN) } else { when };
                (
                    false,
                    CertStatus::Revoked,
                    trf("REVOKED on {}", &[&Time(when)]),
                )
            }
            Status::Unknown(_) => (
                false,
                CertStatus::Unknown,
                tr("UNKNOWN (the OCSP server does not know this certificate)"),
            ),
        };
        return Ok(Answer {
            good,
            status,
            cert_status: Some(cert_status),
            this_update,
            revoked_at,
            untrusted_from,
            responder: Some(responder),
            raw: body.to_vec(),
            basic: basic_der,
        });
    }
    Ok(Answer::error(
        tr("UNKNOWN (no answer for this certificate)"),
        body,
    ))
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
) -> core::result::Result<Cert, Text> {
    let candidates = core::iter::once(issuer).chain(certs.iter());
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
            return Err(tr("OCSP responder was not issued by the certificate's CA"));
        }
        if !c.has_eku(cert::EKU_OCSP_SIGNING) {
            return Err(tr(
                "OCSP responder certificate is not issued for OCSP signing",
            ));
        }
        let chain = trust.check(c, at);
        return if chain.ok {
            Ok(c.clone())
        } else {
            Err(trf("OCSP responder is not trusted ({})", &[&chain.status]))
        };
    }
    Err(tr("OCSP response signature is invalid"))
}

/// Test helpers for this crate's and the application's tests: test keys, certificates issued
/// on the spot, and OCSP answers made to order. Not for production (feature `testkit`).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    extern crate std;

    use super::*;
    use crate::time;

    /// The operating system's random numbers.
    struct Os;

    impl crate::Rng for Os {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            getrandom::fill(buf).map_err(|_| Error::new("no random numbers"))
        }
    }

    /// A test key file from tests/fixtures (password Qwerty12).
    pub fn key(p: &str) -> crate::p12::Key {
        let d = std::fs::read(std::format!(
            "{}/../tests/fixtures/{p}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        crate::p12::open(&d, "Qwerty12", None).unwrap()
    }

    /// A certificate for `subject`'s key issued by `by`, with the OCSP signing purpose when
    /// `ocsp`.
    pub fn issue(by: &crate::p12::Key, subject: &Cert, ocsp: bool) -> Cert {
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
        let sig = by.private_key.sign(&tbs, &mut Os).unwrap();
        Cert::parse(&der::seq(&[&tbs, &alg, &der::bit_string(&sig)])).unwrap()
    }

    /// An answer about `c`.
    pub struct Reply<'a> {
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
        pub fn encode(&self) -> Vec<u8> {
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
            let sig = self.signer.private_key.sign(&rd, &mut Os).unwrap();
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

    pub const GOOD: [u8; 2] = [0x80, 0];
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::testing::now_ms;
    use crate::time;

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

    #[test]
    fn answers() {
        let ca = key("ocsp/ca.p12");
        let carol = key("ocsp/carol.p12").cert;
        let trust = TrustStore::new(vec![ca.cert.clone()]);
        let now = now_ms();
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
        assert!(
            a.good && a.cert_status == Some(CertStatus::Good),
            "{}",
            a.status
        );
        assert!(a.status.to_string().starts_with("GOOD"));
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
        assert!(
            !a.good && a.cert_status == Some(CertStatus::Revoked),
            "{}",
            a.status
        );
        assert_eq!(a.revoked_at, Some((now - 86_400_000) / 1000 * 1000));
        let a = stored(&Reply {
            status: vec![0x82, 0],
            ..reply()
        });
        assert!(
            !a.good && a.cert_status == Some(CertStatus::Unknown),
            "{}",
            a.status
        );

        // about another certificate, or from a CA in trouble
        let a = stored(&Reply {
            serial: vec![1, 2, 3],
            ..reply()
        });
        assert!(
            !a.good
                && a.status
                    .to_string()
                    .contains("no answer for this certificate"),
            "{}",
            a.status
        );
        let r = der::seq(&[&der::tlv(der::ENUMERATED, &[3])]);
        let a = read_embedded(&r, &carol, &ca.cert, &trust).unwrap();
        assert!(
            !a.good && a.status.to_string().contains("status 3"),
            "{}",
            a.status
        );
    }

    #[test]
    fn who_may_answer() {
        let ca = key("ocsp/ca.p12");
        let carol_key = key("ocsp/carol.p12");
        let carol = carol_key.cert.clone();
        let other = key("keys/alice_rsa.p12");
        let trust = TrustStore::new(vec![ca.cert.clone()]);
        let now = now_ms();
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
            !a.good && a.status.to_string().contains("not issued for OCSP signing"),
            "{}",
            a.status
        );
        // ... certified by someone else
        let a = check(&responder(issue(&carol_key, &other.cert, true)));
        assert!(
            !a.good
                && a.status
                    .to_string()
                    .contains("not issued by the certificate's CA"),
            "{}",
            a.status
        );
        // ... any key at all
        let a = check(&other);
        assert!(
            !a.good
                && a.status
                    .to_string()
                    .contains("not issued by the certificate's CA"),
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
            !a.good && a.status.to_string().contains("signature is invalid"),
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
        let now = now_ms();
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
            read_fresh(&r.encode(), &carol, &ca.cert, &sent, &trust, now).unwrap()
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
                assert!(
                    a.status.to_string().contains("out of date"),
                    "{name}: {}",
                    a.status
                );
            }
        }
        let a = fresh(now, None, Some(der::octets(&[8; 16])));
        assert!(
            a.status.to_string().contains("nonce mismatch"),
            "{}",
            a.status
        );
        // a fresh answer is dated when it was checked, not when it was made
        let a = fresh(now - 2 * 1440 * minute, None, Some(nested));
        assert_eq!(a.status.args, vec![crate::text::Arg::Time(Some(now))]);
    }

    #[test]
    fn certificate_id_hashes() {
        let ca =
            |a: &str| Cert::parse(&crate::testing::fixture(&format!("keys/ca_{a}.cer"))).unwrap();
        assert_eq!(cert_id_hash(&ca("gost2004")), gost::H_GOST34311);
        assert_eq!(cert_id_hash(&ca("gost2015")), gost::H_GOST2015_512);
        assert_eq!(cert_id_hash(&ca("rsa")), gost::H_SHA256);
    }
}
