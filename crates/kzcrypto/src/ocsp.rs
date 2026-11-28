//! OCSP (RFC 6960): requests about a certificate, and checking the answers (signature,
//! responder, nonce, freshness). The caller sends the request and passes the answer back.

use ::der::asn1::{Any, BitString, OctetString, OctetStringRef};
use ::der::{Decode, Encode, Sequence};
use x509_cert::certificate::Raw;
use x509_ocsp::{CertStatus as X, OcspResponse, OcspResponseStatus, ResponseData};

use crate::asn1::{self, err as asn1};
use crate::cert::{self, Cert};
use crate::prelude::*;
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

/// What an OCSP answer says, or why it can't be used.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// Not revoked; `checked`: when that was known (the time of checking, for a fresh answer).
    Good {
        checked: Option<i64>,
    },
    Revoked {
        at: Option<i64>,
    },
    /// The server does not know the certificate.
    Unknown,
    /// The answer says nothing about this certificate.
    NoAnswerForCert,
    /// The server answered with this error status (RFC 6960 4.2.1).
    ServerError(u8),
    /// The answer's signer can't be accepted.
    Responder(ResponderProblem),
    /// The answer is not for this request (another nonce).
    NonceMismatch,
    /// The answer is too old, or made too far ahead.
    OutOfDate,
}

/// Why an OCSP answer's signer can't be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponderProblem {
    /// Neither the CA nor a certificate it issued signed it.
    BadSignature,
    NotIssuedByCa,
    /// The responder's certificate is not for OCSP signing (extended key usage).
    NotForOcspSigning,
    /// The responder's certificate path is not good.
    Untrusted(crate::trust::PathStatus),
}

/// An OCSP answer about one certificate.
pub struct Answer {
    /// Known not to be revoked.
    pub good: bool,
    pub status: Status,
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
    fn error(status: Status, raw: &[u8]) -> Answer {
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
pub fn wrap_basic(basic: &[u8]) -> Result<Vec<u8>> {
    asn1::der(&OcspResponse {
        response_status: OcspResponseStatus::Successful,
        response_bytes: Some(x509_ocsp::ResponseBytes {
            response_type: asn1::oid(BASIC)?,
            response: OctetString::new(basic).map_err(asn1)?,
        }),
    })
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

fn ms(t: &x509_ocsp::OcspGeneralizedTime) -> Result<i64> {
    i64::try_from(t.0.to_unix_duration().as_millis()).map_err(|_| Error::BadTime)
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
    let req_cert = cert_id(alg, name_hash, key_hash, &c.serial)?;
    // RFC 8954: the extension value is the DER of an OCTET STRING holding the nonce
    let nonce = x509_cert::ext::Extension {
        extn_id: asn1::oid(NONCE)?,
        critical: false,
        extn_value: OctetString::new(asn1::der(&OctetStringRef::new(nonce).map_err(asn1)?)?)
            .map_err(asn1)?,
    };
    asn1::der(&x509_ocsp::OcspRequest::<Raw> {
        tbs_request: x509_ocsp::TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: vec![x509_ocsp::Request {
                req_cert,
                single_request_extensions: None,
            }],
            request_extensions: Some(vec![nonce]),
        },
        optional_signature: None,
    })
}

/// A CertID (RFC 6960 4.1.1) for the certificate with serial number `serial`.
fn cert_id(
    alg: &str,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
    serial: &[u8],
) -> Result<x509_ocsp::CertId<Raw>> {
    Ok(x509_ocsp::CertId {
        hash_algorithm: spki::AlgorithmIdentifierOwned {
            oid: asn1::oid(alg)?,
            parameters: Some(Any::null()),
        },
        issuer_name_hash: OctetString::new(name_hash).map_err(asn1)?,
        issuer_key_hash: OctetString::new(key_hash).map_err(asn1)?,
        // through DER, as [`Raw`] reads long serial numbers that it would not make
        serial_number: Decode::from_der(&asn1::der(&asn1::positive(serial)?)?).map_err(asn1)?,
    })
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
            Status::ServerError(resp.response_status as u8),
            body,
        ));
    }
    let rb = resp.response_bytes.ok_or(Error::OcspNotBasic)?;
    if rb.response_type.to_string() != BASIC {
        return Err(Error::OcspNotBasic);
    }
    let basic_der = rb.response.as_bytes().to_vec();
    let basic = Basic::from_der(&basic_der).map_err(asn1)?;
    let tbs = basic.tbs_response_data.to_der().map_err(asn1)?;
    let rd = &ResponseData::from_der(&tbs).map_err(asn1)?;
    let sig_alg = basic.signature_algorithm.oid.to_string();
    let sig = basic
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Asn1("signature BIT STRING with unused bits".into()))?;
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
        Err(problem) => return Ok(Answer::error(Status::Responder(problem), body)),
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
            return Ok(Answer::error(Status::NonceMismatch, body));
        }
        nonce_ok = true;
    }
    for s in &rd.responses {
        let id = &s.cert_id;
        if asn1::strip_zeros(id.serial_number.as_bytes()) != c.serial.as_slice() {
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
            // recent (Policy::ocsp_max_age_ms).
            let p = trust.policy;
            let skew = p.clock_skew_ms;
            let fresh = match next_update {
                Some(n) => n >= now,
                None => nonce_ok || this_update.is_some_and(|t| t >= now - p.ocsp_max_age_ms),
            };
            if !fresh || this_update.is_some_and(|t| t > now + skew) {
                return Ok(Answer::error(Status::OutOfDate, body));
            }
        }
        let checked = match fresh {
            Some((_, now)) => Some(now),
            None => this_update,
        };
        let (mut revoked_at, mut untrusted_from) = (None, None);
        let (good, cert_status, status) = match &s.cert_status {
            X::Good(_) => (true, CertStatus::Good, Status::Good { checked }),
            X::Revoked(info) => {
                use x509_cert::ext::pkix::CrlReason as R;
                let when = Some(ms(&info.revocation_time)?);
                let compromised = matches!(
                    info.revocation_reason,
                    Some(R::KeyCompromise | R::CaCompromise | R::AaCompromise)
                );
                revoked_at = when;
                untrusted_from = if compromised { Some(i64::MIN) } else { when };
                (false, CertStatus::Revoked, Status::Revoked { at: when })
            }
            X::Unknown(_) => (false, CertStatus::Unknown, Status::Unknown),
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
    Ok(Answer::error(Status::NoAnswerForCert, body))
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
) -> core::result::Result<Cert, ResponderProblem> {
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
            return Err(ResponderProblem::NotIssuedByCa);
        }
        if !c.has_eku(cert::EKU_OCSP_SIGNING) {
            return Err(ResponderProblem::NotForOcspSigning);
        }
        let chain = trust.check(c, at);
        return if chain.ok {
            Ok(c.clone())
        } else {
            Err(ResponderProblem::Untrusted(chain.status))
        };
    }
    Err(ResponderProblem::BadSignature)
}

/// Test helpers for this crate's and the application's tests: test keys, certificates issued
/// on the spot, and OCSP answers made to order. Not for production (feature `testkit`).
#[cfg(any(test, feature = "testkit"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
pub mod testkit {
    extern crate std;

    use super::*;
    use crate::time;

    /// The operating system's random numbers.
    struct Os;

    impl crate::Rng for Os {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            getrandom::fill(buf).map_err(|e| Error::Random(format!("{e}")))
        }
    }

    /// A test key file from testdata (password Qwerty12).
    pub fn key(p: &str) -> crate::p12::Key {
        let d = std::fs::read(std::format!(
            "{}/../../testdata/{p}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        crate::p12::open(&d, "Qwerty12", None).unwrap()
    }

    /// A certificate for `subject`'s key issued by `by`, with the OCSP signing purpose when
    /// `ocsp`.
    pub fn issue(by: &crate::p12::Key, subject: &Cert, ocsp: bool) -> Cert {
        use ::der::asn1::{GeneralizedTime, ObjectIdentifier};
        use core::str::FromStr;
        use x509_cert::time::{Time, Validity};
        let alg = spki::AlgorithmIdentifierOwned {
            oid: asn1::oid(by.private_key.sig_oid()).unwrap(),
            parameters: Some(Any::null()),
        };
        // RFC 5280 4.1.2.5: UTCTime through 2049, as real certificates have (and as a CMS
        // writes them back)
        let time = |ms: i64| {
            let d = core::time::Duration::from_millis(u64::try_from(ms).unwrap());
            match ::der::asn1::UtcTime::from_unix_duration(d) {
                Ok(t) => Time::UtcTime(t),
                Err(_) => Time::GeneralTime(GeneralizedTime::from_unix_duration(d).unwrap()),
            }
        };
        let extensions = ocsp.then(|| {
            let eku = x509_cert::ext::pkix::ExtendedKeyUsage(vec![
                ObjectIdentifier::new(cert::EKU_OCSP_SIGNING).unwrap(),
            ]);
            vec![x509_cert::ext::Extension {
                extn_id: ObjectIdentifier::new("2.5.29.37").unwrap(),
                critical: false,
                extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
            }]
        });
        let tbs = Tbs {
            version: 2,
            serial_number: 99,
            signature: alg.clone(),
            issuer: asn1::any(&by.cert.subject).unwrap(),
            validity: Validity::<Raw>::new(time(by.cert.not_before), time(by.cert.not_after)),
            subject: x509_cert::name::Name::from_str("CN=TEST OCSP RESPONDER").unwrap(),
            subject_public_key_info: asn1::any(&subject.spki).unwrap(),
            extensions,
        }
        .to_der()
        .unwrap();
        let sig = by.private_key.sign(&tbs, &mut Os).unwrap();
        let c = Certificate {
            tbs_certificate: asn1::any(&tbs).unwrap(),
            signature_algorithm: alg,
            signature: BitString::from_bytes(&sig).unwrap(),
        };
        Cert::parse(&c.to_der().unwrap()).unwrap()
    }

    /// TBSCertificate (RFC 5280 4.1), v3.
    #[derive(Sequence)]
    struct Tbs {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        version: u8,
        serial_number: u8,
        signature: spki::AlgorithmIdentifierOwned,
        issuer: Any,
        validity: x509_cert::time::Validity<Raw>,
        subject: x509_cert::name::Name,
        subject_public_key_info: Any,
        #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
        extensions: Option<Vec<x509_cert::ext::Extension>>,
    }

    #[derive(Sequence)]
    struct Certificate {
        tbs_certificate: Any,
        signature_algorithm: spki::AlgorithmIdentifierOwned,
        signature: BitString,
    }

    /// An answer about `c`.
    pub struct Reply<'a> {
        pub signer: &'a crate::p12::Key,
        pub certs: Vec<Cert>,
        pub issuer: &'a Cert,
        pub serial: Vec<u8>,
        /// CertStatus, as encoded ([`GOOD`], or made to order).
        pub status: Vec<u8>,
        pub this_update: i64,
        pub next_update: Option<i64>,
        /// The nonce extension's value (octets as sent, or as some servers echo them).
        pub nonce: Option<Vec<u8>>,
        /// Writes the default version out, as some responders do.
        pub version: bool,
    }

    /// SingleResponse with the status as encoded.
    #[derive(Sequence)]
    struct Single {
        cert_id: x509_ocsp::CertId<Raw>,
        status: Any,
        this_update: Any,
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
        next_update: Option<Any>,
    }

    /// ResponseData that may write the default version out, and names the responder by its
    /// name (as encoded).
    #[derive(Sequence)]
    struct Data {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
        version: Option<u8>,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
        responder: Any,
        produced_at: Any,
        responses: Vec<Single>,
        #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
        extensions: Option<Vec<x509_cert::ext::Extension>>,
    }

    impl Reply<'_> {
        pub fn encode(&self) -> Vec<u8> {
            let alg = gost::H_SHA256;
            let (nh, kh) = issuer_hashes(self.issuer, alg).unwrap();
            let gt = |ms: i64| asn1::any(&time::encode_generalized(ms).unwrap()).unwrap();
            let single = Single {
                cert_id: cert_id(alg, nh, kh, &self.serial).unwrap(),
                status: asn1::any(&self.status).unwrap(),
                this_update: gt(self.this_update),
                next_update: self.next_update.map(gt),
            };
            let extensions = self.nonce.as_ref().map(|n| {
                vec![x509_cert::ext::Extension {
                    extn_id: asn1::oid(NONCE).unwrap(),
                    critical: false,
                    extn_value: OctetString::new(n.clone()).unwrap(),
                }]
            });
            let rd = Data {
                version: self.version.then_some(0),
                responder: asn1::any(&self.signer.cert.subject).unwrap(),
                produced_at: gt(self.this_update),
                responses: vec![single],
                extensions,
            }
            .to_der()
            .unwrap();
            let sig = self.signer.private_key.sign(&rd, &mut Os).unwrap();
            let basic = Basic {
                tbs_response_data: asn1::any(&rd).unwrap(),
                signature_algorithm: spki::AlgorithmIdentifierOwned {
                    oid: asn1::oid(self.signer.private_key.sig_oid()).unwrap(),
                    parameters: Some(Any::null()),
                },
                signature: BitString::from_bytes(&sig).unwrap(),
                certs: (!self.certs.is_empty()).then(|| {
                    self.certs
                        .iter()
                        .map(|c| asn1::any(&c.der).unwrap())
                        .collect()
                }),
            };
            wrap_basic(&basic.to_der().unwrap()).unwrap()
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

    fn octets(b: &[u8]) -> Vec<u8> {
        OctetStringRef::new(b).unwrap().to_der().unwrap()
    }

    /// Short or empty pieces in a stored answer are errors, not crashes.
    #[test]
    fn broken_stored_answers_are_errors() {
        let trust = crate::testing::nca();
        let ca = trust.certs()[0].clone();
        let empty: &[u8] = &[0x30, 0];
        let short: &[u8] = &[0x30, 4, 0x30, 0, 0x30, 0];
        for basic in [empty, short] {
            assert!(read_embedded(&wrap_basic(basic).unwrap(), &ca, &ca, &trust).is_err());
        }
        // successful (ENUMERATED 0) with no response bytes
        assert!(read_embedded(&[0x30, 3, 0x0a, 1, 0], &ca, &ca, &trust).is_err());
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
            "{:?}",
            a.status
        );
        assert!(matches!(a.status, Status::Good { .. }));
        assert_eq!(a.this_update, Some(now / 1000 * 1000));
        assert_eq!(a.responder.as_ref(), Some(&ca.cert));
        assert!(!a.basic.is_empty());
        let a = stored(&Reply {
            version: true,
            ..reply()
        });
        assert!(a.good, "{:?}", a.status);

        // [1] RevokedInfo { revocationTime }
        let revoked = asn1::implicit(1, {
            let t = time::encode_generalized(now - 86_400_000).unwrap();
            let mut seq = vec![0x30, t.len() as u8];
            seq.extend(t);
            seq
        });
        let a = stored(&Reply {
            status: revoked,
            ..reply()
        });
        assert!(
            !a.good && a.cert_status == Some(CertStatus::Revoked),
            "{:?}",
            a.status
        );
        assert_eq!(a.revoked_at, Some((now - 86_400_000) / 1000 * 1000));
        let a = stored(&Reply {
            status: vec![0x82, 0],
            ..reply()
        });
        assert!(
            !a.good && a.cert_status == Some(CertStatus::Unknown),
            "{:?}",
            a.status
        );

        // about another certificate, or from a CA in trouble
        let a = stored(&Reply {
            serial: vec![1, 2, 3],
            ..reply()
        });
        assert!(
            !a.good && a.status == Status::NoAnswerForCert,
            "{:?}",
            a.status
        );
        // tryLater (3), with no response bytes
        let r = [0x30, 3, 0x0a, 1, 3];
        let a = read_embedded(&r, &carol, &ca.cert, &trust).unwrap();
        assert!(
            !a.good && a.status == Status::ServerError(3),
            "{:?}",
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
        assert!(a.good, "{:?}", a.status);
        assert_eq!(a.responder.as_ref(), Some(&delegated.cert));
        // ... not for OCSP signing
        let a = check(&responder(issue(&ca, &other.cert, false)));
        assert!(
            !a.good && a.status == Status::Responder(ResponderProblem::NotForOcspSigning),
            "{:?}",
            a.status
        );
        // ... certified by someone else
        let a = check(&responder(issue(&carol_key, &other.cert, true)));
        assert!(
            !a.good && a.status == Status::Responder(ResponderProblem::NotIssuedByCa),
            "{:?}",
            a.status
        );
        // ... any key at all
        let a = check(&other);
        assert!(
            !a.good && a.status == Status::Responder(ResponderProblem::NotIssuedByCa),
            "{:?}",
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
            !a.good && a.status == Status::Responder(ResponderProblem::BadSignature),
            "{:?}",
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
        let nested = octets(&sent);
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
                fresh(now, None, Some(octets(&[8; 16]))),
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
            assert_eq!(a.good, ok, "{name}: {:?}", a.status);
            if !ok && name != "other nonce" {
                assert!(a.status == Status::OutOfDate, "{name}: {:?}", a.status);
            }
        }
        let a = fresh(now, None, Some(octets(&[8; 16])));
        assert!(a.status == Status::NonceMismatch, "{:?}", a.status);
        // a fresh answer is dated when it was checked, not when it was made
        let a = fresh(now - 2 * 1440 * minute, None, Some(nested));
        assert_eq!(a.status, Status::Good { checked: Some(now) });
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
