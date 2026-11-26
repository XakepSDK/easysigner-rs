//! Timestamps (RFC 3161) from NCA's TSA: requests, checking the answer against the request,
//! and checking a timestamp token over stamped bytes. The caller sends the request.

use crate::cert::{self, Cert};
use crate::cms::{ATTR_SIGNING_CERT, ATTR_SIGNING_CERT_V2, SignedData};
use ::der::asn1::OctetString;
use ::der::{Decode, Encode};
use spki::AlgorithmIdentifier;
use x509_tsp::cmpv2::status::PkiStatus;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion};

use crate::asn1::{err as asn1, oid, positive, strip_zeros};
use crate::gost;
use crate::prelude::*;
use crate::trust::{Chain, TrustStore};
use crate::verify::{self, Outcome};
use crate::{Error, Result};

pub const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
/// The content type to send a request with.
pub const CONTENT_TYPE: &str = "application/timestamp-query";

/// The parts of a TSTInfo kzsigner uses.
pub struct TstInfo {
    pub policy: String,
    pub imprint_alg: String,
    pub imprint: Vec<u8>,
    pub gen_time: i64,
    pub nonce: Option<Vec<u8>>,
}

impl TstInfo {
    /// From a token's encapsulated content (DER), read by `x509-tsp`.
    pub fn parse(data: &[u8]) -> Result<TstInfo> {
        let t = x509_tsp::TstInfo::from_der(data).map_err(asn1)?;
        let ms =
            i64::try_from(t.gen_time.to_unix_duration().as_millis()).map_err(|_| Error::BadTime)?;
        Ok(TstInfo {
            policy: t.policy.to_string(),
            imprint_alg: t.message_imprint.hash_algorithm.oid.to_string(),
            imprint: t.message_imprint.hashed_message.as_bytes().to_vec(),
            gen_time: ms,
            nonce: t.nonce.map(|n| strip_zeros(n.as_bytes()).to_vec()),
        })
    }
}

/// A timestamp request (TimeStampReq).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub hash_oid: String,
    pub hash: Vec<u8>,
    pub policy: Option<String>,
    pub nonce: Option<Vec<u8>>,
    pub cert_req: bool,
}

impl Request {
    /// A request for a token over `hash` (made with `hash_oid`) under `policy`, with the TSA's
    /// certificate. `nonce`: random bytes (8 are usual); the first byte is adjusted so that the
    /// nonce is a positive INTEGER with no leading zero byte, and reads back exactly as sent.
    /// Fails when `hash_oid` or `policy` is not an object identifier.
    pub fn new(hash_oid: &str, hash: &[u8], policy: &str, nonce: &[u8]) -> Result<Request> {
        oid(hash_oid)?;
        oid(policy)?;
        let mut nonce = nonce.to_vec();
        if let Some(b) = nonce.first_mut() {
            *b = (*b & 0x7f) | 0x40;
        }
        Ok(Request {
            hash_oid: hash_oid.into(),
            hash: hash.to_vec(),
            policy: Some(policy.into()),
            nonce: Some(nonce),
            cert_req: true,
        })
    }

    /// Fails when `hash_oid` or `policy` is not an object identifier.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let req = TimeStampReq {
            version: TspVersion::V1,
            // the hash algorithm without parameters, as Bouncy Castle (NCALayer's library)
            // writes it
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifier {
                    oid: oid(&self.hash_oid)?,
                    parameters: None,
                },
                hashed_message: OctetString::new(self.hash.clone()).map_err(asn1)?,
            },
            req_policy: self.policy.as_deref().map(oid).transpose()?,
            nonce: self.nonce.as_deref().map(positive).transpose()?,
            cert_req: self.cert_req,
            extensions: None,
        };
        req.to_der().map_err(asn1)
    }

    pub fn parse(data: &[u8]) -> Result<Request> {
        let r = TimeStampReq::from_der(data).map_err(asn1)?;
        Ok(Request {
            hash_oid: r.message_imprint.hash_algorithm.oid.to_string(),
            hash: r.message_imprint.hashed_message.as_bytes().to_vec(),
            policy: r.req_policy.map(|p| p.to_string()),
            nonce: r.nonce.map(|n| strip_zeros(n.as_bytes()).to_vec()),
            cert_req: r.cert_req,
        })
    }
}

/// The checked token (a ContentInfo, as encoded) in the TSA's answer `resp` to `req`.
pub fn read_answer(req: &Request, resp: &[u8]) -> Result<Vec<u8>> {
    let token = read_response(resp)?;
    validate(req, &token).map_err(|e| Error::TimestampMismatch(Box::new(e)))?;
    Ok(token)
}

/// The certificate that signed a timestamp token, when the token carries it.
pub fn token_cert(token: &[u8]) -> Option<Cert> {
    let sd = SignedData::parse_inner(token).ok()?;
    sd.signers.first().and_then(|s| sd.signer_cert(s))
}

/// The token (a ContentInfo, DER) from a TimeStampResp.
pub fn read_response(resp: &[u8]) -> Result<Vec<u8>> {
    let bad = |e: ::der::Error| Error::TimestampUnreadable(format!("{e}"));
    let r = TimeStampResp::from_der(resp)
        .or_else(|_| TimeStampResp::from_ber(resp))
        .map_err(bad)?;
    match (r.status.status, r.time_stamp_token) {
        (PkiStatus::Accepted | PkiStatus::GrantedWithMods, Some(tok)) => tok.to_der().map_err(bad),
        _ => {
            let text = r
                .status
                .status_string
                .as_ref()
                .and_then(|t| t.first())
                .map(|t| t.as_str().to_string());
            Err(Error::TimestampRefused(text))
        }
    }
}

/// Whether `token` answers `req`: nonce, policy, hash and (when asked for) certificate.
pub fn validate(req: &Request, token: &[u8]) -> Result<()> {
    let sd = SignedData::parse_inner(token)?;
    let info = TstInfo::parse(sd.content.as_deref().ok_or(Error::NoContent)?)?;
    let strip = |n: &Option<Vec<u8>>| {
        n.as_deref()
            .map(|b| b[b.iter().position(|&x| x != 0).unwrap_or(b.len())..].to_vec())
    };
    if req.nonce.is_some() && strip(&info.nonce) != strip(&req.nonce) {
        return Err(Error::WrongNonce);
    }
    if let Some(p) = &req.policy
        && *p != info.policy
    {
        return Err(Error::WrongPolicy);
    }
    if info.imprint_alg != req.hash_oid || info.imprint != req.hash {
        return Err(Error::WrongImprint);
    }
    if req.cert_req && sd.signers.first().and_then(|s| sd.signer_cert(s)).is_none() {
        return Err(Error::NoTsaCertificate);
    }
    Ok(())
}

/// What a timestamp token says and whether it holds (see [`check_token`]).
pub struct TokenCheck {
    /// When the TSA says the stamped bytes existed.
    pub gen_time: i64,
    /// The TSA's certificate, when the token carries it.
    pub tsa_cert: Option<Cert>,
    /// The token covers the stamped bytes.
    pub imprint_ok: bool,
    /// The TSA's signature holds and names its certificate.
    pub signature_ok: bool,
    /// The TSA certificate's path to a trusted CA, at `gen_time`.
    pub chain: Option<Chain>,
    /// The TSA's certificate is issued for timestamping.
    pub purpose_ok: bool,
}

impl TokenCheck {
    /// The token holds: it covers the stamped bytes and its signature is valid.
    pub fn ok(&self) -> bool {
        self.imprint_ok && self.signature_ok
    }

    /// The TSA is trusted: its certificate leads to a trusted CA and is for timestamping.
    pub fn trusted(&self) -> bool {
        self.purpose_ok && self.chain.as_ref().is_some_and(|c| c.ok)
    }

    /// The CA that certified a trusted TSA.
    pub fn tsa_ca(&self) -> Option<&Cert> {
        self.chain
            .as_ref()
            .filter(|_| self.trusted())
            .and_then(|c| c.issuer.as_ref())
    }
}

/// Checks a timestamp token (a ContentInfo) over `stamped` (for CAdES-T, the signature value).
/// An error: the token can't be read or is not a timestamp token.
pub fn check_token(stamped: &[u8], token: &[u8], trust: &TrustStore) -> Result<TokenCheck> {
    let sd = SignedData::parse_inner(token)?;
    if sd.signers.len() != 1 {
        return Err(Error::MultipleSigners);
    }
    if sd.content_type != TST_INFO {
        return Err(Error::NotTstInfo);
    }
    let tsi = &sd.signers[0];
    if tsi.signed_attr(ATTR_SIGNING_CERT).is_none()
        && tsi.signed_attr(ATTR_SIGNING_CERT_V2).is_none()
    {
        return Err(Error::NoSigningCertAttr);
    }
    let content = sd.content.clone().ok_or(Error::NoContent)?;
    let info = TstInfo::parse(&content)?;
    let tsa_cert: Option<Cert> = sd.signer_cert(tsi);
    let imprint_ok = gost::hash(&info.imprint_alg, stamped).is_ok_and(|h| h == info.imprint);
    let signature_ok = tsa_cert.as_ref().is_some_and(|c| {
        matches!(
            verify::check_signer(tsi, c, &content, TST_INFO),
            Ok(Outcome::Valid)
        ) && verify::signing_certificate_matches(tsi, c).unwrap_or(false)
    });
    let chain = tsa_cert.as_ref().map(|c| trust.check(c, info.gen_time));
    let purpose_ok = tsa_cert
        .as_ref()
        .is_some_and(|c| c.has_eku(cert::EKU_TIME_STAMPING));
    Ok(TokenCheck {
        gen_time: info.gen_time,
        tsa_cert,
        imprint_ok,
        signature_ok,
        chain,
        purpose_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(case: &str, n: &str) -> Vec<u8> {
        crate::testing::fixture(&format!("nca-live/{case}/{n}"))
    }

    /// A TSA's answer is only taken when it answers this request: its nonce, policy, hash and
    /// certificate.
    #[test]
    fn answers_must_match_the_request() {
        let case = "sha256-policy-6.2";
        let resp = live(case, "tsr.der");
        let token = &read_response(&resp).unwrap()[..];
        let req = || Request::parse(&live(case, "tsq.der")).unwrap();
        assert!(req().cert_req && req().nonce.is_some() && req().policy.is_some());
        validate(&req(), token).unwrap();

        // the nonce compares as a number: a leading zero byte does not matter
        let mut r = req();
        r.nonce.as_mut().unwrap().insert(0, 0);
        validate(&r, token).unwrap();
        let mut r = req();
        *r.nonce.as_mut().unwrap().last_mut().unwrap() ^= 1;
        let e = validate(&r, token).unwrap_err();
        assert_eq!(e, Error::WrongNonce);
        // no nonce asked: none checked
        let mut r = req();
        r.nonce = None;
        validate(&r, token).unwrap();

        let mut r = req();
        r.policy = Some("1.2.398.3.3.2.6.4".into());
        let e = validate(&r, token).unwrap_err();
        assert_eq!(e, Error::WrongPolicy);
        let mut r = req();
        r.policy = None;
        validate(&r, token).unwrap();

        let mut r = req();
        r.hash[0] ^= 1;
        let e = validate(&r, token).unwrap_err();
        assert_eq!(e, Error::WrongImprint);
        let mut r = req();
        r.hash_oid = gost::H_SHA1.into();
        let e = validate(&r, token).unwrap_err();
        assert_eq!(e, Error::WrongImprint);

        // a token without the TSA's certificate, when the request asked for it
        let mut sd = SignedData::parse_inner(token).unwrap();
        sd.certs.clear();
        let bare = sd.encode().unwrap();
        let e = validate(&req(), &bare).unwrap_err();
        assert_eq!(e, Error::NoTsaCertificate);
        let mut r = req();
        r.cert_req = false;
        validate(&r, &bare).unwrap();
    }

    #[test]
    fn requests_and_responses() {
        let r = Request {
            hash_oid: gost::H_SHA256.into(),
            hash: vec![7; 32],
            policy: Some("1.2.398.3.3.2.6.2".into()),
            nonce: Some(vec![0x41, 2, 3]),
            cert_req: true,
        };
        let back = Request::parse(&r.encode().unwrap()).unwrap();
        assert_eq!(back.hash_oid, r.hash_oid);
        assert_eq!(back.hash, r.hash);
        assert_eq!(back.policy, r.policy);
        assert_eq!(back.nonce, r.nonce);
        assert!(back.cert_req);
        let r = Request {
            cert_req: false,
            policy: None,
            nonce: None,
            ..r
        };
        let back = Request::parse(&r.encode().unwrap()).unwrap();
        assert!(!back.cert_req && back.policy.is_none() && back.nonce.is_none());

        // granted (0) and granted with modifications (1) give the token; anything else is a
        // refusal, even with a token
        let token = ::cms::content_info::ContentInfo {
            content_type: oid(crate::cms::SIGNED_DATA).unwrap(),
            content: ::der::asn1::Any::null(),
        };
        let resp = |status, token: Option<_>| {
            TimeStampResp {
                status: x509_tsp::cmpv2::status::PkiStatusInfo {
                    status,
                    status_string: None,
                    fail_info: None,
                },
                time_stamp_token: token,
            }
            .to_der()
            .unwrap()
        };
        for (code, ok) in [
            (PkiStatus::Accepted, true),
            (PkiStatus::GrantedWithMods, true),
            (PkiStatus::Rejection, false),
            (PkiStatus::RevocationNotification, false),
        ] {
            let r = resp(code, Some(token.clone()));
            assert_eq!(read_response(&r).is_ok(), ok, "status {code:?}");
        }
        assert!(read_response(&resp(PkiStatus::Accepted, None)).is_err());
    }

    #[test]
    fn tst_info_fields() {
        /// TSTInfo's required fields, and a nonce.
        #[derive(::der::Sequence)]
        struct Body {
            version: u8,
            policy: ::der::asn1::ObjectIdentifier,
            imprint: MessageImprint,
            serial: u8,
            gen_time: ::der::asn1::Any,
            #[asn1(optional = "true")]
            nonce: Option<::der::asn1::Int>,
        }
        let body = |nonce: bool| {
            Body {
                version: 1,
                policy: oid("1.2.398.3.3.2.6.2").unwrap(),
                imprint: MessageImprint {
                    hash_algorithm: AlgorithmIdentifier {
                        oid: oid(gost::H_SHA256).unwrap(),
                        parameters: None,
                    },
                    hashed_message: OctetString::new([9; 32]).unwrap(),
                },
                serial: 77,
                gen_time: crate::asn1::any(
                    &crate::time::encode_generalized(1_700_000_000_000).unwrap(),
                )
                .unwrap(),
                nonce: nonce.then(|| positive(&[0x42, 1]).unwrap()),
            }
            .to_der()
            .unwrap()
        };
        // the five required fields are enough
        let t = TstInfo::parse(&body(false)).unwrap();
        assert_eq!(t.policy, "1.2.398.3.3.2.6.2");
        assert_eq!(t.imprint_alg, gost::H_SHA256);
        assert_eq!(t.imprint, vec![9; 32]);
        assert_eq!(t.gen_time, 1_700_000_000_000);
        assert!(t.nonce.is_none());
        assert_eq!(
            TstInfo::parse(&body(true)).unwrap().nonce,
            Some(vec![0x42, 1])
        );
        // SEQUENCE { 1, 1.2.3 }
        let short = [0x30, 7, 2, 1, 1, 6, 2, 0x2a, 3];
        assert!(TstInfo::parse(&short).is_err());
    }

    /// The token must cover the stamped bytes and be signed by a trusted TSA.
    #[test]
    fn tokens() {
        let trust = crate::testing::nca();
        let case = "gost2015-policy-6.4";
        let resp = live(case, "tsr.der");
        let token = &read_response(&resp).unwrap()[..];
        let mut data = live(case, "data.bin");
        let c = check_token(&data, token, &trust).unwrap();
        assert!(c.ok() && c.trusted() && c.tsa_ca().is_some());
        assert!(c.tsa_cert.is_some() && c.gen_time > 0);
        data[0] ^= 1;
        let c = check_token(&data, token, &trust).unwrap();
        assert!(!c.imprint_ok && c.signature_ok && !c.ok());
        // the TSA's signature broken
        let mut sd = SignedData::parse_inner(token).unwrap();
        sd.signers[0].signature[5] ^= 1;
        let c = check_token(&live(case, "data.bin"), &sd.encode().unwrap(), &trust).unwrap();
        assert!(c.imprint_ok && !c.signature_ok && !c.ok());
        // a TSA nobody trusts
        let c = check_token(&live(case, "data.bin"), token, &TrustStore::new(vec![])).unwrap();
        assert!(c.ok() && !c.trusted() && c.tsa_ca().is_none());
        // requests made here
        let r = Request::new(gost::H_SHA256, &[1; 32], "1.2.3", &[0xff, 0]).unwrap();
        assert_eq!(r.nonce, Some(vec![0x7f, 0]));
        assert!(r.cert_req);
        let r = Request::new(gost::H_SHA256, &[1; 32], "1.2.3", &[0x00, 0]).unwrap();
        assert_eq!(r.nonce, Some(vec![0x40, 0]));
        // object identifiers from outside are checked, never a panic
        for bad in [
            "",
            "1",
            "1.",
            "x.2",
            "3.1",
            "1.40",
            "+1.2",
            "1.2.99999999999999999999",
        ] {
            let e = Request::new(bad, &[1; 32], "1.2.3", &[1]).unwrap_err();
            assert_eq!(e.kind(), crate::ErrorKind::Malformed, "{bad}");
            assert!(
                Request::new(gost::H_SHA256, &[1; 32], bad, &[1]).is_err(),
                "{bad}"
            );
        }
        let mut r = Request::new(gost::H_SHA256, &[1; 32], "1.2.3", &[1]).unwrap();
        r.policy = Some("nonsense".into());
        assert!(r.encode().is_err());
    }
}
