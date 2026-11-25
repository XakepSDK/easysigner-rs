//! Timestamps (RFC 3161) from NCA's TSA: requests, checking the answer against the request,
//! and checking a timestamp token over stamped bytes. The caller sends the request.

use crate::cert::{self, Cert};
use crate::cms::{ATTR_SIGNING_CERT, ATTR_SIGNING_CERT_V2, SignedData};
use crate::der::{self, Tlv};
use crate::gost::{self, Scheme};
use crate::keys::alg_id;
use crate::prelude::*;
use crate::text::trf;
use crate::trust::{Chain, TrustStore};
use crate::verify::{self, Outcome};
use crate::{Error, ErrorKind, Result};

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
    pub fn parse(data: &[u8]) -> Result<TstInfo> {
        let k = der::parse(data)?.items(der::SEQUENCE)?;
        if k.len() < 5 {
            return Err(Error::new("TSTInfo too short"));
        }
        let mi = k[2].items(der::SEQUENCE)?;
        let nonce = k[5..]
            .iter()
            .find(|t| t.tag == der::INTEGER)
            .map(|t| t.uint().map(<[u8]>::to_vec))
            .transpose()?;
        Ok(TstInfo {
            policy: k[1].oid()?,
            imprint_alg: alg_id(&mi[0])?.0,
            imprint: mi[1].octets()?,
            gen_time: k[4].time()?,
            nonce,
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
        der::check_oid(hash_oid)?;
        der::check_oid(policy)?;
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
        der::check_oid(&self.hash_oid)?;
        if let Some(p) = &self.policy {
            der::check_oid(p)?;
        }
        let mut b = der::small_int(1);
        // the hash algorithm without parameters, as Bouncy Castle (NCALayer's library) writes it
        b.extend(der::seq(&[
            &der::seq(&[&der::oid(&self.hash_oid)]),
            &der::octets(&self.hash),
        ]));
        if let Some(p) = &self.policy {
            b.extend(der::oid(p));
        }
        if let Some(n) = &self.nonce {
            b.extend(der::uint(n));
        }
        if self.cert_req {
            b.extend(der::boolean(true));
        }
        Ok(der::tlv(der::SEQUENCE, &b))
    }

    pub fn parse(data: &[u8]) -> Result<Request> {
        let k = der::parse(data)?.items(der::SEQUENCE)?;
        let mi = k
            .get(1)
            .ok_or_else(|| Error::new("bad timestamp request"))?
            .items(der::SEQUENCE)?;
        let mut r = Request {
            hash_oid: alg_id(&mi[0])?.0,
            hash: mi[1].octets()?,
            policy: None,
            nonce: None,
            cert_req: false,
        };
        for t in &k[2..] {
            match t.tag {
                der::OID => r.policy = Some(t.oid()?),
                der::INTEGER => r.nonce = Some(t.uint()?.to_vec()),
                der::BOOLEAN => r.cert_req = t.boolean()?,
                _ => {}
            }
        }
        Ok(r)
    }
}

/// The hash and NCA TSA policy NCALayer uses for each key type.
pub fn hash_and_policy(scheme: Option<Scheme>) -> (&'static str, &'static str) {
    hash_and_policy_for(scheme.map_or("", |s| s.key_oid))
}

/// The hash and NCA TSA policy for timestamps over the work of a key of type `key_alg` (a
/// certificate's key algorithm), as [`hash_and_policy`] picks them for a signing key.
pub fn hash_and_policy_for(key_alg: &str) -> (&'static str, &'static str) {
    if key_alg == gost::KEY_GOST2004 {
        (gost::H_GOST34311, "1.2.398.3.3.2.6.1")
    } else if gost::is_gost(key_alg) {
        (gost::H_GOST2015_512, "1.2.398.3.3.2.6.4")
    } else {
        (gost::H_SHA256, "1.2.398.3.3.2.6.2")
    }
}

/// The checked token (a ContentInfo, as encoded) in the TSA's answer `resp` to `req`.
pub fn read_answer(req: &Request, resp: &[u8]) -> Result<Vec<u8>> {
    let token = read_response(resp)?;
    validate(req, token).map_err(|e| {
        Error::new(trf(
            "The timestamp server's answer does not match the request: {}",
            &[&e],
        ))
    })?;
    Ok(token.to_vec())
}

/// The certificate that signed a timestamp token, when the token carries it.
pub fn token_cert(token: &[u8]) -> Option<Cert> {
    let sd = SignedData::parse_inner(token).ok()?;
    sd.signers.first().and_then(|s| sd.signer_cert(s))
}

/// The token (a ContentInfo, as encoded) from a TimeStampResp.
pub fn read_response(resp: &[u8]) -> Result<&[u8]> {
    let bad = |e: Error| {
        Error::of(
            ErrorKind::Malformed,
            trf("The timestamp server's answer is unreadable ({})", &[&e]),
        )
    };
    let k = der::parse(resp)
        .and_then(|t| t.items(der::SEQUENCE))
        .map_err(bad)?;
    let status = k
        .first()
        .ok_or_else(|| bad(Error::new("empty")))?
        .items(der::SEQUENCE)
        .map_err(bad)?;
    let code = status
        .first()
        .map(|s| s.small_int())
        .transpose()
        .map_err(bad)?
        .unwrap_or(2);
    match k.get(1) {
        Some(tok) if code == 0 || code == 1 => Ok(tok.raw),
        _ => {
            let text = status
                .get(1)
                .filter(|t| t.tag == der::SEQUENCE)
                .and_then(|t| t.children().ok())
                .and_then(|c| c.first().and_then(Tlv::text));
            Err(Error::new(trf(
                "The timestamp server refused the request{}",
                &[&text.map(|t| format!(": {t}")).unwrap_or_default()],
            )))
        }
    }
}

/// Whether `token` answers `req`: nonce, policy, hash and (when asked for) certificate.
pub fn validate(req: &Request, token: &[u8]) -> Result<()> {
    let sd = SignedData::parse_inner(token)?;
    let info = TstInfo::parse(
        sd.content
            .as_deref()
            .ok_or_else(|| Error::new("token without TSTInfo"))?,
    )?;
    let strip = |n: &Option<Vec<u8>>| {
        n.as_deref()
            .map(|b| b[b.iter().position(|&x| x != 0).unwrap_or(b.len())..].to_vec())
    };
    if req.nonce.is_some() && strip(&info.nonce) != strip(&req.nonce) {
        return Err(Error::new("response contains wrong nonce value."));
    }
    if let Some(p) = &req.policy
        && *p != info.policy
    {
        return Err(Error::new("TSA policy wrong for request."));
    }
    if info.imprint_alg != req.hash_oid || info.imprint != req.hash {
        return Err(Error::new("response for different message imprint digest."));
    }
    if req.cert_req && sd.signers.first().and_then(|s| sd.signer_cert(s)).is_none() {
        return Err(Error::new(
            "Certificate requested but not present in response.",
        ));
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
        return Err(Error::new("time-stamp token signed by multiple signers."));
    }
    if sd.content_type != TST_INFO {
        return Err(Error::new("ContentInfo object not for a time stamp."));
    }
    let tsi = &sd.signers[0];
    if tsi.signed_attr(ATTR_SIGNING_CERT).is_none()
        && tsi.signed_attr(ATTR_SIGNING_CERT_V2).is_none()
    {
        return Err(Error::new(
            "no signing certificate attribute found, time stamp invalid.",
        ));
    }
    let content = sd
        .content
        .clone()
        .ok_or_else(|| Error::new("time stamp without TSTInfo"))?;
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
        let token = read_response(&resp).unwrap();
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
        assert!(e.to_string().contains("nonce"), "{e}");
        // no nonce asked: none checked
        let mut r = req();
        r.nonce = None;
        validate(&r, token).unwrap();

        let mut r = req();
        r.policy = Some("1.2.398.3.3.2.6.4".into());
        let e = validate(&r, token).unwrap_err();
        assert!(e.to_string().contains("policy"), "{e}");
        let mut r = req();
        r.policy = None;
        validate(&r, token).unwrap();

        let mut r = req();
        r.hash[0] ^= 1;
        let e = validate(&r, token).unwrap_err();
        assert!(e.to_string().contains("imprint"), "{e}");
        let mut r = req();
        r.hash_oid = gost::H_SHA1.into();
        let e = validate(&r, token).unwrap_err();
        assert!(e.to_string().contains("imprint"), "{e}");

        // a token without the TSA's certificate, when the request asked for it
        let mut sd = SignedData::parse_inner(token).unwrap();
        sd.certs.clear();
        let bare = sd.encode();
        let e = validate(&req(), &bare).unwrap_err();
        assert!(e.to_string().contains("Certificate requested"), "{e}");
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
        let token = der::seq(&[&der::small_int(5)]);
        for (code, ok) in [(0, true), (1, true), (2, false), (5, false)] {
            let resp = der::seq(&[&der::seq(&[&der::small_int(code)]), &token]);
            assert_eq!(read_response(&resp).is_ok(), ok, "status {code}");
        }
        let resp = der::seq(&[&der::seq(&[&der::small_int(0)])]);
        assert!(read_response(&resp).is_err());

        assert_eq!(
            hash_and_policy_for(gost::KEY_GOST2004),
            (gost::H_GOST34311, "1.2.398.3.3.2.6.1")
        );
        assert_eq!(
            hash_and_policy_for(gost::KEY_GOST2015_512),
            (gost::H_GOST2015_512, "1.2.398.3.3.2.6.4")
        );
        assert_eq!(
            hash_and_policy_for(gost::RSA_ENCRYPTION),
            (gost::H_SHA256, "1.2.398.3.3.2.6.2")
        );
    }

    #[test]
    fn tst_info_fields() {
        let body = |nonce: bool| {
            let mut b = der::small_int(1);
            b.extend(der::oid("1.2.398.3.3.2.6.2"));
            b.extend(der::seq(&[
                &der::seq(&[&der::oid(gost::H_SHA256)]),
                &der::octets(&[9; 32]),
            ]));
            b.extend(der::small_int(77));
            b.extend(crate::time::encode_generalized(1_700_000_000_000));
            if nonce {
                b.extend(der::uint(&[0x42, 1]));
            }
            der::tlv(der::SEQUENCE, &b)
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
        let short = der::seq(&[&der::small_int(1), &der::oid("1.2.3")]);
        assert!(TstInfo::parse(&short).is_err());
    }

    /// The token must cover the stamped bytes and be signed by a trusted TSA.
    #[test]
    fn tokens() {
        let trust = TrustStore::new(vec![]);
        let case = "gost2015-policy-6.4";
        let resp = live(case, "tsr.der");
        let token = read_response(&resp).unwrap();
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
        let c = check_token(&live(case, "data.bin"), &sd.encode(), &trust).unwrap();
        assert!(c.imprint_ok && !c.signature_ok && !c.ok());
        // a TSA nobody trusts
        let c = check_token(&live(case, "data.bin"), token, &TrustStore::empty()).unwrap();
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
            assert_eq!(e.kind, crate::ErrorKind::Malformed, "{bad}");
            assert!(
                Request::new(gost::H_SHA256, &[1; 32], bad, &[1]).is_err(),
                "{bad}"
            );
        }
        let mut r = Request::new(gost::H_SHA256, &[1; 32], "2.999.1", &[1]).unwrap();
        r.policy = Some("nonsense".into());
        assert!(r.encode().is_err());
    }
}
