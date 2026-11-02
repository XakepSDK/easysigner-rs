//! CAdES-T signature timestamps: requesting them from a TSA and checking them.

use crate::cert::{self, Cert};
use crate::cms::{self, SignedData, SignerInfo};
use crate::der::{self, Tlv};
use crate::gost::{self, Scheme};
use crate::i18n::{tr, trf};
use crate::keys::alg_id;
use crate::report::SignerReport;
use crate::trust::TrustStore;
use crate::verify::{self, Outcome};
use crate::{Error, Result, http};

pub const DEFAULT_TSA_URL: &str = "http://tsp.pki.gov.kz:80";
pub const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

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
pub struct Request {
    pub hash_oid: String,
    pub hash: Vec<u8>,
    pub policy: Option<String>,
    pub nonce: Option<Vec<u8>>,
    pub cert_req: bool,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
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
        der::tlv(der::SEQUENCE, &b)
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
fn hash_and_policy(scheme: Option<Scheme>) -> (&'static str, &'static str) {
    match scheme {
        None => (gost::H_SHA256, "1.2.398.3.3.2.6.2"),
        Some(s) if s.key_oid == gost::KEY_GOST2004 => (gost::H_GOST34311, "1.2.398.3.3.2.6.1"),
        Some(_) => (gost::H_GOST2015_512, "1.2.398.3.3.2.6.4"),
    }
}

/// Adds a timestamp from the TSA at `url` to the single signer of `d`.
pub fn stamp(d: &mut SignedData, url: &str, scheme: Option<Scheme>) -> Result<()> {
    let si = &mut d.signers[0];
    let (hash_oid, policy) = hash_and_policy(scheme);
    let mut nonce = [0u8; 8];
    crate::random(&mut nonce)?;
    // a positive INTEGER with no leading zero byte, so it reads back exactly as sent
    nonce[0] = (nonce[0] & 0x7f) | 0x40;
    let req = Request {
        hash_oid: hash_oid.into(),
        hash: gost::hash(hash_oid, &si.signature)?,
        policy: Some(policy.into()),
        nonce: Some(nonce.to_vec()),
        cert_req: true,
    };
    let resp = http::post(
        url,
        "application/timestamp-query",
        &req.encode(),
        "timestamp server",
    )?;
    let token = read_response(&resp)?;
    validate(&req, token).map_err(|e| {
        Error::new(trf(
            "The timestamp server's answer does not match the request: {}",
            &[&e.0],
        ))
    })?;
    si.add_unsigned(cms::ATTR_TIMESTAMP_TOKEN, token);
    Ok(())
}

/// The token (a ContentInfo, as encoded) from a TimeStampResp.
fn read_response(resp: &[u8]) -> Result<&[u8]> {
    let bad = |e: Error| {
        Error::new(trf(
            "The timestamp server's answer is unreadable ({})",
            &[&e.0],
        ))
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

fn validate(req: &Request, token: &[u8]) -> Result<()> {
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

/// Checks the signature timestamp of `si`, if any, and records it in `sr`. Returns the CA
/// certificate that issued a trusted TSA's certificate, for [`same_ca`].
pub fn check(sr: &mut SignerReport, si: &SignerInfo, trust: &TrustStore) -> Option<Cert> {
    let value = si
        .unsigned()
        .into_iter()
        .find(|(o, _)| o == cms::ATTR_TIMESTAMP_TOKEN)
        .and_then(|(_, v)| v.into_iter().next())?;
    match check_token(sr, &si.signature, &value, trust) {
        Ok(ca) => ca,
        Err(e) => {
            sr.timestamp_ok = Some(false);
            sr.timestamp_info = Some(trf("unreadable timestamp: {}", &[&e.0]));
            None
        }
    }
}

/// Order 500/НҚ p.17.2: the TSA's certificate should come from the signer's CA. Adds a warning
/// to `sr` when `tsa_ca` (from [`check`]) and `signer_ca` (the signer's verified issuer)
/// differ. NCA RK's own CA certificates (GOST, RSA, every generation) count as one CA.
pub fn same_ca(sr: &mut SignerReport, tsa_ca: &Cert, signer_ca: &Cert, trust: &TrustStore) {
    if tsa_ca == signer_ca || (trust.is_nca(tsa_ca) && trust.is_nca(signer_ca)) {
        return;
    }
    sr.warnings.push(trf(
        "The timestamp authority '{}' was certified by {}, not by the signer's CA ({}).",
        &[
            &sr.timestamp_info.clone().unwrap_or_default(),
            &tsa_ca.cn(),
            &signer_ca.cn(),
        ],
    ));
}

/// Checks a timestamp token over `stamped` (for CAdES-T, the signature value) and records the
/// result in `sr`. Returns the CA certificate that issued the TSA's certificate when the TSA is
/// trusted.
pub fn check_token(
    sr: &mut SignerReport,
    stamped: &[u8],
    token: &[u8],
    trust: &TrustStore,
) -> Result<Option<Cert>> {
    let sd = SignedData::parse_inner(token)?;
    if sd.signers.len() != 1 {
        return Err(Error::new("time-stamp token signed by multiple signers."));
    }
    if sd.content_type != TST_INFO {
        return Err(Error::new("ContentInfo object not for a time stamp."));
    }
    let tsi = &sd.signers[0];
    if tsi.signed_attr(cms::ATTR_SIGNING_CERT).is_none()
        && tsi.signed_attr(cms::ATTR_SIGNING_CERT_V2).is_none()
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
    sr.timestamp_time = Some(info.gen_time);
    let tsa_cert: Option<Cert> = sd.signer_cert(tsi);
    sr.timestamp_info = Some(
        tsa_cert
            .as_ref()
            .map(Cert::cn)
            .unwrap_or_else(|| tr("unknown TSA").into()),
    );
    let imprint_ok = gost::hash(&info.imprint_alg, stamped).is_ok_and(|h| h == info.imprint);
    let sig_ok = tsa_cert.as_ref().is_some_and(|c| {
        matches!(
            verify::check_signer(tsi, c, &content, TST_INFO),
            Ok(Outcome::Valid)
        ) && verify::signing_certificate_matches(tsi, c).unwrap_or(false)
    });
    sr.timestamp_ok = Some(imprint_ok && sig_ok);
    let Some(tsa_cert) = tsa_cert else {
        return Ok(None);
    };
    let chain = trust.check(&tsa_cert, info.gen_time);
    let purpose_ok = tsa_cert.has_eku(cert::EKU_TIME_STAMPING);
    sr.timestamp_trusted = Some(chain.ok && purpose_ok);
    let tsa = sr.timestamp_info.clone().unwrap_or_default();
    if !chain.ok {
        sr.warnings.push(trf(
            "The timestamp authority '{}' is not a trusted NCA RK TSA.",
            &[&tsa],
        ));
    } else if !purpose_ok {
        sr.warnings.push(
            tr("The timestamp authority's certificate is not issued for timestamping.").into(),
        );
    }
    Ok(chain.issuer.filter(|_| chain.ok && purpose_ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real exchanges with NCA's TSA (tests/fixtures/nca-live, captured 2026-11-01).
    #[test]
    fn real_nca_timestamps() {
        let trust = TrustStore::new(vec![]);
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/nca-live");
        let nca = |n: &str| {
            let (_, d) = crate::trust::BUNDLED_CA
                .iter()
                .find(|(x, _)| *x == n)
                .unwrap();
            Cert::parse_any(d).unwrap()
        };
        let other =
            Cert::parse_any(&std::fs::read(format!("{dir}/../ocsp/ca.cer")).unwrap()).unwrap();
        for case in ["sha256-policy-6.2", "gost2015-policy-6.4"] {
            let f = |n: &str| std::fs::read(format!("{dir}/{case}/{n}")).unwrap();
            let req = Request::parse(&f("tsq.der")).unwrap();
            let resp = f("tsr.der");
            let token = read_response(&resp).unwrap();
            validate(&req, token).unwrap_or_else(|e| panic!("{case}: {e}"));
            let mut sr = SignerReport::default();
            check_token(&mut sr, &f("data.bin"), token, &trust).unwrap();
            assert_eq!(sr.timestamp_ok, Some(true), "{case}: token signature");
            assert_eq!(sr.timestamp_trusted, Some(true), "{case}: TSA trusted");
            assert!(sr.warnings.is_empty(), "{case}: {:?}", sr.warnings);
            println!("{case}: {:?} {:?}", sr.timestamp_info, sr.timestamp_time);

            // p.17.2: a signer certified by NCA RK (any of its CA certificates) is fine; one
            // from another CA gets a warning
            let tsa_ca = check_token(&mut sr, &f("data.bin"), token, &trust)
                .unwrap()
                .unwrap();
            for (signer_ca, warns) in [
                (tsa_ca.clone(), false),
                (nca("nca_gost_2022"), false),
                (nca("nca_rsa"), false),
                (other.clone(), true),
            ] {
                let mut sr = SignerReport::default();
                same_ca(&mut sr, &tsa_ca, &signer_ca, &trust);
                assert_eq!(
                    sr.warnings.len(),
                    usize::from(warns),
                    "{case}: {:?}",
                    sr.warnings
                );
            }
        }
        let rejected = std::fs::read(format!("{dir}/rejected-policy-6.1/tsr.der")).unwrap();
        let e = read_response(&rejected).unwrap_err();
        assert!(e.0.contains("Missing certificate or key error"), "{e}");
    }
}
