//! Timestamps from NCA's TSA: [`kzcrypto::tsp`] makes and checks the messages; this module
//! sends the requests and records what a token says in a signer's report.

pub use kzcrypto::tsp::*;
pub use kzcrypto_nca::tsp::*;

use crate::Result;
use crate::cert::Cert;
use crate::cms::{self, SignedData, SignerInfo};
use crate::env::Env;
use crate::gost::{self, Scheme};
use crate::i18n::{tr, trf};
use crate::report::SignerReport;

pub const DEFAULT_TSA_URL: &str = "http://tsp.pki.gov.kz:80";

/// Adds a timestamp from the TSA at `url` to the single signer of `d`.
pub fn stamp(d: &mut SignedData, url: &str, scheme: Option<Scheme>, env: &Env) -> Result<()> {
    let si = &mut d.signers[0];
    let (hash_oid, policy) = hash_and_policy(scheme);
    let token = request(
        url,
        hash_oid,
        &gost::hash(hash_oid, &si.signature)?,
        policy,
        env,
    )?;
    si.add_unsigned(cms::ATTR_TIMESTAMP_TOKEN, &token)?;
    Ok(())
}

/// A checked timestamp token (ContentInfo) from the TSA at `url` over `hash` (made with
/// `hash_oid`), under `policy`.
pub fn request(url: &str, hash_oid: &str, hash: &[u8], policy: &str, env: &Env) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 8];
    crate::random(&mut nonce)?;
    let req = Request::new(hash_oid, hash, policy, &nonce)?;
    let resp = env
        .net
        .post(crate::Server::Timestamp, url, CONTENT_TYPE, &req.encode()?)?;
    Ok(read_answer(&req, &resp)?)
}

/// Checks the signature timestamp of `si`, if any, and records it in `sr`. Returns the CA
/// certificate that issued a trusted TSA's certificate, for [`same_ca`].
pub fn check(sr: &mut SignerReport, si: &SignerInfo, env: &Env) -> Option<Cert> {
    let value = si
        .unsigned()
        .into_iter()
        .find(|(o, _)| o == cms::ATTR_TIMESTAMP_TOKEN)
        .and_then(|(_, v)| v.into_iter().next())?;
    match check_token(sr, &si.signature, &value, env) {
        Ok(ca) => ca,
        Err(e) => {
            sr.timestamp_ok = Some(false);
            sr.timestamp_info = Some(trf("unreadable timestamp: {}", &[&e]));
            None
        }
    }
}

/// Order 500/НҚ p.17.2: the TSA's certificate should come from the signer's CA. Adds a warning
/// to `sr` when `tsa_ca` (from [`check`]) and `signer_ca` (the signer's verified issuer)
/// differ. NCA RK's own CA certificates (GOST, RSA, every generation) count as one CA.
pub fn same_ca(sr: &mut SignerReport, tsa_ca: &Cert, signer_ca: &Cert) {
    use crate::trust::is_nca;
    if tsa_ca == signer_ca || (is_nca(tsa_ca) && is_nca(signer_ca)) {
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
    env: &Env,
) -> Result<Option<Cert>> {
    let trust = &env.trust;
    let c = kzcrypto::tsp::check_token(stamped, token, trust)?;
    sr.timestamp_time = Some(c.gen_time);
    sr.timestamp_info = Some(
        c.tsa_cert
            .as_ref()
            .map(Cert::cn)
            .unwrap_or_else(|| tr("unknown TSA").into()),
    );
    sr.timestamp_ok = Some(c.ok());
    let Some(chain) = &c.chain else {
        return Ok(None);
    };
    sr.timestamp_trusted = Some(c.trusted());
    let tsa = sr.timestamp_info.clone().unwrap_or_default();
    if !chain.ok {
        sr.warnings.push(trf(
            "The timestamp authority '{}' is not a trusted NCA RK TSA.",
            &[&tsa],
        ));
    } else if !c.purpose_ok {
        sr.warnings.push(
            tr("The timestamp authority's certificate is not issued for timestamping.").into(),
        );
    }
    Ok(c.tsa_ca().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;

    /// Real exchanges with NCA's TSA (tests/fixtures/nca-live, captured 2026-11-01).
    #[test]
    fn real_nca_timestamps() {
        let env = Env::new(crate::trust::trust_store(vec![]));
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
            let token = &read_response(&resp).unwrap()[..];
            kzcrypto::tsp::validate(&req, token).unwrap_or_else(|e| panic!("{case}: {e}"));
            let mut sr = SignerReport::default();
            check_token(&mut sr, &f("data.bin"), token, &env).unwrap();
            assert_eq!(sr.timestamp_ok, Some(true), "{case}: token signature");
            assert_eq!(sr.timestamp_trusted, Some(true), "{case}: TSA trusted");
            assert!(sr.warnings.is_empty(), "{case}: {:?}", sr.warnings);
            println!("{case}: {:?} {:?}", sr.timestamp_info, sr.timestamp_time);

            // p.17.2: a signer certified by NCA RK (any of its CA certificates) is fine; one
            // from another CA gets a warning
            let tsa_ca = check_token(&mut sr, &f("data.bin"), token, &env)
                .unwrap()
                .unwrap();
            for (signer_ca, warns) in [
                (tsa_ca.clone(), false),
                (nca("nca_gost_2022"), false),
                (nca("nca_rsa"), false),
                (other.clone(), true),
            ] {
                let mut sr = SignerReport::default();
                same_ca(&mut sr, &tsa_ca, &signer_ca);
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
        assert!(
            e.to_string().contains("Missing certificate or key error"),
            "{e}"
        );
    }

    fn live(case: &str, n: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/nca-live/{case}/{n}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// The token must cover the stamped bytes and be signed by its TSA.
    #[test]
    fn tokens_over_other_data() {
        let env = Env::new(crate::trust::trust_store(vec![]));
        let case = "gost2015-policy-6.4";
        let resp = live(case, "tsr.der");
        let token = &read_response(&resp).unwrap()[..];
        let mut data = live(case, "data.bin");
        let mut sr = SignerReport::default();
        check_token(&mut sr, &data, token, &env).unwrap();
        assert_eq!(sr.timestamp_ok, Some(true));
        data[0] ^= 1;
        let mut sr = SignerReport::default();
        check_token(&mut sr, &data, token, &env).unwrap();
        assert_eq!(sr.timestamp_ok, Some(false));
        // the TSA's signature broken
        let mut sd = SignedData::parse_inner(token).unwrap();
        sd.signers[0].signature[5] ^= 1;
        let mut sr = SignerReport::default();
        check_token(
            &mut sr,
            &live(case, "data.bin"),
            &sd.encode().unwrap(),
            &env,
        )
        .unwrap();
        assert_eq!(sr.timestamp_ok, Some(false));
    }
}
