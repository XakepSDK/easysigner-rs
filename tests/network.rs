//! The core's network calls (OCSP, timestamps, archive timestamps) against the fake test
//! servers on 127.0.0.1 (tests/common/nca.rs), not NCA's.

#[path = "common/nca.rs"]
mod nca;

use std::path::PathBuf;

use kzsigner::cert::Cert;
use kzsigner::cms::SignedData;
use kzsigner::env::Env;
use kzsigner::trust::TrustStore;
use kzsigner::{gost, ltv, ocsp, p12, tsp};

fn fixture(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(p),
    )
    .unwrap()
}

fn carol() -> (Cert, Cert, Env) {
    let ca = Cert::parse(&fixture("ocsp/ca.cer")).unwrap();
    let carol = p12::open(&fixture("ocsp/carol.p12"), "Qwerty12", None)
        .unwrap()
        .cert;
    (carol, ca.clone(), Env::new(TrustStore::only(vec![ca])))
}

fn tsa() -> Cert {
    p12::open(&fixture("keys/tsa.p12"), "Qwerty12", None)
        .unwrap()
        .cert
}

fn down() -> String {
    nca::serve(|_| None, "application/octet-stream")
}

#[test]
fn ocsp_check() {
    let (c, ca, trust) = carol();
    let (good, status, answer) = ocsp::check(&c, Some(&ca), &nca::fake_ocsp(false), &trust);
    assert!(good, "{status}");
    assert_eq!(answer, "good");
    assert!(status.starts_with("GOOD"), "{status}");

    let (good, status, answer) = ocsp::check(&c, Some(&ca), &nca::fake_ocsp(true), &trust);
    assert!(!good);
    assert_eq!(answer, "revoked");
    assert!(status.starts_with("REVOKED"), "{status}");

    let (good, status, answer) = ocsp::check(&c, None, &nca::fake_ocsp(false), &trust);
    assert!(!good && answer.is_empty());
    assert!(status.starts_with("UNKNOWN"), "{status}");

    let (good, status, answer) = ocsp::check(&c, Some(&ca), &down(), &trust);
    assert!(!good && answer.is_empty());
    assert!(status.starts_with("ERROR"), "{status}");
}

#[test]
fn timestamp_request() {
    let data = b"stamp me";
    let (alg, policy) = tsp::hash_and_policy(None);
    let hash = gost::hash(alg, data).unwrap();
    let env = Env::new(TrustStore::empty());
    let token = tsp::request(&nca::fake_tsa(), alg, &hash, policy, &env).unwrap();
    let check =
        kzsigner::kzcrypto::tsp::check_token(data, &token, &TrustStore::only(vec![tsa()])).unwrap();
    assert!(check.imprint_ok && check.signature_ok && check.trusted());
    assert!(
        kzsigner::kzcrypto::tsp::check_token(b"other data", &token, &TrustStore::empty())
            .map(|c| !c.imprint_ok)
            .unwrap_or(true)
    );

    assert!(tsp::request(&down(), alg, &hash, policy, &env).is_err());
}

/// A revoked answer refuses the certificate; it does not fall back to a revocation list.
#[test]
fn revoked_by_ocsp() {
    let (c, _, trust) = carol();
    let now = kzsigner::time::now_ms();
    let g = ltv::gather(&[(c.clone(), true)], &nca::fake_ocsp(true), &trust, now);
    assert_eq!(g.refused.len(), 1, "{:?}", g.refused);
    assert!(g.warnings.is_empty(), "{:?}", g.warnings);
    assert!(g.kept.ocsps.is_empty());

    let g = ltv::gather(&[(c, true)], &nca::fake_ocsp(false), &trust, now);
    assert!(
        g.refused.is_empty() && g.warnings.is_empty(),
        "{:?}",
        g.warnings
    );
    assert_eq!(g.kept.ocsps.len(), 1);
}

/// A new archive timestamp covers what the signature holds, and checks.
#[test]
fn new_archive_timestamp() {
    let mut sd = SignedData::parse(&fixture("ltv/lta.cms")).unwrap();
    let content = sd.content.clone().unwrap();
    ltv::archive(
        &mut sd,
        0,
        &content,
        &nca::fake_tsa(),
        &ltv::Kept::default(),
        &Env::new(TrustStore::empty()),
    )
    .unwrap();
    let (_, ca, _) = carol();
    let trust = Env::new(TrustStore::only(vec![ca, tsa()]));
    let sd = SignedData::parse(&sd.encode()).unwrap();
    let stamps = ltv::check_archives(&sd, &sd.signers[0], Some(&content), &trust);
    assert_eq!(stamps.len(), 4);
    for a in &stamps {
        assert!(a.checked && a.valid && a.trusted, "{a:?}");
    }
}
