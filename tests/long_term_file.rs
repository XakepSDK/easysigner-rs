//! A CAdES B-LTA file made by an earlier build (tests/fixtures/ltv/lta.cms: doc.txt signed by
//! the OCSP test CA's carol, made long-term with that CA's OCSP answer and the fake test TSA,
//! then renewed twice) still verifies. Making and checking a file with the same build can't
//! tell when both sides change the same way; this file can.

use std::path::PathBuf;

use kzsigner::Engine;
use kzsigner::cert::Cert;

fn fixture(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(p),
    )
    .unwrap()
}

#[test]
fn an_older_lta_file_verifies() {
    let tsa = kzsigner::p12::open(&fixture("keys/tsa.p12"), "Qwerty12", None)
        .unwrap()
        .cert;
    let e = Engine::new(vec![Cert::parse(&fixture("ocsp/ca.cer")).unwrap(), tsa]);
    let data = fixture("ltv/lta.cms");
    let r = e.verify(&data, None, None).unwrap();
    let s = &r.signers[0];
    assert!(r.valid && r.signers.len() == 1, "{s:#?}");
    assert_eq!(s.level, Some("B-LTA"));
    assert_eq!(s.ocsp_answer, Some("good"), "{s:#?}");
    assert_eq!(s.archive_timestamps.len(), 3);
    for a in &s.archive_timestamps {
        assert!(
            a.checked && a.valid && a.trusted && a.error.is_none(),
            "{a:?}"
        );
        assert_eq!(a.tsa.as_deref(), Some("FAKE TEST TSA"));
    }
    assert!(
        s.archive_timestamps
            .windows(2)
            .all(|w| w[0].time <= w[1].time)
    );

    // without the kept data, the same file is no longer long-term
    let mut sd = kzsigner::cms::SignedData::parse(&data).unwrap();
    sd.crls = None;
    let r = e.verify(&sd.encode(), None, None).unwrap();
    let s = &r.signers[0];
    assert!(!r.valid && s.signature_ok, "{s:#?}");
    assert!(
        s.archive_timestamps.iter().all(|a| !a.valid
            && a.error
                .as_deref()
                .is_some_and(|e| e.contains("no longer in the signature"))),
        "{s:#?}"
    );
    // still saying when and by whom
    for a in &s.archive_timestamps {
        assert!(a.checked && a.time.is_some(), "{a:?}");
        assert_eq!(a.tsa.as_deref(), Some("FAKE TEST TSA"));
    }

    // without the document the timestamps are not checked, but their times are known
    let sd = kzsigner::cms::SignedData::parse(&data).unwrap();
    let si = &sd.signers[0];
    let trust = kzsigner::trust::TrustStore::new(vec![]);
    let stamps = kzsigner::ltv::check_archives(&sd, si, None, &trust);
    assert_eq!(stamps.len(), 3);
    for a in &stamps {
        assert!(!a.checked && !a.valid && a.time.is_some(), "{a:?}");
        assert!(a.error.as_deref().unwrap().contains("not checked"), "{a:?}");
    }
}
