//! Checking signed files (screens 5 and 6), against the fake NCA servers.

use super::sign::{NOWHERE, carol, fake_nca, file, test_cas};
use super::*;

fn kalkan_nca(ocsp: &str) -> Arc<Nca> {
    let mut cas = test_cas();
    for a in ["rsa", "gost2004", "gost2015"] {
        cas.push(Cert::parse_any(&file(&format!("kalkan/ca_{a}.cer"))).unwrap());
    }
    Arc::new(Nca::with(NOWHERE, ocsp, cas))
}

fn run(nca: &Arc<Nca>, name: &str, bytes: Vec<u8>, original: Option<Vec<u8>>) -> Checked {
    check_file(nca.clone(), name.into(), bytes, original, "en".into())
}

/// Carol signs `name` with the fake NCA; returns the signed file.
fn signed_by_carol(test: &str, name: &str, bytes: Vec<u8>) -> Signed {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol(test, &g);
    v.sign(
        fake_nca(false),
        id,
        name.into(),
        bytes,
        None,
        ChipPrompt::default(),
        "en".into(),
    )
    .unwrap()
}

#[test]
fn a_freshly_signed_pdf_is_valid_with_ncas_time() {
    let s = signed_by_carol("check-pdf", "Dogovor.pdf", file("pdf/plain.pdf"));
    let c = run(&fake_nca(false), &s.name, s.bytes.clone(), None);
    assert_eq!(c.verdict, Verdict::Valid, "{c:?}");
    assert_eq!(c.format, Some(Format::Pdf));
    assert_eq!(c.document_name, "Dogovor-signed.pdf");
    assert_eq!(c.signers.len(), 1);
    let sg = &c.signers[0];
    assert!(sg.valid && sg.nca_time && sg.reason.is_none(), "{sg:?}");
    assert!(!sg.name.is_empty());
    assert_eq!(sg.signed_ms, s.nca_time_ms);
    assert!(c.fingerprint.is_some());
    assert_eq!(c.document.as_deref(), Some(&s.bytes[..]));
}

#[test]
fn revoked_keys_and_changed_documents_are_not_valid() {
    let s = signed_by_carol("check-cms", "Akt.docx", b"the act".to_vec());
    let c = run(&fake_nca(true), &s.name, s.bytes.clone(), None);
    assert_eq!(c.verdict, Verdict::Invalid, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::Revoked));
    assert_eq!(c.format, Some(Format::Cms));
    assert_eq!(c.document_name, "Akt.docx");
    assert_eq!(c.document.as_deref(), Some(&b"the act"[..]));

    // a detached .cms: needs the document, and a different one is "changed"
    let det = file("kalkan/detached_gost2015.cms");
    let nca = kalkan_nca(NOWHERE);
    let c = run(&nca, "doc.txt.cms", det.clone(), None);
    assert_eq!(c.verdict, Verdict::NeedsDocument);
    assert_eq!(c.format, Some(Format::DetachedCms));
    assert_eq!(c.signers.len(), 1);
    let c = run(&nca, "doc.txt.cms", det, Some(b"another text".to_vec()));
    assert_eq!(c.verdict, Verdict::Invalid, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::Changed));
}

#[test]
fn keys_not_from_a_trusted_ca_are_not_recognized() {
    let c = run(
        &Arc::new(Nca::with(NOWHERE, NOWHERE, vec![])),
        "doc.txt.cms",
        file("kalkan/timestamped_rsa.cms"),
        None,
    );
    assert_eq!(c.verdict, Verdict::Invalid, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::NotRecognized));
}

#[test]
fn without_ncas_answer_it_is_unknown() {
    let c = run(
        &kalkan_nca(NOWHERE),
        "doc.txt.cms",
        file("kalkan/timestamped_rsa.cms"),
        None,
    );
    assert_eq!(c.verdict, Verdict::Unknown, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::NotConfirmed));
}

#[test]
fn unsigned_files_are_not_signed() {
    let nca = kalkan_nca(NOWHERE);
    for (name, f) in [("a.pdf", "pdf/plain.pdf"), ("doc.txt", "kalkan/doc.txt")] {
        let c = run(&nca, name, file(f), None);
        assert_eq!(c.verdict, Verdict::NotSigned, "{name}: {c:?}");
        assert!(c.signers.is_empty());
    }
}

#[test]
fn an_expired_key_is_expired_or_expired_since() {
    let mut s = kzsigner::report::SignerReport {
        cert_der: Some(vec![1]),
        signature_ok: true,
        chain_ok: true,
        cert_valid_at_signing: Some(false),
        ocsp_answer: Some("good"),
        ..Default::default()
    };
    // no NCA time: checked as of today, when the key has expired since
    assert_eq!(crate::check::reason(&s), Reason::ExpiredSince);
    // NCA's time says the key had expired when it signed
    s.timestamp_time = Some(1);
    s.timestamp_ok = Some(true);
    s.timestamp_trusted = Some(true);
    assert_eq!(crate::check::reason(&s), Reason::Expired);
}
