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
    // a "good" answer from NCA is not a problem to show
    assert!(sg.problems.is_empty(), "{:?}", sg.problems);
}

#[test]
fn a_signed_xml_is_checked_as_xml() {
    let s = signed_by_carol("check-xml", "act.xml", file("app/act.xml"));
    assert_eq!(s.name, "act-signed.xml");
    let c = run(&fake_nca(false), &s.name, s.bytes.clone(), None);
    assert_eq!(c.verdict, Verdict::Valid, "{c:?}");
    assert_eq!(c.format, Some(Format::Xml));
    assert_eq!(c.signers.len(), 1);
    assert_eq!(c.document.as_deref(), Some(&s.bytes[..]));

    // the same XML unsigned: not signed, not broken
    let c = run(&fake_nca(false), "act.xml", file("app/act.xml"), None);
    assert_eq!(c.verdict, Verdict::NotSigned, "{c:?}");
    assert_eq!(c.format, Some(Format::Xml));
}

#[test]
fn a_document_card_is_checked_with_its_original() {
    let nca = fake_nca(false);
    let key = kzsigner::p12::open(&file("ocsp/carol.p12"), "Qwerty12", None).unwrap();
    let r = nca
        .engine
        .sign_card(b"the act", "Akt.txt", &key, &nca.tsa, &nca.ocsp, None, None)
        .unwrap();
    let c = run(&nca, "Akt-card.pdf", r.cms, None);
    assert_eq!(c.format, Some(Format::Card), "{c:?}");
    assert_eq!(c.document_name, "Akt.txt");
    assert_eq!(c.document.as_deref(), Some(&b"the act"[..]));
    assert_eq!(c.signers.len(), 1);
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
    let c = run(
        &nca,
        "doc.txt.cms",
        det.clone(),
        Some(b"another text".to_vec()),
    );
    assert_eq!(c.verdict, Verdict::Invalid, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::Changed));
    // with its own document: checked (NCA can't be asked here), and that document is shown
    let doc = file("kalkan/doc.txt");
    let c = run(&nca, "doc.txt.cms", det, Some(doc.clone()));
    assert_eq!(c.format, Some(Format::DetachedCms));
    assert_eq!(c.verdict, Verdict::Unknown, "{c:?}");
    assert_eq!(c.signers[0].reason, Some(Reason::NotConfirmed));
    assert_eq!(c.document.as_deref(), Some(&doc[..]));
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
        revocation: Some(kzsigner::report::Answer::Said(
            kzsigner::report::CertStatus::Good,
        )),
        ..Default::default()
    };
    // no NCA time: checked as of today, when the key has expired since
    assert_eq!(s.reason().map(Reason::from), Some(Reason::ExpiredSince));
    // NCA's time says the key had expired when it signed
    s.timestamp_time = Some(1);
    s.timestamp_ok = Some(true);
    s.timestamp_trusted = Some(true);
    assert_eq!(s.reason().map(Reason::from), Some(Reason::Expired));
}

/// Makes the signed files the app's emulator tests check (testdata/app), signed by
/// carol against the fake NCA, and prints what checking each says. Run by hand:
/// cargo test -p kzsigner-ffi make_app_fixtures -- --ignored --nocapture
#[test]
#[ignore]
fn make_app_fixtures() {
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/app");
    let pdf = signed_by_carol("fix-pdf", "contract.pdf", file("pdf/plain.pdf"));
    std::fs::write(out.join(&pdf.name), &pdf.bytes).unwrap();
    let act = signed_by_carol(
        "fix-cms",
        "act.txt",
        b"Act No. 17: test services, November.".to_vec(),
    );
    std::fs::write(out.join(&act.name), &act.bytes).unwrap();
    // the same with its text changed after signing
    let mut changed = act.bytes.clone();
    let at = changed.windows(6).position(|w| w == b"No. 17").unwrap();
    changed[at + 4] = b'9';
    std::fs::write(out.join("act-changed.txt.cms"), &changed).unwrap();

    let mut cas = test_cas();
    cas.push(Cert::parse_any(&file("kalkan/ca_gost2015.cer")).unwrap());
    let good = Arc::new(Nca::with(
        NOWHERE,
        &super::sign::nca::fake_ocsp(false),
        cas.clone(),
    ));
    let revoked = Arc::new(Nca::with(
        NOWHERE,
        &super::sign::nca::fake_ocsp(true),
        cas.clone(),
    ));
    let down = Arc::new(Nca::with(NOWHERE, NOWHERE, cas));
    let app = |f: &str| std::fs::read(out.join(f)).unwrap();
    for (what, nca, name, orig) in [
        ("pdf good", &good, &pdf.name[..], None),
        ("pdf revoked", &revoked, &pdf.name[..], None),
        ("pdf down", &down, &pdf.name[..], None),
        ("cms good", &good, "act.txt.cms", None),
        ("cms revoked", &revoked, "act.txt.cms", None),
        ("cms down", &down, "act.txt.cms", None),
        ("changed", &good, "act-changed.txt.cms", None),
        ("detached", &good, "doc.txt.cms", None),
        ("detached+doc", &good, "doc.txt.cms", Some(app("doc.txt"))),
        (
            "detached+other",
            &good,
            "doc.txt.cms",
            Some(file("pdf/plain.pdf")),
        ),
    ] {
        let c = run(nca, name, app(name), orig);
        println!(
            "{what}: {:?} {:?} rev={:?} kept={}",
            c.verdict,
            c.signers.first().map(|s| s.reason),
            c.signers.first().map(|s| s.revocation_answer),
            c.signers.first().is_some_and(|s| s.revocation_kept)
        );
    }
}
