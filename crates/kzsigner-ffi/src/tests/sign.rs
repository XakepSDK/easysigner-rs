//! Signing, against fake NCA servers on 127.0.0.1 (tests/common/nca.rs).

use super::*;

#[path = "../../../kzsigner/tests/common/nca.rs"]
#[allow(dead_code)]
pub(super) mod nca;

pub(super) fn file(path: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(path),
    )
    .unwrap()
}

/// The test CAs: the OCSP one (carol's), the test keys', and the fake TSA.
pub(super) fn test_cas() -> Vec<Cert> {
    let mut cas: Vec<Cert> = [
        "ocsp/ca.cer",
        "keys/ca_rsa.cer",
        "keys/ca_gost2015.cer",
        "keys/ca_gost2015_256.cer",
    ]
    .iter()
    .map(|p| Cert::parse_any(&file(p)).unwrap())
    .collect();
    // the fake TSA's own certificate (self-signed), so its time counts as NCA's
    cas.push(
        kzsigner::p12::open(&file("keys/tsa.p12"), "Qwerty12", None)
            .unwrap()
            .cert,
    );
    cas
}

/// NCA played by the fakes; `revoked`: what the OCSP server says of every key.
pub(super) fn fake_nca(revoked: bool) -> Arc<Nca> {
    Arc::new(Nca::with(
        &nca::fake_tsa(),
        &nca::fake_ocsp(revoked),
        test_cas(),
    ))
}

/// A port nothing listens on: no internet.
pub(super) const NOWHERE: &str = "http://127.0.0.1:9/";

fn sign_prompt() -> ChipPrompt {
    ChipPrompt {
        title: "Sign".into(),
        ..Default::default()
    }
}

/// A vault with carol's key (her CA has the fake OCSP server).
pub(super) fn carol(test: &str, g: &Arc<SoftwareGuard>) -> (Arc<Vault>, String) {
    let v = vault(&dir(test).join("keys.kzs"), g);
    let id = v
        .add_key(
            super::test_nca(),
            file("ocsp/carol.p12"),
            "Qwerty12".into(),
            prompt(),
        )
        .unwrap();
    g.prompts.lock().unwrap().clear();
    (v, id)
}

fn sign(
    v: &Vault,
    nca: &Arc<Nca>,
    id: &str,
    name: &str,
    bytes: Vec<u8>,
) -> Result<Signed, SignError> {
    v.sign(
        nca.clone(),
        id.into(),
        name.into(),
        bytes,
        None,
        sign_prompt(),
        "ru".into(),
    )
}

#[test]
fn inspect_says_what_signing_makes() {
    let d = inspect("Dogovor.pdf".into(), file("pdf/plain.pdf"));
    assert_eq!(d.kind, DocKind::Pdf);
    assert_eq!(d.output, Output::InsidePdf);
    assert_eq!(d.output_name, "Dogovor-signed.pdf");
    assert!(d.signers.is_empty());

    let d = inspect("doc.txt".into(), file("kalkan/doc.txt"));
    assert_eq!((d.kind, d.output), (DocKind::Other, Output::NewCms));
    assert_eq!(d.output_name, "doc.txt.cms");

    let d = inspect("doc.txt.cms".into(), file("kalkan/cosigned_rsa.cms"));
    assert_eq!((d.kind, d.output), (DocKind::Cms, Output::JoinCms));
    assert_eq!(d.inner_name.as_deref(), Some("doc.txt"));
    assert_eq!(d.inner_kind, Some(DocKind::Other));
    assert_eq!(d.output_name, "doc.txt.cms");
    assert_eq!(d.signers.len(), 2);
    assert!(d.signers.iter().all(|s| !s.name.is_empty()));
    assert!(cms_content(file("kalkan/cosigned_rsa.cms")).is_some());

    let d = inspect("doc.txt.cms".into(), file("kalkan/detached_gost2015.cms"));
    assert_eq!(d.output, Output::Cannot);
    assert_eq!(cms_content(file("kalkan/detached_gost2015.cms")), None);

    let d = inspect("key.p12".into(), file("keys/alice_rsa.p12"));
    assert_eq!(d.kind, DocKind::Key);

    let d = inspect("act.xml".into(), file("app/act.xml"));
    assert_eq!((d.kind, d.output), (DocKind::Xml, Output::InsideXml));
    assert_eq!(d.output_name, "act-signed.xml");

    // a .cms of a PDF says so, to show the PDF inside
    let key = kzsigner::p12::open(&file("keys/alice_rsa.p12"), "Qwerty12", None).unwrap();
    let e = kzsigner::Engine::new(test_cas());
    let cms = e
        .sign(kzsigner::SignRequest::cms(
            &file("pdf/plain.pdf"),
            &key,
            kzsigner::Cms::default(),
        ))
        .unwrap()
        .cms;
    let d = inspect("Dogovor.pdf.cms".into(), cms);
    assert_eq!(d.inner_kind, Some(DocKind::Pdf));
    assert_eq!(d.output, Output::JoinCms);
    // names: the extension comes off only when there is a name before it
    assert_eq!(crate::sign::inner_name("Dogovor.PDF.CMS"), "Dogovor.PDF");
    assert_eq!(crate::sign::inner_name("a.p7s"), "a");
    assert_eq!(crate::sign::inner_name(".cms"), ".cms");
    assert_eq!(crate::sign::inner_name("doc.txt"), "doc.txt");
}

#[test]
fn signs_an_xml_inside_it() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("xml", &g);
    let nca = fake_nca(false);
    let s = sign(&v, &nca, &id, "act.xml", file("app/act.xml")).unwrap();
    assert_eq!(s.name, "act-signed.xml");
    assert!(nca.engine.is_xml(&s.bytes), "an XML, not a .cms");
    let rep = nca.engine.verify(&s.bytes, None, None).unwrap();
    assert_eq!(rep.signers.len(), 1);
    assert!(rep.signers[0].signature_ok);
    // and a second signature can go into the same XML
    let d = inspect(s.name, s.bytes);
    assert_eq!(d.signers.len(), 1);
    assert_eq!(d.output, Output::InsideXml);
}

#[test]
fn signs_a_pdf_with_one_prompt_and_ncas_time() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("pdf", &g);
    let nca = fake_nca(false);
    let before = now();
    let s = sign(&v, &nca, &id, "Dogovor.pdf", file("pdf/plain.pdf")).unwrap();
    assert_eq!(s.name, "Dogovor-signed.pdf");
    assert!(!s.joined);
    let t = s.nca_time_ms.expect("NCA's time");
    assert!(t >= before - 1000 && t <= now() + 1000);
    assert_eq!(g.prompts.lock().unwrap().len(), 1);
    assert_eq!(g.prompts.lock().unwrap()[0].title, "Sign");

    let rep = nca.engine.verify(&s.bytes, None, None).unwrap();
    assert!(rep.is_pdf);
    assert_eq!(rep.signers.len(), 1);
    assert!(rep.signers[0].signature_ok);

    // and a second signature joins it in the same PDF
    let d = inspect(s.name.clone(), s.bytes.clone());
    assert_eq!(d.signers.len(), 1);
    assert_eq!(d.output_name, "Dogovor-signed-signed.pdf");
}

#[test]
fn signs_other_files_into_a_cms_and_joins_one() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("cms", &g);
    let nca = fake_nca(false);
    let s = sign(
        &v,
        &nca,
        &id,
        "Akt.docx",
        b"not really a Word file".to_vec(),
    )
    .unwrap();
    assert_eq!(s.name, "Akt.docx.cms");
    assert!(s.nca_time_ms.is_some());
    assert_eq!(
        cms_content(s.bytes.clone()).unwrap(),
        b"not really a Word file"
    );

    let d = inspect(s.name.clone(), s.bytes.clone());
    assert_eq!(d.output, Output::JoinCms);
    assert_eq!(d.inner_name.as_deref(), Some("Akt.docx"));
    let s2 = sign(&v, &nca, &id, &s.name, s.bytes).unwrap();
    assert!(s2.joined);
    assert_eq!(s2.name, "Akt.docx.cms");
    assert_eq!(inspect(s2.name, s2.bytes).signers.len(), 2);
}

#[test]
fn a_revoked_or_unknown_key_signs_nothing_and_asks_nothing() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("revoked", &g);
    let pdf = file("pdf/plain.pdf");
    assert!(matches!(
        sign(&v, &fake_nca(true), &id, "a.pdf", pdf.clone()),
        Err(SignError::KeyCantSign {
            reason: CantSign::Revoked,
            ..
        })
    ));
    // the test CA, not NCA's: not recognized
    let real = Arc::new(Nca::with(&nca::fake_tsa(), &nca::fake_ocsp(false), vec![]));
    assert!(matches!(
        sign(&v, &real, &id, "a.pdf", pdf),
        Err(SignError::KeyCantSign {
            reason: CantSign::NotRecognized,
            ..
        })
    ));
    assert!(g.prompts.lock().unwrap().is_empty());
}

#[test]
fn without_internet_nothing_is_signed() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("offline", &g);
    let pdf = file("pdf/plain.pdf");
    // NCA's OCSP server can't be reached: before any prompt
    let off = Arc::new(Nca::with(NOWHERE, NOWHERE, test_cas()));
    assert!(matches!(
        sign(&v, &off, &id, "a.pdf", pdf.clone()),
        Err(SignError::NoAnswer)
    ));
    assert!(g.prompts.lock().unwrap().is_empty());
    // its timestamp server can't
    let no_tsa = Arc::new(Nca::with(NOWHERE, &nca::fake_ocsp(false), test_cas()));
    assert!(matches!(
        sign(&v, &no_tsa, &id, "a.pdf", pdf),
        Err(SignError::NoAnswer)
    ));
}

#[test]
fn a_detached_cms_cant_be_signed_here() {
    let g = Arc::new(SoftwareGuard::default());
    let (v, id) = carol("detached", &g);
    assert!(matches!(
        sign(
            &v,
            &fake_nca(false),
            &id,
            "doc.txt.cms",
            file("kalkan/detached_gost2015.cms")
        ),
        Err(SignError::Cannot)
    ));
    assert!(g.prompts.lock().unwrap().is_empty());
}

#[test]
fn a_key_kept_under_its_password_asks_for_it() {
    let mut sg = SoftwareGuard::default();
    sg.no_screen_lock = true;
    let g = Arc::new(sg);
    let (v, id) = carol("password", &g);
    let nca = fake_nca(false);
    let pdf = file("pdf/plain.pdf");
    let with = |pw: &str| {
        v.sign(
            nca.clone(),
            id.clone(),
            "a.pdf".into(),
            pdf.clone(),
            Some(pw.into()),
            sign_prompt(),
            "kk".into(),
        )
    };
    assert!(matches!(with("Йцукен12"), Err(SignError::WrongPassword)));
    with("Qwerty12").unwrap();
    assert!(g.prompts.lock().unwrap().is_empty());
}
