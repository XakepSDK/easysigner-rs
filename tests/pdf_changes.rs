//! A PDF changed after it was signed (an incremental update that redraws a page) must not
//! verify, while later signatures alone keep the earlier ones valid.

use std::path::Path;

use kzsigner::Engine;
use lopdf::{Dictionary, Document, IncrementalDocument, Object, Stream};

fn key(e: &Engine, f: &str) -> kzsigner::p12::Key {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kalkan");
    e.open_key(&std::fs::read(fx.join(f)).unwrap(), "Qwerty12", None)
        .unwrap()
}

/// Appends an update that replaces the first page's content.
fn redraw_first_page(data: &[u8]) -> Vec<u8> {
    let prev = Document::load_mem(data).unwrap();
    let page_id = *prev.get_pages().values().next().unwrap();
    let mut page = prev.get_dictionary(page_id).unwrap().clone();
    let max = prev.max_id;
    let mut inc = IncrementalDocument::create_from(data.to_vec(), prev);
    let content = Stream::new(
        Dictionary::new(),
        b"BT /F1 40 Tf 50 700 Td (PAY 1000000 TO MALLORY) Tj ET".to_vec(),
    );
    inc.new_document
        .objects
        .insert((max + 1, 0), Object::Stream(content));
    page.set("Contents", Object::Reference((max + 1, 0)));
    inc.new_document
        .objects
        .insert(page_id, Object::Dictionary(page));
    inc.new_document.max_id = max + 1;
    let mut out = Vec::new();
    inc.save_to(&mut out).unwrap();
    out
}

#[test]
fn changes_after_signing_are_caught() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = Engine::new(vec![]);
    let (rsa, gost) = (key(&e, "alice_rsa.p12"), key(&e, "alice_gost2015.p12"));
    for f in ["plain.pdf", "objstm.pdf", "land.pdf"] {
        let one = e
            .sign_pdf(&std::fs::read(fx.join(f)).unwrap(), &rsa, None)
            .unwrap()
            .cms;
        let two = e.sign_pdf(&one, &gost, None).unwrap().cms;
        let r = e.verify(&two, None, None).unwrap();
        assert_eq!(r.signers.len(), 2);
        for s in &r.signers {
            assert!(s.signature_ok, "{f}: {:?}", s.signature_error);
        }
        assert!(
            r.signers[0]
                .notes
                .iter()
                .any(|n| n.contains("1 time(s)") && n.contains("only to add signatures")),
            "{f}: {:?}",
            r.signers[0].notes
        );

        let evil = redraw_first_page(&two);
        let r = e.verify(&evil, None, None).unwrap();
        for s in &r.signers {
            assert!(!s.signature_ok && !s.valid, "{f}: a changed page passed");
            assert!(
                s.signature_error
                    .as_deref()
                    .unwrap_or("")
                    .contains("a page (object"),
                "{f}: {:?}",
                s.signature_error
            );
        }
        // and signing on top of the change does not make it pass
        let three = e.sign_pdf(&evil, &rsa, None).unwrap().cms;
        let r = e.verify(&three, None, None).unwrap();
        assert!(!r.signers[0].signature_ok && !r.signers[1].signature_ok);
        assert!(r.signers[2].signature_ok);
    }
}

#[test]
fn certified_pdfs_that_allow_no_changes_are_not_signed() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = Engine::new(vec![]);
    let rsa = key(&e, "alice_rsa.p12");
    let mut doc = Document::load(fx.join("plain.pdf")).unwrap();
    let params = Dictionary::from_iter([("P", Object::Integer(1))]);
    let reference = Dictionary::from_iter([
        ("TransformMethod", Object::Name(b"DocMDP".to_vec())),
        ("TransformParams", Object::Dictionary(params)),
    ]);
    let sig = Dictionary::from_iter([(
        "Reference",
        Object::Array(vec![Object::Dictionary(reference)]),
    )]);
    let perms = Dictionary::from_iter([("DocMDP", Object::Dictionary(sig))]);
    doc.catalog_mut()
        .unwrap()
        .set("Perms", Object::Dictionary(perms));
    let mut data = Vec::new();
    doc.save_to(&mut data).unwrap();
    let Err(err) = e.sign_pdf(&data, &rsa, None) else {
        panic!("signed a no-changes PDF");
    };
    assert!(err.0.contains("DocMDP"), "{}", err.0);
}
