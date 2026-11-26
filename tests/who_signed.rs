//! The Who signed page (src/pdf/whosigned.rs): the first signer adds it and certifies the PDF,
//! later signers' boxes go into the next free spot, never over another app's box, and the
//! signatures stay valid.

use std::path::Path;

use kzsigner::Engine;
use kzsigner::pdf::whosigned::{SPOTS, WhoSigned};
use lopdf::{Dictionary, Document, IncrementalDocument, Object};

fn fx(p: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(p),
    )
    .unwrap()
}

fn engine() -> Engine {
    let ca = |n: &str| kzsigner::cert::Cert::parse_any(&fx(n)).unwrap();
    Engine::new(vec![ca("kalkan/ca_rsa.cer"), ca("kalkan/ca_gost2015.cer")])
}

fn key(e: &Engine, f: &str) -> kzsigner::p12::Key {
    e.open_key(&fx(&format!("kalkan/{f}")), "Qwerty12", None)
        .unwrap()
}

fn page() -> WhoSigned {
    WhoSigned {
        document: "Dogovor_arendy_2026.pdf".into(),
    }
}

/// The signature widgets' rectangles on the last page, in order.
fn boxes(pdf: &[u8]) -> Vec<[f32; 4]> {
    let doc = Document::load_mem(pdf).unwrap();
    let last = *doc.get_pages().values().last().unwrap();
    let p = doc.get_dictionary(last).unwrap();
    let Ok(annots) = p.get(b"Annots") else {
        return vec![];
    };
    let annots = doc
        .dereference(annots)
        .unwrap()
        .1
        .as_array()
        .unwrap()
        .clone();
    annots
        .iter()
        .filter_map(|a| {
            let d = doc.dereference(a).ok()?.1.as_dict().ok()?.clone();
            let r = d.get(b"Rect").ok()?.as_array().ok()?.clone();
            let v: Vec<f32> = r.iter().map(|x| x.as_float().unwrap()).collect();
            (v[2] - v[0] > 1.0).then(|| [v[0], v[1], v[2], v[3]])
        })
        .collect()
}

fn pages(pdf: &[u8]) -> usize {
    Document::load_mem(pdf).unwrap().get_pages().len()
}

fn valid(e: &Engine, pdf: &[u8]) -> usize {
    let r = e.verify(pdf, None, None).unwrap();
    for s in &r.signers {
        assert!(s.valid, "{:?} {:?}", s.signature_error, s.warnings);
    }
    assert!(r.valid);
    r.signers.len()
}

#[test]
fn the_first_signer_adds_the_page_and_locks_the_pdf() {
    let e = engine();
    let plain = fx("pdf/plain.pdf");
    let n = pages(&plain);
    let one = e
        .sign(kzsigner::SignRequest::pdf_page(
            &plain,
            &key(&e, "alice_rsa.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    assert_eq!(pages(&one), n + 1, "one page added at the end");
    assert!(kzsigner::pdf::whosigned::ends_with_page(&one));
    assert!(!kzsigner::pdf::whosigned::ends_with_page(&plain));
    assert_eq!(valid(&e, &one), 1);
    let b = boxes(&one);
    assert_eq!(b.len(), 1);
    // top left of the grid, in the left column
    assert!(b[0][0] < 100.0 && b[0][3] > 500.0, "{b:?}");

    // certified: only signatures and form filling after it (DocMDP P=2)
    let doc = Document::load_mem(&one).unwrap();
    let perms = doc
        .catalog()
        .unwrap()
        .get(b"Perms")
        .unwrap()
        .as_dict()
        .unwrap();
    let sig = doc
        .get_dictionary(perms.get(b"DocMDP").unwrap().as_reference().unwrap())
        .unwrap();
    let r = sig.get(b"Reference").unwrap().as_array().unwrap()[0]
        .as_dict()
        .unwrap();
    let p = r.get(b"TransformParams").unwrap().as_dict().unwrap();
    assert_eq!(p.get(b"P").unwrap().as_i64().unwrap(), 2);

    // the second signer: the next spot, to the right; no new page, still certified once
    let two = e
        .sign(kzsigner::SignRequest::pdf_page(
            &one,
            &key(&e, "bob_gost2015.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    assert_eq!(pages(&two), n + 1);
    assert_eq!(valid(&e, &two), 2);
    let b = boxes(&two);
    assert_eq!(b.len(), 2);
    assert!(
        (b[1][1] - b[0][1]).abs() < 0.5 && b[1][0] > b[0][2],
        "same row, to the right: {b:?}"
    );
}

/// Another app's stamp (as NCALayer puts one) on the page: the next box goes after it, and
/// never over it.
#[test]
fn boxes_go_after_other_apps_stamps() {
    let e = engine();
    let one = e
        .sign(kzsigner::SignRequest::pdf_page(
            &fx("pdf/plain.pdf"),
            &key(&e, "alice_rsa.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    // an NCALayer-style signature widget across the middle of the page, added by hand as an
    // incremental update (a visible signature field without a value is enough to take room)
    let doc = Document::load_mem(&one).unwrap();
    let last = *doc.get_pages().values().last().unwrap();
    let mut page_dict = doc.get_dictionary(last).unwrap().clone();
    let max = doc.max_id;
    let widget_id = (max + 1, 0);
    let widget = Dictionary::from_iter([
        ("Type", Object::from("Annot")),
        ("Subtype", "Widget".into()),
        ("FT", "Sig".into()),
        ("T", Object::string_literal("NCALayer")),
        (
            "Rect",
            Object::Array(vec![100.into(), 380.into(), 300.into(), 440.into()]),
        ),
        ("P", last.into()),
    ]);
    let mut annots = page_dict
        .get(b"Annots")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    annots.push(widget_id.into());
    page_dict.set("Annots", Object::Array(annots));
    let mut inc = IncrementalDocument::create_from(one.clone(), doc);
    inc.new_document.objects.insert(widget_id, widget.into());
    inc.new_document.objects.insert(last, page_dict.into());
    inc.new_document.max_id = max + 1;
    let mut with_other = Vec::new();
    inc.save_to(&mut with_other).unwrap();

    let two = e
        .sign(kzsigner::SignRequest::pdf_page(
            &with_other,
            &key(&e, "bob_gost2015.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    let b = boxes(&two);
    let new = b.last().unwrap();
    let other = [100.0, 380.0, 300.0, 440.0];
    let overlap = new[0] < other[2] && other[0] < new[2] && new[1] < other[3] && other[1] < new[3];
    assert!(!overlap, "{new:?} over {other:?}");
    assert!(
        new[3] <= other[1] + 0.5,
        "below the other app's stamp: {new:?}"
    );
}

#[test]
fn after_twenty_boxes_one_note_then_invisible() {
    let e = engine();
    let k = key(&e, "alice_rsa.p12");
    let mut pdf = fx("pdf/plain.pdf");
    for _ in 0..SPOTS + 2 {
        pdf = e
            .sign(kzsigner::SignRequest::pdf_page(&pdf, &k, &page()))
            .unwrap()
            .cms;
    }
    let b = boxes(&pdf);
    assert_eq!(b.len(), SPOTS + 1, "20 boxes and the note");
    let note = b[SPOTS];
    assert!(
        note[2] - note[0] > 400.0,
        "the note spans the page: {note:?}"
    );
    assert_eq!(valid(&e, &pdf), SPOTS + 2);
}

/// A PDF signed elsewhere first has no Who signed page: nothing is drawn over its content.
#[test]
fn a_pdf_signed_elsewhere_gets_an_invisible_signature() {
    let e = engine();
    let plain = fx("pdf/plain.pdf");
    let one = e
        .sign(kzsigner::SignRequest::pdf(
            &plain,
            &key(&e, "alice_rsa.p12"),
        ))
        .unwrap()
        .cms;
    let two = e
        .sign(kzsigner::SignRequest::pdf_page(
            &one,
            &key(&e, "bob_gost2015.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    assert_eq!(pages(&two), pages(&plain));
    assert!(boxes(&two).is_empty());
    assert_eq!(valid(&e, &two), 2);
    // and it is not certified: someone else signed first
    let doc = Document::load_mem(&two).unwrap();
    assert!(doc.catalog().unwrap().get(b"Perms").is_err());
}

/// After the first signature, changing the page content is caught (DocMDP and the change
/// check), while signatures stay fine.
#[test]
fn changes_after_the_first_signature_are_caught() {
    let e = engine();
    let one = e
        .sign(kzsigner::SignRequest::pdf_page(
            &fx("pdf/plain.pdf"),
            &key(&e, "alice_rsa.p12"),
            &page(),
        ))
        .unwrap()
        .cms;
    let doc = Document::load_mem(&one).unwrap();
    let first = *doc.get_pages().values().next().unwrap();
    let mut p = doc.get_dictionary(first).unwrap().clone();
    let max = doc.max_id;
    let content = lopdf::Stream::new(
        Dictionary::new(),
        b"BT /F1 40 Tf 50 700 Td (PAY) Tj ET".to_vec(),
    );
    p.set("Contents", Object::Reference((max + 1, 0)));
    let mut inc = IncrementalDocument::create_from(one.clone(), doc);
    inc.new_document
        .objects
        .insert((max + 1, 0), Object::Stream(content));
    inc.new_document.objects.insert(first, p.into());
    inc.new_document.max_id = max + 1;
    let mut evil = Vec::new();
    inc.save_to(&mut evil).unwrap();
    let r = e.verify(&evil, None, None).unwrap();
    assert!(!r.valid);
    assert!(!r.signers[0].signature_ok);
}

/// Writes a PDF with three signers to KZ_WHO_SIGNED_OUT, to look at.
#[test]
fn write_a_sample() {
    let Ok(out) = std::env::var("KZ_WHO_SIGNED_OUT") else {
        return;
    };
    let e = engine();
    let mut pdf = fx("pdf/plain.pdf");
    for k in ["alice_rsa.p12", "bob_gost2015.p12", "bob_rsa.p12"] {
        pdf = e
            .sign(kzsigner::SignRequest::pdf_page(&pdf, &key(&e, k), &page()))
            .unwrap()
            .cms;
    }
    std::fs::write(out, pdf).unwrap();
}
