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

/// The test keys' CAs trusted, as signing checks the key first.
fn engine() -> Engine {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kalkan");
    let ca =
        |n: &str| kzsigner::cert::Cert::parse_any(&std::fs::read(fx.join(n)).unwrap()).unwrap();
    Engine::new(vec![ca("ca_rsa.cer"), ca("ca_gost2015.cer")])
}

#[test]
fn changes_after_signing_are_caught() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let (rsa, gost) = (key(&e, "alice_rsa.p12"), key(&e, "alice_gost2015.p12"));
    for f in ["plain.pdf", "objstm.pdf", "land.pdf"] {
        let one = e
            .sign_pdf(&std::fs::read(fx.join(f)).unwrap(), &rsa, None, None)
            .unwrap()
            .cms;
        let two = e.sign_pdf(&one, &gost, None, None).unwrap().cms;
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
        let three = e.sign_pdf(&evil, &rsa, None, None).unwrap().cms;
        let r = e.verify(&three, None, None).unwrap();
        assert!(!r.signers[0].signature_ok && !r.signers[1].signature_ok);
        assert!(r.signers[2].signature_ok);
    }
}

#[test]
fn certified_pdfs_that_allow_no_changes_are_not_signed() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
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
    let Err(err) = e.sign_pdf(&data, &rsa, None, None) else {
        panic!("signed a no-changes PDF");
    };
    assert!(err.0.contains("DocMDP"), "{}", err.0);
}

#[test]
fn a_cms_holding_a_pdf_is_checked_as_a_cms() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let rsa = key(&e, "alice_rsa.p12");
    let pdf = std::fs::read(fx.join("plain.pdf")).unwrap();
    let cms = e
        .sign(&pdf, &rsa, false, None, None, false, None)
        .unwrap()
        .cms;
    assert!(!e.is_pdf(&cms));
    let r = e.verify(&cms, None, None).unwrap();
    assert!(!r.is_pdf);
    assert_eq!(r.signers.len(), 1);
    assert!(
        r.signers[0].signature_ok,
        "{:?}",
        r.signers[0].signature_error
    );
    assert_eq!(e.extract(&cms).unwrap(), pdf);
}

/// Appends an update made by `change`, which gets the document as it is and the update's objects
/// (each object put there replaces the one with its id), and returns the next free id.
fn update(data: &[u8], change: impl FnOnce(&Document, &mut Document, u32) -> u32) -> Vec<u8> {
    let prev = Document::load_mem(data).unwrap();
    let max = prev.max_id;
    let snapshot = prev.clone();
    let mut inc = IncrementalDocument::create_from(data.to_vec(), prev);
    let last = change(&snapshot, &mut inc.new_document, max + 1);
    inc.new_document.max_id = last.max(max);
    let mut out = Vec::new();
    inc.save_to(&mut out).unwrap();
    out
}

fn first_page(d: &Document) -> (u32, u16) {
    *d.get_pages().values().next().unwrap()
}

fn root(d: &Document) -> (u32, u16) {
    d.trailer.get(b"Root").unwrap().as_reference().unwrap()
}

/// The signature errors of each signer, after `evil`.
fn errors(e: &Engine, evil: &[u8], what: &str) -> Vec<String> {
    let r = e.verify(evil, None, None).unwrap();
    assert_eq!(r.signers.len(), 2, "{what}");
    r.signers
        .iter()
        .map(|s| {
            assert!(!s.valid && !s.signature_ok, "{what} passed");
            s.signature_error.clone().unwrap_or_default()
        })
        .collect()
}

/// A PDF whose page annotations, AcroForm and its fields are separate objects, as many tools
/// write them, with an information dictionary; signing adds to each in place.
fn indirect_form(plain: &[u8]) -> Vec<u8> {
    let mut doc = Document::load_mem(plain).unwrap();
    let info = doc.add_object(Dictionary::from_iter([(
        "Producer",
        Object::string_literal("a test"),
    )]));
    doc.trailer.set("Info", Object::Reference(info));
    let annots = doc.add_object(Object::Array(vec![]));
    let fields = doc.add_object(Object::Array(vec![]));
    let form = doc.add_object(Dictionary::from_iter([(
        "Fields",
        Object::Reference(fields),
    )]));
    let page = first_page(&doc);
    doc.get_dictionary_mut(page)
        .unwrap()
        .set("Annots", Object::Reference(annots));
    doc.catalog_mut()
        .unwrap()
        .set("AcroForm", Object::Reference(form));
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

/// What an update may add after a signature, and what it may not: other annotations or form
/// fields, removed signatures, a replaced form, changes to the catalog, the page tree or any other
/// object. Information dictionary changes are allowed.
#[test]
fn what_updates_may_change() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let (rsa, gost) = (key(&e, "alice_rsa.p12"), key(&e, "alice_gost2015.p12"));
    let plain = std::fs::read(fx.join("plain.pdf")).unwrap();
    for (form, pdf) in [
        ("inline", plain.clone()),
        ("indirect", indirect_form(&plain)),
    ] {
        let one = e.sign_pdf(&pdf, &rsa, None, None).unwrap().cms;
        let two = e.sign_pdf(&one, &gost, None, None).unwrap().cms;
        let r = e.verify(&two, None, None).unwrap();
        assert!(r.valid, "{form}: {:?}", r.signers);
        assert!(r.is_pdf && r.has_content);
        assert_eq!(r.content_size, two.len() as u64);
        assert_eq!(
            r.content_sha256.as_deref(),
            Some(kzsigner::hex(&kzsigner::gost::sha256(&two)).as_str())
        );
        let names: Vec<_> = r.signers.iter().map(|s| s.kind.clone().unwrap()).collect();
        assert_eq!(
            names,
            [
                "PDF signature \"Signature1\"",
                "PDF signature \"Signature2\""
            ],
            "{form}"
        );
        assert_eq!(r.signers[1].index, 2);

        let doc = Document::load_mem(&two).unwrap();
        let page = first_page(&doc);
        let annot = |n: &mut Document, id: u32, ft: Option<&str>| {
            let mut d = Dictionary::from_iter([
                ("Type", Object::from("Annot")),
                ("Subtype", "Text".into()),
                (
                    "Rect",
                    Object::Array(vec![0.into(), 0.into(), 9.into(), 9.into()]),
                ),
                ("T", Object::string_literal("note")),
            ]);
            if let Some(ft) = ft {
                d.set("FT", Object::Name(ft.as_bytes().to_vec()));
            }
            n.objects.insert((id, 0), Object::Dictionary(d));
            Object::Reference((id, 0))
        };
        // where the page's annotations and the form's fields are: in their own objects, or in
        // the page and form dictionaries
        let annots_of = |d: &Document| match d.get_dictionary(page).unwrap().get(b"Annots").unwrap()
        {
            Object::Reference(id) => (
                Some(*id),
                d.get_object(*id).unwrap().as_array().unwrap().clone(),
            ),
            o => (None, o.as_array().unwrap().clone()),
        };
        let set_annots = |old: &Document, n: &mut Document, a: Vec<Object>| match annots_of(old).0 {
            Some(id) => {
                n.objects.insert(id, Object::Array(a));
            }
            None => {
                let mut p = old.get_dictionary(page).unwrap().clone();
                p.set("Annots", Object::Array(a));
                n.objects.insert(page, Object::Dictionary(p));
            }
        };
        let form_of = |d: &Document| match d.catalog().unwrap().get(b"AcroForm").unwrap() {
            Object::Reference(id) => (Some(*id), d.get_dictionary(*id).unwrap().clone()),
            o => (None, o.as_dict().unwrap().clone()),
        };
        let set_fields = |old: &Document, n: &mut Document, f: Vec<Object>| {
            let (form_id, mut form) = form_of(old);
            match form.get(b"Fields").unwrap() {
                Object::Reference(id) => {
                    n.objects.insert(*id, Object::Array(f));
                }
                _ => {
                    form.set("Fields", Object::Array(f));
                    match form_id {
                        Some(id) => {
                            n.objects.insert(id, Object::Dictionary(form));
                        }
                        None => {
                            let mut c = old.catalog().unwrap().clone();
                            c.set("AcroForm", Object::Dictionary(form));
                            n.objects.insert(root(old), Object::Dictionary(c));
                        }
                    }
                }
            }
        };

        // allowed: the information dictionary
        // (the indirect form's file has one, changed in place; the other gets a new one)
        let info = update(&two, |old, n, next| {
            let mut i = Dictionary::new();
            i.set("Producer", Object::string_literal("someone else"));
            match old.trailer.get(b"Info").and_then(Object::as_reference) {
                Ok(id) => {
                    n.objects.insert(id, Object::Dictionary(i));
                }
                Err(_) => {
                    n.objects.insert((next, 0), Object::Dictionary(i));
                    n.trailer.set("Info", Object::Reference((next, 0)));
                }
            }
            next
        });
        let r = e.verify(&info, None, None).unwrap();
        assert!(
            r.valid,
            "{form}: info: {:?}",
            r.signers
                .iter()
                .map(|s| &s.signature_error)
                .collect::<Vec<_>>()
        );

        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "a note on the page",
                update(&two, |old, n, next| {
                    let mut a = annots_of(old).1;
                    a.push(annot(n, next, None));
                    set_annots(old, n, a);
                    next
                }),
                "changed",
            ),
            (
                "a signature removed from the page",
                update(&two, |old, n, next| {
                    let mut a = annots_of(old).1;
                    a.remove(0);
                    set_annots(old, n, a);
                    next
                }),
                "changed",
            ),
            (
                "a text field",
                update(&two, |old, n, next| {
                    let mut f = form_of(old)
                        .1
                        .get(b"Fields")
                        .map(|o| old.dereference(o).unwrap().1.as_array().unwrap().clone())
                        .unwrap();
                    f.push(annot(n, next, Some("Tx")));
                    set_fields(old, n, f);
                    next
                }),
                "changed",
            ),
            (
                "the catalog's form replaced",
                update(&two, |old, n, next| {
                    let mut f = form_of(old).1;
                    f.set("NeedAppearances", true);
                    n.objects.insert((next, 0), Object::Dictionary(f));
                    let mut c = old.catalog().unwrap().clone();
                    c.set("AcroForm", Object::Reference((next, 0)));
                    n.objects.insert(root(old), Object::Dictionary(c));
                    next
                }),
                "the document catalog (object",
            ),
            (
                "the catalog",
                update(&two, |old, n, next| {
                    let mut c = old.catalog().unwrap().clone();
                    c.set("PageMode", Object::from("FullScreen"));
                    n.objects.insert(root(old), Object::Dictionary(c));
                    next
                }),
                "the document catalog (object",
            ),
            (
                "the page tree",
                update(&two, |old, n, next| {
                    let pages = old
                        .catalog()
                        .unwrap()
                        .get(b"Pages")
                        .unwrap()
                        .as_reference()
                        .unwrap();
                    let mut p = old.get_dictionary(pages).unwrap().clone();
                    p.set("Rotate", 90);
                    n.objects.insert(pages, Object::Dictionary(p));
                    next
                }),
                "the page tree (object",
            ),
            (
                "a signature's widget",
                update(&two, |old, n, next| {
                    let id = annots_of(old).1[0].as_reference().unwrap();
                    let mut w = old.get_dictionary(id).unwrap().clone();
                    w.set(
                        "Rect",
                        Object::Array(vec![0.into(), 0.into(), 500.into(), 500.into()]),
                    );
                    n.objects.insert(id, Object::Dictionary(w));
                    next
                }),
                "an annotation (object",
            ),
        ];
        for (what, evil, says) in cases {
            for err in errors(&e, &evil, &format!("{form}, {what}")) {
                assert!(
                    err.contains("changed after this signature") && err.contains(says),
                    "{form}, {what}: {err}"
                );
            }
        }
    }
}

/// A new signature field gets the first free name, and fields inside others are found by their
/// full names.
#[test]
fn signature_field_names() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let rsa = key(&e, "alice_rsa.p12");
    let plain = std::fs::read(fx.join("plain.pdf")).unwrap();
    // a text field already named Signature1
    let mut doc = Document::load_mem(&plain).unwrap();
    let tx = doc.add_object(Dictionary::from_iter([
        ("FT", Object::from("Tx")),
        ("T", Object::string_literal("Signature1")),
    ]));
    doc.catalog_mut().unwrap().set(
        "AcroForm",
        Dictionary::from_iter([("Fields", Object::Array(vec![Object::Reference(tx)]))]),
    );
    let mut taken = Vec::new();
    doc.save_to(&mut taken).unwrap();
    let signed = e.sign_pdf(&taken, &rsa, None, None).unwrap().cms;
    let r = e.verify(&signed, None, None).unwrap();
    assert!(r.valid);
    assert_eq!(
        r.signers[0].kind.as_deref(),
        Some("PDF signature \"Signature2\"")
    );

    // the signature's field moved under a parent field "form" that gives its type
    let mut doc = Document::load_mem(&e.sign_pdf(&plain, &rsa, None, None).unwrap().cms).unwrap();
    let widget = doc
        .catalog()
        .unwrap()
        .get(b"AcroForm")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"Fields")
        .unwrap()
        .as_array()
        .unwrap()[0]
        .as_reference()
        .unwrap();
    let parent = doc.add_object(Dictionary::from_iter([
        ("FT", Object::from("Sig")),
        ("T", Object::string_literal("form")),
        ("Kids", Object::Array(vec![Object::Reference(widget)])),
    ]));
    let w = doc.get_dictionary_mut(widget).unwrap();
    w.remove(b"FT");
    w.set("Parent", Object::Reference(parent));
    let mut form = doc
        .catalog()
        .unwrap()
        .get(b"AcroForm")
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    // listed twice: still one field
    form.set(
        "Fields",
        Object::Array(vec![Object::Reference(parent), Object::Reference(parent)]),
    );
    doc.catalog_mut().unwrap().set("AcroForm", form);
    let mut nested = Vec::new();
    doc.save_to(&mut nested).unwrap();
    // (rewritten whole, so the signature itself no longer holds: only the names are checked)
    let r = e.verify(&nested, None, None).unwrap();
    let kinds: Vec<_> = r.signers.iter().map(|s| s.kind.clone().unwrap()).collect();
    assert_eq!(kinds, ["PDF signature \"form.Signature1\""]);
}

/// The signed PDF's byte range as written: where its four numbers start, and their values.
fn byte_range(data: &[u8]) -> (usize, [usize; 4]) {
    let at = data.windows(11).rposition(|w| w == b"/ByteRange[").unwrap() + 11;
    let end = at + data[at..].iter().position(|&b| b == b']').unwrap();
    let v: Vec<usize> = std::str::from_utf8(&data[at..end])
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    (at, [v[0], v[1], v[2], v[3]])
}

/// `data` with the byte range rewritten to `r` (same widths: "0 " then three ten-digit
/// numbers).
fn with_range(data: &[u8], r: [i64; 4]) -> Vec<u8> {
    let (at, _) = byte_range(data);
    let mut d = data.to_vec();
    let text = format!("{} {:010} {:010} {:010}", r[0], r[1], r[2], r[3]);
    d[at..at + text.len()].copy_from_slice(text.as_bytes());
    d
}

/// A byte range must start at 0, leave out exactly the signature's <hex> value and stay within
/// the file; the value must hold one signer; the signature type must be one kzsigner reads.
#[test]
fn signature_fields_that_do_not_hold() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let rsa = key(&e, "alice_rsa.p12");
    let gost = key(&e, "alice_gost2015.p12");
    let signed = e
        .sign_pdf(
            &std::fs::read(fx.join("plain.pdf")).unwrap(),
            &rsa,
            None,
            None,
        )
        .unwrap();
    assert_eq!(signed.signer_count, 1);
    assert!(!signed.cosigned);
    let two = e.sign_pdf(&signed.cms, &gost, None, None).unwrap();
    assert!(two.cosigned && two.signer_count == 2);
    let pdf = signed.cms;
    assert!(e.verify(&pdf, None, None).unwrap().valid);
    let (_, [_, a, b, c]) = byte_range(&pdf);
    let (a, b, c) = (a as i64, b as i64, c as i64);
    let error = |d: &[u8]| {
        let r = e.verify(d, None, None).unwrap();
        assert!(!r.valid && !r.signers[0].signature_ok);
        r.signers[0].signature_error.clone().unwrap()
    };
    for (what, r, says) in [
        (
            "not from the start",
            [1, a - 1, b, c],
            "byte range is damaged",
        ),
        (
            "an empty gap",
            [0, a, a, c + b - a],
            "byte range is damaged",
        ),
        ("past the end", [0, a, b, c + 1], "byte range is damaged"),
        ("the gap without its <", [0, a + 1, b, c], "leaves out more"),
        (
            "the gap without its >",
            [0, a, b - 1, c + 1],
            "leaves out more",
        ),
        ("more than the value", [0, a - 1, b, c], "leaves out more"),
    ] {
        let err = error(&with_range(&pdf, r));
        assert!(err.contains(says), "{what}: {err}");
    }

    // the value, within its room: two signers
    let gap = &pdf[a as usize + 1..b as usize - 1];
    let hex = std::str::from_utf8(gap).unwrap();
    let mut der: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    // the zeros after the value are padding: cut at the length its header gives
    // (trimming zero digits could also cut the value's own last byte)
    let (head, len) = match der[1] {
        n if n < 0x80 => (2, n as usize),
        n => {
            let k = (n & 0x7f) as usize;
            (
                2 + k,
                der[2..2 + k].iter().fold(0, |l, &b| l << 8 | b as usize),
            )
        }
    };
    der.truncate(head + len);
    let sd = kzsigner::cms::SignedData::parse(&der).unwrap();
    let doubled = kzsigner::hex(&sd.merge(&sd).encode()).to_uppercase();
    assert!(doubled.len() <= gap.len());
    let mut d = pdf.clone();
    d[a as usize + 1..a as usize + 1 + doubled.len()].copy_from_slice(doubled.as_bytes());
    for x in &mut d[a as usize + 1 + doubled.len()..b as usize - 1] {
        *x = b'0';
    }
    assert!(error(&d).contains("exactly one signer"));

    // a signature type kzsigner does not read
    let i = pdf
        .windows(19)
        .position(|w| w == b"ETSI.CAdES.detached")
        .unwrap();
    let mut d = pdf.clone();
    d[i..i + 19].copy_from_slice(b"ETSI.CAdES.detacheX");
    let err = error(&d);
    assert!(
        err.contains("Unsupported PDF signature type: ETSI.CAdES.detacheX"),
        "{err}"
    );
}

/// Signature fields are found down to 32 levels of nesting, and named by their full path.
#[test]
fn deeply_nested_fields() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let found = |levels: usize| {
        let mut doc = Document::load(fx.join("plain.pdf")).unwrap();
        let v = doc.add_object(Dictionary::from_iter([
            ("Type", Object::from("Sig")),
            ("SubFilter", Object::from("ETSI.CAdES.detached")),
        ]));
        let mut field = doc.add_object(Dictionary::from_iter([
            ("FT", Object::from("Sig")),
            ("T", Object::string_literal("s")),
            ("V", Object::Reference(v)),
        ]));
        for _ in 1..levels {
            field = doc.add_object(Dictionary::from_iter([
                ("T", Object::string_literal("p")),
                ("Kids", Object::Array(vec![Object::Reference(field)])),
            ]));
        }
        doc.catalog_mut().unwrap().set(
            "AcroForm",
            Dictionary::from_iter([("Fields", Object::Array(vec![Object::Reference(field)]))]),
        );
        let mut data = Vec::new();
        doc.save_to(&mut data).unwrap();
        let r = e.verify(&data, None, None).unwrap();
        r.signers
            .into_iter()
            .map(|s| s.kind.unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(found(2), ["PDF signature \"p.s\""]);
    // the top field is at depth 0
    assert_eq!(found(33).len(), 1);
    assert!(found(34).is_empty());
}

/// More of what an update may change: the XMP metadata and the DSS may; an annotation known by
/// its Subtype and Rect alone, or a page's content stream, may not. A form in its own object
/// with its fields inline gains a field in place.
#[test]
fn metadata_dss_and_other_objects() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf");
    let e = engine();
    let (rsa, gost) = (key(&e, "alice_rsa.p12"), key(&e, "alice_gost2015.p12"));
    let mut doc = Document::load(fx.join("plain.pdf")).unwrap();
    let link = doc.add_object(Dictionary::from_iter([
        ("Subtype", Object::from("Link")),
        (
            "Rect",
            Object::Array(vec![0.into(), 0.into(), 9.into(), 9.into()]),
        ),
    ]));
    let meta = doc.add_object(Stream::new(
        Dictionary::from_iter([("Type", Object::from("Metadata"))]),
        b"<x:xmpmeta/>".to_vec(),
    ));
    let dss = doc.add_object(Dictionary::from_iter([("Certs", Object::Array(vec![]))]));
    let form = doc.add_object(Dictionary::from_iter([("Fields", Object::Array(vec![]))]));
    let page = first_page(&doc);
    doc.get_dictionary_mut(page)
        .unwrap()
        .set("Annots", Object::Array(vec![Object::Reference(link)]));
    let c = doc.catalog_mut().unwrap();
    c.set("Metadata", Object::Reference(meta));
    c.set("DSS", Object::Reference(dss));
    c.set("AcroForm", Object::Reference(form));
    let mut pdf = Vec::new();
    doc.save_to(&mut pdf).unwrap();

    let one = e.sign_pdf(&pdf, &rsa, None, None).unwrap().cms;
    let two = e.sign_pdf(&one, &gost, None, None).unwrap().cms;
    let r = e.verify(&two, None, None).unwrap();
    assert!(r.valid, "{:?}", r.signers);

    let allowed = [
        update(&two, |old, n, next| {
            let mut s = old.get_object(meta).unwrap().as_stream().unwrap().clone();
            s.set_content(b"<x:xmpmeta>changed</x:xmpmeta>".to_vec());
            n.objects.insert(meta, Object::Stream(s));
            next
        }),
        update(&two, |old, n, next| {
            let mut d = old.get_dictionary(dss).unwrap().clone();
            d.set("OCSPs", Object::Array(vec![]));
            n.objects.insert(dss, Object::Dictionary(d));
            next
        }),
    ];
    for d in allowed {
        let r = e.verify(&d, None, None).unwrap();
        assert!(
            r.valid,
            "{:?}",
            r.signers
                .iter()
                .map(|s| &s.signature_error)
                .collect::<Vec<_>>()
        );
    }
    let refused = [
        (
            update(&two, |old, n, next| {
                let mut d = old.get_dictionary(link).unwrap().clone();
                d.set(
                    "Rect",
                    Object::Array(vec![0.into(), 0.into(), 99.into(), 99.into()]),
                );
                n.objects.insert(link, Object::Dictionary(d));
                next
            }),
            "an annotation (object",
        ),
        (
            update(&two, |old, n, next| {
                let contents = old.get_dictionary(page).unwrap().get(b"Contents").unwrap();
                let id = match contents {
                    Object::Reference(id) => *id,
                    Object::Array(a) => a[0].as_reference().unwrap(),
                    _ => panic!("no contents"),
                };
                let mut s = old.get_object(id).unwrap().as_stream().unwrap().clone();
                s.set_content(b"BT /F1 40 Tf 50 700 Td (CHANGED) Tj ET".to_vec());
                n.objects.insert(id, Object::Stream(s));
                next
            }),
            "an object (object",
        ),
    ];
    for (d, says) in refused {
        for err in errors(&e, &d, says) {
            assert!(err.contains(says), "{err}");
        }
    }
}
