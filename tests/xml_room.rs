//! Whether another XML signature can go inside a signed document (what the window asks before
//! offering it), and that the answer matches what signing does.

use std::path::PathBuf;

use kzsigner::{Engine, cert::Cert, p12};

fn fixture(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn key(name: &str) -> p12::Key {
    p12::open(&std::fs::read(fixture(name)).unwrap(), "Qwerty12", None).unwrap()
}

#[test]
fn room_for_another_signature() {
    let ca = Cert::parse(&std::fs::read(fixture("keys/ca_gost2015.cer")).unwrap()).unwrap();
    let e = Engine::new(vec![ca]);
    let doc = b"<?xml version=\"1.0\"?>\n<r Id=\"r\"><a>1</a></r>\n";
    assert!(e.xml_has_room(doc), "an unsigned document");
    assert!(!e.xml_has_room(b"<r><a>"), "broken XML");

    let signed = e
        .sign_xml(doc, &key("keys/alice_gost2015.p12"), None, None)
        .unwrap()
        .cms;
    assert!(
        e.xml_has_room(&signed),
        "kzsigner's signature leaves the others out"
    );
    let two = e
        .sign_xml(&signed, &key("keys/bob_gost2015.p12"), None, None)
        .unwrap();
    assert!(two.cosigned && two.signer_count == 2);
    let rep = e.verify(&two.cms, None, None).unwrap();
    assert!(rep.valid && rep.signers.len() == 2);

    // without the filter, the first signature covers whatever comes later
    let text = String::from_utf8(signed).unwrap();
    let a = text
        .find("<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\"")
        .unwrap();
    let b = a + text[a..].find("</ds:Transform>").unwrap() + "</ds:Transform>".len();
    let closed = format!("{}{}", &text[..a], &text[b..]);
    assert!(!e.xml_has_room(closed.as_bytes()));
    assert!(
        e.sign_xml(closed.as_bytes(), &key("keys/bob_gost2015.p12"), None, None)
            .is_err()
    );
    // a reference to something that does not hold the new signature is no obstacle
    let part = closed.replacen(
        "<ds:Reference URI=\"\"",
        "<ds:Reference URI=\"#nowhere\"",
        1,
    );
    assert!(!e.xml_has_room(part.as_bytes()), "an unresolved reference");
    let inner = closed
        .replacen("<a>1</a>", "<a Id=\"a\">1</a>", 1)
        .replacen("<ds:Reference URI=\"\"", "<ds:Reference URI=\"#a\"", 1);
    assert!(
        e.xml_has_room(inner.as_bytes()),
        "a part beside the new signature"
    );
    // an XPath 1.0 filter outside the signature namespace is not understood
    let xpath = text.replacen(
        &text[a..b],
        "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">\
         <XPath xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">not(ancestor-or-self::ds:Signature)</XPath></ds:Transform>",
        1,
    );
    assert!(!e.xml_has_room(xpath.as_bytes()));
    let xpath_ds =
        xpath
            .replacen("<XPath ", "<ds:XPath ", 1)
            .replacen("</XPath>", "</ds:XPath>", 1);
    assert!(e.xml_has_room(xpath_ds.as_bytes()));
}
