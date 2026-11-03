//! XML signatures: which certificate in KeyInfo is the signer's, its signed reference, and which
//! transforms count as leaving the other signatures out.

use std::path::PathBuf;

use base64::Engine as _;
use kzsigner::{Engine, cert::Cert, p12};

fn fixture(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn key(name: &str) -> p12::Key {
    p12::open(&std::fs::read(fixture(name)).unwrap(), "Qwerty12", None).unwrap()
}

fn ca() -> Cert {
    Cert::parse(&std::fs::read(fixture("keys/ca_gost2015.cer")).unwrap()).unwrap()
}

fn b64(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

fn signed() -> String {
    let doc = b"<?xml version=\"1.0\"?>\n<r Id=\"r\"><a>1</a></r>\n";
    let s = Engine::new(vec![ca()])
        .sign_xml(doc, &key("keys/alice_gost2015.p12"), None, None)
        .unwrap()
        .cms;
    String::from_utf8(s).unwrap()
}

#[test]
fn the_signers_certificate() {
    let e = Engine::new(vec![ca()]);
    let text = signed();
    let alice = key("keys/alice_gost2015.p12").cert;
    let mine = format!(
        "<ds:X509Certificate>{}</ds:X509Certificate>",
        b64(&alice.der)
    );
    assert!(text.contains(&mine));
    assert!(e.verify(text.as_bytes(), None, None).unwrap().valid);

    // KeyInfo with the CA's certificate too, before or after: the signer's is the one that
    // issued no other
    let ca_cert = format!(
        "<ds:X509Certificate>{}</ds:X509Certificate>",
        b64(&ca().der)
    );
    for both in [format!("{ca_cert}{mine}"), format!("{mine}{ca_cert}")] {
        let t = text.replacen(&mine, &both, 1);
        let r = e.verify(t.as_bytes(), None, None).unwrap();
        assert!(r.valid, "{:?}", r.signers[0].signature_error);
        assert_eq!(
            r.signers[0].serial_hex.as_deref(),
            Some(alice.serial_hex().as_str())
        );
    }

    // KeyInfo is not signed: a certificate with the same key and names but not the one the
    // signed properties name is refused
    let mut der = alice.der.clone();
    let last = der.len() - 1;
    der[last] ^= 1;
    let other = format!("<ds:X509Certificate>{}</ds:X509Certificate>", b64(&der));
    let r = e
        .verify(text.replacen(&mine, &other, 1).as_bytes(), None, None)
        .unwrap();
    let s = &r.signers[0];
    assert!(!r.valid && !s.signature_ok);
    assert!(
        s.signature_error
            .as_deref()
            .unwrap_or("")
            .contains("certificate"),
        "{:?}",
        s.signature_error
    );
}

/// Which forms of the transform leave the other signatures out, so that another signature may
/// go in.
#[test]
fn transforms_that_leave_signatures_out() {
    let e = Engine::new(vec![ca()]);
    let text = signed();
    let a = text
        .find("<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\"")
        .unwrap();
    let b = a + text[a..].find("</ds:Transform>").unwrap() + "</ds:Transform>".len();
    let filter2 = |attrs: &str, expr: &str| {
        format!(
            "<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\">\
             <f:XPath xmlns:f=\"http://www.w3.org/2002/06/xmldsig-filter2\" {attrs}>{expr}</f:XPath>\
             </ds:Transform>"
        )
    };
    let subtract = "Filter=\"subtract\"";
    for (t, room) in [
        (filter2(subtract, "/descendant::ds:Signature"), true),
        (filter2(subtract, " // ds:Signature "), true),
        (
            filter2("Filter=\"union\"", "/descendant::ds:Signature"),
            false,
        ),
        (filter2(subtract, "/descendant::ds:Object"), false),
        (filter2(subtract, "/descendant::Signature"), false),
        // the prefix must name the signature namespace
        (
            filter2(
                &format!("{subtract} xmlns:x=\"urn:other\""),
                "//x:Signature",
            ),
            false,
        ),
        // the XPath element must be filter2's
        (
            "<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\">\
             <x:XPath xmlns:x=\"urn:other\" Filter=\"subtract\">//ds:Signature</x:XPath>\
             </ds:Transform>"
                .into(),
            false,
        ),
    ] {
        let doc = format!("{}{t}{}", &text[..a], &text[b..]);
        assert_eq!(e.xml_has_room(doc.as_bytes()), room, "{t}");
    }
}

/// Documents of other shapes: an empty root element written as `<r/>`, and a DTD with an
/// entity.
#[test]
fn document_shapes() {
    let e = Engine::new(vec![ca()]);
    let alice = key("keys/alice_gost2015.p12");
    for doc in [
        "<r/>",
        "<?xml version=\"1.0\"?>\n<r a=\"1\"/>\n",
        "<r\n/>",
        "<?xml version=\"1.0\"?>\n<!DOCTYPE r [<!ENTITY e \"x\">]>\n<r>&e;</r>\n",
    ] {
        let signed = e.sign_xml(doc.as_bytes(), &alice, None, None).unwrap().cms;
        let text = String::from_utf8(signed.clone()).unwrap();
        assert!(text.trim_end().ends_with("</r>"), "{doc}: {text}");
        let r = e.verify(&signed, None, None).unwrap();
        assert!(r.valid, "{doc}: {:?}", r.signers[0].signature_error);
        assert_eq!(r.content_size, signed.len() as u64);
        assert!(r.has_content);
    }
    // two signers, numbered in order
    let one = e.sign_xml(b"<r/>", &alice, None, None).unwrap().cms;
    let two = e
        .sign_xml(&one, &key("keys/bob_gost2015.p12"), None, None)
        .unwrap()
        .cms;
    let r = e.verify(&two, None, None).unwrap();
    let idx: Vec<usize> = r.signers.iter().map(|s| s.index).collect();
    assert_eq!(idx, [1, 2]);
}
