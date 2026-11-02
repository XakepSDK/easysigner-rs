//! Order 500/НҚ p.16.4: a certificate signs documents only within its CA's rules (key usage,
//! purpose, certificate policy).

use std::path::PathBuf;

use kzsigner::cert::{self, Cert};
use kzsigner::der;
use kzsigner::trust::BUNDLED_CA;

fn bundled(name: &str) -> Cert {
    let (_, d) = BUNDLED_CA.iter().find(|(n, _)| *n == name).unwrap();
    Cert::parse_any(d).unwrap()
}

fn carol() -> Cert {
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ocsp/carol.p12");
    kzsigner::p12::open(&std::fs::read(f).unwrap(), "Qwerty12", None)
        .unwrap()
        .cert
}

/// `c` with extension `oid` set to `value` (or removed).
fn with(mut c: Cert, oid: &str, value: Option<Vec<u8>>) -> Cert {
    c.extensions.retain(|(o, _)| o != oid);
    if let Some(v) = value {
        c.extensions.push((oid.into(), v));
    }
    c
}

fn policies(oids: &[&str]) -> Option<Vec<u8>> {
    let items: Vec<Vec<u8>> = oids.iter().map(|o| der::seq(&[&der::oid(o)])).collect();
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    Some(der::seq(&refs))
}

#[test]
fn policies_must_be_the_cas() {
    let nca = bundled("nca_gost_2022");
    assert_eq!(nca.policies().unwrap(), ["1.2.398.3.3.2"]);
    let c = carol();
    for ok in ["1.2.398.3.3.2", "1.2.398.3.3.2.1"] {
        let c = with(c.clone(), "2.5.29.32", policies(&[ok]));
        assert_eq!(cert::usage_problem(&c, &nca), None, "{ok}");
    }
    for bad in [&["1.2.398.3.3.1.1"][..], &["1.2.398.3.3.20"], &[]] {
        let c = with(c.clone(), "2.5.29.32", policies(bad));
        assert!(cert::usage_problem(&c, &nca).is_some(), "{bad:?}");
    }
    let none = with(c.clone(), "2.5.29.32", None);
    assert!(cert::usage_problem(&none, &nca).is_some());

    // a CA without the extension, or with anyPolicy, sets no rule on policies
    let open = with(nca.clone(), "2.5.29.32", None);
    assert_eq!(cert::usage_problem(&none, &open), None);
    let any = with(nca, "2.5.29.32", policies(&["2.5.29.32.0"]));
    assert_eq!(cert::usage_problem(&none, &any), None);
}

#[test]
fn service_and_ca_keys_may_not_sign_documents() {
    let ca = carol(); // no policies: only usage counts here
    let ca = with(ca, "2.5.29.32", None);
    let c = carol();
    assert_eq!(cert::usage_problem(&c, &ca), None);

    // keyCertSign and cRLSign only
    let ku = |bits: u8| Some(der::tlv(der::BIT_STRING, &[1, bits]));
    assert!(cert::usage_problem(&with(c.clone(), "2.5.29.15", ku(0x06)), &ca).is_some());
    // digitalSignature alone (an AUTH key) is allowed here; signing warns about it
    assert_eq!(
        cert::usage_problem(&with(c.clone(), "2.5.29.15", ku(0x80)), &ca),
        None
    );

    let eku = |o: &str| Some(der::seq(&[&der::oid(o)]));
    for o in [cert::EKU_TIME_STAMPING, cert::EKU_OCSP_SIGNING] {
        assert!(cert::usage_problem(&with(c.clone(), "2.5.29.37", eku(o)), &ca).is_some());
    }
    assert_eq!(
        cert::usage_problem(&with(c, "2.5.29.37", eku(cert::EKU_CLIENT_AUTH)), &ca),
        None
    );
}
