//! CMS signatures: the signed reference to the signer's certificate, checking a signature
//! without its document, and what a report says about each signer.

use std::path::PathBuf;

use kzsigner::cert::Cert;
use kzsigner::cms::{self, SignedData};
use kzsigner::trust::TrustStore;
use kzsigner::verify::{signing_certificate_matches, verify, verify_with};
use kzsigner::{Engine, der, gost, p12};

fn fixture(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn key(name: &str) -> p12::Key {
    p12::open(&std::fs::read(fixture(name)).unwrap(), "Qwerty12", None).unwrap()
}

fn ca(name: &str) -> Cert {
    Cert::parse(&std::fs::read(fixture(name)).unwrap()).unwrap()
}

/// A detached signature by alice (GOST 2015) over `data`.
fn signed(data: &[u8]) -> Vec<u8> {
    Engine::new(vec![ca("keys/ca_gost2015.cer")])
        .sign(
            data,
            &key("keys/alice_gost2015.p12"),
            true,
            None,
            None,
            false,
            None,
        )
        .unwrap()
        .cms
}

/// `c` with one byte of its CA's signature changed: the same names, serial and key.
fn forged(c: &Cert) -> Cert {
    let mut d = c.der.clone();
    let last = d.len() - 1;
    d[last] ^= 1;
    Cert::parse(&d).unwrap()
}

/// The signed reference to the certificate, in each form it comes in.
#[test]
fn signing_certificate_reference() {
    let alice = key("keys/alice_gost2015.p12").cert;
    let bob = key("keys/bob_gost2015.p12").cert;
    let sd = SignedData::parse(&signed(b"hello")).unwrap();
    let si = &sd.signers[0];
    assert!(signing_certificate_matches(si, &alice).unwrap());
    assert!(!signing_certificate_matches(si, &bob).unwrap());
    assert!(!signing_certificate_matches(si, &forged(&alice)).unwrap());

    // signed attributes with just this one attribute
    let with = |oid: &str, value: Vec<u8>| {
        let mut s = si.clone();
        s.signed_attrs = Some(der::sorted_set(
            der::ctx(0),
            &mut [cms::attribute(oid, &value)],
        ));
        s
    };
    let ess = |id: Vec<u8>| der::seq(&[&der::seq(&[&id])]);
    let v2 = cms::ATTR_SIGNING_CERT_V2;
    let v1 = cms::ATTR_SIGNING_CERT;
    let gost512 = gost::H_GOST2015_512;
    let h = |alg: &str, c: &Cert| der::octets(&gost::hash(alg, &c.der).unwrap());
    let alg = der::seq(&[&der::oid(gost512)]);
    for (name, s, want) in [
        // ESSCertIDv2 with its hash algorithm named
        (
            "v2 GOST",
            with(v2, ess(der::seq(&[&alg, &h(gost512, &alice)]))),
            true,
        ),
        (
            "v2 GOST, bob",
            with(v2, ess(der::seq(&[&alg, &h(gost512, &bob)]))),
            false,
        ),
        // the default, SHA-256
        (
            "v2 default",
            with(v2, ess(der::seq(&[&h(gost::H_SHA256, &alice)]))),
            true,
        ),
        (
            "v2 default, bob",
            with(v2, ess(der::seq(&[&h(gost::H_SHA256, &bob)]))),
            false,
        ),
        // the older ESSCertID, SHA-1
        (
            "v1",
            with(v1, ess(der::seq(&[&h(gost::H_SHA1, &alice)]))),
            true,
        ),
        (
            "v1, bob",
            with(v1, ess(der::seq(&[&h(gost::H_SHA1, &bob)]))),
            false,
        ),
        // none: nothing to compare
        (
            "none",
            with(cms::ATTR_CONTENT_TYPE, der::oid("1.2.840.113549.1.7.1")),
            true,
        ),
    ] {
        assert_eq!(
            signing_certificate_matches(&s, &alice).unwrap(),
            want,
            "{name}"
        );
    }

    // in a file: the signature checks, but its reference names another certificate
    let mut sd = SignedData::parse(&signed(b"hello")).unwrap();
    sd.certs = vec![forged(&alice).der];
    let rep = verify(&sd.encode(), Some(b"hello"), &TrustStore::new(vec![]), None).unwrap();
    let s = &rep.signers[0];
    assert!(!s.signature_ok && !rep.valid);
    assert!(
        s.signature_error
            .as_deref()
            .unwrap()
            .contains("signed reference"),
        "{:?}",
        s.signature_error
    );
}

/// Without the document, a signature can still be checked over its signed attributes.
#[test]
fn signature_without_its_document() {
    let trust = TrustStore::new(vec![ca("keys/ca_gost2015.cer")]);
    let good = signed(b"hello");
    let rep = verify_with(&good, None, &trust, None, true, None).unwrap();
    let s = &rep.signers[0];
    assert!(s.signature_ok, "{:?}", s.signature_error);
    let md = gost::hash(gost::H_GOST2015_512, b"hello").unwrap();
    assert!(
        s.warnings.iter().any(
            |w| w.contains("Only the signature was checked") && w.contains(&kzsigner::hex(&md))
        ),
        "{:?}",
        s.warnings
    );
    // never valid: the document was not compared
    assert!(!rep.valid);

    // a changed signature, or a reference to another certificate
    let mut sd = SignedData::parse(&good).unwrap();
    sd.signers[0].signature[3] ^= 1;
    let mut forged_cert = SignedData::parse(&good).unwrap();
    forged_cert.certs = vec![forged(&key("keys/alice_gost2015.p12").cert).der];
    let mut no_attrs = SignedData::parse(&good).unwrap();
    no_attrs.signers[0].signed_attrs = None;
    for (name, d) in [
        ("signature", sd),
        ("certificate", forged_cert),
        ("attributes", no_attrs),
    ] {
        let rep = verify_with(&d.encode(), None, &trust, None, true, None).unwrap();
        let s = &rep.signers[0];
        assert!(!s.signature_ok, "{name}");
        assert!(
            s.signature_error
                .as_deref()
                .unwrap()
                .contains("does not match"),
            "{name}"
        );
    }

    // a plain check of a detached signature without the document checks nothing
    let rep = verify(&good, None, &trust, None).unwrap();
    let s = &rep.signers[0];
    assert!(!s.signature_ok && !rep.valid);
    assert!(
        s.signature_error
            .as_deref()
            .unwrap()
            .contains("Not checked")
    );
}

#[test]
fn what_a_report_says() {
    let trust = TrustStore::new(vec![ca("keys/ca_gost2015.cer")]);
    let before = kzsigner::time::now_ms() / 1000 * 1000;
    let rep = verify(&signed(b"hello"), Some(b"hello"), &trust, None).unwrap();
    assert!(rep.valid);
    let s = &rep.signers[0];
    assert_eq!(s.index, 1);
    assert!(s.signing_time.is_some_and(|t| t >= before));
    assert_eq!(
        s.algorithm.as_deref(),
        Some("GOST 34.10-2015 (512) / GOST 34.11-2015")
    );
    assert_eq!(s.cert_valid_at_signing, Some(true));
    // no timestamp: the time is the signer's own claim; the certificate is valid now
    assert!(
        s.warnings
            .iter()
            .any(|w| w.contains("signer's own computer clock")),
        "{:?}",
        s.warnings
    );
    assert!(
        !s.warnings.iter().any(|w| w.contains("not valid")),
        "{:?}",
        s.warnings
    );
}
