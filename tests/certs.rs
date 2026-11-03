//! Certificates and keys: what trusting a certificate rests on (its CA's signature, its dates,
//! the CA's rights), how a certificate is described to people, and which private key goes with
//! which certificate.

use std::path::PathBuf;

use kzsigner::cert::{self, Cert};
use kzsigner::trust::TrustStore;
use kzsigner::{Engine, cms, der, p12};

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

/// `c` with one byte of its CA's signature changed.
fn forged(c: &Cert) -> Cert {
    let mut der = c.der.clone();
    let last = der.len() - 1;
    der[last] ^= 1;
    Cert::parse(&der).unwrap()
}

#[test]
fn trust_rests_on_the_ca_signature() {
    for a in ["rsa", "gost2004", "gost2015"] {
        let ca = ca(&format!("keys/ca_{a}.cer"));
        let alice = key(&format!("keys/alice_{a}.p12")).cert;
        let store = TrustStore::new(vec![ca.clone()]);
        let now = kzsigner::time::now_ms();
        assert!(alice.signed_by(&ca), "{a}");
        assert!(store.check(&alice, now).ok, "{a}");

        // the same names, but not the CA's signature
        let fake = forged(&alice);
        assert!(!fake.signed_by(&ca), "{a}");
        let chain = store.check(&fake, now);
        assert!(!chain.ok && chain.issuer.is_none(), "{a}: {}", chain.status);

        // a trusted root whose own signature is broken
        let bad_root = forged(&ca);
        let chain = TrustStore::new(vec![bad_root.clone()]).check(&bad_root, now);
        assert!(!chain.ok, "{a}");
        assert!(chain.status.contains("signature"), "{a}: {}", chain.status);

        // a certificate is not its own CA
        assert!(!alice.signed_by(&alice), "{a}");
    }
}

#[test]
fn dates_and_ca_rights() {
    let ca = ca("keys/ca_rsa.cer");
    let alice = key("keys/alice_rsa.p12").cert;
    assert!(alice.not_before < alice.not_after);
    assert!(!alice.valid_on(alice.not_before - 1));
    assert!(alice.valid_on(alice.not_before));
    assert!(alice.valid_on(alice.not_after));
    assert!(!alice.valid_on(alice.not_after + 1));
    let store = TrustStore::new(vec![ca.clone()]);
    assert!(store.check(&alice, alice.not_before).ok);
    let late = store.check(&alice, alice.not_after + 1);
    assert!(
        !late.ok && late.status.contains("not valid on"),
        "{}",
        late.status
    );

    assert!(ca.is_ca() && ca.may_sign_certs());
    assert!(!alice.is_ca(), "CA:FALSE");
    assert!(!alice.may_sign_certs(), "key usage without keyCertSign");
    assert!(ca.self_issued() && !alice.self_issued());
}

#[test]
fn names() {
    let alice = key("keys/alice_rsa.p12").cert;
    let ca = ca("keys/ca_rsa.cer");
    assert_eq!(
        cert::dn(&ca.subject),
        "CN=TEST KZ CA rsa, O=kzsigner test, C=KZ"
    );
    let rdns = alice.subject_rdns();
    assert!(rdns.contains(&("SERIALNUMBER".into(), "IIN123456789012".into())));
    assert!(rdns.contains(&("C".into(), "KZ".into())));
    assert_eq!(alice.cn(), "ИВАНОВ АЛИБЕК");
    assert_eq!(cert::holder_name(&alice), "ИВАНОВ АЛИБЕК");
    assert_eq!(alice.serial_hex(), "58cadcceeefa9dba");
    assert_eq!(cert::types(&alice), vec!["SIGNATURE".to_string()]);
    assert!(cert::types(&ca).is_empty());

    // equal names: the same bytes, or the same text in another case and spacing
    assert!(cert::names_equal(&alice.issuer, &ca.subject));
    assert!(!cert::names_equal(&alice.subject, &ca.subject));
    let text = String::from_utf8_lossy(&ca.subject).into_owned();
    assert!(text.contains("kzsigner test"));
    let spaced = ca
        .subject
        .windows(13)
        .position(|w| w == b"kzsigner test")
        .map(|i| {
            let mut v = ca.subject.clone();
            v[i..i + 13].copy_from_slice(b"KZSIGNER TEST");
            v
        })
        .unwrap();
    assert!(cert::names_equal(&spaced, &ca.subject));
    // and spacing: one name, written with extra spaces and as another string type
    let name = |tag: u8, cn: &str| {
        der::seq(&[&der::set_of(vec![der::seq(&[
            &der::oid("2.5.4.3"),
            &der::tlv(tag, cn.as_bytes()),
        ])])])
    };
    assert!(cert::names_equal(
        &name(0x0c, "Test  KZ   CA"),
        &name(0x13, " test kz ca ")
    ));
    assert!(!cert::names_equal(
        &name(0x0c, "Test KZ CA"),
        &name(0x0c, "TestKZ CA")
    ));
    assert!(!cert::names_equal(b"", b"\x30\x00"));

    // the report a verification shows
    let r = Engine::new(vec![]).describe(&alice);
    assert_eq!(r.serial_hex.as_deref(), Some("58cadcceeefa9dba"));
    assert!(r.subject.contains(&("IIN".into(), "123456789012".into())));
    assert_eq!(r.issuer_cn.as_deref(), Some("TEST KZ CA rsa"));
}

#[test]
fn key_algorithms() {
    let rsa = key("keys/alice_rsa.p12").cert;
    let g15 = key("keys/alice_gost2015.p12").cert;
    let g04 = key("keys/alice_gost2004.p12").cert;
    assert_eq!(rsa.key_alg(), kzsigner::gost::RSA_ENCRYPTION);
    assert_eq!(cert::key_alg_name(&rsa), "RSA");
    assert_eq!(
        cert::key_alg_name(&g15),
        "GOST 34.10-2015 (512) / GOST 34.11-2015"
    );
    assert_eq!(
        cert::key_alg_name(&g04),
        "GOST 34.310-2004 / GOST 34.311-95"
    );
    assert_eq!(
        cert::alg_name(
            kzsigner::gost::RSA_ENCRYPTION,
            Some(kzsigner::gost::H_SHA256)
        ),
        "RSA / SHA-256"
    );
    assert_eq!(cert::digest_label(Some(kzsigner::gost::H_SHA1)), "SHA-1");
    for c in [&rsa, &g15, &g04] {
        assert!(kzsigner::gost::is_gost(&c.key_alg()) != (c == &rsa));
        // the key bits are the end of the SubjectPublicKeyInfo
        let bits = c.public_key_bits().unwrap();
        assert!(bits.len() > 32 && c.spki.ends_with(&bits));
    }
}

#[test]
fn keys_match_their_certificates() {
    for a in ["rsa", "gost2004", "gost2015", "gost2015_256"] {
        let alice = key(&format!("keys/alice_{a}.p12"));
        let bob = key(&format!("keys/bob_{a}.p12"));
        assert!(
            alice.private_key.matches(&alice.cert.public_key().unwrap()),
            "{a}"
        );
        assert!(
            !alice.private_key.matches(&bob.cert.public_key().unwrap()),
            "{a}"
        );
    }
    let rsa = key("keys/alice_rsa.p12");
    let gost = key("keys/alice_gost2015.p12");
    assert!(!rsa.private_key.matches(&gost.cert.public_key().unwrap()));
    assert!(!gost.private_key.matches(&rsa.cert.public_key().unwrap()));
}

#[test]
fn warnings_about_a_key() {
    let alice = key("keys/alice_gost2015.p12").cert;
    assert!(cert::key_warnings(&alice).is_empty());
    let mut old = alice.clone();
    old.not_after = 1_000;
    let w = cert::key_warnings(&old);
    assert!(w.len() == 1 && w[0].contains("expired"), "{w:?}");
    let mut early = alice.clone();
    early.not_before = i64::MAX / 2;
    let w = Engine::new(vec![]).key_warnings(&early);
    assert!(w.len() == 1 && w[0].contains("not valid until"), "{w:?}");
    // a CA key has no non-repudiation usage
    let w = cert::key_warnings(&ca("keys/ca_gost2015.cer"));
    assert!(w.len() == 1 && w[0].contains("non-repudiation"), "{w:?}");
}

#[test]
fn signing_time_and_signed_files() {
    let e = Engine::new(vec![ca("keys/ca_gost2015.cer")]);
    let before = kzsigner::time::now_ms() / 1000 * 1000;
    let signed = e
        .sign(
            b"hello",
            &key("keys/alice_gost2015.p12"),
            false,
            None,
            None,
            false,
            None,
        )
        .unwrap()
        .cms;
    let after = kzsigner::time::now_ms();
    let sd = cms::SignedData::parse(&signed).unwrap();
    let t = sd.signers[0].signing_time().unwrap();
    assert!(t >= before && t <= after, "{before} <= {t} <= {after}");
    assert!(e.is_signed_cms(&signed));
    assert!(!e.is_signed_cms(b"hello"));
    assert!(kzsigner::crypto_version().contains("GOST"));
    assert!(kzsigner::version().contains('.'));
}

/// A certificate for `subject`'s public key, issued and signed by `issuer` (any key, CA or
/// not), valid as long as the issuer's certificate.
fn issue(issuer: &p12::Key, subject: &Cert) -> Cert {
    let alg = der::alg_null(issuer.private_key.sig_oid());
    let validity = der::seq(&[
        &kzsigner::time::encode_generalized(issuer.cert.not_before),
        &kzsigner::time::encode_generalized(issuer.cert.not_after),
    ]);
    let tbs = der::seq(&[
        &der::tlv(der::ctx(0), &der::small_int(2)),
        &der::small_int(4242),
        &alg,
        &issuer.cert.subject,
        &validity,
        &subject.subject,
        &subject.spki,
    ]);
    let sig = issuer.private_key.sign(&tbs).unwrap();
    Cert::parse(&der::seq(&[&tbs, &alg, &der::bit_string(&sig)])).unwrap()
}

/// Only a CA's certificate may issue others: one issued by a person's key is not trusted, even
/// when that person's certificate is.
#[test]
fn issuers_must_be_cas() {
    let ca = ca("keys/ca_rsa.cer");
    let alice = key("keys/alice_rsa.p12");
    let bob = key("keys/bob_rsa.p12").cert;
    let now = kzsigner::time::now_ms();
    let by_alice = issue(&alice, &bob);
    assert!(by_alice.signed_by(&alice.cert));
    let store = TrustStore::new(vec![ca.clone(), alice.cert.clone()]);
    let chain = store.check(&by_alice, now);
    assert!(!chain.ok, "{}", chain.status);
    assert!(chain.status.contains("is not a CA"), "{}", chain.status);

    // a trusted certificate that is not a root still needs its own issuer
    let chain = TrustStore::new(vec![alice.cert.clone()]).check(&alice.cert, now);
    assert!(!chain.ok && chain.issuer.is_none(), "{}", chain.status);
    assert!(
        chain.status.contains("Issuer not found"),
        "{}",
        chain.status
    );
}
