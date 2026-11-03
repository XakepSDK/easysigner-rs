use kzsigner::p12;

#[test]
fn opens_all_fixture_keys() {
    for dir in ["tests/fixtures/keys", "tests/fixtures/kalkan"] {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "p12") {
                let k = p12::open(&std::fs::read(&p).unwrap(), "Qwerty12", None)
                    .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
                println!(
                    "{} alias={} cn={} chain={}",
                    p.display(),
                    k.alias,
                    k.cert.cn(),
                    k.chain.len()
                );
                let sig = k.private_key.sign(b"hello").unwrap();
                assert!(
                    k.cert
                        .public_key()
                        .unwrap()
                        .verify(k.private_key.sig_oid(), None, b"hello", &sig)
                        .unwrap()
                );
                assert!(
                    k.cert
                        .public_key()
                        .map(|p| k.private_key.matches(&p))
                        .unwrap()
                );
                if k.chain.len() > 1 {
                    assert!(
                        k.chain[0].signed_by(&k.chain[1]),
                        "chain sig {}",
                        p.display()
                    );
                }
            }
        }
    }
}

#[test]
fn wrong_password() {
    let e = p12::open(
        &std::fs::read("tests/fixtures/kalkan/alice_rsa.p12").unwrap(),
        "x",
        None,
    )
    .err()
    .unwrap();
    assert!(e.0.contains("password is probably wrong"), "{e}");
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{p}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn aliases_and_chains() {
    for a in ["rsa", "gost2004", "gost2015", "gost2015_256"] {
        for (who, cn) in [("alice", "ИВАНОВ АЛИБЕК"), ("bob", "ПЕТРОВА АЙГУЛЬ")]
        {
            let k = p12::open(&read(&format!("keys/{who}_{a}.p12")), "Qwerty12", None).unwrap();
            assert_eq!(k.alias, who);
            assert!(k.other_aliases.is_empty());
            assert_eq!(k.cert.cn(), cn);
            // the key's certificate, then its CA's
            assert_eq!(k.chain.len(), 2, "{who} {a}");
            assert_eq!(k.chain[0], k.cert);
            assert_eq!(k.chain[1].cn(), format!("TEST KZ CA {a}"));
        }
    }
    let tsa = p12::open(&read("keys/tsa.p12"), "Qwerty12", None).unwrap();
    assert_eq!(tsa.chain, vec![tsa.cert.clone()]);
    let k = p12::open(&read("kalkan/alice_rsa.p12"), "Qwerty12", None).unwrap();
    assert_eq!(k.alias, "key");
}

/// PBES2 with each cipher, an unencrypted key bag and a file without a MAC open to the same key.
#[test]
fn other_pkcs12_forms() {
    let want = p12::open(&read("keys/alice_rsa.p12"), "Qwerty12", None).unwrap();
    for f in ["aes128", "aes192", "des3", "plain", "nomac"] {
        let k = p12::open(&read(&format!("p12/{f}.p12")), "Qwerty12", None)
            .unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(k.alias, "alice", "{f}");
        assert_eq!(k.cert, want.cert, "{f}");
        assert_eq!(k.chain.len(), 2, "{f}");
        assert!(
            k.private_key.matches(&want.cert.public_key().unwrap()),
            "{f}"
        );
    }
    for f in ["aes128", "des3", "plain"] {
        let e = p12::open(&read(&format!("p12/{f}.p12")), "Qwerty13", None)
            .err()
            .unwrap();
        assert!(e.0.contains("password is probably wrong"), "{f}: {e}");
    }
}

/// A file whose MAC does not match is refused, even with the right password.
#[test]
fn bad_mac() {
    for f in ["keys/alice_gost2015.p12", "p12/plain.p12"] {
        let mut d = read(f);
        let pfx = kzsigner::der::parse(&d)
            .unwrap()
            .items(kzsigner::der::SEQUENCE)
            .unwrap();
        let mac = pfx[2].items(kzsigner::der::SEQUENCE).unwrap();
        let digest = mac[0].items(kzsigner::der::SEQUENCE).unwrap()[1]
            .octets()
            .unwrap();
        let at = d.windows(digest.len()).position(|w| w == digest).unwrap();
        d[at] ^= 1;
        let e = p12::open(&d, "Qwerty12", None).err().unwrap();
        assert_eq!(
            e.0, "Could not open the key file. The password is probably wrong.",
            "{f}"
        );
    }
}

#[test]
fn not_pkcs12() {
    use kzsigner::der::{oid, seq, small_int, tlv};
    let data = oid("1.2.840.113549.1.7.1");
    let signed = oid("1.2.840.113549.1.7.2");
    let content = tlv(0xa0, &kzsigner::der::octets(&seq(&[])));
    for (d, why) in [
        (seq(&[&small_int(3)]), "too few fields"),
        (
            seq(&[&small_int(3), &seq(&[&data])]),
            "public-key integrity",
        ),
        (
            seq(&[&small_int(3), &seq(&[&signed, &content])]),
            "public-key integrity",
        ),
    ] {
        let e = p12::open(&d, "Qwerty12", None).err().unwrap();
        assert!(e.0.contains("not a PKCS#12") && e.0.contains(why), "{e}");
    }
    // the right shape with nothing inside
    let e = p12::open(
        &seq(&[&small_int(3), &seq(&[&data, &content])]),
        "Qwerty12",
        None,
    )
    .err()
    .unwrap();
    assert!(e.0.contains("no private key"), "{e}");
}
