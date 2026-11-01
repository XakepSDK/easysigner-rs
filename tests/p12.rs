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
