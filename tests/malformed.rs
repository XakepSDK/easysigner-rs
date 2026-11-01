//! Damaged and hostile input must give an error, never a crash (release builds abort on panic):
//! fixtures with bytes changed or cut off, deep nesting, broken OIDs.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use kzsigner::{Engine, p12};

/// A small deterministic generator, so a failure can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn damaged(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut d = data.to_vec();
    match rng.below(4) {
        0 => {
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(d.len());
                d[i] = rng.next() as u8;
            }
        }
        1 => d.truncate(rng.below(d.len())),
        2 => {
            // a length byte set to something large or indefinite
            let i = rng.below(d.len());
            d[i] = [0x80, 0x81, 0x84, 0xff][rng.below(4)];
        }
        _ => {
            let i = rng.below(d.len());
            let j = (i + 1 + rng.below(64)).min(d.len());
            d.drain(i..j);
        }
    }
    d
}

fn no_panic(what: &str, f: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        panic!("panicked on {what}");
    }
}

#[test]
fn damaged_files_give_errors_not_crashes() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let e = Engine::new(vec![]);
    let cms: Vec<Vec<u8>> = [
        "kalkan/cosigned_gost2015.cms",
        "kalkan/timestamped_rsa.cms",
        "kalkan/detached_gost2015.cms",
    ]
    .iter()
    .map(|f| std::fs::read(fx.join(f)).unwrap())
    .collect();
    let keys: Vec<Vec<u8>> = [
        "kalkan/alice_gost2015.p12",
        "kalkan/alice_rsa.p12",
        "keys/alice_gost2004.p12",
    ]
    .iter()
    .map(|f| std::fs::read(fx.join(f)).unwrap())
    .collect();
    let mut rng = Rng(1);
    for round in 0..1500 {
        let c = damaged(&mut rng, &cms[round % cms.len()]);
        no_panic(&format!("cms round {round}"), || {
            let _ = e.verify(&c, Some(b"x"), None);
            let _ = e.extract(&c);
            let _ = e.is_signed_cms(&c);
        });
        let k = damaged(&mut rng, &keys[round % keys.len()]);
        no_panic(&format!("p12 round {round}"), || {
            let _ = p12::open(&k, "Qwerty12", None);
        });
    }
}

#[test]
fn deep_nesting_and_bad_oids_are_errors() {
    let e = Engine::new(vec![]);
    // 200 000 nested indefinite-length SEQUENCEs
    let mut deep = b"\x30\x80".repeat(200_000);
    deep.extend(b"\x00\x00".repeat(200_000));
    assert!(e.verify(&deep, None, None).is_err());
    // nested constructed OCTET STRINGs
    let mut d = vec![0x04, 0x00];
    for _ in 0..100 {
        let mut n = vec![0x24, 0x80];
        n.extend(&d);
        n.extend([0, 0]);
        d = n;
    }
    assert!(kzsigner::der::parse(&d).and_then(|t| t.octets()).is_err());
    // an OID whose last byte says "more follows"
    assert!(
        kzsigner::der::parse(b"\x06\x01\x80")
            .and_then(|t| t.oid())
            .is_err()
    );
    assert!(
        kzsigner::der::parse(b"\x06\x0b\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
            .and_then(|t| t.oid())
            .is_err()
    );
}

/// PDFs (plain, object streams, signed) with bytes changed or cut, for checking, signing and
/// reading as a card.
#[test]
fn damaged_pdfs_give_errors_not_crashes() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let e = Engine::new(vec![]);
    let key = e
        .open_key(
            &std::fs::read(fx.join("kalkan/alice_rsa.p12")).unwrap(),
            "Qwerty12",
            None,
        )
        .unwrap();
    let mut pdfs: Vec<Vec<u8>> = ["pdf/plain.pdf", "pdf/objstm.pdf", "pdf/land.pdf"]
        .iter()
        .map(|f| std::fs::read(fx.join(f)).unwrap())
        .collect();
    let signed = e.sign_pdf(&pdfs[0], &key, None).unwrap().cms;
    let twice = e.sign_pdf(&signed, &key, None).unwrap().cms;
    pdfs.push(e.sign_pdf(&pdfs[1], &key, None).unwrap().cms);
    pdfs.push(twice);
    let mut rng = Rng(7);
    for round in 0..1200 {
        let p = damaged(&mut rng, &pdfs[round % pdfs.len()]);
        no_panic(&format!("pdf round {round}"), || {
            let _ = e.verify(&p, None, None);
            let _ = e.card_original(&p);
            if round % 4 == 0 {
                let _ = e.sign_pdf(&p, &key, None);
            }
        });
    }
}

#[test]
fn hostile_pdfs_give_errors_not_crashes() {
    let e = Engine::new(vec![]);
    let pdf = |body: &str| {
        format!(
            "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R] >> >>\nendobj\n{body}\ntrailer\n<< /Root 1 0 R /Size 9 >>\n%%EOF\n"
        )
        .into_bytes()
    };
    let cases = [
        // a page tree that contains itself
        pdf(
            "2 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /FT /Sig /Kids [3 0 R] >>\nendobj",
        ),
        // deeply nested arrays and dictionaries
        pdf(&format!(
            "2 0 obj\n{}{}\nendobj",
            "[".repeat(100_000),
            "]".repeat(100_000)
        )),
        pdf(&format!(
            "2 0 obj\n{}{}\nendobj",
            "<< /A ".repeat(50_000),
            ">>".repeat(50_000)
        )),
        // a signature whose byte range points outside the file
        pdf(
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n3 0 obj\n<< /FT /Sig /T (s) /V << /SubFilter /ETSI.CAdES.detached /ByteRange [0 99999999999 1 -5] /Contents <3080> >> >>\nendobj",
        ),
    ];
    for (i, c) in cases.iter().enumerate() {
        no_panic(&format!("hostile pdf {i}"), || {
            let _ = e.verify(c, None, None);
            let _ = e.card_original(c);
        });
    }
}
