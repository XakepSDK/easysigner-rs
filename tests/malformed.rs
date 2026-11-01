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
