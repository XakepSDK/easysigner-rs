//! Revocation lists (Order 500/НҚ p.18), with lists made here and signed by the test CA in
//! fixtures/ocsp: a listed certificate is revoked, an unlisted one is good, and a list that is
//! out of date, from another CA or badly signed gives no answer.

use std::path::PathBuf;

use kzsigner::crl::{self, Crl};
use kzsigner::der;
use kzsigner::p12::{self, Key};
use kzsigner::time::{encode_generalized, now_ms};

const DAY: i64 = 86_400_000;

fn key(name: &str) -> Key {
    let f = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ocsp")
        .join(name);
    p12::open(&std::fs::read(f).unwrap(), "Qwerty12", None).unwrap()
}

/// A CRL from `ca` listing `serials`, valid from `this` to `next`.
fn make(ca: &Key, serials: &[&[u8]], this: i64, next: i64) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = serials
        .iter()
        .map(|s| der::seq(&[&der::uint(s), &encode_generalized(this - DAY)]))
        .collect();
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    let mut parts = vec![
        der::small_int(1),
        der::alg_null(ca.private_key.sig_oid()),
        ca.cert.subject.clone(),
        encode_generalized(this),
        encode_generalized(next),
    ];
    if !entries.is_empty() {
        parts.push(der::seq(&refs));
    }
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&parts);
    let sig = ca.private_key.sign(&tbs).unwrap();
    der::seq(&[
        &tbs,
        &der::alg_null(ca.private_key.sig_oid()),
        &der::bit_string(&sig),
    ])
}

#[test]
fn revocation_lists_decide_only_when_current_and_from_the_ca() {
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    let now = now_ms();
    let check = |data: &[u8]| crl::evaluate(&Crl::parse(data).unwrap(), &carol.cert, &ca.cert, now);

    let (good, status, answer) = check(&make(&ca, &[b"\x01\x02"], now - DAY, now + DAY));
    assert!(good && answer == "good", "{status}");

    let (good, status, answer) = check(&make(&ca, &[&carol.cert.serial], now - DAY, now + DAY));
    assert!(!good && answer == "revoked", "{status}");
    // a leading zero byte in the list's serial still matches
    let mut padded = vec![0u8];
    padded.extend(&carol.cert.serial);
    if carol.cert.serial[0] < 0x80 {
        let (_, _, answer) = check(&make(&ca, &[&padded], now - DAY, now + DAY));
        assert_eq!(answer, "revoked");
    }

    // past its nextUpdate: no answer, whatever it lists (p.18)
    let (good, _, answer) = check(&make(&ca, &[], now - 3 * DAY, now - DAY));
    assert!(!good && answer.is_empty());

    // signed by someone else (carol's own key, under the CA's name)
    let mut forged = make(&carol, &[], now - DAY, now + DAY);
    let (good, _, answer) = check(&forged);
    assert!(!good && answer.is_empty());
    // a changed byte breaks the signature
    let n = forged.len();
    forged[n - 1] ^= 1;
    let (good, _, answer) = check(&forged);
    assert!(!good && answer.is_empty());

    // from a CA other than the certificate's: no answer
    let other = crl::evaluate(
        &Crl::parse(&make(&carol, &[], now - DAY, now + DAY)).unwrap(),
        &carol.cert,
        &carol.cert,
        now,
    );
    assert!(other.2.is_empty());
}

#[test]
fn distribution_points_give_the_http_addresses() {
    // DistributionPoint { distributionPoint [0] { fullName [0] { [6] URI } } }
    let uri = |u: &str| der::tlv(der::ctx_prim(6), u.as_bytes());
    let dp = |u: &str| der::seq(&[&der::tlv(der::ctx(0), &der::tlv(der::ctx(0), &uri(u)))]);
    let ext = der::seq(&[
        &dp("http://crl.pki.gov.kz/nca_gost2022.crl"),
        &dp("ldap://example/cn=crl"),
        &dp("http://crl1.pki.gov.kz/nca_gost2022.crl"),
    ]);
    assert_eq!(
        crl::uris_in(&ext),
        [
            "http://crl.pki.gov.kz/nca_gost2022.crl",
            "http://crl1.pki.gov.kz/nca_gost2022.crl"
        ]
    );
    assert!(crl::uris_in(b"\x30\x80garbage").is_empty());
}

#[test]
fn damaged_lists_are_errors() {
    assert!(Crl::parse(b"").is_err());
    assert!(Crl::parse(&der::seq(&[&der::seq(&[])])).is_err());
    let ca = key("ca.p12");
    let good = make(&ca, &[b"\x05"], now_ms() - DAY, now_ms() + DAY);
    for cut in [1, good.len() / 2, good.len() - 1] {
        assert!(Crl::parse(&good[..cut]).is_err());
    }
}
