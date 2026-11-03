//! Revocation lists (Order 500/НҚ p.18), with lists made here and signed by the test CA in
//! fixtures/ocsp: a listed certificate is revoked, an unlisted one is good, and a list that is
//! out of date, from another CA, badly signed, or has an unknown critical extension gives no
//! answer. A named delta list must be read too.

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

const DELTA: &str = "2.5.29.27";
const FRESHEST: &str = "2.5.29.46";

/// An extension: (oid, critical, DER value).
type Ext<'a> = (&'a str, bool, Vec<u8>);

/// A CRL signed by `signer` under the name `issuer`, listing `serials`, valid from `this` to
/// `next`, with `exts`.
fn make_by(
    signer: &Key,
    issuer: &[u8],
    serials: &[&[u8]],
    this: i64,
    next: i64,
    exts: &[Ext],
) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = serials
        .iter()
        .map(|s| der::seq(&[&der::uint(s), &encode_generalized(this - DAY)]))
        .collect();
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    let mut parts = vec![
        der::small_int(1),
        der::alg_null(signer.private_key.sig_oid()),
        issuer.to_vec(),
        encode_generalized(this),
        encode_generalized(next),
    ];
    if !entries.is_empty() {
        parts.push(der::seq(&refs));
    }
    if !exts.is_empty() {
        let list: Vec<Vec<u8>> = exts
            .iter()
            .map(|(oid, critical, v)| {
                let (o, c, v) = (der::oid(oid), der::boolean(true), der::octets(v));
                if *critical {
                    der::seq(&[&o, &c, &v])
                } else {
                    der::seq(&[&o, &v])
                }
            })
            .collect();
        let refs: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
        parts.push(der::tlv(der::ctx(0), &der::seq(&refs)));
    }
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&parts);
    let sig = signer.private_key.sign(&tbs).unwrap();
    der::seq(&[
        &tbs,
        &der::alg_null(signer.private_key.sig_oid()),
        &der::bit_string(&sig),
    ])
}

/// A CRL from `ca` listing `serials`, valid from `this` to `next`.
fn make(ca: &Key, serials: &[&[u8]], this: i64, next: i64) -> Vec<u8> {
    make_by(ca, &ca.cert.subject, serials, this, next, &[])
}

#[test]
fn revocation_lists_decide_only_when_current_and_from_the_ca() {
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    let now = now_ms();
    let check = |data: &[u8]| {
        crl::evaluate(
            &Crl::parse(data).unwrap(),
            None,
            false,
            &carol.cert,
            &ca.cert,
            now,
        )
    };

    let (good, status, answer) = check(&make(&ca, &[b"\x01\x02"], now - DAY, now + DAY));
    assert!(good && answer == "good", "{status}");

    let (good, status, answer) = check(&make(&ca, &[&carol.cert.serial], now - DAY, now + DAY));
    assert!(!good && answer == "revoked", "{status}");

    // past its nextUpdate: no answer, whatever it lists (p.18)
    let (good, _, answer) = check(&make(&ca, &[], now - 3 * DAY, now - DAY));
    assert!(!good && answer.is_empty());

    // under the CA's name but signed with carol's key
    let forged = make_by(&carol, &ca.cert.subject, &[], now - DAY, now + DAY, &[]);
    let (good, status, answer) = check(&forged);
    assert!(
        !good && answer.is_empty() && status.contains("signature"),
        "{status}"
    );
    // a changed byte breaks the signature of a real one too
    let mut real = make(&ca, &[], now - DAY, now + DAY);
    let n = real.len();
    real[n - 1] ^= 1;
    let (good, _, answer) = check(&real);
    assert!(!good && answer.is_empty());

    // from a CA other than the certificate's: no answer
    let (good, status, answer) = check(&make(&carol, &[], now - DAY, now + DAY));
    assert!(
        !good && answer.is_empty() && status.contains("CA"),
        "{status}"
    );
}

#[test]
fn unknown_critical_extensions_make_a_list_unusable() {
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    let now = now_ms();
    let eval = |exts: &[Ext]| {
        let data = make_by(&ca, &ca.cert.subject, &[], now - DAY, now + DAY, exts);
        crl::evaluate(
            &Crl::parse(&data).unwrap(),
            None,
            false,
            &carol.cert,
            &ca.cert,
            now,
        )
    };
    // a critical issuingDistributionPoint (a partial list): no answer
    let (good, _, answer) = eval(&[("2.5.29.28", true, der::seq(&[]))]);
    assert!(!good && answer.is_empty());
    // the same not critical, and a critical cRLNumber, are fine
    assert_eq!(eval(&[("2.5.29.28", false, der::seq(&[]))]).2, "good");
    assert_eq!(eval(&[("2.5.29.20", true, der::small_int(7))]).2, "good");
}

#[test]
fn delta_lists_are_read_with_the_full_list() {
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    let now = now_ms();
    let crl_of = |serials: &[&[u8]], exts: &[Ext]| {
        Crl::parse(&make_by(
            &ca,
            &ca.cert.subject,
            serials,
            now - DAY,
            now + DAY,
            exts,
        ))
        .unwrap()
    };
    let ind: Ext = (DELTA, true, der::small_int(1));
    let uri = der::tlv(der::ctx_prim(6), b"http://example/delta.crl");
    let point = der::seq(&[&der::seq(&[&der::tlv(
        der::ctx(0),
        &der::tlv(der::ctx(0), &uri),
    )])]);
    let base = crl_of(&[], &[(FRESHEST, false, point)]);
    assert_eq!(base.freshest, ["http://example/delta.crl"]);
    let eval = |b: &Crl, d: Option<&Crl>, due| crl::evaluate(b, d, due, &carol.cert, &ca.cert, now);

    // revoked since the full list: the delta decides
    let delta = crl_of(&[&carol.cert.serial], std::slice::from_ref(&ind));
    assert!(delta.is_delta);
    assert_eq!(eval(&base, Some(&delta), true).2, "revoked");
    // in neither: good
    assert_eq!(
        eval(&base, Some(&crl_of(&[], std::slice::from_ref(&ind))), true).2,
        "good"
    );
    // a delta is named but couldn't be read: no answer
    assert_eq!(eval(&base, None, true).2, "");
    // a full list given as the delta, or a delta given as the full list: no answer
    assert_eq!(eval(&base, Some(&crl_of(&[], &[])), true).2, "");
    assert_eq!(eval(&delta, None, false).2, "");
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

const MINUTE: i64 = 60_000;

#[test]
fn which_lists_are_current() {
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    // whole seconds, as the list's times are written
    let now = now_ms() / 1000 * 1000;
    let eval = |this: i64, next: i64| {
        crl::evaluate(
            &Crl::parse(&make(&ca, &[], this, next)).unwrap(),
            None,
            false,
            &carol.cert,
            &ca.cert,
            now,
        )
        .2
    };
    // made a little ahead (clock skew up to 5 minutes), or due for renewal this very moment
    assert_eq!(eval(now + 5 * MINUTE, now + DAY), "good");
    assert_eq!(eval(now + 6 * MINUTE, now + DAY), "");
    assert_eq!(eval(now - DAY, now), "good");
    assert_eq!(eval(now - DAY, now - 1000), "");

    // the list must be from the certificate's CA and from the issuer given
    let alice = p12::open(
        &std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys/alice_rsa.p12"),
        )
        .unwrap(),
        "Qwerty12",
        None,
    )
    .unwrap();
    let list = Crl::parse(&make(&ca, &[], now - DAY, now + DAY)).unwrap();
    let (good, status, _) = crl::evaluate(&list, None, false, &carol.cert, &alice.cert, now);
    assert!(
        !good && status.contains("not from the certificate's CA"),
        "{status}"
    );
}

#[test]
fn addresses_deep_inside() {
    let uri = der::tlv(der::ctx_prim(6), b"http://example/x.crl");
    let nest = |n: usize| (0..n).fold(uri.clone(), |d, _| der::seq(&[&d]));
    // the address itself sits at depth n
    assert_eq!(crl::uris_in(&nest(8)), ["http://example/x.crl"]);
    assert!(crl::uris_in(&nest(9)).is_empty());
}

/// A local server for revocation lists: answers each GET with `answer()` (None: an error) and
/// counts the requests. Returns its URL and the count.
fn serve(
    answer: impl Fn() -> Option<Vec<u8>> + Send + 'static,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ca.crl", listener.local_addr().unwrap());
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = hits.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend(&chunk[..n]),
                }
            }
            count.fetch_add(1, Ordering::SeqCst);
            let _ = match answer() {
                Some(b) => s
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", b.len())
                            .as_bytes(),
                    )
                    .and_then(|_| s.write_all(&b)),
                None => s.write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"),
            };
        }
    });
    (url, hits)
}

/// `carol`'s certificate naming the list at `url`.
fn naming(carol: &Key, url: &str) -> kzsigner::cert::Cert {
    let uri = der::tlv(der::ctx_prim(6), url.as_bytes());
    let dp = der::seq(&[&der::seq(&[&der::tlv(
        der::ctx(0),
        &der::tlv(der::ctx(0), &uri),
    )])]);
    let mut c = carol.cert.clone();
    c.extensions.retain(|(o, _)| o != "2.5.29.31");
    c.extensions.push(("2.5.29.31".into(), dp));
    c
}

/// Lists fetched from the address a certificate names, kept until they are due (at most an
/// hour), and a failure kept for five minutes.
#[test]
fn fetched_lists() {
    use std::sync::atomic::Ordering;
    let ca = key("ca.p12");
    let carol = key("carol.p12");
    let now = now_ms();
    let list = make(&ca, &[], now - DAY, now + DAY);
    let (url, hits) = serve(move || Some(list.clone()));
    let c = naming(&carol, &url);
    assert_eq!(crl::urls(&c), std::slice::from_ref(&url));
    assert!(crl::urls(&carol.cert).iter().all(|u| *u != url));

    let (base, delta, due) = crl::lists(&c, now).unwrap();
    assert!(base.next_update.is_some() && delta.is_none() && !due);
    // (check reads the clock itself, a little after `now`: the list is still kept)
    let (good, status, answer) = crl::check(&c, Some(&ca.cert));
    assert!(good && answer == "good", "{status}");
    assert_eq!(crl::check(&c, None).2, "");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "kept");
    crl::lists(&c, now + 59 * MINUTE).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "kept for the hour");
    crl::lists(&c, now + 61 * MINUTE).unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "fetched again after an hour"
    );

    // a list due sooner than in an hour is kept until it is due
    let soon = make(&ca, &[], now - DAY, now + 10 * MINUTE);
    let (url, hits) = serve(move || Some(soon.clone()));
    let c = naming(&carol, &url);
    crl::lists(&c, now).unwrap();
    crl::lists(&c, now + 9 * MINUTE).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    crl::lists(&c, now + 11 * MINUTE).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // a server that fails: not asked again for five minutes
    let (url, hits) = serve(|| None);
    let c = naming(&carol, &url);
    assert!(crl::lists(&c, now).is_err());
    assert!(crl::lists(&c, now + 4 * MINUTE).is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(crl::lists(&c, now + 6 * MINUTE).is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// The optional parts of a list: its version, nextUpdate (as either time type), entries with
/// their own extensions.
#[test]
fn list_forms() {
    let ca = key("ca.p12");
    let now = now_ms() / 1000 * 1000;
    let utc = |ms: i64| kzsigner::time::encode(ms);
    let list = |parts: &[Vec<u8>]| {
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let tbs = der::seq(&refs);
        let sig = ca.private_key.sign(&tbs).unwrap();
        der::seq(&[
            &tbs,
            &der::alg_null(ca.private_key.sig_oid()),
            &der::bit_string(&sig),
        ])
    };
    let alg = der::alg_null(ca.private_key.sig_oid());
    let name = ca.cert.subject.clone();
    let entry = |serial: u8, more: &[Vec<u8>]| {
        let mut e = vec![der::uint(&[serial]), encode_generalized(now - DAY)];
        e.extend(more.iter().cloned());
        let refs: Vec<&[u8]> = e.iter().map(Vec::as_slice).collect();
        der::seq(&refs)
    };
    let entries = der::seq(&[&entry(5, &[]), &entry(6, &[der::seq(&[])])]);

    // no version, no nextUpdate
    let c = Crl::parse(&list(&[
        alg.clone(),
        name.clone(),
        encode_generalized(now),
        entries.clone(),
    ]))
    .unwrap();
    assert_eq!(c.this_update, now);
    assert_eq!(c.next_update, None);
    assert_eq!(c.revoked.len(), 2);
    // no version, a UTCTime nextUpdate
    let c = Crl::parse(&list(&[
        alg.clone(),
        name.clone(),
        utc(now),
        utc(now + DAY),
        entries.clone(),
    ]))
    .unwrap();
    assert_eq!((c.this_update, c.next_update), (now, Some(now + DAY)));
    assert_eq!(c.revoked[1].0, vec![6]);
    assert!(c.signed_by(&ca.cert));
    // an entry without its date
    let short = der::seq(&[&der::seq(&[&der::uint(&[5])])]);
    assert!(Crl::parse(&list(&[alg.clone(), name.clone(), utc(now), short])).is_err());
    // no signature
    let tbs = der::seq(&[&alg, &name, &utc(now)]);
    assert!(Crl::parse(&der::seq(&[&tbs, &alg])).is_err());
}
