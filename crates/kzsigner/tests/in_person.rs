//! Signing in person (src/inperson): the lawyer's phone and each signer's phone, over an
//! in-memory connection; the signer's OCSP and timestamp requests through the lawyer's phone
//! go to the fake test servers on 127.0.0.1 (tests/common/nca.rs), not NCA's.

#[path = "common/nca.rs"]
mod nca;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use kzsigner::Server;
use kzsigner::cert::Cert;
use kzsigner::env::{Env, Http, Transport};
use kzsigner::inperson::{self, Channel, Lawyer, Offer, Pipe, Served, Signer};
use kzsigner::p12::Key;
use kzsigner::pdf::whosigned::WhoSigned;
use kzsigner::trust::TrustStore;

fn fx(p: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata")
            .join(p),
    )
    .unwrap()
}

fn key(p: &str) -> Key {
    kzsigner::p12::open(&fx(p), "Qwerty12", None).unwrap()
}

fn cert(p: &str) -> Cert {
    Cert::parse_any(&fx(p)).unwrap()
}

/// Trusts the test CAs (and the fake TSA).
fn env() -> Env {
    Env::new(TrustStore::new(vec![
        cert("kalkan/ca_gost2015.cer"),
        cert("ocsp/ca.cer"),
        key("keys/tsa.p12").cert,
    ]))
}

fn lawyer(timestamp: bool) -> Lawyer {
    lawyer_with(key("kalkan/alice_gost2015.p12"), timestamp)
}

fn lawyer_with(k: Key, timestamp: bool) -> Lawyer {
    Lawyer::new(
        fx("pdf/plain.pdf"),
        k,
        "Dogovor_arendy_2026.pdf",
        WhoSigned {
            document: "Dogovor_arendy_2026.pdf".into(),
        },
        timestamp,
    )
    .unwrap()
}

/// The lawyer serves one signer on another thread, accepting or not; how it ended and the
/// lawyer back.
fn serve(l: Lawyer, accept: bool) -> (Pipe, thread::JoinHandle<(Served, Lawyer)>) {
    serve_with(l, accept, env())
}

fn serve_with(
    mut l: Lawyer,
    accept: bool,
    env: Env,
) -> (Pipe, thread::JoinHandle<(Served, Lawyer)>) {
    let (mut a, b) = inperson::pipe();
    let h = thread::spawn(move || {
        let s = l.serve(&mut a, &env, &mut |_| accept).unwrap();
        (s, l)
    });
    (b, h)
}

fn signatures(pdf: &[u8]) -> Vec<(bool, String)> {
    let r = kzsigner::pdf::verify(pdf, &env(), None).unwrap();
    r.signers
        .iter()
        .map(|s| (s.valid, s.subject_dn.clone().unwrap_or_default()))
        .collect()
}

#[test]
fn a_signer_reads_signs_and_gets_the_final_copy() {
    let mut l = lawyer(false);
    l.sign_self(None, &env()).unwrap();
    let before = l.pdf().to_vec();

    let (ch, h) = serve(l, true);
    let bob = key("kalkan/bob_gost2015.p12");
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    let Offer::Sign(req) = s.start(&env(), None).unwrap() else {
        panic!("no request")
    };
    assert_eq!(req.title, "Dogovor_arendy_2026.pdf");
    assert_eq!(req.slot, 1);
    assert!(!req.lawyer_name.is_empty());

    // the file shown: the document so far, the new revision without the signature yet
    let copy = s.read(&env(), None).unwrap();
    assert!(copy.matches);
    assert!(copy.pdf.starts_with(&before));
    assert_eq!(copy.earlier.signers.len(), 1);
    assert!(copy.earlier.valid);

    let out = s.sign(&bob, &env(), None, None).unwrap();
    assert!(out.accepted && out.ack.accepted && out.ack.slot == 1);
    let (served, mut l) = h.join().unwrap();
    assert!(matches!(served, Served::Signed(_)), "{served:?}");
    assert_eq!(l.signers().len(), 2);
    let sigs = signatures(l.pdf());
    assert_eq!(sigs.len(), 2);
    assert!(sigs.iter().all(|(v, _)| *v), "{sigs:?}");

    // before the end, a rescan shows the status; after it, it brings the signed document
    for finished in [false, true] {
        if finished {
            l.finish();
        }
        let (ch, h) = serve(l, true);
        let mut s = Signer::new(Box::new(ch), bob.cert.clone());
        let Offer::Signed {
            ack,
            final_pdf,
            lawyer_cert,
        } = s.start(&env(), None).unwrap()
        else {
            panic!("not signed")
        };
        assert!(ack.accepted && ack.slot == 1);
        assert_eq!(lawyer_cert, out.lawyer_cert);
        assert_eq!(final_pdf.is_some(), finished);
        let (served, back) = h.join().unwrap();
        assert!(matches!(served, Served::Status(_)));
        l = back;
    }

    // an ack signed by someone other than the lawyer met before doesn't count
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone()).with_lawyer(bob.cert.der.clone());
    assert!(s.start(&env(), None).is_err());
    let (_, l) = h.join().unwrap();

    // and nobody new signs a finished document
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), dave("keys/alice_gost2015_256.p12").cert);
    assert!(matches!(s.start(&env(), None).unwrap(), Offer::Refused(_)));
    assert!(matches!(h.join().unwrap().0, Served::Refused(_)));
}

#[test]
fn a_rejected_or_dropped_signature_changes_nothing_and_the_spot_is_reused() {
    let mut l = lawyer(false);
    l.sign_self(None, &env()).unwrap();
    let before = l.pdf().to_vec();
    let bob = key("kalkan/bob_gost2015.p12");

    // the lawyer rejects
    let (ch, h) = serve(l, false);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    assert!(matches!(s.start(&env(), None).unwrap(), Offer::Sign(_)));
    let out = s.sign(&bob, &env(), None, None).unwrap();
    assert!(!out.accepted);
    let (served, l) = h.join().unwrap();
    assert!(matches!(served, Served::Rejected(_)));
    assert_eq!(l.pdf(), before);

    // the signer walks away after the request
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    assert!(matches!(s.start(&env(), None).unwrap(), Offer::Sign(_)));
    drop(s);
    let (served, l) = h.join().unwrap();
    assert_eq!(served, Served::Dropped);
    assert_eq!(l.pdf(), before);

    // or says no
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    assert!(matches!(s.start(&env(), None).unwrap(), Offer::Sign(_)));
    s.cancel();
    let (served, l) = h.join().unwrap();
    assert_eq!(served, Served::Cancelled);

    // the same spot, signed for real
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    let Offer::Sign(req) = s.start(&env(), None).unwrap() else {
        panic!()
    };
    assert_eq!(req.slot, 1);
    assert!(s.sign(&bob, &env(), None, None).unwrap().accepted);
    let (_, l) = h.join().unwrap();
    assert_eq!(signatures(l.pdf()).len(), 2);
}

/// The first signer in person certifies the document (the lawyer need not sign).
#[test]
fn the_first_signer_certifies() {
    let l = lawyer(false);
    let bob = key("kalkan/bob_gost2015.p12");
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), bob.cert.clone());
    let Offer::Sign(req) = s.start(&env(), None).unwrap() else {
        panic!()
    };
    assert_eq!(req.slot, 0);
    assert!(s.sign(&bob, &env(), None, None).unwrap().accepted);
    let (_, l) = h.join().unwrap();
    let doc = lopdf::Document::load_mem(l.pdf()).unwrap();
    assert!(doc.catalog().unwrap().get(b"Perms").is_ok());
    assert!(signatures(l.pdf()).iter().all(|(v, _)| *v));
}

/// A lawyer's phone that shows one file and asks to sign another is caught when the signer
/// reads it: signing is refused and the signed request is kept.
#[test]
fn a_file_that_is_not_the_one_requested_blocks_signing() {
    // a byte of the document changed, or a file that can't even be checked
    for unreadable in [false, true] {
        swapped_file(unreadable);
    }
}

fn swapped_file(unreadable: bool) {
    struct Swap(Pipe, bool);
    impl Channel for Swap {
        fn send(&mut self, m: &[u8]) -> kzsigner::Result<()> {
            let mut m = m.to_vec();
            // the File message (kind 4): format, kind, master_len (8 bytes), the PDF
            if m[1] == 4 {
                if self.1 {
                    m[2..10].fill(0);
                } else {
                    let at = m.len() / 3;
                    m[at] ^= 1;
                }
            }
            self.0.send(&m)
        }
        fn recv(&mut self) -> kzsigner::Result<Vec<u8>> {
            self.0.recv()
        }
        fn transcript(&self) -> [u8; 32] {
            self.0.transcript()
        }
    }
    let mut l = lawyer(false);
    l.sign_self(None, &env()).unwrap();
    let before = l.pdf().to_vec();
    let (a, b) = inperson::pipe();
    let h = thread::spawn(move || {
        let mut a = Swap(a, unreadable);
        let s = l.serve(&mut a, &env(), &mut |_| true).unwrap();
        (s, l)
    });
    let bob = key("kalkan/bob_gost2015.p12");
    let mut s = Signer::new(Box::new(b), bob.cert.clone());
    assert!(matches!(s.start(&env(), None).unwrap(), Offer::Sign(_)));
    match s.read(&env(), None) {
        Ok(copy) => assert!(!copy.matches && !unreadable),
        Err(_) => assert!(unreadable),
    }
    assert!(s.request_evidence().is_some());
    let e = s.sign(&bob, &env(), None, None).unwrap_err().to_string();
    assert!(e.contains("not the one"), "{e}");
    let (served, l) = h.join().unwrap();
    assert!(matches!(served, Served::Refused(_)), "{served:?}");
    assert_eq!(l.pdf(), before);
}

/// A signer without internet: OCSP and the timestamp through the lawyer's phone, checked on
/// the signer's.
#[test]
fn ocsp_and_timestamp_through_the_lawyers_phone() {
    let ocsp = nca::fake_ocsp(false);
    let tsa = nca::fake_tsa();
    // a lawyer the fake OCSP responder knows too
    let mut l = lawyer_with(dave("keys/alice_gost2015_256.p12"), true);
    l.sign_self(Some(&tsa), &env()).unwrap();
    // the lawyer's phone counts what it passes on
    struct Counting(Arc<AtomicUsize>);
    impl Transport for Counting {
        fn post(&self, s: Server, url: &str, ct: &str, body: &[u8]) -> kzsigner::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Http.post(s, url, ct, body)
        }
        fn get(&self, s: Server, url: &str, limit: u64) -> kzsigner::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Http.get(s, url, limit)
        }
    }
    let passed = Arc::new(AtomicUsize::new(0));
    let l = l.allow_relay_host("127.0.0.1");
    let (ch, h) = serve_with(l, true, env().with_net(Arc::new(Counting(passed.clone()))));
    let carol = dave("kalkan/bob_gost2015.p12");
    let mut s = Signer::new(Box::new(ch), carol.cert.clone());
    // the signer's network is the lawyer's phone; a direct one would fail
    let relayed = Env::new(TrustStore::new(vec![
        cert("kalkan/ca_gost2015.cer"),
        cert("ocsp/ca.cer"),
        key("keys/tsa.p12").cert,
    ]))
    .with_net(s.relay());
    let Offer::Sign(req) = s.start(&relayed, None).unwrap() else {
        panic!()
    };
    assert!(req.timestamp);
    let out = s.sign(&carol, &relayed, Some(&tsa), Some(&ocsp)).unwrap();
    assert!(out.accepted, "{:?}", out.warnings);
    let (_, l) = h.join().unwrap();
    // the signer's OCSP request and timestamp request
    assert_eq!(passed.load(Ordering::SeqCst), 2);
    let r = kzsigner::pdf::verify(l.pdf(), &env(), None).unwrap();
    assert_eq!(r.signers.len(), 2);
    assert!(
        r.signers
            .iter()
            .all(|s| s.valid && s.timestamp_ok == Some(true))
    );

    // scanning again with the checks going through the lawyer's phone
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), carol.cert.clone());
    let relayed = env().with_net(s.relay());
    assert!(matches!(
        s.start(&relayed, Some(&ocsp)).unwrap(),
        Offer::Signed { .. }
    ));
    let (_, l) = h.join().unwrap();

    // a revoked key is refused before anything is signed, and nothing changes
    let ocsp = nca::fake_ocsp(true);
    let before = l.pdf().to_vec();
    let (ch, h) = serve(l, true);
    let carol = dave("keys/bob_gost2015_256.p12");
    let mut s = Signer::new(Box::new(ch), carol.cert.clone());
    let relayed = env().with_net(s.relay());
    assert!(matches!(s.start(&relayed, None).unwrap(), Offer::Sign(_)));
    assert!(s.sign(&carol, &relayed, Some(&tsa), Some(&ocsp)).is_err());
    let (served, l) = h.join().unwrap();
    assert!(matches!(served, Served::Refused(_)), "{served:?}");
    assert_eq!(l.pdf(), before);

    // the lawyer's phone passes requests on to NCA's servers only (here, without 127.0.0.1)
    let l = lawyer(false);
    let (ch, h) = serve(l, true);
    let mut s = Signer::new(Box::new(ch), carol.cert.clone());
    let relayed = env().with_net(s.relay());
    assert!(matches!(s.start(&relayed, None).unwrap(), Offer::Sign(_)));
    let e = s
        .sign(&carol, &relayed, None, Some(&nca::fake_ocsp(false)))
        .map(|o| o.warnings)
        .unwrap_or_else(|e| vec![e.to_string()]);
    assert!(e.iter().any(|w| w.contains("NCA's servers only")), "{e:?}");
    let _ = h.join().unwrap();
}

/// A GOST 2015 key with a certificate from the fake OCSP responder's test CA.
fn dave(file: &str) -> Key {
    let ca = key("ocsp/ca.p12");
    let mut k = key(file);
    k.cert = kzsigner::kzcrypto::ocsp::testkit::issue(&ca, &k.cert, false);
    k
}

/// Only GOST 2015 keys sign in person.
#[test]
fn other_keys_are_refused() {
    let rsa = key("kalkan/alice_rsa.p12");
    assert!(Lawyer::new(fx("pdf/plain.pdf"), rsa, "x", WhoSigned::default(), false).is_err());
    let (ch, h) = serve(lawyer(false), true);
    let mut s = Signer::new(Box::new(ch), key("kalkan/bob_gost2004.p12").cert);
    assert!(s.start(&env(), None).is_err());
    drop(s);
    assert_eq!(h.join().unwrap().0, Served::Dropped);
}
