//! Signing in person, two phones over TCP on 127.0.0.1, against the fake NCA servers.

use super::sign::{fake_nca, file};
use super::*;
use der_testkit as der;
use std::thread;

/// A .p12 (no encryption, no MAC: password "") of test key `p` with a certificate from the
/// fake OCSP responder's CA: a GOST 2015 key NCA (played by the fakes) says is good.
fn ncas_key(p: &str) -> Vec<u8> {
    ncas_key_as(p, "CN=TEST OCSP RESPONDER")
}

/// [`ncas_key`], issued to `name`.
fn ncas_key_as(p: &str, name: &str) -> Vec<u8> {
    let (k, pkcs8) = kzsigner::p12::open_with_pkcs8(&file(p), "Qwerty12", None).unwrap();
    let ca = kzsigner::p12::open(&file("ocsp/ca.p12"), "Qwerty12", None).unwrap();
    let cert = kzcrypto::ocsp::testkit::issue_as(&ca, &k.cert, false, name);
    let data = |b: &[u8]| {
        der::seq(&[
            &der::oid("1.2.840.113549.1.7.1"),
            &der::tlv(der::ctx(0), &der::octets(b)),
        ])
    };
    let bag = |id: &str, v: &[u8]| der::seq(&[&der::oid(id), &der::tlv(der::ctx(0), v)]);
    let cert_bag = der::seq(&[
        &der::oid("1.2.840.113549.1.9.22.1"),
        &der::tlv(der::ctx(0), &der::octets(&cert.der)),
    ]);
    let contents = der::seq(&[
        &bag("1.2.840.113549.1.12.10.1.1", &pkcs8),
        &bag("1.2.840.113549.1.12.10.1.3", &cert_bag),
    ]);
    der::seq(&[&der::small_int(3), &data(&der::seq(&[&data(&contents)]))])
}

/// A vault with one of those keys.
fn person(test: &str, p: &str) -> (Arc<Vault>, String, Arc<SoftwareGuard>) {
    let g = Arc::new(SoftwareGuard::default());
    let v = vault(&dir(test).join("keys.kzs"), &g);
    let id = v
        .add_key(super::test_nca(), ncas_key(p), String::new(), prompt())
        .unwrap();
    g.prompts.lock().unwrap().clear();
    (v, id, g)
}

/// The lawyer's screen: accepts or rejects everyone, and notes who came.
struct Screen {
    accept: bool,
    seen: Mutex<Vec<String>>,
}

impl Desk for Screen {
    fn arrived(&self, who: Person) {
        self.seen
            .lock()
            .unwrap()
            .push(format!("arrived {}", who.name));
    }
    fn decide(&self, who: Arrival) -> bool {
        assert!(who.nca_time_ms.is_some(), "NCA's time on the signature");
        self.seen
            .lock()
            .unwrap()
            .push(format!("decide {}", who.name));
        self.accept
    }
}

fn screen(accept: bool) -> Arc<Screen> {
    Arc::new(Screen {
        accept,
        seen: Mutex::new(vec![]),
    })
}

fn sign_prompt() -> ChipPrompt {
    ChipPrompt {
        title: "Sign".into(),
        ..Default::default()
    }
}

fn meeting(test: &str, nca: &Arc<Nca>) -> (Arc<Meeting>, Arc<SoftwareGuard>) {
    let (v, id, g) = person(test, "keys/alice_gost2015_256.p12");
    let m = v
        .start_meeting(
            nca.clone(),
            id,
            "Dogovor.pdf".into(),
            file("pdf/plain.pdf"),
            None,
            sign_prompt(),
            "en".into(),
        )
        .unwrap();
    (m, g)
}

/// One signer's whole visit: scan, read, sign; the lawyer's turn as it ended.
fn come(
    m: &Arc<Meeting>,
    desk: Arc<Screen>,
    v: &Vault,
    id: &str,
    nca: &Arc<Nca>,
    online: bool,
) -> (Visit, Option<Outcome>, Turn) {
    let qr = m.invite(vec!["127.0.0.1".into()]).unwrap();
    let mm = m.clone();
    let h = thread::spawn(move || mm.wait(desk));
    let guest = v.visit(nca.clone(), id.into(), qr, online).unwrap();
    let visit = guest.visit();
    let outcome = if let Visit::Sign { .. } = visit {
        let r = guest.read().unwrap();
        assert!(r.matches);
        assert!(kzsigner::pdf::is_pdf(&r.pdf));
        Some(
            v.sign_visit(guest.clone(), None, sign_prompt(), "en".into())
                .unwrap(),
        )
    } else {
        None
    };
    drop(guest);
    (visit, outcome, h.join().unwrap())
}

#[test]
fn a_signer_scans_signs_is_accepted_and_collects_the_final_copy() {
    let nca = fake_nca(false);
    let (m, lg) = meeting("meet-lawyer", &nca);
    assert_eq!(
        lg.prompts.lock().unwrap().len(),
        1,
        "the lawyer's key opens once"
    );
    assert_eq!(m.signers().len(), 1);

    let (v, id, sg) = person("meet-signer", "keys/bob_gost2015_256.p12");
    let desk = screen(true);
    let (visit, outcome, turn) = come(&m, desk.clone(), &v, &id, &nca, true);
    let Visit::Sign { number, title, .. } = visit else {
        panic!("{visit:?}")
    };
    assert_eq!(number, 2);
    assert_eq!(title, "Dogovor.pdf");
    assert_eq!(outcome, Some(Outcome { accepted: true }));
    assert!(matches!(turn, Turn::Signed { .. }), "{turn:?}");
    assert_eq!(desk.seen.lock().unwrap().len(), 2);
    assert_eq!(m.signers().len(), 2);
    assert_eq!(
        sg.prompts.lock().unwrap().len(),
        1,
        "the signer's key opens once"
    );

    let signed = m.finish().unwrap();
    assert!(m.finished());
    assert_eq!(signed.name, "Dogovor-signed.pdf");
    assert!(signed.joined);
    let rep = nca.engine.verify(&signed.bytes, None, None).unwrap();
    assert_eq!(rep.signers.len(), 2);
    assert!(rep.signers.iter().all(|s| s.signature_ok));

    // scanning again hands over the finished document
    let (visit, outcome, turn) = come(&m, screen(true), &v, &id, &nca, true);
    assert_eq!(outcome, None);
    assert_eq!(
        visit,
        Visit::Signed {
            document: Some(signed.bytes)
        }
    );
    assert!(matches!(turn, Turn::Collected { .. }), "{turn:?}");
}

#[test]
fn rejected_offline_and_stopped() {
    let nca = fake_nca(false);
    let (m, _) = meeting("meet-lawyer2", &nca);
    let (v, id, _) = person("meet-signer2", "keys/bob_gost2015_256.p12");

    // without internet on the signer's phone, NCA is reached through the lawyer's
    let (visit, outcome, turn) = come(&m, screen(false), &v, &id, &nca, false);
    assert!(matches!(visit, Visit::Sign { number: 2, .. }), "{visit:?}");
    assert_eq!(outcome, Some(Outcome { accepted: false }));
    assert!(matches!(turn, Turn::Rejected { .. }), "{turn:?}");
    assert_eq!(m.signers().len(), 1, "the lawyer only");

    // a QR that is not ours, and a phone nobody listens at
    assert!(matches!(
        v.visit(nca.clone(), id.clone(), "hello".into(), true),
        Err(MeetError::NotAnInvitation)
    ));

    // the lawyer leaves the screen
    let _ = m.invite(vec!["127.0.0.1".into()]).unwrap();
    let mm = m.clone();
    let h = thread::spawn(move || mm.wait(screen(true)));
    thread::sleep(std::time::Duration::from_millis(100));
    m.stop();
    assert_eq!(h.join().unwrap(), Turn::Stopped);
}

/// Writes testdata/inperson's keys (the app's screenshot test signs with them):
/// `cargo test -p kzsigner-ffi -- --ignored write_in_person_keys`.
#[test]
#[ignore]
fn write_in_person_keys() {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/inperson");
    std::fs::create_dir_all(&d).unwrap();
    for (out, key, name) in [
        (
            "lawyer.p12",
            "keys/alice_gost2015_256.p12",
            "CN=СЕРИКОВА АЙГЕРИМ,SN=СЕРИКОВА,GN=БОЛАТОВНА,SERIALNUMBER=IIN880412400231,C=KZ",
        ),
        (
            "signer.p12",
            "keys/bob_gost2015_256.p12",
            "CN=ИВАНОВ АЛИБЕК,SN=ИВАНОВ,GN=СЕРИКОВИЧ,SERIALNUMBER=IIN900101300123,C=KZ",
        ),
    ] {
        std::fs::write(d.join(out), ncas_key_as(key, name)).unwrap();
    }
}

#[test]
fn the_screenshot_keys_open() {
    for f in ["inperson/lawyer.p12", "inperson/signer.p12"] {
        let k = kzsigner::p12::open(&file(f), "", None).unwrap();
        assert!(kzsigner::cert::get(&kzsigner::cert::rdns(&k.cert.subject), "CN").is_some());
    }
}

/// A stranger on the network who connects (and says nothing, or something wrong) doesn't use
/// up the QR code: the signer who scanned it still signs.
#[test]
fn strangers_dont_use_up_the_qr_code() {
    use std::io::Write;
    let nca = fake_nca(false);
    let (m, _) = meeting("meet-lawyer3", &nca);
    let (v, id, _) = person("meet-signer3", "keys/bob_gost2015_256.p12");
    let qr = m.invite(vec!["127.0.0.1".into()]).unwrap();
    let port = qr_port(&qr);
    let mm = m.clone();
    let h = thread::spawn(move || mm.wait(screen(true)));
    // a stranger with a key of their own, then garbage
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let key = kzsigner::inperson::session::Invitation::new(vec![]).unwrap();
    let k = kzsigner::inperson::session::Engagement::parse(&key.engagement.qr())
        .unwrap()
        .key;
    s.write_all(&(k.len() as u32).to_be_bytes()).unwrap();
    s.write_all(&k).unwrap();
    s.write_all(&[0, 0, 0, 40]).unwrap();
    s.write_all(&[7; 40]).unwrap();
    drop(s);
    // the signer who scanned
    let g = v.visit(nca.clone(), id.clone(), qr, true).unwrap();
    assert!(matches!(g.visit(), Visit::Sign { .. }), "{:?}", g.visit());
    let o = v.sign_visit(g, None, sign_prompt(), "en".into()).unwrap();
    assert!(o.accepted);
    assert!(matches!(h.join().unwrap(), Turn::Signed { .. }));
}

fn qr_port(qr: &str) -> u16 {
    let e = kzsigner::inperson::session::Engagement::parse(qr).unwrap();
    match &e.hints[0] {
        kzsigner::inperson::session::Hint::Tcp(a) => a.rsplit(':').next().unwrap().parse().unwrap(),
        h => panic!("{h:?}"),
    }
}
