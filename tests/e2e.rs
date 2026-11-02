//! End-to-end checks of the kzsigner executable, the same ones the Java version ran in
//! test/run-tests.sh: throwaway test keys (GOST 2015-512, GOST 2015-256, GOST 2004, RSA), a fake
//! local TSA, and files and keys made by NCA's own Kalkan library (tests/fixtures/kalkan).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use kzsigner::cms;
use kzsigner::der;
use kzsigner::tsp::{Request, TST_INFO};

const PASSWORD: &str = "Qwerty12";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Test only: a fake TSA on 127.0.0.1 (NOT NCA's), key from tsa.p12. Returns its URL.
fn fake_tsa() -> String {
    let key = kzsigner::p12::open(
        &std::fs::read(fixtures().join("keys/tsa.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut serial = 1u64;
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let body = loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break Some(buf[end + 4..end + 4 + len].to_vec());
                    }
                }
            };
            let resp = body.and_then(|b| respond(&b, &key, serial));
            serial += 1;
            let _ = match resp {
                Some(r) => s
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\n\r\n", r.len())
                            .as_bytes(),
                    )
                    .and_then(|_| s.write_all(&r)),
                None => s.write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"),
            };
        }
    });
    url
}

/// A tiny HTTP server on 127.0.0.1: answers each POST body with `answer(body)`.
fn serve(
    answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ctype: &'static str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let body = loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend(&chunk[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break Some(buf[end + 4..end + 4 + len].to_vec());
                    }
                }
            };
            let _ = match body.and_then(|b| answer(&b)) {
                Some(r) => s
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n", r.len())
                            .as_bytes(),
                    )
                    .and_then(|_| s.write_all(&r)),
                None => s.write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"),
            };
        }
    });
    url
}

/// Test only: a fake OCSP responder for the test CA in fixtures/ocsp, signing with the CA's own
/// key; every certificate is "good", or "revoked" when `revoked`. Returns its URL.
fn fake_ocsp(revoked: bool) -> String {
    let ca = kzsigner::p12::open(
        &std::fs::read(fixtures().join("ocsp/ca.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    serve(
        move |body| {
            let req = der::parse(body).ok()?.items(der::SEQUENCE).ok()?;
            let tbs = req.first()?.items(der::SEQUENCE).ok()?;
            let list = tbs
                .iter()
                .find(|t| t.tag == der::SEQUENCE)?
                .items(der::SEQUENCE)
                .ok()?;
            let cert_id = list
                .first()?
                .items(der::SEQUENCE)
                .ok()?
                .first()?
                .raw
                .to_vec();
            let now = kzsigner::time::now_ms();
            let status = if revoked {
                der::tlv(
                    der::ctx(1),
                    &kzsigner::time::encode_generalized(now - 86_400_000),
                )
            } else {
                vec![0x80, 0x00]
            };
            let single = der::seq(&[
                &cert_id,
                &status,
                &kzsigner::time::encode_generalized(now),
                &der::tlv(
                    der::ctx(0),
                    &kzsigner::time::encode_generalized(now + 3_600_000),
                ),
            ]);
            let mut parts: Vec<Vec<u8>> = vec![
                der::tlv(der::ctx(1), &ca.cert.subject),
                kzsigner::time::encode_generalized(now),
                der::seq(&[&single]),
            ];
            // echo the nonce
            if let Some(ext) = tbs.iter().find(|t| t.tag == der::ctx(2)) {
                parts.push(der::tlv(der::ctx(1), ext.content));
            }
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let rd = der::seq(&refs);
            let sig = ca.private_key.sign(&rd).ok()?;
            let basic = der::seq(&[
                &rd,
                &der::alg_null(ca.private_key.sig_oid()),
                &der::bit_string(&sig),
            ]);
            Some(der::seq(&[
                &der::tlv(der::ENUMERATED, &[0]),
                &der::tlv(
                    der::ctx(0),
                    &der::seq(&[&der::oid("1.3.6.1.5.5.7.48.1.1"), &der::octets(&basic)]),
                ),
            ]))
        },
        "application/ocsp-response",
    )
}

fn respond(body: &[u8], key: &kzsigner::p12::Key, serial: u64) -> Option<Vec<u8>> {
    let req = Request::parse(body).ok()?;
    let known = [
        kzsigner::gost::H_SHA256,
        kzsigner::gost::H_GOST34311,
        kzsigner::gost::H_GOST2015_256,
        kzsigner::gost::H_GOST2015_512,
    ];
    if !known.contains(&req.hash_oid.as_str()) {
        return None;
    }
    let policy = req.policy.clone().unwrap_or("1.2.398.3.3.2.6.2".into());
    let mut info = der::small_int(1);
    info.extend(der::oid(&policy));
    info.extend(der::seq(&[
        &der::seq(&[&der::oid(&req.hash_oid)]),
        &der::octets(&req.hash),
    ]));
    info.extend(der::small_int(serial));
    info.extend(kzsigner::time::encode_generalized(kzsigner::time::now_ms()));
    if let Some(n) = &req.nonce {
        info.extend(der::uint(n));
    }
    let info = der::tlv(der::SEQUENCE, &info);
    let token = cms::sign_once(&info, TST_INFO, true, &key.private_key, &key.cert)
        .ok()?
        .encode();
    Some(der::seq(&[&der::seq(&[&der::small_int(0)]), &token]))
}

struct Run {
    dir: PathBuf,
    pass: usize,
    fail: Vec<String>,
}

impl Run {
    /// Runs kzsigner in the work folder; returns stdout + stderr.
    fn kz(&self, args: &[&str]) -> String {
        self.kz_env(args, PASSWORD).0
    }

    fn kz_env(&self, args: &[&str], password: &str) -> (String, String) {
        // the test keys' CAs, so that signing's own key check (Order 500 p.4) trusts them
        let mut args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        if args.first().is_some_and(|a| a == "sign")
            && !args.iter().any(|a| a == "--trust" || a == "--no-test-ca")
        {
            for dir in ["keys", "kalkan"] {
                for a in ["rsa", "gost2004", "gost2015", "gost2015_256"] {
                    let f = fixtures().join(dir).join(format!("ca_{a}.cer"));
                    if f.exists() {
                        args.push("--trust".into());
                        args.push(f.display().to_string());
                    }
                }
            }
        }
        args.retain(|a| a != "--no-test-ca");
        let o = Command::new(env!("CARGO_BIN_EXE_kzsigner"))
            .args(&args)
            .current_dir(&self.dir)
            .env("KZSIGNER_PASSWORD", password)
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        (format!("{out}{}", String::from_utf8_lossy(&o.stderr)), out)
    }

    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            println!("ok   {name}");
            self.pass += 1;
        } else {
            println!("FAIL {name}");
            self.fail.push(name.into());
        }
    }

    fn path(&self, f: &str) -> PathBuf {
        self.dir.join(f)
    }
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn end_to_end() {
    let dir = std::env::temp_dir().join(format!("kzsigner-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut t = Run {
        dir: dir.clone(),
        pass: 0,
        fail: vec![],
    };
    let k = fixtures().join("keys");
    let fx = fixtures().join("kalkan");
    let key = |n: &str| s(&k.join(n));
    let tsa = fake_tsa();
    let doc = "Договор №1 test document\n";
    std::fs::write(t.path("doc.txt"), doc).unwrap();

    for a in ["gost2015", "gost2015_256", "gost2004", "rsa"] {
        let d = format!("d_{a}.txt");
        std::fs::write(t.path(&d), doc).unwrap();
        let ca = key(&format!("ca_{a}.cer"));
        t.kz(&["sign", "-k", &key(&format!("alice_{a}.p12")), &d]);
        t.kz(&[
            "sign",
            "-k",
            &key(&format!("bob_{a}.p12")),
            &format!("{d}.cms"),
        ]);
        let v = t.kz(&[
            "sign",
            "--no-test-ca",
            "-k",
            &key(&format!("alice_{a}.p12")),
            &d,
            "-o",
            "x.cms",
        ]);
        t.check(
            &format!("{a}: a key from an untrusted CA is refused before signing"),
            v.contains("Your key cannot sign") && !t.path("x.cms").exists(),
        );
        let v = t.kz(&["verify", &format!("{d}.cms"), "--trust", &ca]);
        t.check(
            &format!("{a}: sign + co-sign verifies (2 signers)"),
            v.contains("VALID - all 2"),
        );
        let v = t.kz(&["verify", &format!("{d}.cms")]);
        t.check(
            &format!("{a}: untrusted CA is reported"),
            v.contains("NOT VALID"),
        );
        t.kz(&["extract", &format!("{d}.cms"), "-o", &format!("x_{a}.txt")]);
        let x = std::fs::read(t.path(&format!("x_{a}.txt"))).unwrap_or_default();
        t.check(
            &format!("{a}: extract returns the original"),
            x == doc.as_bytes(),
        );
        let ts = format!("ts_{a}.cms");
        t.kz(&[
            "sign",
            "-k",
            &key(&format!("alice_{a}.p12")),
            "doc.txt",
            "--tsa",
            &tsa,
            "-o",
            &ts,
        ]);
        let v = t.kz(&["verify", &ts, "--trust", &ca]);
        t.check(
            &format!("{a}: timestamped signature verifies"),
            v.contains("timestamp by FAKE TEST TSA, signature ok"),
        );
    }

    let mut d = std::fs::read(t.path("d_gost2015.txt.cms")).unwrap();
    let i = d.windows(4).position(|w| w == b"test").unwrap();
    d[i] = b'T';
    std::fs::write(t.path("t.cms"), d).unwrap();
    let v = t.kz(&["verify", "t.cms", "--trust", &key("ca_gost2015.cer")]);
    t.check("tampered document is rejected", v.contains("content hash"));

    std::fs::copy(t.path("d_rsa.txt.cms"), t.path("mixed.cms")).unwrap();
    t.kz(&["sign", "-k", &key("alice_gost2004.p12"), "mixed.cms"]);
    let v = t.kz(&[
        "verify",
        "mixed.cms",
        "--trust",
        &key("ca_rsa.cer"),
        "--trust",
        &key("ca_gost2004.cer"),
    ]);
    t.check(
        "mixed RSA + GOST co-signing (3 signers)",
        v.contains("VALID - all 3"),
    );

    t.kz(&[
        "sign",
        "-k",
        &key("alice_gost2015.p12"),
        "doc.txt",
        "--detached",
        "-o",
        "det.cms",
    ]);
    t.check(
        "detached: needs the original",
        t.kz(&["verify", "det.cms"]).contains("detached signature"),
    );
    let v = t.kz(&[
        "verify",
        "det.cms",
        "--data",
        "doc.txt",
        "--trust",
        &key("ca_gost2015.cer"),
    ]);
    t.check(
        "detached: verifies with original",
        v.contains("VALID - all 1"),
    );
    std::fs::write(t.path("o.txt"), "other\n").unwrap();
    t.check(
        "detached: wrong original rejected",
        t.kz(&["verify", "det.cms", "--data", "o.txt"])
            .contains("NOT VALID"),
    );
    let v = t.kz(&[
        "sign",
        "-k",
        &key("bob_gost2015.p12"),
        "det.cms",
        "--data",
        "o.txt",
    ]);
    t.check(
        "detached co-sign: wrong original refused",
        v.contains("does not match this .cms"),
    );
    t.kz(&[
        "sign",
        "-k",
        &key("bob_gost2015.p12"),
        "det.cms",
        "--data",
        "doc.txt",
    ]);
    let v = t.kz(&[
        "verify",
        "det.cms",
        "--data",
        "doc.txt",
        "--trust",
        &key("ca_gost2015.cer"),
    ]);
    t.check("detached co-sign", v.contains("VALID - all 2"));

    let (v, _) = t.kz_env(
        &[
            "sign",
            "-k",
            &key("alice_rsa.p12"),
            "doc.txt",
            "-o",
            "w.cms",
        ],
        "x",
    );
    t.check(
        "wrong password message",
        v.contains("password is probably wrong"),
    );

    let b64 = kzsigner::base64_encode(&std::fs::read(t.path("d_rsa.txt.cms")).unwrap());
    let wrapped: Vec<String> = b64
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into())
        .collect();
    std::fs::write(t.path("b64.cms"), wrapped.join("\n") + "\n").unwrap();
    let v = t.kz(&["verify", "b64.cms", "--trust", &key("ca_rsa.cer")]);
    t.check("Base64 .cms accepted", v.contains("VALID - all 2"));

    let (_, json) = t.kz_env(&["verify", "d_rsa.txt.cms", "--json"], PASSWORD);
    t.check(
        "JSON output",
        json_ok(&json) && json.matches("\"index\": ").count() == 2,
    );

    t.check(
        "NCA RK's own CA certificate signatures verify (GOST 2004, GOST 2015, RSA)",
        kzsigner::trust::check_bundled().unwrap() == (10, 0),
    );

    // compatibility with files and keys made by NCA's Kalkan library (NCALayer's crypto)
    for a in ["gost2015", "gost2004", "rsa"] {
        let ca = s(&fx.join(format!("ca_{a}.cer")));
        let v = t.kz(&[
            "verify",
            &s(&fx.join(format!("cosigned_{a}.cms"))),
            "--trust",
            &ca,
        ]);
        t.check(
            &format!("kalkan {a}: co-signed file verifies"),
            v.contains("VALID - all 2"),
        );
        let v = t.kz(&[
            "verify",
            &s(&fx.join(format!("timestamped_{a}.cms"))),
            "--trust",
            &ca,
        ]);
        t.check(
            &format!("kalkan {a}: timestamped file verifies"),
            v.contains("FAKE TEST TSA, signature ok"),
        );
        let kc = format!("k_{a}.cms");
        std::fs::copy(fx.join(format!("cosigned_{a}.cms")), t.path(&kc)).unwrap();
        t.kz(&["sign", "-k", &s(&fx.join(format!("alice_{a}.p12"))), &kc]);
        let v = t.kz(&["verify", &kc, "--trust", &ca]);
        t.check(
            &format!("kalkan {a}: key file opens and co-signs a kalkan file (3 signers)"),
            v.contains("VALID - all 3"),
        );
    }
    let v = t.kz(&[
        "verify",
        &s(&fx.join("detached_gost2015.cms")),
        "--data",
        &s(&fx.join("doc.txt")),
        "--trust",
        &s(&fx.join("ca_gost2015.cer")),
    ]);
    t.check(
        "kalkan: detached file verifies with original",
        v.contains("VALID - all 1"),
    );

    println!("\n{} passed, {} failed", t.pass, t.fail.len());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(t.fail.is_empty(), "failed: {:?}", t.fail);
}

#[test]
fn pdf_and_card() {
    let dir = std::env::temp_dir().join(format!("kzsigner-pdf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut t = Run {
        dir: dir.clone(),
        pass: 0,
        fail: vec![],
    };
    let k = fixtures().join("keys");
    let key = |n: &str| s(&k.join(n));
    let carol = s(&fixtures().join("ocsp/carol.p12"));
    let ocsp_ca = s(&fixtures().join("ocsp/ca.cer"));
    let tsa = fake_tsa();
    let ocsp = fake_ocsp(false);
    for f in ["plain.pdf", "objstm.pdf", "land.pdf"] {
        std::fs::copy(fixtures().join("pdf").join(f), t.path(f)).unwrap();
    }
    let orig = std::fs::read(t.path("plain.pdf")).unwrap();

    // PAdES: the signature inside the PDF
    for (a, f) in [
        ("rsa", "plain.pdf"),
        ("gost2015", "objstm.pdf"),
        ("gost2004", "plain.pdf"),
    ] {
        let out = format!("pades_{a}.pdf");
        t.kz(&[
            "sign",
            "--pdf",
            "-k",
            &key(&format!("alice_{a}.p12")),
            f,
            "-o",
            &out,
        ]);
        let v = t.kz(&["verify", &out, "--trust", &key(&format!("ca_{a}.cer"))]);
        t.check(
            &format!("PAdES {a}: signed PDF verifies"),
            v.contains("VALID - all 1"),
        );
        t.kz(&[
            "sign",
            "--pdf",
            "-k",
            &key(&format!("bob_{a}.p12")),
            &out,
            "--tsa",
            &tsa,
        ]);
        let v = t.kz(&["verify", &out, "--trust", &key(&format!("ca_{a}.cer"))]);
        t.check(
            &format!("PAdES {a}: second signature added, both verify"),
            v.contains("VALID - all 2"),
        );
    }
    t.kz(&["sign", "--pdf", "-k", &key("alice_rsa.p12"), "plain.pdf"]);
    let signed = std::fs::read(t.path("plain-signed.pdf")).unwrap();
    t.check(
        "PAdES: the original PDF is kept unchanged at the start",
        signed.starts_with(&orig),
    );
    let mut bad = signed.clone();
    let i = bad.windows(9).position(|w| w == b"Helvetica").unwrap();
    bad[i] = b'h';
    std::fs::write(t.path("bad.pdf"), &bad).unwrap();
    let v = t.kz(&["verify", "bad.pdf", "--trust", &key("ca_rsa.cer")]);
    t.check("PAdES: a changed PDF is rejected", v.contains("NOT VALID"));
    let mut more = signed.clone();
    more.extend(b"\n% appended later\n");
    std::fs::write(t.path("more.pdf"), &more).unwrap();
    let v = t.kz(&["verify", "more.pdf", "--trust", &key("ca_rsa.cer")]);
    t.check(
        "PAdES: changes after the signature are reported",
        v.contains("NOT VALID") || v.contains("after"),
    );

    // document card (ddcard), with an OCSP answer kept in each signature
    let v = t.kz(&[
        "sign",
        "--card",
        "--qr",
        "-k",
        &carol,
        "--trust",
        &ocsp_ca,
        "--tsa",
        &tsa,
        "--ocsp",
        &ocsp,
        "plain.pdf",
    ]);
    t.check(
        "card: made",
        v.contains("plain.pdf.card.pdf") && !v.contains("OCSP"),
    );
    let v = t.kz(&["verify", "plain.pdf.card.pdf", "--trust", &ocsp_ca]);
    t.check(
        "card: verifies, with the kept OCSP answer",
        v.contains("VALID - all 1")
            && v.contains("answer kept in the signature")
            && v.contains("inside the document card"),
    );
    // the kept answer is also in the revocationValues attribute (Order 500 p.8)
    let card =
        kzsigner::pdf::card::read(&std::fs::read(t.path("plain.pdf.card.pdf")).unwrap()).unwrap();
    let mut sd = kzsigner::cms::SignedData::parse(&card.signatures[0].1).unwrap();
    let in_crls = kzsigner::pdf::card::embedded_ocsp(&sd).unwrap();
    let has_attr = sd.signers[0]
        .unsigned()
        .iter()
        .any(|(o, _)| o == kzsigner::pdf::card::ATTR_REVOCATION_VALUES);
    sd.crls = None;
    // the BasicOCSPResponse inside an OCSPResponse
    let basic = |raw: &[u8]| -> Vec<u8> {
        let r = kzsigner::der::parse(raw)
            .unwrap()
            .items(kzsigner::der::SEQUENCE)
            .unwrap();
        let b = r[1]
            .inner()
            .unwrap()
            .items(kzsigner::der::SEQUENCE)
            .unwrap();
        b[1].octets().unwrap()
    };
    let has_certs = sd.signers[0]
        .unsigned()
        .iter()
        .any(|(o, _)| o == kzsigner::pdf::card::ATTR_CERT_VALUES);
    t.check(
        "card: revocationValues holds the same OCSP answer, with certValues",
        has_attr
            && has_certs
            && basic(&kzsigner::pdf::card::embedded_ocsp(&sd).unwrap()) == basic(&in_crls),
    );
    let v = t.kz(&[
        "sign",
        "--card",
        "-k",
        &key("alice_gost2015.p12"),
        "--trust",
        &key("ca_gost2015.cer"),
        "--trust",
        &ocsp_ca,
        "--tsa",
        &tsa,
        "--ocsp",
        "http://127.0.0.1:9/",
        "plain.pdf.card.pdf",
    ]);
    t.check(
        "card: a second signature is added",
        v.contains("Signature added") && v.contains("No OCSP answer"),
    );
    let v = t.kz(&[
        "verify",
        "plain.pdf.card.pdf",
        "--trust",
        &ocsp_ca,
        "--trust",
        &key("ca_gost2015.cer"),
    ]);
    t.check(
        "card: both signatures verify",
        v.contains("VALID - all 2") && v.contains("carries no OCSP answer"),
    );
    t.kz(&["extract", "plain.pdf.card.pdf", "-o", "back.pdf"]);
    t.check(
        "card: extract returns the original",
        std::fs::read(t.path("back.pdf")).unwrap() == orig,
    );
    let (_, json) = t.kz_env(&["verify", "plain.pdf.card.pdf", "--json"], PASSWORD);
    t.check(
        "card: JSON output",
        json_ok(&json) && json.contains("\"cardDocument\": \"plain.pdf\""),
    );

    let v = t.kz(&[
        "sign", "--card", "--lang", "kk/ru", "-k", &carol, "--trust", &ocsp_ca, "--tsa", &tsa,
        "--ocsp", &ocsp, "land.pdf",
    ]);
    t.check(
        "card: Kazakh and Russian, landscape pages",
        v.contains("land.pdf.card.pdf"),
    );
    std::fs::write(t.path("note.txt"), "Справка №5\n").unwrap();
    t.kz(&[
        "sign", "--card", "-k", &carol, "--trust", &ocsp_ca, "--tsa", &tsa, "--ocsp", &ocsp,
        "note.txt",
    ]);
    std::fs::remove_file(t.path("note.txt")).unwrap();
    t.kz(&["extract", "note.txt.card.pdf"]);
    t.check(
        "card: a text document; extract restores it under its own name",
        std::fs::read_to_string(t.path("note.txt")).unwrap_or_default() == "Справка №5\n",
    );
    let v = t.kz(&[
        "sign",
        "--card",
        "-k",
        &carol,
        "--trust",
        &ocsp_ca,
        "--tsa",
        &tsa,
        "--ocsp",
        &fake_ocsp(true),
        "objstm.pdf",
    ]);
    t.check(
        "card: a revoked certificate is refused",
        v.contains("REVOKED") && !t.path("objstm.pdf.card.pdf").exists(),
    );

    // QR codes: the texts a scanner reads, put back together
    let card = std::fs::read(t.path("plain.pdf.card.pdf")).unwrap();
    let doc = lopdf::Document::load_mem(&card).unwrap();
    let names = doc
        .catalog()
        .unwrap()
        .get(b"Names")
        .unwrap()
        .as_dict()
        .unwrap();
    let ef = names.get(b"EmbeddedFiles").unwrap().as_dict().unwrap();
    let list = ef.get(b"Names").unwrap().as_array().unwrap();
    t.check(
        "card: attachments named as ddc names them",
        list[0].as_str().unwrap() == b"Attachement1" && list.len() == 6,
    );
    let info = doc.trailer.get(b"Info").unwrap().as_reference().unwrap();
    let made = doc
        .get_dictionary(info)
        .unwrap()
        .get(b"KzsignerCard")
        .unwrap()
        .as_str()
        .unwrap();
    t.check(
        "card: adding a signature keeps the QR codes",
        made == b"ru;qr",
    );
    let spec = doc.get_dictionary(list[3].as_reference().unwrap()).unwrap();
    let stream = doc
        .get_object(
            spec.get(b"EF")
                .unwrap()
                .as_dict()
                .unwrap()
                .get(b"F")
                .unwrap()
                .as_reference()
                .unwrap(),
        )
        .unwrap()
        .as_stream()
        .unwrap();
    let cms = stream.decompressed_content().unwrap();
    let mut codes = kzsigner::pdf::qr::payloads(1, &cms).unwrap();
    codes.reverse();
    std::fs::write(t.path("scans.txt"), codes.join("\n")).unwrap();
    let v = t.kz(&[
        "verify",
        "--qr",
        "scans.txt",
        "--data",
        "plain.pdf",
        "--trust",
        &ocsp_ca,
    ]);
    t.check(
        "QR: scanned codes verify against the document",
        v.contains("VALID - all 1"),
    );
    let v = t.kz(&[
        "verify",
        "--qr",
        "scans.txt",
        "--data",
        "land.pdf",
        "--trust",
        &ocsp_ca,
    ]);
    t.check("QR: wrong document is rejected", v.contains("NOT VALID"));
    std::fs::write(t.path("scans.txt"), codes[1..].join("\n")).unwrap();
    t.check(
        "QR: a missing code is named",
        t.kz(&["verify", "--qr", "scans.txt", "--data", "plain.pdf"])
            .contains("missing part"),
    );

    println!("\n{} passed, {} failed", t.pass, t.fail.len());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(t.fail.is_empty(), "failed: {:?}", t.fail);
}

#[test]
fn long_term() {
    let dir = std::env::temp_dir().join(format!("kzsigner-lt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut t = Run {
        dir: dir.clone(),
        pass: 0,
        fail: vec![],
    };
    let carol = s(&fixtures().join("ocsp/carol.p12"));
    let ocsp_ca = s(&fixtures().join("ocsp/ca.cer"));
    // the fake TSA's own (self-signed) certificate, trusted for these checks
    let tsa_key = kzsigner::p12::open(
        &std::fs::read(fixtures().join("keys/tsa.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    std::fs::write(t.path("tsa.cer"), &tsa_key.cert.der).unwrap();
    let tsa = fake_tsa();
    let ocsp = fake_ocsp(false);
    let trusted = ["--trust", &ocsp_ca, "--trust", "tsa.cer"];
    let with = |args: &[&str]| -> Vec<String> {
        args.iter()
            .chain(trusted.iter())
            .map(|a| a.to_string())
            .collect()
    };
    let kz = |t: &Run, args: &[&str]| -> String {
        let a = with(args);
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        t.kz(&a)
    };
    std::fs::write(t.path("doc.txt"), "Договор №7\n").unwrap();
    std::fs::copy(fixtures().join("pdf/plain.pdf"), t.path("plain.pdf")).unwrap();

    // CAdES B-LTA in one go
    let v = kz(
        &t,
        &[
            "sign", "-k", &carol, "--tsa", &tsa, "--ocsp", &ocsp, "--level", "LTA", "doc.txt",
        ],
    );
    t.check(
        "LTA: signed",
        v.contains("long-term with archive timestamp (B-LTA)"),
    );
    let v = kz(&t, &["verify", "doc.txt.cms"]);
    t.check(
        "LTA: verifies offline with the kept answer and an archive timestamp",
        v.contains("VALID - all 1")
            && v.contains("B-LTA")
            && v.contains("answer kept in the signature")
            && v.contains("Archived:")
            && v.contains("verified, trusted TSA"),
    );
    let (_, json) = t.kz_env(
        &[
            "verify",
            "doc.txt.cms",
            "--json",
            "--trust",
            &ocsp_ca,
            "--trust",
            "tsa.cer",
        ],
        PASSWORD,
    );
    t.check(
        "LTA: JSON level, archive timestamps, kept-ocsp",
        json_ok(&json)
            && json.contains("\"level\": \"B-LTA\"")
            && json.contains("\"revocationSource\": \"kept-ocsp\"")
            && json.contains("\"archiveTimestamps\": ["),
    );
    // the Order 500 attributes are there too
    let sd = cms::SignedData::parse(&std::fs::read(t.path("doc.txt.cms")).unwrap()).unwrap();
    let attrs: Vec<String> = sd.signers[0]
        .unsigned()
        .into_iter()
        .map(|(o, _)| o)
        .collect();
    t.check(
        "LTA: revocationValues, certValues, archive-time-stamp-v3",
        [
            kzsigner::ltv::ATTR_REVOCATION_VALUES,
            kzsigner::ltv::ATTR_CERT_VALUES,
            kzsigner::ltv::ATTR_ARCHIVE_TIMESTAMP_V3,
        ]
        .iter()
        .all(|a| attrs.iter().any(|x| x == a)),
    );

    // renewing adds a second archive timestamp; both hold
    let v = kz(
        &t,
        &["extend", "doc.txt.cms", "--tsa", &tsa, "--ocsp", &ocsp],
    );
    t.check("extend: renewed", v.contains("Extended to B-LTA"));
    let v = kz(&t, &["verify", "doc.txt.cms"]);
    t.check(
        "extend: two archive timestamps, valid",
        v.contains("VALID - all 1") && v.matches("Archived:").count() == 2,
    );

    // a later revocation does not stop a renewal: the kept answer covers the signing time
    let v = kz(
        &t,
        &[
            "extend",
            "doc.txt.cms",
            "-o",
            "renewed.cms",
            "--tsa",
            &tsa,
            "--ocsp",
            &fake_ocsp(true),
        ],
    );
    t.check(
        "extend: renewing does not ask about the signer again",
        v.contains("Extended to B-LTA") && !v.contains("Error"),
    );
    t.check(
        "extend: the renewed file verifies",
        kz(&t, &["verify", "renewed.cms"]).contains("VALID - all 1"),
    );

    // taking out kept data an archive timestamp covers is caught
    let mut sd = cms::SignedData::parse(&std::fs::read(t.path("doc.txt.cms")).unwrap()).unwrap();
    sd.certs.retain(|c| *c != tsa_key.cert.der);
    std::fs::write(t.path("cut.cms"), sd.encode()).unwrap();
    let v = kz(&t, &["verify", "cut.cms"]);
    t.check(
        "LTA: removed data is caught",
        v.contains("NOT VALID") && v.contains("no longer in the signature"),
    );
    // and so is a changed signed attribute (the signature itself breaks too)
    let v = kz(&t, &["verify", "doc.txt.cms.bak"]);
    t.check(
        "extend: the previous version is kept",
        v.contains("VALID - all 1"),
    );

    // B-T to B-LT, and a detached signature's archive timestamp needs the document
    kz(
        &t,
        &[
            "sign",
            "--detached",
            "-k",
            &carol,
            "--tsa",
            &tsa,
            "-o",
            "det.cms",
            "doc.txt",
        ],
    );
    let v = kz(&t, &["verify", "det.cms", "--data", "doc.txt"]);
    t.check("B-T: reported", v.contains("B-T (timestamped)"));
    let v = kz(&t, &["extend", "det.cms", "--level", "LT", "--ocsp", &ocsp]);
    t.check("extend: B-T to B-LT", v.contains("Extended to B-LT"));
    let v = kz(&t, &["extend", "det.cms", "--tsa", &tsa, "--ocsp", &ocsp]);
    t.check(
        "extend: a detached .cms needs its document for LTA",
        v.contains("Provide the original file"),
    );
    kz(
        &t,
        &[
            "extend", "det.cms", "--data", "doc.txt", "--tsa", &tsa, "--ocsp", &ocsp,
        ],
    );
    let v = kz(&t, &["verify", "det.cms", "--data", "doc.txt"]);
    t.check(
        "extend: detached B-LTA",
        v.contains("VALID - all 1") && v.contains("B-LTA"),
    );
    let v = kz(&t, &["verify", "det.cms"]);
    t.check(
        "LTA: without the document, the archive timestamp is not checked",
        v.contains("the signed document is needed"),
    );
    let v = kz(&t, &["verify", "det.cms", "--data", "plain.pdf"]);
    t.check("LTA: another document fails", v.contains("NOT VALID"));

    // a revoked signer is not made long-term
    kz(
        &t,
        &[
            "sign", "-k", &carol, "--tsa", &tsa, "-o", "rev.cms", "doc.txt",
        ],
    );
    let v = kz(
        &t,
        &[
            "extend",
            "rev.cms",
            "--tsa",
            &tsa,
            "--ocsp",
            &fake_ocsp(true),
        ],
    );
    t.check(
        "extend: a revoked signer is refused",
        v.contains("REVOKED") && v.contains("Error"),
    );

    // without a timestamp there is nothing to make long-term
    kz(&t, &["sign", "-k", &carol, "-o", "bare.cms", "doc.txt"]);
    let v = kz(&t, &["extend", "bare.cms", "--tsa", &tsa, "--ocsp", &ocsp]);
    t.check(
        "extend: needs a timestamp",
        v.contains("has no timestamp") && v.contains("Error"),
    );

    // PAdES B-LTA: DSS and a document timestamp
    let v = kz(
        &t,
        &[
            "sign",
            "--pdf",
            "-k",
            &carol,
            "--tsa",
            &tsa,
            "--ocsp",
            &ocsp,
            "--level",
            "LTA",
            "plain.pdf",
        ],
    );
    t.check("PAdES LTA: signed", v.contains("B-LTA"));
    let v = kz(&t, &["verify", "plain-signed.pdf"]);
    t.check(
        "PAdES LTA: verifies with the DSS and the document timestamp",
        v.contains("VALID - all 1")
            && v.contains("Document timestamp:")
            && v.contains("B-LTA")
            && v.contains("answer kept in the signature"),
    );
    let doc =
        lopdf::Document::load_mem(&std::fs::read(t.path("plain-signed.pdf")).unwrap()).unwrap();
    let kept = kzsigner::pdf::dss(&doc);
    t.check(
        "PAdES LTA: the DSS holds certificates and the OCSP answer",
        !kept.certs.is_empty() && !kept.ocsps.is_empty(),
    );
    let mut more = std::fs::read(t.path("plain-signed.pdf")).unwrap();
    let i = more.windows(9).rposition(|w| w == b"Helvetica").unwrap();
    more[i] = b'h';
    std::fs::write(t.path("bad.pdf"), &more).unwrap();
    t.check(
        "PAdES LTA: a changed PDF fails",
        kz(&t, &["verify", "bad.pdf"]).contains("NOT VALID"),
    );
    // a second signer, then renew: the earlier document timestamp stays valid
    kz(
        &t,
        &[
            "sign",
            "--pdf",
            "-k",
            &carol,
            "--tsa",
            &tsa,
            "plain-signed.pdf",
        ],
    );
    kz(
        &t,
        &["extend", "plain-signed.pdf", "--tsa", &tsa, "--ocsp", &ocsp],
    );
    let v = kz(&t, &["verify", "plain-signed.pdf"]);
    t.check(
        "PAdES: co-signed and renewed, everything valid",
        v.contains("VALID - all 2") && v.matches("Document timestamp:").count() == 2,
    );
    let (_, json) = t.kz_env(
        &[
            "verify",
            "plain-signed.pdf",
            "--json",
            "--trust",
            &ocsp_ca,
            "--trust",
            "tsa.cer",
        ],
        PASSWORD,
    );
    t.check(
        "PAdES: JSON document timestamps",
        json_ok(&json) && json.matches("\"authority\"").count() >= 2,
    );

    // a visible signature: a stamp with a logo, on the first page's top left
    // (only the JPEG's frame header is read; the viewer decodes the rest)
    let jpeg = [
        0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x10, 0x00, 0x20, 0x03, 1, 0x11, 0, 2,
        0x11, 0, 3, 0x11, 0, 0xff, 0xd9,
    ];
    std::fs::write(t.path("logo.jpg"), jpeg).unwrap();
    std::fs::copy(fixtures().join("pdf/plain.pdf"), t.path("stamped.pdf")).unwrap();
    let v = kz(
        &t,
        &[
            "sign",
            "--pdf",
            "--stamp-page",
            "1",
            "--stamp-at",
            "tl",
            "--stamp-lang",
            "kk",
            "--stamp-logo",
            "logo.jpg",
            "-k",
            &carol,
            "--tsa",
            &tsa,
            "--ocsp",
            &ocsp,
            "--level",
            "LTA",
            "stamped.pdf",
        ],
    );
    t.check("stamp: signed", v.contains("Signed by"));
    let data = std::fs::read(t.path("stamped-signed.pdf")).unwrap();
    let doc = lopdf::Document::load_mem(&data).unwrap();
    let page1 = *doc.get_pages().get(&1).unwrap();
    let annots = doc
        .get_dictionary(page1)
        .unwrap()
        .get(b"Annots")
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    // the signature's widget (the document timestamp's is invisible)
    let widget = annots
        .iter()
        .map(|a| doc.get_dictionary(a.as_reference().unwrap()).unwrap())
        .find(|w| w.has(b"AP"))
        .unwrap();
    let rect: Vec<f32> = widget
        .get(b"Rect")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_float().unwrap())
        .collect();
    t.check(
        "stamp: a widget with an appearance near the top left of page 1",
        widget.has(b"AP") && rect[0] < 40.0 && rect[3] > 750.0 && rect[2] - rect[0] > 200.0,
    );
    t.check(
        "stamp: the logo is in the PDF",
        data.windows(9).any(|w| w == b"DCTDecode"),
    );
    let v = kz(&t, &["verify", "stamped-signed.pdf"]);
    t.check(
        "stamp: verifies, long-term",
        v.contains("VALID - all 1") && v.contains("B-LTA"),
    );
    // a second stamp in the same corner goes below the first, not over it
    kz(
        &t,
        &[
            "sign",
            "--pdf",
            "--stamp-page",
            "1",
            "--stamp-at",
            "tl",
            "-k",
            &carol,
            "-o",
            "stamped2.pdf",
            "stamped-signed.pdf",
        ],
    );
    let data = std::fs::read(t.path("stamped2.pdf")).unwrap_or_default();
    let rects: Vec<Vec<f32>> = lopdf::Document::load_mem(&data)
        .map(|doc| {
            let page1 = *doc.get_pages().get(&1).unwrap();
            let annots = doc.get_dictionary(page1).unwrap().get(b"Annots").unwrap();
            annots
                .as_array()
                .unwrap()
                .iter()
                .map(|a| doc.get_dictionary(a.as_reference().unwrap()).unwrap())
                .filter(|w| w.has(b"AP"))
                .map(|w| {
                    w.get(b"Rect")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_float().unwrap())
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default();
    t.check(
        "stamp: a second stamp sits below the first",
        rects.len() == 2 && rects[1][3] < rects[0][1],
    );
    let v = kz(&t, &["verify", "stamped2.pdf"]);
    t.check("stamp: both verify", v.contains("VALID - all 2"));
    // signing by hash, long-term (LT: no archive timestamp, which would need the document)
    let h = t
        .kz(&["hash", "--alg", "sha256", "doc.txt"])
        .trim()
        .to_string();
    let v = kz(
        &t,
        &[
            "sign",
            "--hash",
            &h,
            "-k",
            &carol,
            "--tsa",
            &tsa,
            "--ocsp",
            &ocsp,
            "--level",
            "LT",
            "-o",
            "hash-lt.cms",
        ],
    );
    t.check(
        "hash LT: signed",
        v.contains("Signed by") && !v.contains("not as a long-term"),
    );
    let v = kz(&t, &["verify", "--data", "doc.txt", "hash-lt.cms"]);
    t.check(
        "hash LT: verifies, B-LT",
        v.contains("VALID - all 1") && v.contains("B-LT"),
    );
    let v = kz(&t, &["sign", "--stamp", "-k", &carol, "doc.txt"]);
    t.check("stamp: only with --pdf", v.contains("need --pdf"));

    println!("\n{} passed, {} failed", t.pass, t.fail.len());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(t.fail.is_empty(), "failed: {:?}", t.fail);
}

/// A small JSON syntax check (enough to know the output parses).
fn json_ok(s: &str) -> bool {
    fn ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }
    fn val(b: &[u8], i: &mut usize) -> bool {
        ws(b, i);
        let Some(&c) = b.get(*i) else { return false };
        match c {
            b'{' | b'[' => {
                let close = if c == b'{' { b'}' } else { b']' };
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&close) {
                    *i += 1;
                    return true;
                }
                loop {
                    if c == b'{' {
                        ws(b, i);
                        if !string(b, i) {
                            return false;
                        }
                        ws(b, i);
                        if b.get(*i) != Some(&b':') {
                            return false;
                        }
                        *i += 1;
                    }
                    if !val(b, i) {
                        return false;
                    }
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(x) if *x == close => {
                            *i += 1;
                            return true;
                        }
                        _ => return false,
                    }
                }
            }
            b'"' => string(b, i),
            _ => {
                let start = *i;
                while *i < b.len() && (b[*i].is_ascii_alphanumeric() || b"-+.".contains(&b[*i])) {
                    *i += 1;
                }
                let w = &s_of(b)[start..*i];
                matches!(w, "true" | "false" | "null") || w.parse::<f64>().is_ok()
            }
        }
    }
    fn s_of(b: &[u8]) -> &str {
        std::str::from_utf8(b).unwrap_or("")
    }
    fn string(b: &[u8], i: &mut usize) -> bool {
        if b.get(*i) != Some(&b'"') {
            return false;
        }
        *i += 1;
        while let Some(&c) = b.get(*i) {
            *i += 1;
            match c {
                b'\\' => *i += 1,
                b'"' => return true,
                _ => {}
            }
        }
        false
    }
    let b = s.as_bytes();
    let mut i = 0;
    let ok = val(b, &mut i);
    ws(b, &mut i);
    ok && i == b.len()
}

/// XAdES: signing XML documents inside them, and checking them.
#[test]
fn xml() {
    let dir = std::env::temp_dir().join(format!("kzsigner-xml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut t = Run {
        dir: dir.clone(),
        pass: 0,
        fail: vec![],
    };
    let tsa_key = kzsigner::p12::open(
        &std::fs::read(fixtures().join("keys/tsa.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    std::fs::write(t.path("tsa.cer"), &tsa_key.cert.der).unwrap();
    let tsa = fake_tsa();
    let doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- заявка -->\n<z:Request xmlns:z=\"urn:z\" xmlns=\"urn:d\" xml:lang=\"kk\">\n  <z:Item n=\"1\">Договор &amp; №7</z:Item>\n  <Empty/>\n</z:Request>\n";
    std::fs::write(t.path("req.xml"), doc).unwrap();

    for a in ["gost2015", "gost2015_256", "gost2004", "rsa"] {
        let key = s(&fixtures().join(format!("keys/alice_{a}.p12")));
        let ca = s(&fixtures().join(format!("keys/ca_{a}.cer")));
        let out = format!("req-{a}.xml");
        let v = t.kz(&["sign", "--xml", "-k", &key, "-o", &out, "req.xml"]);
        t.check(&format!("xml {a}: signed"), v.contains("Signed by"));
        let signed = std::fs::read_to_string(t.path(&out)).unwrap_or_default();
        t.check(
            &format!("xml {a}: the document is kept as it was, the signature inside"),
            signed.starts_with(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- заявка -->\n<z:Request",
            ) && signed.contains("<ds:Signature")
                && signed.contains("<xades:SigningCertificateV2>")
                && signed.ends_with("</z:Request>\n"),
        );
        let v = t.kz(&["verify", "--trust", &ca, &out]);
        t.check(
            &format!("xml {a}: verifies (XAdES B-B)"),
            v.contains("VALID - all 1") && v.contains("B-B") && !v.contains("plain XML signature"),
        );
        // any change to the document is caught
        std::fs::write(t.path("bad.xml"), signed.replace("№7", "№8")).unwrap();
        let v = t.kz(&["verify", "--trust", &ca, "bad.xml"]);
        t.check(
            &format!("xml {a}: a changed document is caught"),
            v.contains("NOT VALID") && v.contains("was changed"),
        );
    }

    // with an NCA (here: fake) timestamp: XAdES B-T
    let key = s(&fixtures().join("keys/alice_gost2015.p12"));
    let ca = s(&fixtures().join("keys/ca_gost2015.cer"));
    let v = t.kz(&[
        "sign", "--xml", "-k", &key, "--tsa", &tsa, "--trust", &ca, "--trust", "tsa.cer", "req.xml",
    ]);
    t.check("xml B-T: signed", v.contains("Signed by"));
    let v = t.kz(&[
        "verify",
        "--trust",
        &ca,
        "--trust",
        "tsa.cer",
        "--json",
        "req-signed.xml",
    ]);
    t.check(
        "xml B-T: verifies with the timestamp",
        v.contains("\"valid\": true") && v.contains("B-T") && v.contains("FAKE TEST TSA"),
    );
    let signed = std::fs::read_to_string(t.path("req-signed.xml")).unwrap();
    // the timestamp covers the signature value
    let i = signed.find("<ds:SignatureValue>").unwrap() + 19;
    let mut bad = signed.clone();
    bad.replace_range(i..i + 1, if &signed[i..i + 1] == "A" { "B" } else { "A" });
    std::fs::write(t.path("bad.xml"), bad).unwrap();
    let v = t.kz(&["verify", "--trust", &ca, "--trust", "tsa.cer", "bad.xml"]);
    t.check(
        "xml B-T: a changed signature value is caught",
        v.contains("NOT VALID"),
    );
    // a copy of the signed properties elsewhere does not fool the check
    let sp = &signed[signed.find("<xades:SignedProperties").unwrap()
        ..signed.find("</xades:SignedProperties>").unwrap() + 25];
    // (inside the signature, which the document's digest leaves out)
    let wrapped = signed.replace(
        "</ds:Object>",
        &format!(
            "<x xmlns:xades=\"{}\">{sp}</x></ds:Object>",
            kzsigner::xml::XADES
        ),
    );
    std::fs::write(t.path("bad.xml"), wrapped).unwrap();
    let v = t.kz(&["verify", "--trust", &ca, "--trust", "tsa.cer", "bad.xml"]);
    t.check(
        "xml: duplicated signed parts are refused",
        v.contains("NOT VALID") && v.contains("more than once"),
    );
    std::fs::write(t.path("bad.xml"), "<a><b></a>").unwrap();
    let v = t.kz(&["verify", "bad.xml"]);
    t.check(
        "xml: broken XML is reported as such",
        v.contains("could not be read"),
    );

    // single-byte encodings keep their bytes; the signature checks out
    for (name, body) in [
        ("windows-1251", &b"\xc4\xee\xe3\xee\xe2\xee\xf0 \xb9 7"[..]),
        ("KZ-1048", &b"\xd8\xe0\xf0\xf2 \xe3\xe0 \xbe\xee\xb3"[..]),
    ] {
        let mut doc = format!("<?xml version=\"1.0\" encoding=\"{name}\"?>\n<doc>").into_bytes();
        doc.extend_from_slice(body);
        doc.extend_from_slice(b"</doc>\n");
        std::fs::write(t.path("enc.xml"), &doc).unwrap();
        let _ = std::fs::remove_file(t.path("enc-signed.xml"));
        let v = t.kz(&["sign", "--xml", "-k", &key, "enc.xml"]);
        t.check(&format!("xml {name}: signed"), v.contains("Signed by"));
        let signed = std::fs::read(t.path("enc-signed.xml")).unwrap_or_default();
        t.check(
            &format!("xml {name}: the document's bytes are kept"),
            signed.starts_with(&doc[..doc.len() - 7]) && signed.ends_with(b"</doc>\n"),
        );
        let v = t.kz(&["verify", "--trust", &ca, "enc-signed.xml"]);
        t.check(
            &format!("xml {name}: verifies"),
            v.contains("VALID - all 1"),
        );
    }

    // a second signature inside: both hold
    let bob = s(&fixtures().join("keys/bob_gost2015.p12"));
    let v = t.kz(&[
        "sign",
        "--xml",
        "-k",
        &bob,
        "--trust",
        &ca,
        "-o",
        "two.xml",
        "req-signed.xml",
    ]);
    t.check("xml: a second signature inside", v.contains("2 signatures"));
    let v = t.kz(&["verify", "--trust", &ca, "--trust", "tsa.cer", "two.xml"]);
    t.check(
        "xml: both signatures verify",
        v.contains("VALID - all 2") && v.contains("ПЕТРОВА"),
    );
    // a signature that covers other signatures leaves no room for another
    let closed = std::fs::read_to_string(t.path("req-signed.xml")).unwrap();
    let a = closed
        .find("<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\"")
        .unwrap();
    let b = a + closed[a..].find("</ds:Transform>").unwrap() + 15;
    std::fs::write(
        t.path("closed.xml"),
        format!("{}{}", &closed[..a], &closed[b..]),
    )
    .unwrap();
    let v = t.kz(&["sign", "--xml", "-k", &bob, "-o", "again.xml", "closed.xml"]);
    t.check(
        "xml: no second signature when the first covers everything",
        v.contains("covers everything"),
    );

    // what is refused
    std::fs::write(t.path("doc.txt"), "not xml").unwrap();
    let v = t.kz(&["sign", "--xml", "-k", &key, "doc.txt"]);
    t.check("xml: only XML", v.contains("not an XML document"));
    let v = t.kz(&["sign", "--xml", "--level", "LTA", "-k", &key, "req.xml"]);
    t.check(
        "xml: no long-term level yet",
        v.contains("--level is not supported"),
    );
    let v = t.kz(&["verify", "--trust", &ca, "req.xml"]);
    t.check("xml: an unsigned document", v.contains("no signatures"));
    // text that looks like the signer's own placeholders stays as it was
    std::fs::write(t.path("odd.xml"), "<a>@@SP@@ @@SV@@ @@UP@@</a>").unwrap();
    t.kz(&["sign", "--xml", "-k", &key, "odd.xml"]);
    let v = t.kz(&["verify", "--trust", &ca, "odd-signed.xml"]);
    t.check(
        "xml: placeholder-like text is left alone",
        v.contains("VALID - all 1")
            && std::fs::read_to_string(t.path("odd-signed.xml"))
                .unwrap_or_default()
                .starts_with("<a>@@SP@@ @@SV@@ @@UP@@<ds:Signature"),
    );
    std::fs::write(
        t.path("dtd.xml"),
        "<!DOCTYPE a [<!ATTLIST a x CDATA \"1\">]><a/>",
    )
    .unwrap();
    let v = t.kz(&["sign", "--xml", "-k", &key, "dtd.xml"]);
    t.check("xml: DTD attribute defaults are refused", v.contains("DTD"));
    let v = t.kz(&["verify", "--data", "req.xml", "req-signed.xml"]);
    t.check(
        "xml: --data is not for XML",
        v.contains("check the signed XML file alone"),
    );

    println!("\n{} passed, {} failed", t.pass, t.fail.len());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(t.fail.is_empty(), "failed: {:?}", t.fail);
}

/// Signing a document by its hash only, as NCALayer's createCAdESFromBase64Hash does.
#[test]
fn by_hash() {
    let dir = std::env::temp_dir().join(format!("kzsigner-hash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut t = Run {
        dir: dir.clone(),
        pass: 0,
        fail: vec![],
    };
    std::fs::write(t.path("doc.txt"), "Договор №7\n").unwrap();
    for (a, alg) in [
        ("gost2015", "gost2015"),
        ("gost2015_256", "gost2015-256"),
        ("gost2004", "gost2004"),
        ("rsa", "sha256"),
    ] {
        let key = s(&fixtures().join(format!("keys/alice_{a}.p12")));
        let ca = s(&fixtures().join(format!("keys/ca_{a}.cer")));
        let h = t.kz(&["hash", "--alg", alg, "doc.txt"]).trim().to_string();
        let out = format!("doc-{a}.cms");
        let v = t.kz(&["sign", "--hash", &h, "-k", &key, "-o", &out]);
        t.check(&format!("hash {a}: signed"), v.contains("Signed by"));
        let v = t.kz(&["verify", "--trust", &ca, "--data", "doc.txt", &out]);
        t.check(
            &format!("hash {a}: verifies against the document"),
            v.contains("VALID - all 1"),
        );
        std::fs::write(t.path("other.txt"), "Договор №8\n").unwrap();
        let v = t.kz(&["verify", "--trust", &ca, "--data", "other.txt", &out]);
        t.check(
            &format!("hash {a}: another document does not"),
            v.contains("NOT VALID"),
        );
    }
    let key = s(&fixtures().join("keys/alice_gost2015.p12"));
    // hex works too; the length must fit the key
    let h = t
        .kz(&["hash", "--alg", "gost2015", "doc.txt"])
        .trim()
        .to_string();
    let hex: String = kzsigner::base64_decode(&h)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let v = t.kz(&["sign", "--hash", &hex, "-k", &key, "-o", "hex.cms"]);
    t.check("hash: hex", v.contains("Signed by"));
    let sha = t
        .kz(&["hash", "--alg", "sha256", "doc.txt"])
        .trim()
        .to_string();
    let v = t.kz(&["sign", "--hash", &sha, "-k", &key, "-o", "x.cms"]);
    t.check("hash: wrong length refused", v.contains("64-byte"));
    let v = t.kz(&["sign", "--hash", &h, "-k", &key, "doc.txt"]);
    t.check("hash: no FILE with --hash", v.contains("not a file"));
    let v = t.kz(&[
        "sign", "--hash", &h, "-k", &key, "--level", "LTA", "-o", "x.cms",
    ]);
    t.check("hash: no LTA", v.contains("use LT with --hash"));

    println!("\n{} passed, {} failed", t.pass, t.fail.len());
    let _ = std::fs::remove_dir_all(&dir);
    assert!(t.fail.is_empty(), "failed: {:?}", t.fail);
}
