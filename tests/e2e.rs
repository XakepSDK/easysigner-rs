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
