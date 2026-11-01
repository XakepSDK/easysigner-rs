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
        let o = Command::new(env!("CARGO_BIN_EXE_kzsigner"))
            .args(args)
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
