//! Fake NCA servers for tests, on 127.0.0.1 (NOT NCA's): a TSA and an OCSP responder with
//! the test keys in tests/fixtures. Shared by the end-to-end tests and the app core's
//! (ffi) tests.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use kzsigner::cms;
use kzsigner::der;
use kzsigner::tsp::{Request, TST_INFO};

const PASSWORD: &str = "Qwerty12";

/// tests/fixtures, from this crate or from ffi/.
fn fixtures() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let f = here.join("tests/fixtures");
    if f.exists() {
        f
    } else {
        here.join("../tests/fixtures")
    }
}

/// Test only: a fake TSA on 127.0.0.1 (NOT NCA's), key from tsa.p12. Returns its URL.
pub fn fake_tsa() -> String {
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
pub fn serve(
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
pub fn fake_ocsp(revoked: bool) -> String {
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
