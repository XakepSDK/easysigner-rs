//! Fake NCA servers for tests, on 127.0.0.1 (NOT NCA's): a TSA and an OCSP responder with
//! the test keys in testdata. Shared by the end-to-end tests and the app core's
//! (ffi) tests.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use der_testkit as der;
use kzsigner::cms;
use kzsigner::tsp::{Request, TST_INFO};

const PASSWORD: &str = "Qwerty12";

/// When the fake OCSP responder says a key was revoked: 2026-11-02 00:00 UTC.
const REVOKED_AT: i64 = 1_793_577_600_000;

/// testdata/ at the checkout's root, found from the crate that includes this file (every one is
/// two folders down); or from the current folder, for the fake servers built on one machine and
/// run from a checkout on another (CI's emulators).
fn fixtures() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    [here.join("../../testdata"), PathBuf::from("testdata")]
        .into_iter()
        .find(|f| f.exists())
        .unwrap_or_else(|| PathBuf::from("testdata"))
}

/// Test only: a fake TSA on 127.0.0.1 (NOT NCA's), key from tsa.p12. Returns its URL.
pub fn fake_tsa() -> String {
    serve(tsa_answer(), "application/timestamp-reply")
}

/// The fake TSA's answer to a request body: a time stamp signed with tsa.p12.
pub fn tsa_answer() -> impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static {
    let key = kzsigner::p12::open(
        &std::fs::read(fixtures().join("keys/tsa.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    let serial = std::sync::atomic::AtomicU64::new(1);
    move |body| {
        let n = serial.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        respond(body, &key, n)
    }
}

/// A tiny HTTP server on 127.0.0.1: answers each POST body with `answer(body)`.
pub fn serve(
    answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ctype: &'static str,
) -> String {
    serve_at("127.0.0.1:0", answer, ctype)
}

/// The same on `addr`; None from `answer` is an HTTP 500 (as a server that is down).
pub fn serve_at(
    addr: &str,
    answer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ctype: &'static str,
) -> String {
    let listener = TcpListener::bind(addr).unwrap();
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
    serve(ocsp_answer(move || revoked), "application/ocsp-response")
}

/// The fake OCSP responder's answer to a request body; `revoked()` says how to answer.
pub fn ocsp_answer(
    revoked: impl Fn() -> bool + Send + 'static,
) -> impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static {
    let ca = kzsigner::p12::open(
        &std::fs::read(fixtures().join("ocsp/ca.p12")).unwrap(),
        PASSWORD,
        None,
    )
    .unwrap();
    {
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
            let status = if revoked() {
                // revoked at a fixed time, before every signature the tests check (the test
                // CA starts on 2026-11-01): not "a day ago", which a stored signed file
                // (testdata/app) outlives
                der::tlv(
                    der::ctx(1),
                    &kzsigner::time::encode_generalized(REVOKED_AT.min(now - 86_400_000)).unwrap(),
                )
            } else {
                vec![0x80, 0x00]
            };
            let single = der::seq(&[
                &cert_id,
                &status,
                &kzsigner::time::encode_generalized(now).unwrap(),
                &der::tlv(
                    der::ctx(0),
                    &kzsigner::time::encode_generalized(now + 3_600_000).unwrap(),
                ),
            ]);
            let mut parts: Vec<Vec<u8>> = vec![
                der::tlv(der::ctx(1), &ca.cert.subject),
                kzsigner::time::encode_generalized(now).unwrap(),
                der::seq(&[&single]),
            ];
            // echo the nonce
            if let Some(ext) = tbs.iter().find(|t| t.tag == der::ctx(2)) {
                parts.push(der::tlv(der::ctx(1), ext.content));
            }
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let rd = der::seq(&refs);
            let sig = ca.private_key.sign(&rd, &mut kzsigner::OsRng).ok()?;
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
        }
    }
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
    info.extend(kzsigner::time::encode_generalized(kzsigner::time::now_ms()).unwrap());
    if let Some(n) = &req.nonce {
        info.extend(der::uint(n));
    }
    let info = der::tlv(der::SEQUENCE, &info);
    let token = cms::sign_once(
        &info,
        TST_INFO,
        true,
        &key.private_key,
        &key.cert,
        kzsigner::time::now_ms(),
        &mut kzsigner::OsRng,
    )
    .ok()?
    .encode()
    .ok()?;
    Some(der::seq(&[&der::seq(&[&der::small_int(0)]), &token]))
}
