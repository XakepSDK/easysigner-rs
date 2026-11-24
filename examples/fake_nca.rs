//! Fake NCA servers for the emulator tests (NOT NCA's): a TSA on 127.0.0.1:18080 and an OCSP
//! responder on :18081, with the test keys in tests/fixtures, plus a control port on :18082
//! that the tests POST a mode to: "good", "revoked", "ocsp-down", "tsa-down" or "up".
//! The emulator reaches them as 10.0.2.2. Run: cargo run --example fake_nca

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

#[path = "../tests/common/nca.rs"]
#[allow(dead_code)]
mod nca;

const GOOD: u8 = 0;
const REVOKED: u8 = 1;
const OCSP_DOWN: u8 = 2;

fn main() {
    let ocsp_mode = Arc::new(AtomicU8::new(GOOD));
    let tsa_down = Arc::new(AtomicU8::new(0));

    let t = tsa_down.clone();
    let tsa = nca::tsa_answer();
    nca::serve_at(
        "127.0.0.1:18080",
        move |b| (t.load(Ordering::SeqCst) == 0).then(|| tsa(b)).flatten(),
        "application/timestamp-reply",
    );

    let m = ocsp_mode.clone();
    let m2 = ocsp_mode.clone();
    let ocsp = nca::ocsp_answer(move || m2.load(Ordering::SeqCst) == REVOKED);
    nca::serve_at(
        "127.0.0.1:18081",
        move |b| {
            (m.load(Ordering::SeqCst) != OCSP_DOWN)
                .then(|| ocsp(b))
                .flatten()
        },
        "application/ocsp-response",
    );

    nca::serve_at(
        "127.0.0.1:18082",
        move |b| {
            let mode = String::from_utf8_lossy(b).trim().to_string();
            match mode.as_str() {
                "good" => ocsp_mode.store(GOOD, Ordering::SeqCst),
                "revoked" => ocsp_mode.store(REVOKED, Ordering::SeqCst),
                "ocsp-down" => ocsp_mode.store(OCSP_DOWN, Ordering::SeqCst),
                "tsa-down" => tsa_down.store(1, Ordering::SeqCst),
                "up" => {
                    tsa_down.store(0, Ordering::SeqCst);
                    ocsp_mode.store(GOOD, Ordering::SeqCst)
                }
                _ => return None,
            }
            eprintln!("fake NCA: {mode}");
            Some(b"ok".to_vec())
        },
        "text/plain",
    );
    eprintln!("fake NCA: TSA :18080, OCSP :18081, control :18082");
    loop {
        std::thread::park();
    }
}
