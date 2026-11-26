//! Timestamp messages: the TSA's answer, a token, its TSTInfo, and a request.
#![no_main]

use kzcrypto::tsp;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static TRUST: LazyLock<kzcrypto::trust::TrustStore> =
    LazyLock::new(|| kzcrypto_nca::trust_store(Vec::new()));

fuzz_target!(|data: &[u8]| {
    let _ = tsp::TstInfo::parse(data);
    let _ = tsp::Request::parse(data);
    let _ = tsp::token_cert(data);
    let _ = tsp::check_token(b"stamped", data, &TRUST);
    if let Ok(req) = tsp::Request::new(kzcrypto::gost::H_SHA256, &[7; 32], "1.2.3", &[1; 8]) {
        let _ = tsp::read_answer(&req, data);
    }
});
