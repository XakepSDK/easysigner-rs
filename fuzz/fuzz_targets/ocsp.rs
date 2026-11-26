//! An OCSP response, fresh (with a nonce) and as kept inside a signature.
#![no_main]

use kzcrypto::cert::Cert;
use kzcrypto::ocsp;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static TRUST: LazyLock<kzcrypto::trust::TrustStore> =
    LazyLock::new(|| kzcrypto_nca::trust_store(Vec::new()));
static CA: LazyLock<Cert> =
    LazyLock::new(|| kzcrypto_nca::bundled().into_iter().next().expect("bundled CA"));

fuzz_target!(|data: &[u8]| {
    let _ = ocsp::read_embedded(data, &CA, &CA, &TRUST);
    let _ = ocsp::read_fresh(data, &CA, &CA, &[1; 16], &TRUST, 1_700_000_000_000);
    let _ = ocsp::basic_of(data);
});
