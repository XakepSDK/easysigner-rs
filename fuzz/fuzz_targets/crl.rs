//! A revocation list (CRL), and what it says about a certificate.
#![no_main]

use kzcrypto::cert::Cert;
use kzcrypto::crl::{self, Crl};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static CA: LazyLock<Cert> =
    LazyLock::new(|| kzcrypto_nca::bundled().into_iter().next().expect("bundled CA"));

fuzz_target!(|data: &[u8]| {
    let Ok(l) = Crl::parse(data) else {
        return;
    };
    let now = l.this_update;
    let _ = (l.signed_by(&CA), l.revocation_of(&CA), l.untrusted_from(&CA));
    let _ = crl::delta_urls(&CA, &l);
    let policy = kzcrypto_nca::POLICY;
    let _ = crl::evaluate(&l, Some(&l), true, &CA, &CA, now, &policy);
    let _ = crl::evaluate(&l, None, false, &CA, &CA, now, &policy);
});
