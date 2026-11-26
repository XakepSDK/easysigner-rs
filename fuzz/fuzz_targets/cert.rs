//! A certificate (DER, Base64 or PEM), and everything read from it: names, key, extensions,
//! the path check and the signing rules.
#![no_main]

use kzcrypto::cert::{self, Cert};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static TRUST: LazyLock<kzcrypto::trust::TrustStore> =
    LazyLock::new(|| kzcrypto_nca::trust_store(Vec::new()));

fuzz_target!(|data: &[u8]| {
    let Ok(c) = Cert::parse_any(data) else {
        return;
    };
    let _ = (c.public_key(), c.public_key_bits(), c.key_alg(), c.serial_hex());
    let _ = (c.key_usage(), c.extended_key_usage(), c.policies(), c.subject_key_id());
    let _ = (c.is_ca(), c.may_sign_certs(), c.self_issued(), c.cn(), c.subject_rdns());
    let _ = (cert::dn(&c.issuer), kzcrypto::crl::urls(&c));
    let _ = c.signed_by(&c);
    let _ = TRUST.check(&c, c.not_before);
    let _ = kzcrypto_nca::may_not_sign(&c, Some(&c));
});
