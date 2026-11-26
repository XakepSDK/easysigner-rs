//! A CMS signed file: its parts, its signers' attributes and signatures, and writing it back.
#![no_main]

use kzcrypto::cms::SignedData;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(sd) = SignedData::parse(data) else {
        return;
    };
    let _ = (sd.certificates(), sd.crl_items(), sd.encode());
    let content = sd.content.clone().unwrap_or_default();
    for si in &sd.signers {
        let _ = (si.signed(), si.unsigned(), si.signing_time(), si.unsigned_values());
        let _ = (si.archive_fields(), si.encode(), si.signed_bytes(&content));
        if let Some(c) = sd.signer_cert(si) {
            let _ = si.identifies(&c);
            let _ = kzcrypto::verify::check_signer(si, &c, &content, &sd.content_type);
        }
    }
    let _ = sd.merge(&sd).encode();
});
