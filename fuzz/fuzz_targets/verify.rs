//! Checking a file: .cms (attached or detached), PDF, XML. Everything the
//! Check screen reads. No network: no OCSP address is given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static ENGINE: LazyLock<kzsigner::Engine> = LazyLock::new(|| kzsigner::Engine::new(Vec::new()));

fuzz_target!(|data: &[u8]| {
    let _ = ENGINE.verify(data, None, None);
    // a detached signature with a document: the first byte says where to split
    if let Some((&n, rest)) = data.split_first() {
        let at = (n as usize).min(rest.len());
        let (sig, doc) = rest.split_at(rest.len() - at);
        let _ = ENGINE.verify(sig, Some(doc), None);
    }
});
