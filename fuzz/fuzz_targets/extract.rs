//! Taking the document out of a .cms.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static ENGINE: LazyLock<kzsigner::Engine> = LazyLock::new(|| kzsigner::Engine::new(Vec::new()));

fuzz_target!(|data: &[u8]| {
    let _ = ENGINE.extract(data);
    let _ = ENGINE.is_signed_cms(data);
});
