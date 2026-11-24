//! Opening a .p12 key file. The password is fixed: a wrong one must be an error, never a crash,
//! and the parser runs before the password is checked.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static ENGINE: LazyLock<kzsigner::Engine> = LazyLock::new(|| kzsigner::Engine::new(Vec::new()));

fuzz_target!(|data: &[u8]| {
    let _ = ENGINE.open_key(data, "Qwerty12", None);
});
