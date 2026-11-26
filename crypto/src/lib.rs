//! kzcrypto: the cryptography of kzsigner, on its own.
//!
//! KZ GOST (GOST 34.310-2004, GOST 34.10-2015, GOST 34.311-95 and GOST 34.11-2015 as NCA RK uses
//! them), RSA, PKCS#12 key files, X.509 certificates, CMS SignedData (CAdES), timestamp (TSP),
//! OCSP and CRL messages, and certificate path checks against trusted CAs.
//!
//! The crate is `no_std` + `alloc`: it has no files, network, clock or operating-system random
//! numbers. It takes bytes in and gives bytes out. The caller:
//!
//! * does all I/O: reads key files and documents, sends the TSP and OCSP requests this crate
//!   builds and hands their answers back, downloads revocation lists;
//! * passes the current time in, as milliseconds since 1970 (UTC);
//! * passes a random source in ([`Rng`]) wherever randomness is needed (signing, nonces).
//!
//! Errors and statuses are values ([`Error`], [`trust::PathStatus`], [`ocsp::Status`], ...),
//! not messages: the application words them in its own language.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod asn1;
pub mod cert;
pub mod cms;
pub mod crl;
pub mod error;
pub mod gost;
pub mod keys;
pub mod ocsp;
pub mod p12;
pub mod time;
pub mod trust;
pub mod tsp;
pub mod verify;

mod prelude {
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

use prelude::*;

/// The crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::{Error, ErrorKind, Result};

/// A source of cryptographically secure random bytes, supplied by the caller (on a computer or
/// phone: the operating system's generator).
pub trait Rng {
    /// Fills `buf` with random bytes, or fails; never returns predictable bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// `rand_core` view of an [`Rng`], for the RSA code. A failure of the source stops the
/// operation; it is kept in `failed` to report the caller's own error.
pub(crate) struct RandCore<'a> {
    pub rng: &'a mut dyn Rng,
    pub failed: Option<Error>,
}

impl rand_core::TryRng for RandCore<'_> {
    type Error = Error;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Error> {
        self.rng.fill(dst).inspect_err(|e| {
            self.failed.get_or_insert(e.clone());
        })
    }
}

impl rand_core::TryCryptoRng for RandCore<'_> {}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Standard Base64 without whitespace; padding optional. None if it is not Base64.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test helpers: an OS random source and the test key files.

    use super::*;

    pub struct OsRng;

    impl Rng for OsRng {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            getrandom::fill(buf).map_err(|e| Error::Random(format!("{e}")))
        }
    }

    pub fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    pub fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../tests/fixtures/{path}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// A trust store with NCA RK's CA certificates (from `kzcrypto-nca`'s files).
    pub fn nca() -> crate::trust::TrustStore {
        let dir = format!(
            "{}/../crates/kzcrypto-nca/certs",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut certs: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        certs.sort();
        crate::trust::TrustStore::new(
            certs
                .iter()
                .map(|p| crate::cert::Cert::parse_any(&std::fs::read(p).unwrap()).unwrap())
                .collect(),
        )
    }

    pub fn key(name: &str) -> crate::p12::Key {
        crate::p12::open(&fixture(&format!("keys/{name}.p12")), "Qwerty12", None).unwrap()
    }
}
