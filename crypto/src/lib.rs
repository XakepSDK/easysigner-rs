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
//! Messages for people (errors and statuses) are [`Text`]s: an English template and its
//! arguments, so that the application can show them in its own language. `Display` gives the
//! English.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod cert;
pub mod cms;
pub mod crl;
pub mod der;
pub mod gost;
pub mod keys;
pub mod ocsp;
pub mod p12;
pub mod text;
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
pub use text::{Text, tr, trf};

/// The crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What went wrong, for programs. The [`Text`] says it for people.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u32)]
pub enum ErrorKind {
    /// Anything else.
    Other = 1,
    /// The input is not well-formed (ASN.1, a certificate, a CMS file, a key file, ...).
    Malformed = 2,
    /// An algorithm, key type or format this crate does not support.
    Unsupported = 3,
    /// The key file's password is wrong.
    WrongPassword = 4,
    /// The random source failed.
    Random = 5,
}

/// An error: what kind, and a message for people.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub text: Text,
}

impl Error {
    /// An error of kind [`ErrorKind::Other`].
    pub fn new(t: impl Into<Text>) -> Error {
        Error {
            kind: ErrorKind::Other,
            text: t.into(),
        }
    }

    /// An error of kind [`ErrorKind::Malformed`].
    pub fn malformed(t: impl Into<Text>) -> Error {
        Error::of(ErrorKind::Malformed, t)
    }

    /// An error of kind [`ErrorKind::Unsupported`].
    pub fn unsupported(t: impl Into<Text>) -> Error {
        Error::of(ErrorKind::Unsupported, t)
    }

    pub fn of(kind: ErrorKind, t: impl Into<Text>) -> Error {
        Error {
            kind,
            text: t.into(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.text, f)
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

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
            getrandom::fill(buf).map_err(|_| Error::of(ErrorKind::Random, "no random numbers"))
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

    pub fn key(name: &str) -> crate::p12::Key {
        crate::p12::open(&fixture(&format!("keys/{name}.p12")), "Qwerty12", None).unwrap()
    }
}
