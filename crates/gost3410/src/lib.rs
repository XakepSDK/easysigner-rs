//! GOST R 34.10-2012 (and 34.10-2001) digital signatures, in the conventions of Kazakhstan's
//! NCA RK (GOST 34.310-2004 and ST RK GOST R 34.10-2015 keys), on RustCrypto's
//! `elliptic-curve` stack.
//!
//! Curves: [`CryptoProA`], [`Tc26_256A`] and [`Tc26_512A`]. Arithmetic is constant-time
//! (`primeorder` complete formulas on `crypto-bigint` Montgomery fields), and secret scalars are
//! wiped when dropped.
//!
//! The signing and checking rules are GOST R 34.10's: e = hash mod q (1 when 0), r = x(kG) mod q,
//! s = r·d + k·e mod q. NCA reads the hash and writes keys and signatures **little-endian**:
//! the hash's bytes are the integer's little-endian bytes, a public key is x || y and a signature
//! is r || s, each little-endian. [`Signature::to_nca_bytes`] and [`Signature::to_bytes`] (the
//! standard s || r, big-endian) give both forms.
//!
//! The nonce k is hedged (RFC 6979 section 3.6 style): HMAC-SHA-512 keyed with the private key
//! over fresh random bytes, the hash and a counter. With a good random source it is uniformly
//! random; with a broken one it still never repeats for different messages and cannot be
//! guessed without the key.

#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod curves;
mod dsa;

pub use curves::{CryptoProA, Tc26_256A, Tc26_512A, cryptopro_a, p256, p512, tc26_256a, tc26_512a};
pub use dsa::{Signature, SigningKey, VerifyingKey};
pub use elliptic_curve;
pub use signature;

/// A GOST R 34.10 curve of this crate.
pub trait GostCurve: primeorder::PrimeCurveParams {
    /// The parameter set's name.
    const NAME: &'static str;
    /// The curve's cofactor: 1, or 4 for TC26 256-A, whose public keys are checked to lie in the
    /// order-q subgroup.
    const COFACTOR: u32;
    /// Parameter-set OIDs naming this curve: NCA RK's, then the Russian TC26/CryptoPro ones.
    const PARAM_SET_OIDS: &'static [&'static str];
}
