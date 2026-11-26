//! Small helpers around RustCrypto's `der` crate, shared by the modules.

use ::der::asn1::{Any, Int, ObjectIdentifier};
use ::der::{Decode, Encode};

use crate::prelude::*;
use crate::{Error, Result, trf};

/// `T` from DER, or from BER (Kalkan writes BER: indefinite lengths, constructed strings).
pub fn ber<'a, T: Decode<'a, Error = ::der::Error>>(b: &'a [u8]) -> ::der::Result<T> {
    T::from_der(b).or_else(|_| T::from_ber(b))
}

/// A decoding or encoding failure, as [`ErrorKind::Malformed`](crate::ErrorKind).
pub fn err(e: ::der::Error) -> Error {
    Error::malformed(format!("malformed ASN.1: {e}"))
}

/// `t` as DER.
pub fn der<T: Encode + ?Sized>(t: &T) -> Result<Vec<u8>> {
    t.to_der().map_err(err)
}

/// The value `b` (one whole TLV) as an `Any`.
pub fn any(b: &[u8]) -> Result<Any> {
    ber(b).map_err(err)
}

/// The OID `s` (dotted), or [`ErrorKind::Malformed`](crate::ErrorKind).
pub fn oid(s: &str) -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(s)
        .map_err(|_| Error::malformed(trf("'{}' is not an object identifier", &[&s])))
}

/// An INTEGER's content without leading zero bytes (one zero for zero), as
/// [`Cert::serial`](crate::cert::Cert::serial).
pub fn strip_zeros(mut b: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = b
        && !rest.is_empty()
    {
        b = rest;
    }
    b
}

/// A non-negative INTEGER from unsigned big-endian bytes.
pub fn positive(n: &[u8]) -> Result<Int> {
    let n = strip_zeros(n);
    let mut b = Vec::with_capacity(n.len() + 1);
    if n.first().is_none_or(|&x| x & 0x80 != 0) {
        b.push(0);
    }
    b.extend(n);
    Int::new(&b).map_err(err)
}

/// An AlgorithmIdentifier with NULL parameters, as encoded.
pub fn alg_null(o: &str) -> Result<Vec<u8>> {
    der(&spki::AlgorithmIdentifierOwned {
        oid: oid(o)?,
        parameters: Some(Any::null()),
    })
}

/// `der` (a constructed element) with its tag replaced by `[n]`, for IMPLICIT tagging.
pub fn implicit(n: u8, mut der: Vec<u8>) -> Vec<u8> {
    if let Some(t) = der.first_mut() {
        *t = 0xa0 | n;
    }
    der
}
