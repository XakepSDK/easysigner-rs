//! Small helpers around RustCrypto's `der` crate.

use ::der::asn1::{AnyRef, OctetString};
use ::der::{Decode, EncodingRules, Reader, SliceReader};

/// `T` from DER, or else from BER (Kalkan and NCALayer write BER).
pub fn ber<'a, T: Decode<'a, Error = ::der::Error>>(b: &'a [u8]) -> ::der::Result<T> {
    T::from_der(b).or_else(|_| T::from_ber(b))
}

/// The first element of `data` (DER or BER, indefinite lengths too), as encoded, without what
/// follows it (such as a PDF signature's zero padding).
pub fn first_element(data: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new_with_encoding_rules(data, EncodingRules::Ber).ok()?;
    AnyRef::decode(&mut r).ok()?;
    let len = usize::try_from(r.position()).ok()?;
    data.get(..len)
}

/// The content of an OCTET STRING (DER or BER).
pub fn octets(v: &[u8]) -> Option<Vec<u8>> {
    ber::<OctetString>(v)
        .ok()
        .map(|o| o.into_bytes().into_vec())
}
