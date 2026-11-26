//! What can go wrong, as values: no wording here. The application words each [`Error`] in its
//! own language; [`Error::code`] gives a stable number for other languages and logs.
//!
//! A `String` inside a variant is data, not a message: an object identifier, a key alias, or
//! the parser's own diagnostic (for developers).

use crate::prelude::*;

/// The broad class of an [`Error`], for programs that only need to branch on it.
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

/// An error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // --- malformed input
    /// ASN.1 that can't be read (or written); the parser's diagnostic.
    Asn1(String),
    /// A time that can't be read, or is out of range.
    BadTime,
    /// Text that is not a dotted object identifier.
    NotOid(String),
    /// A certificate that can't be read.
    BadCertificate,
    /// A public key that can't be read; the parser's diagnostic, when there is one.
    BadPublicKey(Option<String>),
    /// A private key that can't be read; the parser's diagnostic, when there is one.
    BadPrivateKey(Option<String>),
    /// A GOST key without its curve parameters.
    NoCurveParameters,
    /// A revocation list (CRL) that can't be read.
    BadCrl,
    /// A file that is not a CMS/PKCS#7 signed file; why.
    NotCms(Box<Error>),
    /// A CMS ContentInfo that holds something other than SignedData.
    NotSignedData,
    /// A ContentInfo that should hold content, without it.
    NoContent,
    /// Signed attributes without the content-type attribute.
    NoContentTypeAttr,
    /// The content-type attribute differs from the signed content's type.
    ContentTypeMismatch,
    /// Signed attributes without the message-digest attribute.
    NoMessageDigestAttr,
    /// An OCSP response that is not a basic OCSP response (or has no content).
    OcspNotBasic,

    // --- key files (PKCS#12)
    /// The key file could not be opened: the password is probably wrong, or the format is not
    /// supported; the underlying problem.
    KeyFileUnreadable(Box<Error>),
    /// The file is not a PKCS#12 key file; why.
    NotPkcs12(Box<Error>),
    /// The key file's integrity check failed: wrong password.
    WrongPassword,
    /// Decryption gave garbage (bad padding): wrong password or a damaged file.
    DecryptionFailed,
    /// Encryption parameters that don't fit the algorithm (lengths, missing parts).
    BadEncryptionParameters,
    /// An iteration count outside 1 to 10,000,000.
    BadIterationCount(i64),
    /// The key file holds no private key.
    NoPrivateKey,
    /// No key with this alias; the aliases there are.
    NoSuchAlias {
        alias: String,
        available: Vec<String>,
    },
    /// The key file has no certificate for its key.
    NoCertificateForKey,

    // --- algorithms
    /// An algorithm (digest, signature, cipher, MAC, key derivation, content type) this crate
    /// does not support; its OID.
    UnsupportedAlgorithm(String),
    /// A key type this crate does not support; its OID.
    UnsupportedKey(String),
    /// A GOST curve parameter set this crate does not support; its OID.
    UnsupportedCurve(String),
    /// PFX in public-key integrity mode (only password integrity is supported).
    UnsupportedPfxMode,
    /// The key can't make or check signatures of this algorithm (OID).
    KeyAlgorithmMismatch(String),
    /// GOST 34.310-2004 keys only check old signatures.
    Gost2004CannotSign,
    /// The signature could not be made; the library's diagnostic, when there is one.
    SigningFailed(Option<String>),

    // --- timestamps
    /// The timestamp server's answer can't be read; the parser's diagnostic.
    TimestampUnreadable(String),
    /// The timestamp server refused; its own status text, when it sent one.
    TimestampRefused(Option<String>),
    /// The timestamp server's answer does not answer the request; how.
    TimestampMismatch(Box<Error>),
    /// The token's nonce is not the request's.
    WrongNonce,
    /// The token's policy is not the requested one.
    WrongPolicy,
    /// The token is over another hash.
    WrongImprint,
    /// The certificate was asked for and is not in the token.
    NoTsaCertificate,
    /// A token signed by more than one signer.
    MultipleSigners,
    /// A ContentInfo that is not a timestamp (TSTInfo).
    NotTstInfo,
    /// A token without the signing-certificate attribute.
    NoSigningCertAttr,

    // --- the caller
    /// The caller's random source failed; its diagnostic.
    Random(String),

    // --- the module itself
    /// A known-answer self-test or a key's pairwise check failed: this build or this machine
    /// does not compute correctly, and nothing should be signed or checked with it.
    SelfTestFailed(crate::selftest::SelfTest),
}

impl Error {
    /// The broad class.
    pub fn kind(&self) -> ErrorKind {
        use Error as E;
        match self {
            E::Asn1(_)
            | E::BadTime
            | E::NotOid(_)
            | E::BadCertificate
            | E::BadPublicKey(_)
            | E::BadPrivateKey(_)
            | E::NoCurveParameters
            | E::BadCrl
            | E::NotCms(_)
            | E::NotSignedData
            | E::NoContent
            | E::OcspNotBasic
            | E::NotPkcs12(_)
            | E::BadEncryptionParameters
            | E::TimestampUnreadable(_)
            | E::NotTstInfo => ErrorKind::Malformed,
            E::UnsupportedAlgorithm(_)
            | E::UnsupportedKey(_)
            | E::UnsupportedCurve(_)
            | E::UnsupportedPfxMode
            | E::Gost2004CannotSign
            | E::BadIterationCount(_) => ErrorKind::Unsupported,
            E::WrongPassword => ErrorKind::WrongPassword,
            E::Random(_) => ErrorKind::Random,
            _ => ErrorKind::Other,
        }
    }

    /// A stable number for each variant (never reused), for logs and other languages.
    pub fn code(&self) -> u32 {
        use Error as E;
        match self {
            E::Asn1(_) => 100,
            E::BadTime => 101,
            E::NotOid(_) => 102,
            E::BadCertificate => 103,
            E::BadPublicKey(_) => 104,
            E::BadPrivateKey(_) => 105,
            E::NoCurveParameters => 106,
            E::BadCrl => 107,
            E::NotCms(_) => 108,
            E::NotSignedData => 109,
            E::NoContent => 110,
            E::NoContentTypeAttr => 111,
            E::ContentTypeMismatch => 112,
            E::NoMessageDigestAttr => 113,
            E::OcspNotBasic => 114,
            E::KeyFileUnreadable(_) => 200,
            E::NotPkcs12(_) => 201,
            E::WrongPassword => 202,
            E::DecryptionFailed => 203,
            E::BadEncryptionParameters => 204,
            E::BadIterationCount(_) => 205,
            E::NoPrivateKey => 206,
            E::NoSuchAlias { .. } => 207,
            E::NoCertificateForKey => 208,
            E::UnsupportedAlgorithm(_) => 300,
            E::UnsupportedKey(_) => 301,
            E::UnsupportedCurve(_) => 302,
            E::UnsupportedPfxMode => 303,
            E::KeyAlgorithmMismatch(_) => 304,
            E::Gost2004CannotSign => 305,
            E::SigningFailed(_) => 306,
            E::TimestampUnreadable(_) => 400,
            E::TimestampRefused(_) => 401,
            E::TimestampMismatch(_) => 402,
            E::WrongNonce => 403,
            E::WrongPolicy => 404,
            E::WrongImprint => 405,
            E::NoTsaCertificate => 406,
            E::MultipleSigners => 407,
            E::NotTstInfo => 408,
            E::NoSigningCertAttr => 409,
            E::Random(_) => 500,
            E::SelfTestFailed(_) => 600,
        }
    }
}

/// The variant and its data (no wording: the application words errors).
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "kzcrypto error {}: {self:?}", self.code())
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
