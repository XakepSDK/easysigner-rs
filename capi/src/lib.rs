//! The C interface to kzcrypto (header: `include/kzcrypto.h`).
//!
//! Conventions:
//!
//! * Every call returns a [`KzStatus`]; `KZ_STATUS_OK` (0) is success.
//! * Input bytes are a pointer and a length; a null pointer is allowed only with length 0.
//!   Text input (passwords, OIDs) is UTF-8.
//! * Output bytes come in a [`KzBuf`] that the library allocates and the caller frees with
//!   [`kz_buf_free`]. On failure, outputs are left empty.
//! * `err` (optional, may be null): on failure, the reason in English, UTF-8, not
//!   NUL-terminated. Free it with [`kz_buf_free`].
//! * Keys and trust stores are opaque handles, freed with their `_free` call.
//! * Time is milliseconds since 1970 (UTC), passed in by the caller.
//! * Randomness: a [`KzRng`] callback filled in by the caller; null uses the operating system's
//!   generator.
//! * Calls are thread-safe; a handle may be used from several threads as long as nobody frees
//!   it meanwhile.
//! * A panic never crosses the boundary: it becomes `KZ_STATUS_PANIC` (in builds that unwind;
//!   a build with `panic = "abort"` stops the process instead).

#![deny(unsafe_op_in_unsafe_fn)]
// the C calls take raw pointers by design; each one documents what it requires
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use kzcrypto::cms::{self, SignedData};
use kzcrypto::trust::TrustStore;
use kzcrypto::verify::Outcome;
use kzcrypto::{ErrorKind, cert::Cert, ocsp, p12, tsp};

/// The result of a call.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KzStatus {
    Ok = 0,
    /// Anything else (see `err`).
    Other = 1,
    /// The input is not well-formed (ASN.1, certificate, CMS, key file, ...).
    Malformed = 2,
    /// An algorithm, key type or format kzcrypto does not support.
    Unsupported = 3,
    /// The key file's password is wrong.
    WrongPassword = 4,
    /// The random source failed.
    Random = 5,
    /// A null pointer, a length without data, text that is not UTF-8, an index out of range.
    InvalidArgument = 100,
    /// A bug inside kzcrypto; please report it.
    Panic = 101,
}

/// Bytes owned by the library; free with [`kz_buf_free`].
#[repr(C)]
pub struct KzBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

/// A random source: fills `len` bytes at `buf` and returns 0, or returns non-zero on failure.
pub type KzRng = Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize) -> i32>;

/// A private key with its certificate (opaque).
pub struct KzKey(p12::Key);

/// Trusted CA certificates (opaque).
pub struct KzTrust(TrustStore);

/// How one signature of a CMS file checks out.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KzSignature {
    /// The signature holds over the content.
    Valid = 0,
    /// The signature does not hold.
    Invalid = 1,
    /// The content's hash differs from the signed one (the document was changed).
    DigestMismatch = 2,
    /// The file does not carry the signer's certificate.
    NoCertificate = 3,
    /// Detached signature and no content given.
    NoContent = 4,
}

/// See [`kz_cms_check_signer`].
#[repr(C)]
pub struct KzSignerCheck {
    pub signature: KzSignature,
    /// The signed reference to the signer's certificate (CAdES) matches the certificate.
    pub certificate_reference_ok: bool,
    /// The signing-time attribute, when `has_signing_time`.
    pub signing_time_ms: i64,
    pub has_signing_time: bool,
}

/// What an OCSP answer says about a certificate.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KzOcspStatus {
    Good = 0,
    Revoked = 1,
    /// The responder does not know the certificate.
    Unknown = 2,
    /// No usable answer: an error status, a bad signature, an untrusted responder, another
    /// nonce, out of date (see `err` for which).
    Error = 3,
}

enum Fail {
    Crypto(kzcrypto::Error),
    Arg(&'static str),
}

impl From<kzcrypto::Error> for Fail {
    fn from(e: kzcrypto::Error) -> Fail {
        Fail::Crypto(e)
    }
}

type R<T = ()> = Result<T, Fail>;

fn status_of(kind: ErrorKind) -> KzStatus {
    match kind {
        ErrorKind::Malformed => KzStatus::Malformed,
        ErrorKind::Unsupported => KzStatus::Unsupported,
        ErrorKind::WrongPassword => KzStatus::WrongPassword,
        ErrorKind::Random => KzStatus::Random,
        _ => KzStatus::Other,
    }
}

/// Runs `f`, turning its failure or panic into a status and an English message in `err`.
fn guard(err: *mut KzBuf, f: impl FnOnce() -> R) -> KzStatus {
    let (status, message) = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => return KzStatus::Ok,
        Ok(Err(Fail::Crypto(e))) => (status_of(e.kind), e.to_string()),
        Ok(Err(Fail::Arg(what))) => (KzStatus::InvalidArgument, what.to_string()),
        Err(_) => (KzStatus::Panic, "internal error in kzcrypto".to_string()),
    };
    // SAFETY: `err` is null or points to a KzBuf the caller owns (the calls' contract)
    unsafe { put(err, message.into_bytes()) };
    status
}

/// Stores `v` in `*out` (when not null), handing its ownership to the caller.
unsafe fn put(out: *mut KzBuf, v: Vec<u8>) {
    if out.is_null() {
        return;
    }
    let mut v = v.into_boxed_slice();
    let buf = KzBuf {
        ptr: v.as_mut_ptr(),
        len: v.len(),
    };
    std::mem::forget(v);
    // SAFETY: `out` is a valid, writable KzBuf (checked non-null above; the caller's contract)
    unsafe { out.write(buf) };
}

/// Empties `*out` (when not null) so that a failed call leaves no stale pointer.
unsafe fn clear(out: *mut KzBuf) {
    if !out.is_null() {
        // SAFETY: as in `put`
        unsafe {
            out.write(KzBuf {
                ptr: ptr::null_mut(),
                len: 0,
            })
        };
    }
}

/// The bytes at `p`, `len` long. Null is accepted for an empty input only.
unsafe fn bytes<'a>(p: *const u8, len: usize) -> R<&'a [u8]> {
    if p.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(Fail::Arg("null pointer with a non-zero length"))
        };
    }
    // SAFETY: the caller passes `len` readable bytes at `p`, unchanged during the call
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}

unsafe fn utf8<'a>(p: *const u8, len: usize) -> R<&'a str> {
    // SAFETY: as in `bytes`
    let b = unsafe { bytes(p, len) }?;
    std::str::from_utf8(b).map_err(|_| Fail::Arg("text is not UTF-8"))
}

/// A NUL-terminated UTF-8 string; None for null.
unsafe fn cstr<'a>(p: *const c_char) -> R<Option<&'a str>> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller passes a NUL-terminated string, unchanged during the call
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str()
        .map(Some)
        .map_err(|_| Fail::Arg("text is not UTF-8"))
}

unsafe fn required<'a>(p: *const c_char) -> R<&'a str> {
    // SAFETY: as in `cstr`
    unsafe { cstr(p) }?.ok_or(Fail::Arg("null pointer"))
}

unsafe fn handle<'a, T>(p: *const T) -> R<&'a T> {
    // SAFETY: the caller passes a live handle from this library, or null
    unsafe { p.as_ref() }.ok_or(Fail::Arg("null handle"))
}

/// The caller's random source, or the operating system's.
struct Rng {
    f: KzRng,
    ctx: *mut c_void,
}

impl kzcrypto::Rng for Rng {
    fn fill(&mut self, buf: &mut [u8]) -> kzcrypto::Result<()> {
        let failed = |what: &'static str| kzcrypto::Error::of(ErrorKind::Random, what);
        match self.f {
            None => getrandom::fill(buf).map_err(|_| failed("no random numbers from the system")),
            Some(f) => {
                // SAFETY: the caller's callback writes at most `len` bytes at `buf`
                let r = unsafe { f(self.ctx, buf.as_mut_ptr(), buf.len()) };
                if r == 0 {
                    Ok(())
                } else {
                    Err(failed("the random source failed"))
                }
            }
        }
    }
}

// ------------------------------------------------------------------ general

/// The library's version, NUL-terminated (static; do not free).
#[unsafe(no_mangle)]
pub extern "C" fn kz_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Frees bytes the library returned, and empties `*buf`. Null, or an empty buffer, is fine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_buf_free(buf: *mut KzBuf) {
    if buf.is_null() {
        return;
    }
    // SAFETY: `buf` is a KzBuf filled by this library (or empty)
    let b = unsafe { buf.read() };
    if !b.ptr.is_null() {
        // SAFETY: ptr/len came from a boxed slice that `put` gave away
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(b.ptr, b.len)) });
    }
    // SAFETY: as above
    unsafe { clear(buf) };
}

/// The hash of `data` with the digest algorithm `alg_oid` (e.g. "1.2.398.3.10.1.3.3" for
/// GOST 34.11-2015 512-bit, "2.16.840.1.101.3.4.2.1" for SHA-256).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_hash(
    alg_oid: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract (see the module documentation)
    unsafe { clear(out) };
    guard(err, || unsafe {
        let h = kzcrypto::gost::hash(required(alg_oid)?, bytes(data, data_len)?)?;
        put(out, h);
        Ok(())
    })
}

// ------------------------------------------------------------------ keys

/// Opens a .p12 key file with `password` (UTF-8). `alias`: the key to take from a file with
/// several (NUL-terminated), or null for the first. On success `*out` is a key to free with
/// [`kz_key_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_key_open(
    p12_file: *const u8,
    p12_len: usize,
    password: *const u8,
    password_len: usize,
    alias: *const c_char,
    out: *mut *mut KzKey,
    err: *mut KzBuf,
) -> KzStatus {
    if out.is_null() {
        return guard(err, || Err(Fail::Arg("null output")));
    }
    // SAFETY: `out` is writable (checked above)
    unsafe { out.write(ptr::null_mut()) };
    guard(err, || unsafe {
        let key = p12::open(
            bytes(p12_file, p12_len)?,
            utf8(password, password_len)?,
            cstr(alias)?,
        )?;
        out.write(Box::into_raw(Box::new(KzKey(key))));
        Ok(())
    })
}

/// Frees a key (its private key is wiped). Null is fine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_key_free(key: *mut KzKey) {
    if !key.is_null() {
        // SAFETY: `key` came from kz_key_open and is freed once
        drop(unsafe { Box::from_raw(key) });
    }
}

/// The key's certificate (DER).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_key_certificate(
    key: *const KzKey,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        put(out, handle(key)?.0.cert.der.clone());
        Ok(())
    })
}

/// Signs `content` into a CMS SignedData (DER) with one CAdES-BES signature, as NCALayer does.
/// `attach`: put the content inside (else a detached signature). `now_ms`: the signing time.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kz_sign_cms(
    key: *const KzKey,
    content: *const u8,
    content_len: usize,
    attach: bool,
    now_ms: i64,
    rng: KzRng,
    rng_ctx: *mut c_void,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        let k = &handle(key)?.0;
        let sd = cms::sign_once(
            bytes(content, content_len)?,
            cms::ID_DATA,
            attach,
            &k.private_key,
            &k.cert,
            now_ms,
            &mut Rng {
                f: rng,
                ctx: rng_ctx,
            },
        )?;
        put(out, sd.encode());
        Ok(())
    })
}

/// A detached CMS signature over a document known only by its hash `digest` (made with the
/// key's digest algorithm: GOST 34.11-2015 for 2015 keys, GOST 34.311-95 for 2004 keys, SHA-256
/// for RSA).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_sign_digest(
    key: *const KzKey,
    digest: *const u8,
    digest_len: usize,
    now_ms: i64,
    rng: KzRng,
    rng_ctx: *mut c_void,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        let k = &handle(key)?.0;
        let md = bytes(digest, digest_len)?;
        if Ok(md.len()) != kzcrypto::gost::digest_len(k.private_key.digest_oid()) {
            return Err(Fail::Arg(
                "the digest's length is not the key's digest length",
            ));
        }
        let sd = cms::sign_digest(
            md,
            cms::ID_DATA,
            &k.private_key,
            &k.cert,
            Some(now_ms),
            &[],
            &mut Rng {
                f: rng,
                ctx: rng_ctx,
            },
        )?;
        put(out, sd.encode());
        Ok(())
    })
}

// ------------------------------------------------------------------ trust

/// A trust store with NCA RK's root and issuing CA certificates (built in). Free with
/// [`kz_trust_free`].
#[unsafe(no_mangle)]
pub extern "C" fn kz_trust_new_nca() -> *mut KzTrust {
    Box::into_raw(Box::new(KzTrust(TrustStore::new(vec![]))))
}

/// A trust store that trusts nothing until [`kz_trust_add`].
#[unsafe(no_mangle)]
pub extern "C" fn kz_trust_new_empty() -> *mut KzTrust {
    Box::into_raw(Box::new(KzTrust(TrustStore::empty())))
}

/// Trusts one more CA certificate (DER, or Base64/PEM).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_trust_add(
    trust: *mut KzTrust,
    cert: *const u8,
    cert_len: usize,
    err: *mut KzBuf,
) -> KzStatus {
    guard(err, || unsafe {
        let t = trust.as_mut().ok_or(Fail::Arg("null handle"))?;
        let c = Cert::parse_any(bytes(cert, cert_len)?)?;
        t.0.add(c);
        Ok(())
    })
}

/// Frees a trust store. Null is fine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_trust_free(trust: *mut KzTrust) {
    if !trust.is_null() {
        // SAFETY: `trust` came from kz_trust_new_* and is freed once
        drop(unsafe { Box::from_raw(trust) });
    }
}

/// Checks the path from `cert` (DER) to a trusted CA at `at_ms`: every signature, validity,
/// and that each issuer is a CA. `*trusted` is the answer; when false, `err` says why (the call
/// itself still returns `KZ_STATUS_OK`). `issuer` (optional): the direct issuer's certificate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_cert_check(
    trust: *const KzTrust,
    cert: *const u8,
    cert_len: usize,
    at_ms: i64,
    trusted: *mut bool,
    issuer: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(issuer) };
    let mut why = None;
    let s = guard(err, || unsafe {
        let t = &handle(trust)?.0;
        if trusted.is_null() {
            return Err(Fail::Arg("null output"));
        }
        let c = Cert::parse(bytes(cert, cert_len)?)?;
        let chain = t.check(&c, at_ms);
        trusted.write(chain.ok);
        if let Some(i) = chain.issuer {
            put(issuer, i.der);
        }
        if !chain.ok {
            why = Some(chain.status.to_string());
        }
        Ok(())
    });
    if let Some(w) = why {
        // SAFETY: as in `guard`
        unsafe { put(err, w.into_bytes()) };
    }
    s
}

// ------------------------------------------------------------------ CMS

fn signed_data(raw: &[u8]) -> R<SignedData> {
    Ok(SignedData::parse(raw)?)
}

/// The number of signatures in a CMS file (DER, BER, Base64 or PEM).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_cms_signer_count(
    cms_file: *const u8,
    cms_len: usize,
    count: *mut usize,
    err: *mut KzBuf,
) -> KzStatus {
    guard(err, || unsafe {
        if count.is_null() {
            return Err(Fail::Arg("null output"));
        }
        count.write(signed_data(bytes(cms_file, cms_len)?)?.signers.len());
        Ok(())
    })
}

/// The document embedded in a CMS file; empty for a detached signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_cms_content(
    cms_file: *const u8,
    cms_len: usize,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        put(
            out,
            signed_data(bytes(cms_file, cms_len)?)?
                .content
                .unwrap_or_default(),
        );
        Ok(())
    })
}

/// Checks signature number `index` (from 0) of a CMS file over its content, or over
/// `detached` (the original document) for a detached signature. `signer_cert` (optional): the
/// signer's certificate (DER), to check with [`kz_cert_check`] and revocation. Certificates,
/// trust and revocation are not part of this check.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kz_cms_check_signer(
    cms_file: *const u8,
    cms_len: usize,
    index: usize,
    detached: *const u8,
    detached_len: usize,
    result: *mut KzSignerCheck,
    signer_cert: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(signer_cert) };
    guard(err, || unsafe {
        if result.is_null() {
            return Err(Fail::Arg("null output"));
        }
        let sd = signed_data(bytes(cms_file, cms_len)?)?;
        let si = sd
            .signers
            .get(index)
            .ok_or(Fail::Arg("no signature with this index"))?;
        let signing_time = si.signing_time();
        let mut r = KzSignerCheck {
            signature: KzSignature::NoCertificate,
            certificate_reference_ok: false,
            signing_time_ms: signing_time.unwrap_or(0),
            has_signing_time: signing_time.is_some(),
        };
        if let Some(c) = sd.signer_cert(si) {
            let original = bytes(detached, detached_len)?;
            let content = match &sd.content {
                Some(c) => Some(c.as_slice()),
                None if !original.is_empty() => Some(original),
                None => None,
            };
            r.signature = match content {
                None => KzSignature::NoContent,
                Some(content) => {
                    match kzcrypto::verify::check_signer(si, &c, content, &sd.content_type)? {
                        Outcome::Valid => KzSignature::Valid,
                        Outcome::Invalid => KzSignature::Invalid,
                        Outcome::DigestMismatch => KzSignature::DigestMismatch,
                    }
                }
            };
            r.certificate_reference_ok =
                kzcrypto::verify::signing_certificate_matches(si, &c).unwrap_or(false);
            put(signer_cert, c.der);
        }
        result.write(r);
        Ok(())
    })
}

// ------------------------------------------------------------------ timestamps

/// A timestamp request (RFC 3161) over `hash` (made with `hash_oid`) under `policy`, asking
/// for the TSA's certificate. `nonce`: random bytes (8 are usual). Send it with content type
/// "application/timestamp-query", and pass the answer to [`kz_tsp_read_answer`].
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kz_tsp_request(
    hash_oid: *const c_char,
    hash: *const u8,
    hash_len: usize,
    policy: *const c_char,
    nonce: *const u8,
    nonce_len: usize,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        let r = tsp::Request::new(
            required(hash_oid)?,
            bytes(hash, hash_len)?,
            required(policy)?,
            bytes(nonce, nonce_len)?,
        )?;
        put(out, r.encode()?);
        Ok(())
    })
}

/// The timestamp token in the TSA's `answer` to `request`, checked against the request
/// (nonce, policy, hash, certificate).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kz_tsp_read_answer(
    request: *const u8,
    request_len: usize,
    answer: *const u8,
    answer_len: usize,
    token: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(token) };
    guard(err, || unsafe {
        let req = tsp::Request::parse(bytes(request, request_len)?)?;
        put(token, tsp::read_answer(&req, bytes(answer, answer_len)?)?);
        Ok(())
    })
}

// ------------------------------------------------------------------ OCSP

/// An OCSP request about `cert` (DER), issued by `issuer` (DER), with `nonce` (16 random bytes
/// are usual). Send it with content type "application/ocsp-request".
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kz_ocsp_request(
    cert: *const u8,
    cert_len: usize,
    issuer: *const u8,
    issuer_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    out: *mut KzBuf,
    err: *mut KzBuf,
) -> KzStatus {
    // SAFETY: the pointers follow this call's contract
    unsafe { clear(out) };
    guard(err, || unsafe {
        let c = Cert::parse(bytes(cert, cert_len)?)?;
        let i = Cert::parse(bytes(issuer, issuer_len)?)?;
        put(out, ocsp::request(&c, &i, bytes(nonce, nonce_len)?)?);
        Ok(())
    })
}

/// Checks the OCSP server's `answer` to a [`kz_ocsp_request`] with `nonce`, received at
/// `now_ms`: the responder's signature and authority (`trust`), the nonce and freshness.
/// `*status` is the answer; `revoked_at_ms` (optional) gets the revocation time for a revoked
/// certificate. When the status is not GOOD, `err` says why (the call still returns
/// `KZ_STATUS_OK`).
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn kz_ocsp_read(
    answer: *const u8,
    answer_len: usize,
    cert: *const u8,
    cert_len: usize,
    issuer: *const u8,
    issuer_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    trust: *const KzTrust,
    now_ms: i64,
    status: *mut KzOcspStatus,
    revoked_at_ms: *mut i64,
    err: *mut KzBuf,
) -> KzStatus {
    let mut why = None;
    let s = guard(err, || unsafe {
        if status.is_null() {
            return Err(Fail::Arg("null output"));
        }
        let c = Cert::parse(bytes(cert, cert_len)?)?;
        let i = Cert::parse(bytes(issuer, issuer_len)?)?;
        let a = ocsp::read_fresh(
            bytes(answer, answer_len)?,
            &c,
            &i,
            bytes(nonce, nonce_len)?,
            &handle(trust)?.0,
            now_ms,
        )?;
        status.write(match a.cert_status {
            Some(ocsp::CertStatus::Good) if a.good => KzOcspStatus::Good,
            Some(ocsp::CertStatus::Revoked) => KzOcspStatus::Revoked,
            Some(ocsp::CertStatus::Unknown) => KzOcspStatus::Unknown,
            _ => KzOcspStatus::Error,
        });
        if !revoked_at_ms.is_null()
            && let Some(t) = a.revoked_at
        {
            revoked_at_ms.write(t);
        }
        if !a.good {
            why = Some(a.status.to_string());
        }
        Ok(())
    });
    if let Some(w) = why {
        // SAFETY: as in `guard`
        unsafe { put(err, w.into_bytes()) };
    }
    s
}
