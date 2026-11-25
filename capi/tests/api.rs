//! The C interface called from Rust, so that `cargo test` (and mutation testing) covers it.
//! capi/tests/c/test.c checks the same calls from C (scripts/capi-test.sh).

use std::ffi::c_void;
use std::ptr;

use kzcrypto_capi::*;

const NOW: i64 = 1_798_761_600_000; // 2027-01-01

fn fixture(p: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../tests/fixtures/{p}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn empty() -> KzBuf {
    KzBuf {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

/// The bytes of `b`, freeing it.
fn take(mut b: KzBuf) -> Vec<u8> {
    let v = if b.ptr.is_null() {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    };
    unsafe { kz_buf_free(&mut b) };
    assert!(b.ptr.is_null() && b.len == 0);
    v
}

fn text(b: KzBuf) -> String {
    String::from_utf8(take(b)).unwrap()
}

fn open(file: &str, password: &str) -> (KzStatus, *mut KzKey, String) {
    let p12 = fixture(file);
    let mut key = ptr::null_mut();
    let mut err = empty();
    let s = unsafe {
        kz_key_open(
            p12.as_ptr(),
            p12.len(),
            password.as_ptr(),
            password.len(),
            ptr::null(),
            &mut key,
            &mut err,
        )
    };
    (s, key, text(err))
}

unsafe extern "C" fn counting(ctx: *mut c_void, buf: *mut u8, len: usize) -> i32 {
    let n = unsafe { &mut *(ctx as *mut usize) };
    for i in 0..len {
        unsafe { *buf.add(i) = (*n * 167 + 13) as u8 };
        *n += 1;
    }
    0
}

unsafe extern "C" fn broken(_: *mut c_void, _: *mut u8, _: usize) -> i32 {
    1
}

fn sign(key: *const KzKey, doc: &[u8], attach: bool) -> Vec<u8> {
    let mut out = empty();
    let s = unsafe {
        kz_sign_cms(
            key,
            doc.as_ptr(),
            doc.len(),
            attach,
            NOW,
            None,
            ptr::null_mut(),
            &mut out,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Ok);
    take(out)
}

fn check(cms: &[u8], index: usize, detached: &[u8]) -> (KzStatus, Option<KzSignerCheck>, Vec<u8>) {
    let mut r = KzSignerCheck {
        signature: KzSignature::Invalid,
        certificate_reference_ok: false,
        signing_time_ms: 0,
        has_signing_time: false,
    };
    let mut cert = empty();
    let s = unsafe {
        kz_cms_check_signer(
            cms.as_ptr(),
            cms.len(),
            index,
            detached.as_ptr(),
            detached.len(),
            &mut r,
            &mut cert,
            ptr::null_mut(),
        )
    };
    (s, (s == KzStatus::Ok).then_some(r), take(cert))
}

fn hash(oid: &str, data: &[u8]) -> (KzStatus, Vec<u8>, String) {
    let oid = std::ffi::CString::new(oid).unwrap();
    let (mut out, mut err) = (empty(), empty());
    let s = unsafe { kz_hash(oid.as_ptr(), data.as_ptr(), data.len(), &mut out, &mut err) };
    (s, take(out), text(err))
}

#[test]
fn version_and_hashes() {
    let v = unsafe { std::ffi::CStr::from_ptr(kz_version()) };
    assert_eq!(v.to_str().unwrap(), "0.1.0-dev");
    let (s, h, e) = hash("1.2.398.3.10.1.3.3", b"");
    assert_eq!((s, h.len(), e.as_str()), (KzStatus::Ok, 64, ""));
    assert_eq!((h[0], h[63]), (0x8e, 0x8a));
    let (s, h, e) = hash("1.2.3", b"x");
    assert_eq!(s, KzStatus::Unsupported);
    assert!(h.is_empty() && e.contains("1.2.3"), "{e}");
    // a length without data, a null OID
    let mut err = empty();
    let s = unsafe { kz_hash(c"1".as_ptr(), ptr::null(), 3, ptr::null_mut(), &mut err) };
    assert_eq!(s, KzStatus::InvalidArgument);
    assert!(text(err).contains("null pointer"));
    let s = unsafe {
        kz_hash(
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);
    let bad = [0xffu8];
    let s = unsafe {
        kz_hash(
            bad.as_ptr().cast(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);
}

#[test]
fn keys_sign_and_check() {
    let (s, key, e) = open("keys/alice_gost2015.p12", "wrong");
    assert_eq!(s, KzStatus::WrongPassword);
    assert!(key.is_null() && e.contains("password"), "{e}");
    let (s, _, _) = open("keys/ca_gost2015.cer", "Qwerty12");
    assert_eq!(s, KzStatus::Other);
    let s = unsafe {
        kz_key_open(
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);
    let pw = [0xffu8];
    let mut k = ptr::null_mut();
    let s = unsafe {
        kz_key_open(
            pw.as_ptr(),
            1,
            pw.as_ptr(),
            1,
            ptr::null(),
            &mut k,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);

    for file in [
        "keys/alice_gost2015.p12",
        "keys/alice_gost2004.p12",
        "keys/alice_rsa.p12",
    ] {
        let (s, key, _) = open(file, "Qwerty12");
        assert_eq!(s, KzStatus::Ok, "{file}");
        let mut c = empty();
        assert_eq!(
            unsafe { kz_key_certificate(key, &mut c, ptr::null_mut()) },
            KzStatus::Ok
        );
        let cert = take(c);
        assert!(cert.len() > 100);

        let doc = b"a document";
        let cms = sign(key, doc, true);
        let mut n = 0usize;
        let s = unsafe { kz_cms_signer_count(cms.as_ptr(), cms.len(), &mut n, ptr::null_mut()) };
        assert_eq!((s, n), (KzStatus::Ok, 1));
        let mut content = empty();
        let s = unsafe { kz_cms_content(cms.as_ptr(), cms.len(), &mut content, ptr::null_mut()) };
        assert_eq!(s, KzStatus::Ok);
        assert_eq!(take(content), doc);

        let (s, r, signer) = check(&cms, 0, b"");
        let r = r.unwrap();
        assert_eq!(s, KzStatus::Ok);
        assert_eq!(r.signature, KzSignature::Valid, "{file}");
        assert!(r.certificate_reference_ok && r.has_signing_time);
        assert_eq!(r.signing_time_ms, NOW);
        assert_eq!(signer, cert);
        assert_eq!(check(&cms, 1, b"").0, KzStatus::InvalidArgument);

        // the document changed inside the file
        let mut changed = cms.clone();
        let at = changed.windows(doc.len()).position(|w| w == doc).unwrap();
        changed[at] ^= 1;
        let r = check(&changed, 0, b"").1.unwrap();
        assert_eq!(r.signature, KzSignature::DigestMismatch);
        // the signature changed
        let mut changed = cms.clone();
        let n = changed.len();
        changed[n - 5] ^= 1;
        let r = check(&changed, 0, b"").1.unwrap();
        assert_eq!(r.signature, KzSignature::Invalid);

        // detached
        let cms = sign(key, doc, false);
        let mut content = empty();
        unsafe { kz_cms_content(cms.as_ptr(), cms.len(), &mut content, ptr::null_mut()) };
        assert!(take(content).is_empty());
        assert_eq!(
            check(&cms, 0, b"").1.unwrap().signature,
            KzSignature::NoContent
        );
        assert_eq!(check(&cms, 0, doc).1.unwrap().signature, KzSignature::Valid);
        assert_eq!(
            check(&cms, 0, b"another").1.unwrap().signature,
            KzSignature::DigestMismatch
        );
        unsafe { kz_key_free(key) };
    }
    // not a CMS file
    let mut err = empty();
    let mut n = 0usize;
    let s = unsafe { kz_cms_signer_count(b"x".as_ptr(), 1, &mut n, &mut err) };
    assert_eq!(s, KzStatus::Malformed);
    assert!(text(err).contains("CMS"));
    let s = unsafe { kz_cms_signer_count(b"x".as_ptr(), 1, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(s, KzStatus::InvalidArgument);
}

#[test]
fn signing_by_hash_and_randomness() {
    let (_, key, _) = open("keys/alice_gost2015.p12", "Qwerty12");
    let doc = b"by hash";
    let (_, h, _) = hash("1.2.398.3.10.1.3.3", doc);
    let mut out = empty();
    let mut n = 0usize;
    let s = unsafe {
        kz_sign_digest(
            key,
            h.as_ptr(),
            h.len(),
            NOW,
            Some(counting),
            (&mut n as *mut usize).cast(),
            &mut out,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Ok);
    assert!(n > 0, "the caller's random source was used");
    let cms = take(out);
    let mut out = empty();
    assert_eq!(check(&cms, 0, doc).1.unwrap().signature, KzSignature::Valid);
    // a digest of another length
    let mut err = empty();
    let s = unsafe {
        kz_sign_digest(
            key,
            h.as_ptr(),
            32,
            NOW,
            None,
            ptr::null_mut(),
            &mut out,
            &mut err,
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);
    assert!(text(err).contains("length"));
    // a random source that fails stops signing, with nothing returned
    for attach in [true, false] {
        let mut err = empty();
        let s = unsafe {
            kz_sign_cms(
                key,
                doc.as_ptr(),
                doc.len(),
                attach,
                NOW,
                Some(broken),
                ptr::null_mut(),
                &mut out,
                &mut err,
            )
        };
        assert_eq!(s, KzStatus::Random);
        assert!(out.ptr.is_null());
        assert!(text(err).contains("random"));
    }
    let s = unsafe {
        kz_sign_digest(
            key,
            h.as_ptr(),
            h.len(),
            NOW,
            Some(broken),
            ptr::null_mut(),
            &mut out,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Random);
    // RSA keys take randomness too (blinding)
    let (_, rsa, _) = open("keys/alice_rsa.p12", "Qwerty12");
    let s = unsafe {
        kz_sign_cms(
            rsa,
            doc.as_ptr(),
            doc.len(),
            true,
            NOW,
            Some(broken),
            ptr::null_mut(),
            &mut out,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Random);
    unsafe {
        kz_key_free(key);
        kz_key_free(rsa);
        kz_key_free(ptr::null_mut());
    }
    assert_eq!(
        unsafe { kz_key_certificate(ptr::null(), ptr::null_mut(), ptr::null_mut()) },
        KzStatus::InvalidArgument
    );
}

fn cert_check(trust: *const KzTrust, cert: &[u8], at: i64) -> (bool, Vec<u8>, String) {
    let mut ok = false;
    let (mut issuer, mut err) = (empty(), empty());
    let s = unsafe {
        kz_cert_check(
            trust,
            cert.as_ptr(),
            cert.len(),
            at,
            &mut ok,
            &mut issuer,
            &mut err,
        )
    };
    assert_eq!(s, KzStatus::Ok);
    (ok, take(issuer), text(err))
}

#[test]
fn trust_and_revocation() {
    let (_, key, _) = open("keys/alice_gost2015.p12", "Qwerty12");
    let mut c = empty();
    unsafe { kz_key_certificate(key, &mut c, ptr::null_mut()) };
    let cert = take(c);
    let ca = fixture("keys/ca_gost2015.cer");

    let nca = kz_trust_new_nca();
    let (ok, issuer, why) = cert_check(nca, &cert, NOW);
    assert!(
        !ok && issuer.is_empty() && why.contains("Issuer not found"),
        "{why}"
    );
    let test = kz_trust_new_empty();
    assert!(!cert_check(test, &cert, NOW).0);
    assert_eq!(
        unsafe { kz_trust_add(test, ca.as_ptr(), ca.len(), ptr::null_mut()) },
        KzStatus::Ok
    );
    let (ok, issuer, why) = cert_check(test, &cert, NOW);
    assert!(ok && why.is_empty(), "{why}");
    assert_eq!(issuer, ca);
    // before the certificate's time
    let (ok, _, why) = cert_check(test, &cert, 0);
    assert!(!ok && why.contains("not valid on"), "{why}");
    let mut err = empty();
    assert_eq!(
        unsafe { kz_trust_add(test, b"junk".as_ptr(), 4, &mut err) },
        KzStatus::Malformed
    );
    assert!(!text(err).is_empty());
    assert_eq!(
        unsafe { kz_trust_add(ptr::null_mut(), ca.as_ptr(), ca.len(), ptr::null_mut()) },
        KzStatus::InvalidArgument
    );
    let s = unsafe {
        kz_cert_check(
            test,
            cert.as_ptr(),
            cert.len(),
            NOW,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);

    // OCSP
    let nonce = [9u8; 16];
    let mut req = empty();
    let s = unsafe {
        kz_ocsp_request(
            cert.as_ptr(),
            cert.len(),
            ca.as_ptr(),
            ca.len(),
            nonce.as_ptr(),
            nonce.len(),
            &mut req,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Ok);
    let req = take(req);
    assert!(
        req.windows(16).any(|w| w == nonce),
        "the nonce is in the request"
    );
    let ocsp = |answer: &[u8]| {
        let mut st = KzOcspStatus::Good;
        let mut at = 0i64;
        let mut err = empty();
        let s = unsafe {
            kz_ocsp_read(
                answer.as_ptr(),
                answer.len(),
                cert.as_ptr(),
                cert.len(),
                ca.as_ptr(),
                ca.len(),
                nonce.as_ptr(),
                nonce.len(),
                test,
                NOW,
                &mut st,
                &mut at,
                &mut err,
            )
        };
        (s, st, at, text(err))
    };
    // an error status from the server is an answer, not a failure
    let (s, st, _, why) = ocsp(&[0x30, 0x03, 0x0a, 0x01, 0x02]);
    assert_eq!((s, st), (KzStatus::Ok, KzOcspStatus::Error));
    assert!(why.contains("status 2"), "{why}");
    let (s, _, _, why) = ocsp(&[0x30, 0x00]);
    assert_ne!(s, KzStatus::Ok);
    assert!(!why.is_empty());

    unsafe {
        kz_trust_free(nca);
        kz_trust_free(test);
        kz_trust_free(ptr::null_mut());
        kz_key_free(key);
    }
}

#[test]
fn timestamps() {
    let dir = "nca-live/sha256-policy-6.2";
    let mut tsq = fixture(&format!("{dir}/tsq.der"));
    let tsr = fixture(&format!("{dir}/tsr.der"));
    let read = |tsq: &[u8]| {
        let (mut token, mut err) = (empty(), empty());
        let s = unsafe {
            kz_tsp_read_answer(
                tsq.as_ptr(),
                tsq.len(),
                tsr.as_ptr(),
                tsr.len(),
                &mut token,
                &mut err,
            )
        };
        (s, take(token), text(err))
    };
    let (s, token, _) = read(&tsq);
    assert_eq!(s, KzStatus::Ok);
    assert!(token.len() > 500);
    let n = tsq.len();
    tsq[n - 4] ^= 1;
    let (s, token, why) = read(&tsq);
    assert_ne!(s, KzStatus::Ok);
    assert!(token.is_empty() && why.contains("nonce"), "{why}");

    let digest = [7u8; 32];
    let nonce = [0xffu8, 1, 2, 3, 4, 5, 6, 7];
    let mut req = empty();
    let s = unsafe {
        kz_tsp_request(
            c"2.16.840.1.101.3.4.2.1".as_ptr(),
            digest.as_ptr(),
            digest.len(),
            c"1.2.398.3.3.2.6.2".as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            &mut req,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::Ok);
    let r = kzcrypto::tsp::Request::parse(&take(req)).unwrap();
    let mut req = empty();
    assert_eq!(r.hash, digest);
    assert_eq!(r.policy.as_deref(), Some("1.2.398.3.3.2.6.2"));
    assert_eq!(r.nonce.as_deref(), Some(&[0x7f, 1, 2, 3, 4, 5, 6, 7][..]));
    assert!(r.cert_req);
    let s = unsafe {
        kz_tsp_request(
            ptr::null(),
            digest.as_ptr(),
            digest.len(),
            c"1.2".as_ptr(),
            nonce.as_ptr(),
            nonce.len(),
            &mut req,
            ptr::null_mut(),
        )
    };
    assert_eq!(s, KzStatus::InvalidArgument);
    // a malformed object identifier is an error, not a crash of the calling process
    for bad in [c"1", c"1.2.x", c"9.9", c""] {
        let mut req = empty();
        let s = unsafe {
            kz_tsp_request(
                bad.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                c"1.2".as_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                &mut req,
                ptr::null_mut(),
            )
        };
        assert_eq!(s, KzStatus::Malformed, "{bad:?}");
        assert!(req.ptr.is_null());
    }
}
