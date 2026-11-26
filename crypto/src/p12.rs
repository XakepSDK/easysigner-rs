//! Opens NCA .p12 key files: PKCS#12 with KZ GOST or RSA keys, as Kalkan writes them (BER,
//! 3DES-encrypted key, RC2-40-encrypted certificates, SHA-1 MAC), and PBES2 (AES) files.

use cipher::block_padding::Pkcs7;
use cipher::{BlockCipherDecrypt, BlockModeDecrypt, InnerIvInit, KeyInit};
use digest::block_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use pkcs12::kdf::{Pkcs12KeyType, derive_key};

use ::der::asn1::{AnyRef, OctetString};
use ::der::{Decode, Encode, Sequence};
use pkcs12::cms::encrypted_data::EncryptedData;
use pkcs12::pbe_params::{EncryptedPrivateKeyInfo, Pbes2Params, Pkcs12PbeParams};
use pkcs12::safe_bag::SafeContents;
use pkcs12::{AuthenticatedSafe, CertBag, MacData, Pfx};
use spki::AlgorithmIdentifierOwned;

use crate::cert::Cert;
use crate::keys::PrivateKey;
use crate::prelude::*;
use crate::text::{tr, trf};
use crate::{Error, ErrorKind, Result, hex};

/// A private key opened from a .p12 file, with its certificate chain.
pub struct Key {
    pub alias: String,
    pub private_key: PrivateKey,
    pub cert: Cert,
    pub chain: Vec<Cert>,
    /// Other keys in the same file, selectable by alias.
    pub other_aliases: Vec<String>,
}

const DATA: &str = "1.2.840.113549.1.7.1";
const ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
const KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const X509_CERT: &str = "1.2.840.113549.1.9.22.1";
const FRIENDLY_NAME: &str = "1.2.840.113549.1.9.20";
const LOCAL_KEY_ID: &str = "1.2.840.113549.1.9.21";

struct Bag<T> {
    alias: Option<String>,
    local_id: Option<String>,
    value: T,
}

pub fn open(p12: &[u8], password: &str, wanted_alias: Option<&str>) -> Result<Key> {
    open_with_pkcs8(p12, password, wanted_alias).map(|(k, _)| k)
}

/// [`open`], also returning the key's PKCS#8 PrivateKeyInfo (for the key store, which keeps
/// it re-encrypted). Every decrypted key in the file is wiped before returning.
pub fn open_with_pkcs8(
    p12: &[u8],
    password: &str,
    wanted_alias: Option<&str>,
) -> Result<(Key, zeroize::Zeroizing<Vec<u8>>)> {
    use zeroize::Zeroize;
    let auth_safe = read_pfx(p12, password)?;
    let mut keys: Vec<Bag<Vec<u8>>> = Vec::new();
    let mut certs: Vec<Bag<Cert>> = Vec::new();
    let read = read_contents(&auth_safe, password, &mut keys, &mut certs);
    let r = pick(read, &keys, certs, wanted_alias);
    for k in &mut keys {
        k.value.zeroize();
    }
    r
}

/// The wanted key and its certificates out of a read file (see [`open_with_pkcs8`]).
fn pick(
    read: Result<()>,
    keys: &[Bag<Vec<u8>>],
    certs: Vec<Bag<Cert>>,
    wanted_alias: Option<&str>,
) -> Result<(Key, zeroize::Zeroizing<Vec<u8>>)> {
    read.map_err(|e| {
        Error::new(trf(
            "Could not open the key file. The password is probably wrong, or the file uses an unsupported format ({})",
            &[&e],
        ))
    })?;
    if keys.is_empty() {
        return Err(Error::new(tr("The key file contains no private key.")));
    }
    let aliases: Vec<String> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| k.alias.clone().unwrap_or_else(|| format!("key{}", i + 1)))
        .collect();
    let alias = wanted_alias
        .map(str::to_string)
        .unwrap_or_else(|| aliases[0].clone());
    let Some(idx) = aliases.iter().position(|a| *a == alias) else {
        return Err(Error::new(trf(
            "No key with alias '{}'. Available: [{}]",
            &[&alias, &aliases.join(", ")],
        )));
    };
    let kb = &keys[idx];
    let private_key = PrivateKey::from_pkcs8(&kb.value)
        .map_err(|e| Error::unsupported(trf("Unsupported private key type: {}", &[&e])))?;
    let pool: Vec<Cert> = certs.iter().map(|b| b.value.clone()).collect();
    let mut leaf = None;
    for c in &certs {
        if kb.local_id.is_some() && kb.local_id == c.local_id {
            leaf = Some(c.value.clone());
        }
    }
    if leaf.is_none() {
        leaf = pool
            .iter()
            .find(|c| c.public_key().is_ok_and(|p| private_key.matches(&p)))
            .cloned();
    }
    let leaf =
        leaf.ok_or_else(|| Error::new(tr("The key file has no certificate for its key.")))?;
    let other_aliases = aliases.iter().filter(|a| **a != alias).cloned().collect();
    let pkcs8 = zeroize::Zeroizing::new(kb.value.clone());
    let key = Key {
        alias,
        private_key,
        chain: chain(&leaf, &pool),
        cert: leaf,
        other_aliases,
    };
    Ok((key, pkcs8))
}

/// Why a key file did not open, for screens that pick their own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// Not a .p12 key at all, or one without a usable private key.
    NotAKey,
    WrongPassword,
}

/// Why [`open`] fails on this file and password, or None when it opens.
pub fn problem(p12: &[u8], password: &str) -> Option<Problem> {
    let Ok((auth_safe, mac)) = pfx_parts(p12) else {
        return Some(Problem::NotAKey);
    };
    let has_mac = mac.is_some();
    if let Some(mac) = mac
        && !check_mac(&mac, &auth_safe, password).unwrap_or(false)
    {
        return Some(Problem::WrongPassword);
    }
    match open_with_pkcs8(p12, password, None) {
        Ok(_) => None,
        // without a MAC, a wrong password shows only as contents that don't decrypt
        Err(_) if !has_mac => Some(Problem::WrongPassword),
        Err(_) => Some(Problem::NotAKey),
    }
}

/// Kalkan writes BER (indefinite lengths, constructed OCTET STRINGs); others write DER.
fn ber<'a, T: Decode<'a, Error = ::der::Error>>(b: &'a [u8]) -> ::der::Result<T> {
    T::from_der(b).or_else(|_| T::from_ber(b))
}

/// The bytes of an OCTET STRING held in an ANY (a ContentInfo's content), joined when BER
/// splits them.
fn octets(any: &::der::Any) -> ::der::Result<Vec<u8>> {
    let enc = any.to_der()?;
    Ok(ber::<OctetString>(&enc)?.into_bytes().into_vec())
}

/// The AuthenticatedSafe bytes and the MAC, unchecked.
fn pfx_parts(p12: &[u8]) -> Result<(Vec<u8>, Option<MacData>)> {
    let not_p12 = |e: &dyn core::fmt::Display| {
        Error::new(trf(
            "Could not open the key file: it is not a PKCS#12 (.p12) key ({})",
            &[&format!("{e}")],
        ))
    };
    let pfx: Pfx = ber(p12).map_err(|e| not_p12(&e))?;
    if pfx.auth_safe.content_type.to_string() != DATA {
        return Err(not_p12(
            &"unsupported PFX content (public-key integrity mode)",
        ));
    }
    let auth_safe = octets(&pfx.auth_safe.content).map_err(|e| not_p12(&e))?;
    Ok((auth_safe, pfx.mac_data))
}

/// Checks the MAC and returns the AuthenticatedSafe bytes.
fn read_pfx(p12: &[u8], password: &str) -> Result<Vec<u8>> {
    let (auth_safe, mac) = pfx_parts(p12)?;
    if let Some(mac) = mac {
        let ok = check_mac(&mac, &auth_safe, password).unwrap_or(false);
        if !ok {
            return Err(Error::of(
                ErrorKind::WrongPassword,
                tr("Could not open the key file. The password is probably wrong."),
            ));
        }
    }
    Ok(auth_safe)
}

fn check_mac(mac: &MacData, data: &[u8], password: &str) -> Result<bool> {
    let expected = mac.mac.digest.as_bytes();
    let salt = mac.mac_salt.as_bytes();
    let iter = iterations(i64::from(mac.iterations))?;
    let pw = bmp_password(password);
    use hmac::{KeyInit as _, Mac};
    macro_rules! mac_with {
        ($h:ty) => {{
            let key = kdf::<$h>(
                &pw,
                salt,
                iter,
                Pkcs12KeyType::Mac,
                <$h as digest::OutputSizeUser>::output_size(),
            )?;
            let mut h =
                <hmac::Hmac<$h>>::new_from_slice(&key).map_err(|_| Error::new("MAC key"))?;
            h.update(data);
            Ok(h.verify_slice(expected).is_ok())
        }};
    }
    match mac.mac.algorithm.oid.to_string().as_str() {
        crate::gost::H_SHA1 => mac_with!(sha1::Sha1),
        crate::gost::H_SHA256 => mac_with!(sha2::Sha256),
        crate::gost::H_SHA384 => mac_with!(sha2::Sha384),
        crate::gost::H_SHA512 => mac_with!(sha2::Sha512),
        crate::gost::H_SHA224 => mac_with!(sha2::Sha224),
        o => Err(Error::new(format!("unsupported MAC algorithm {o}"))),
    }
}

fn asn1(e: ::der::Error) -> Error {
    Error::malformed(format!("malformed ASN.1: {e}"))
}

fn read_contents(
    auth_safe: &[u8],
    password: &str,
    keys: &mut Vec<Bag<Vec<u8>>>,
    certs: &mut Vec<Bag<Cert>>,
) -> Result<()> {
    let safe: AuthenticatedSafe = ber(auth_safe).map_err(asn1)?;
    for ci in safe.iter() {
        let safe_contents = match ci.content_type.to_string().as_str() {
            DATA => octets(&ci.content).map_err(asn1)?,
            ENCRYPTED_DATA => {
                let enc = ci.content.to_der().map_err(asn1)?;
                let ed: EncryptedData = ber(&enc).map_err(asn1)?;
                let eci = ed.enc_content_info;
                let data = eci
                    .encrypted_content
                    .ok_or_else(|| Error::new("encrypted data without content"))?;
                decrypt(&eci.content_enc_alg, data.as_bytes(), password)?
            }
            o => return Err(Error::new(format!("unsupported PKCS#12 content type {o}"))),
        };
        let bags: SafeContents = ber(&safe_contents).map_err(asn1)?;
        for bag in &bags {
            read_bag(bag, password, keys, certs)?;
        }
    }
    Ok(())
}

fn read_bag(
    bag: &pkcs12::SafeBag,
    password: &str,
    keys: &mut Vec<Bag<Vec<u8>>>,
    certs: &mut Vec<Bag<Cert>>,
) -> Result<()> {
    // bag_value keeps its [0] EXPLICIT wrapper
    let value = ber::<AnyRef<'_>>(&bag.bag_value).map_err(asn1)?.value();
    let (mut alias, mut local_id) = (None, None);
    for a in bag.bag_attributes.iter().flat_map(|s| s.iter()) {
        let Some(v) = a.values.iter().next() else {
            continue;
        };
        match a.oid.to_string().as_str() {
            FRIENDLY_NAME => {
                alias = v
                    .decode_as::<::der::asn1::BmpString>()
                    .ok()
                    .map(|b| b.to_string())
            }
            LOCAL_KEY_ID => {
                local_id = Some(hex(v.decode_as::<OctetString>().map_err(asn1)?.as_bytes()))
            }
            _ => {}
        }
    }
    let key_alias = alias.clone().or_else(|| local_id.clone());
    match bag.bag_id.to_string().as_str() {
        SHROUDED_KEY_BAG => {
            let e: EncryptedPrivateKeyInfo = ber(value).map_err(asn1)?;
            let pki = decrypt(
                &e.encryption_algorithm,
                e.encrypted_data.as_bytes(),
                password,
            )?;
            keys.push(Bag {
                alias: key_alias,
                local_id,
                value: pki,
            });
        }
        KEY_BAG => keys.push(Bag {
            alias: key_alias,
            local_id,
            value: value.to_vec(),
        }),
        CERT_BAG => {
            let cb: CertBag = ber(value).map_err(asn1)?;
            if cb.cert_id.to_string() == X509_CERT {
                let c = Cert::parse(cb.cert_value.as_bytes())?;
                certs.push(Bag {
                    alias,
                    local_id,
                    value: c,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// `leaf` followed by its issuers found in the file, as far as they go.
fn chain(leaf: &Cert, pool: &[Cert]) -> Vec<Cert> {
    let mut chain = Vec::new();
    let mut cur = Some(leaf.clone());
    while let Some(c) = cur {
        if chain.len() >= 10 {
            break;
        }
        chain.push(c.clone());
        if c.self_issued() {
            break;
        }
        cur = pool
            .iter()
            .rfind(|p| crate::cert::names_equal(&p.subject, &c.issuer) && **p != c)
            .cloned();
    }
    chain
}

// ------------------------------------------------------------------ password-based encryption

fn bmp_password(p: &str) -> Vec<u8> {
    if p.is_empty() {
        return vec![];
    }
    let mut out: Vec<u8> = p.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    out.extend([0, 0]);
    out
}

/// An iteration count from the file. Real ones are a few thousand to a few hundred thousand; a
/// damaged or hostile file must not keep the program hashing for hours.
fn iterations(n: i64) -> Result<u32> {
    match n {
        1..=10_000_000 => Ok(n as u32),
        n => Err(Error::new(format!("unsupported iteration count {n}"))),
    }
}

/// The PKCS#12 key derivation (RFC 7292 appendix B), from RustCrypto's pkcs12 crate.
fn kdf<D: Digest + FixedOutputReset + BlockSizeUser>(
    pw: &[u8],
    salt: &[u8],
    iterations: u32,
    id: Pkcs12KeyType,
    n: usize,
) -> Result<Vec<u8>> {
    derive_key::<D>(pw, salt, id, iterations.clamp(1, i32::MAX as u32) as i32, n)
        .map_err(|e| Error::new(format!("key derivation: {e}")))
}

/// CBC decryption with PKCS#7 padding (RustCrypto's cbc crate).
fn cbc_decrypt<C: BlockCipherDecrypt>(c: C, iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let d =
        cbc::Decryptor::<C>::inner_iv_slice_init(c, iv).map_err(|_| Error::new("bad IV length"))?;
    let mut buf = data.to_vec();
    let n = d
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| Error::new("bad padding (wrong password?)"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

fn new_cipher<C: KeyInit>(key: &[u8]) -> Result<C> {
    C::new_from_slice(key).map_err(|_| Error::new("bad key length"))
}

/// Decrypts with a PKCS#12 PBE algorithm or PBES2.
fn decrypt(alg: &AlgorithmIdentifierOwned, data: &[u8], password: &str) -> Result<Vec<u8>> {
    let oid = alg.oid.to_string();
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Error::new("encryption without parameters"))?
        .to_der()
        .map_err(asn1)?;
    if oid == "1.2.840.113549.1.5.13" {
        return pbes2(&params, data, password);
    }
    let p: Pkcs12PbeParams = ber(&params).map_err(asn1)?;
    let salt = p.salt.as_bytes();
    let iter = iterations(i64::from(p.iterations))?;
    let pw = bmp_password(password);
    let key = |n| kdf::<sha1::Sha1>(&pw, salt, iter, Pkcs12KeyType::EncryptionKey, n);
    let iv = |n| kdf::<sha1::Sha1>(&pw, salt, iter, Pkcs12KeyType::Iv, n);
    match oid.as_str() {
        "1.2.840.113549.1.12.1.3" => {
            cbc_decrypt(new_cipher::<des::TdesEde3>(&key(24)?)?, &iv(8)?, data)
        }
        "1.2.840.113549.1.12.1.4" => {
            cbc_decrypt(new_cipher::<des::TdesEde2>(&key(16)?)?, &iv(8)?, data)
        }
        "1.2.840.113549.1.12.1.5" => cbc_decrypt(
            rc2::Rc2::new_with_eff_key_len(&key(16)?, 128),
            &iv(8)?,
            data,
        ),
        "1.2.840.113549.1.12.1.6" => {
            cbc_decrypt(rc2::Rc2::new_with_eff_key_len(&key(5)?, 40), &iv(8)?, data)
        }
        o => Err(Error::new(format!("unsupported key file encryption {o}"))),
    }
}

/// PBKDF2-params (RFC 8018 A.2); the PRF is optional (default HMAC-SHA-1), which pkcs12's
/// own type does not allow.
#[derive(Sequence)]
struct Pbkdf2Params {
    salt: OctetString,
    iteration_count: u32,
    #[asn1(optional = "true")]
    _key_length: Option<u16>,
    #[asn1(optional = "true")]
    prf: Option<AlgorithmIdentifierOwned>,
}

fn pbes2(params: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    let p: Pbes2Params = ber(params).map_err(asn1)?;
    let kdf_oid = p.kdf.oid.to_string();
    if kdf_oid != "1.2.840.113549.1.5.12" {
        return Err(Error::new(format!("unsupported key derivation {kdf_oid}")));
    }
    let kp: Pbkdf2Params = p
        .kdf
        .parameters
        .as_ref()
        .ok_or_else(|| Error::new("PBKDF2 without parameters"))?
        .decode_as()
        .map_err(asn1)?;
    let salt = kp.salt.as_bytes();
    let iter = iterations(i64::from(kp.iteration_count))?;
    let prf = kp
        .prf
        .map_or_else(|| "1.2.840.113549.2.7".to_string(), |a| a.oid.to_string());
    let enc_oid = p.encryption.oid.to_string();
    let iv = p
        .encryption
        .parameters
        .as_ref()
        .ok_or_else(|| Error::new("cipher without IV"))?
        .decode_as::<OctetString>()
        .map_err(asn1)?;
    let iv = iv.as_bytes();
    let key_len = match enc_oid.as_str() {
        "2.16.840.1.101.3.4.1.2" => 16,
        "2.16.840.1.101.3.4.1.22" => 24,
        "2.16.840.1.101.3.4.1.42" => 32,
        "1.2.840.113549.3.7" => 24,
        o => return Err(Error::new(format!("unsupported cipher {o}"))),
    };
    let mut key = zeroize::Zeroizing::new(vec![0u8; key_len]);
    let pw = password.as_bytes();
    match prf.as_str() {
        "1.2.840.113549.2.7" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw, salt, iter, &mut key),
        "1.2.840.113549.2.8" => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pw, salt, iter, &mut key),
        "1.2.840.113549.2.9" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, iter, &mut key),
        "1.2.840.113549.2.10" => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pw, salt, iter, &mut key),
        "1.2.840.113549.2.11" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw, salt, iter, &mut key),
        o => return Err(Error::new(format!("unsupported PBKDF2 function {o}"))),
    }
    match key_len {
        16 => cbc_decrypt(new_cipher::<aes::Aes128>(&key)?, iv, data),
        32 => cbc_decrypt(new_cipher::<aes::Aes256>(&key)?, iv, data),
        _ if enc_oid == "1.2.840.113549.3.7" => {
            cbc_decrypt(new_cipher::<des::TdesEde3>(&key)?, iv, data)
        }
        _ => cbc_decrypt(new_cipher::<aes::Aes192>(&key)?, iv, data),
    }
}
