//! Opens NCA .p12 key files: PKCS#12 with KZ GOST or RSA keys, as Kalkan writes them (BER,
//! 3DES-encrypted key, RC2-40-encrypted certificates, SHA-1 MAC), and PBES2 (AES) files.

use cipher::{Array, BlockCipherDecrypt, BlockSizeUser, KeyInit};
use digest::{Digest, FixedOutputReset};

use crate::cert::Cert;
use crate::der::{self, Tlv};
use crate::keys::{PrivateKey, alg_id};
use crate::{Error, Result, hex};

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
    let auth_safe = read_pfx(p12, password)?;
    let mut keys: Vec<Bag<Vec<u8>>> = Vec::new();
    let mut certs: Vec<Bag<Cert>> = Vec::new();
    read_contents(&auth_safe, password, &mut keys, &mut certs).map_err(|e| {
        Error::new(format!(
            "Could not open the key file. The password is probably wrong, or the file uses an unsupported format ({})",
            e.0
        ))
    })?;
    if keys.is_empty() {
        return Err(Error::new("The key file contains no private key."));
    }
    let aliases: Vec<String> =
        keys.iter().enumerate().map(|(i, k)| k.alias.clone().unwrap_or_else(|| format!("key{}", i + 1))).collect();
    let alias = wanted_alias.map(str::to_string).unwrap_or_else(|| aliases[0].clone());
    let Some(idx) = aliases.iter().position(|a| *a == alias) else {
        return Err(Error::new(format!("No key with alias '{alias}'. Available: [{}]", aliases.join(", "))));
    };
    let kb = &keys[idx];
    let private_key = PrivateKey::from_pkcs8(&kb.value)
        .map_err(|e| Error::new(format!("Unsupported private key type: {}", e.0)))?;
    let pool: Vec<Cert> = certs.iter().map(|b| b.value.clone()).collect();
    let mut leaf = None;
    for c in &certs {
        if kb.local_id.is_some() && kb.local_id == c.local_id {
            leaf = Some(c.value.clone());
        }
    }
    if leaf.is_none() {
        leaf = pool.iter().find(|c| c.public_key().is_ok_and(|p| private_key.matches(&p))).cloned();
    }
    let leaf = leaf.ok_or_else(|| Error::new("The key file has no certificate for its key."))?;
    let other_aliases = aliases.iter().filter(|a| **a != alias).cloned().collect();
    Ok(Key { alias, private_key, chain: chain(&leaf, &pool), cert: leaf, other_aliases })
}

/// Checks the MAC and returns the AuthenticatedSafe bytes.
fn read_pfx(p12: &[u8], password: &str) -> Result<Vec<u8>> {
    let not_p12 = |e: Error| {
        Error::new(format!("Could not open the key file: it is not a PKCS#12 (.p12) key ({})", e.0))
    };
    let pfx = der::parse(p12).and_then(|t| t.items(der::SEQUENCE)).map_err(not_p12)?;
    if pfx.len() < 2 {
        return Err(not_p12(Error::new("too few fields")));
    }
    let ci = pfx[1].items(der::SEQUENCE).map_err(not_p12)?;
    if ci.len() < 2 || ci[0].oid().map_err(not_p12)? != DATA {
        return Err(not_p12(Error::new("unsupported PFX content (public-key integrity mode)")));
    }
    let auth_safe = ci[1].inner().and_then(|o| o.octets()).map_err(not_p12)?;
    if let Some(mac) = pfx.get(2) {
        let ok = check_mac(mac, &auth_safe, password).unwrap_or(false);
        if !ok {
            return Err(Error::new("Could not open the key file. The password is probably wrong."));
        }
    }
    Ok(auth_safe)
}

fn check_mac(mac: &Tlv, data: &[u8], password: &str) -> Result<bool> {
    let m = mac.items(der::SEQUENCE)?;
    let di = m[0].items(der::SEQUENCE)?;
    let (oid, _) = alg_id(&di[0])?;
    let expected = di[1].octets()?;
    let salt = m[1].octets()?;
    let iter = m.get(2).map(|i| i.small_int()).transpose()?.unwrap_or(1) as u32;
    let pw = bmp_password(password);
    use hmac::{KeyInit as _, Mac};
    macro_rules! mac_with {
        ($h:ty) => {{
            let key = kdf::<$h>(&pw, &salt, iter, 3, <$h as digest::OutputSizeUser>::output_size());
            let mut h = <hmac::Hmac<$h>>::new_from_slice(&key).map_err(|_| Error::new("MAC key"))?;
            h.update(data);
            Ok(h.verify_slice(&expected).is_ok())
        }};
    }
    match oid.as_str() {
        crate::gost::H_SHA1 => mac_with!(sha1::Sha1),
        crate::gost::H_SHA256 => mac_with!(sha2::Sha256),
        crate::gost::H_SHA384 => mac_with!(sha2::Sha384),
        crate::gost::H_SHA512 => mac_with!(sha2::Sha512),
        crate::gost::H_SHA224 => mac_with!(sha2::Sha224),
        o => Err(Error::new(format!("unsupported MAC algorithm {o}"))),
    }
}

fn read_contents(
    auth_safe: &[u8],
    password: &str,
    keys: &mut Vec<Bag<Vec<u8>>>,
    certs: &mut Vec<Bag<Cert>>,
) -> Result<()> {
    for ci in der::parse(auth_safe)?.items(der::SEQUENCE)? {
        let k = ci.items(der::SEQUENCE)?;
        let ty = k[0].oid()?;
        let safe_contents = match ty.as_str() {
            DATA => k[1].inner()?.octets()?,
            ENCRYPTED_DATA => {
                let ed = k[1].inner()?.items(der::SEQUENCE)?;
                let eci = ed[1].items(der::SEQUENCE)?;
                let enc = eci.get(2).ok_or_else(|| Error::new("encrypted data without content"))?;
                decrypt(&eci[1], &enc.octets()?, password)?
            }
            o => return Err(Error::new(format!("unsupported PKCS#12 content type {o}"))),
        };
        for bag in der::parse(&safe_contents)?.items(der::SEQUENCE)? {
            read_bag(&bag, password, keys, certs)?;
        }
    }
    Ok(())
}

fn read_bag(bag: &Tlv, password: &str, keys: &mut Vec<Bag<Vec<u8>>>, certs: &mut Vec<Bag<Cert>>) -> Result<()> {
    let k = bag.items(der::SEQUENCE)?;
    let ty = k[0].oid()?;
    let value = k[1].inner()?;
    let (mut alias, mut local_id) = (None, None);
    if let Some(attrs) = k.get(2) {
        for a in attrs.items(der::SET)? {
            let ak = a.items(der::SEQUENCE)?;
            let Some(v) = ak[1].children()?.into_iter().next() else { continue };
            match ak[0].oid()?.as_str() {
                FRIENDLY_NAME => alias = v.text(),
                LOCAL_KEY_ID => local_id = Some(hex(&v.octets()?)),
                _ => {}
            }
        }
    }
    let key_alias = alias.clone().or_else(|| local_id.clone());
    match ty.as_str() {
        SHROUDED_KEY_BAG => {
            let e = value.items(der::SEQUENCE)?;
            let pki = decrypt(&e[0], &e[1].octets()?, password)?;
            keys.push(Bag { alias: key_alias, local_id, value: pki });
        }
        KEY_BAG => keys.push(Bag { alias: key_alias, local_id, value: value.raw.to_vec() }),
        CERT_BAG => {
            let cb = value.items(der::SEQUENCE)?;
            if cb[0].oid()? == X509_CERT {
                let c = Cert::parse(&cb[1].inner()?.octets()?)?;
                certs.push(Bag { alias, local_id, value: c });
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
        cur = pool.iter().filter(|p| crate::cert::names_equal(&p.subject, &c.issuer) && **p != c).last().cloned();
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

/// The PKCS#12 key derivation (RFC 7292 appendix B).
fn kdf<D: Digest + FixedOutputReset>(
    pw: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    n: usize,
) -> Vec<u8> {
    let u = <D as digest::OutputSizeUser>::output_size();
    // the hash's block size: 128 bytes for the SHA-384/512 family, 64 for the others
    let v = if u > 32 { 128 } else { 64 };
    let fill = |src: &[u8]| -> Vec<u8> {
        if src.is_empty() {
            return vec![];
        }
        let len = v * src.len().div_ceil(v);
        (0..len).map(|i| src[i % src.len()]).collect()
    };
    let mut i_buf = fill(salt);
    i_buf.extend(fill(pw));
    let d = vec![id; v];
    let mut out = Vec::with_capacity(n);
    let mut h = D::new();
    while out.len() < n {
        Digest::update(&mut h, &d);
        Digest::update(&mut h, &i_buf);
        let mut a = h.finalize_reset().to_vec();
        for _ in 1..iterations.max(1) {
            Digest::update(&mut h, &a);
            a = h.finalize_reset().to_vec();
        }
        let b: Vec<u8> = (0..v).map(|i| a[i % u]).collect();
        for block in i_buf.chunks_mut(v) {
            // block = block + b + 1 (mod 2^(8v))
            let mut carry = 1u16;
            for j in (0..v).rev() {
                let s = block[j] as u16 + b[j] as u16 + carry;
                block[j] = s as u8;
                carry = s >> 8;
            }
        }
        out.extend(&a);
    }
    out.truncate(n);
    out
}

fn cbc_decrypt<C: BlockCipherDecrypt>(c: &C, iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let bs = <C as BlockSizeUser>::block_size();
    if data.is_empty() || data.len() % bs != 0 || iv.len() != bs {
        return Err(Error::new("bad encrypted data length"));
    }
    let mut prev = iv.to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        let mut block = Array::try_from(chunk).map_err(|_| Error::new("block"))?;
        c.decrypt_block(&mut block);
        out.extend(block.iter().zip(&prev).map(|(a, b)| a ^ b));
        prev = chunk.to_vec();
    }
    let pad = *out.last().unwrap() as usize;
    if pad == 0 || pad > bs || out[out.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(Error::new("bad padding (wrong password?)"));
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

fn new_cipher<C: KeyInit>(key: &[u8]) -> Result<C> {
    C::new_from_slice(key).map_err(|_| Error::new("bad key length"))
}

/// Decrypts with a PKCS#12 PBE algorithm or PBES2.
fn decrypt(alg: &Tlv, data: &[u8], password: &str) -> Result<Vec<u8>> {
    let (oid, params) = alg_id(alg)?;
    let params = params.ok_or_else(|| Error::new("encryption without parameters"))?;
    if oid == "1.2.840.113549.1.5.13" {
        return pbes2(&params, data, password);
    }
    let p = params.items(der::SEQUENCE)?;
    let salt = p[0].octets()?;
    let iter = p[1].small_int()? as u32;
    let pw = bmp_password(password);
    let key = |n| kdf::<sha1::Sha1>(&pw, &salt, iter, 1, n);
    let iv = |n| kdf::<sha1::Sha1>(&pw, &salt, iter, 2, n);
    match oid.as_str() {
        "1.2.840.113549.1.12.1.3" => cbc_decrypt(&new_cipher::<des::TdesEde3>(&key(24))?, &iv(8), data),
        "1.2.840.113549.1.12.1.4" => cbc_decrypt(&new_cipher::<des::TdesEde2>(&key(16))?, &iv(8), data),
        "1.2.840.113549.1.12.1.5" => cbc_decrypt(&rc2::Rc2::new_with_eff_key_len(&key(16), 128), &iv(8), data),
        "1.2.840.113549.1.12.1.6" => cbc_decrypt(&rc2::Rc2::new_with_eff_key_len(&key(5), 40), &iv(8), data),
        o => Err(Error::new(format!("unsupported key file encryption {o}"))),
    }
}

fn pbes2(params: &Tlv, data: &[u8], password: &str) -> Result<Vec<u8>> {
    let p = params.items(der::SEQUENCE)?;
    let (kdf_oid, kdf_params) = alg_id(&p[0])?;
    if kdf_oid != "1.2.840.113549.1.5.12" {
        return Err(Error::new(format!("unsupported key derivation {kdf_oid}")));
    }
    let kp = kdf_params.ok_or_else(|| Error::new("PBKDF2 without parameters"))?.items(der::SEQUENCE)?;
    let salt = kp[0].octets()?;
    let iter = kp[1].small_int()? as u32;
    let mut prf = "1.2.840.113549.2.7".to_string();
    for x in &kp[2..] {
        if x.tag == der::SEQUENCE {
            prf = alg_id(x)?.0;
        }
    }
    let (enc_oid, enc_params) = alg_id(&p[1])?;
    let iv = enc_params.ok_or_else(|| Error::new("cipher without IV"))?.octets()?;
    let key_len = match enc_oid.as_str() {
        "2.16.840.1.101.3.4.1.2" => 16,
        "2.16.840.1.101.3.4.1.22" => 24,
        "2.16.840.1.101.3.4.1.42" => 32,
        "1.2.840.113549.3.7" => 24,
        o => return Err(Error::new(format!("unsupported cipher {o}"))),
    };
    let mut key = vec![0u8; key_len];
    let pw = password.as_bytes();
    match prf.as_str() {
        "1.2.840.113549.2.7" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw, &salt, iter, &mut key),
        "1.2.840.113549.2.8" => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pw, &salt, iter, &mut key),
        "1.2.840.113549.2.9" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, &salt, iter, &mut key),
        "1.2.840.113549.2.10" => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pw, &salt, iter, &mut key),
        "1.2.840.113549.2.11" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw, &salt, iter, &mut key),
        o => return Err(Error::new(format!("unsupported PBKDF2 function {o}"))),
    }
    match key_len {
        16 => cbc_decrypt(&new_cipher::<aes::Aes128>(&key)?, &iv, data),
        32 => cbc_decrypt(&new_cipher::<aes::Aes256>(&key)?, &iv, data),
        _ if enc_oid == "1.2.840.113549.3.7" => cbc_decrypt(&new_cipher::<des::TdesEde3>(&key)?, &iv, data),
        _ => cbc_decrypt(&new_cipher::<aes::Aes192>(&key)?, &iv, data),
    }
}
