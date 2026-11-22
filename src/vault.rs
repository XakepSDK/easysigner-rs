//! Keys kept by kzsigner itself, locked to this device.
//!
//! No phone or PC security chip can hold a KZ GOST key, so the chip guards the key instead:
//! the private key (PKCS#8, as it came out of the .p12) is encrypted with AES-256-GCM by a
//! key that lives in the chip and works only after the owner authenticates (see [`Guard`]).
//! A copy of the store is useless on any other device, and there is nothing to guess
//! passwords against offline.
//!
//! Protection levels ([`Level`]): what each signature asks for.
//!
//! * `Standard`: fingerprint or the screen lock PIN (the default; one touch).
//! * `PasswordOnly`: a password; the chip key needs no prompt but still ties the key to this
//!   device. For phones without a screen lock.
//! * `Strict`: fingerprint only; enrolling a new fingerprint resets the key.
//! * `Maximum`: fingerprint and a password.
//!
//! A password layer is the inner one: Argon2id turns the password into an AES key that
//! encrypts the private key, and the chip encrypts that. Every password attempt therefore
//! needs the chip (and, for `Maximum`, a fingerprint); wrong passwords make the next attempt
//! wait longer ([`wait_after`]).
//!
//! Each record's AES-GCM associated data names the certificate (SHA-256) and the level, so a
//! record moved next to another certificate or level does not decrypt. After decrypting, the
//! key must also match the certificate's public key.
//!
//! The store is one file. With "hide my keys" ([`Store::set_hidden`]) the whole list,
//! certificates included, is encrypted with a random list key that the chip guards, and is
//! padded to a multiple of 64 KiB so the file does not tell how many keys it holds. Chip key
//! names are random either way.
//!
//! File: `KZVAULT1` then DER
//! `SEQUENCE { version INTEGER (1), CHOICE { [0] Index, [1] Hidden } }`, where
//! `Hidden ::= SEQUENCE { listKey UTF8String, sealedListKey OCTET STRING, nonce OCTET STRING,
//! encryptedIndex OCTET STRING }` and `Index ::= SEQUENCE OF Entry` (see [`Entry`]).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::cert::Cert;
use crate::der::{self, Tlv};
use crate::i18n::tr;
use crate::keys::PrivateKey;
use crate::p12::{self, Key};

const MAGIC: &[u8] = b"KZVAULT1";
const VERSION: u64 = 1;
/// The hidden list is padded to a multiple of this.
const BUCKET: usize = 64 * 1024;
/// Associated data prefix of a key record.
const RECORD_AAD: &[u8] = b"kzsigner key record v1";
/// Associated data of the hidden list.
const LIST_AAD: &[u8] = b"kzsigner key list v1";
/// The longest a wrong password makes the next attempt wait, in seconds.
const MAX_WAIT: u64 = 300;

/// What signing with a stored key asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    PasswordOnly,
    Standard,
    Strict,
    Maximum,
}

impl Level {
    /// What the chip key itself asks for.
    pub fn chip(self) -> ChipAuth {
        match self {
            Level::PasswordOnly => ChipAuth::None,
            Level::Standard => ChipAuth::BiometricOrPin,
            Level::Strict | Level::Maximum => ChipAuth::BiometricOnly,
        }
    }

    /// Whether a password is asked for too.
    pub fn needs_password(self) -> bool {
        matches!(self, Level::PasswordOnly | Level::Maximum)
    }

    fn code(self) -> u64 {
        match self {
            Level::PasswordOnly => 1,
            Level::Standard => 2,
            Level::Strict => 3,
            Level::Maximum => 4,
        }
    }

    fn from_code(c: i64) -> Option<Level> {
        Some(match c {
            1 => Level::PasswordOnly,
            2 => Level::Standard,
            3 => Level::Strict,
            4 => Level::Maximum,
            _ => return None,
        })
    }
}

/// How the owner unlocks a chip key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipAuth {
    /// No prompt: the key only ties the data to this device.
    None,
    /// Fingerprint (or face), or the screen lock PIN, for each use.
    BiometricOrPin,
    /// Fingerprint (or face) only, for each use; a newly enrolled fingerprint resets the key.
    BiometricOnly,
}

/// Where a chip key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// A separate security chip (Android StrongBox, a TPM, the Secure Enclave).
    Chip,
    /// The processor's protected area (Android TEE).
    Protected,
    /// Ordinary software: nothing stronger than the operating system's file permissions.
    Software,
}

impl Security {
    fn code(self) -> u64 {
        match self {
            Security::Chip => 1,
            Security::Protected => 2,
            Security::Software => 3,
        }
    }

    fn from_code(c: i64) -> Option<Security> {
        Some(match c {
            1 => Security::Chip,
            2 => Security::Protected,
            3 => Security::Software,
            _ => return None,
        })
    }
}

/// What the device offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// A screen lock (PIN, pattern or password) is set.
    pub screen_lock: bool,
    /// A fingerprint or face is enrolled.
    pub biometric: bool,
    /// Keys can live in hardware (chip or protected area), not just software.
    pub hardware: bool,
}

/// The texts of the system's fingerprint/PIN prompt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prompt {
    pub title: String,
    pub subtitle: String,
    pub detail: String,
}

/// Why the chip did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardError {
    /// The owner closed the prompt.
    Cancelled,
    /// The chip key is gone for good (screen lock removed, new fingerprint for a
    /// fingerprint-only key, the app's data wiped).
    KeyReset,
    Failed(String),
}

/// The device's key protection: a chip (or the best the device has) holding AES-256 keys that
/// never leave it. `seal` and `open` show the system prompt when the key needs one and block
/// until it is answered, so call them off the window's thread.
pub trait Guard: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    /// Makes a new key named `name`, unlocked as `auth` says.
    fn create(&self, name: &str, auth: ChipAuth) -> std::result::Result<Security, GuardError>;
    /// AES-GCM encryption of `plain` with key `name`; returns what [`Guard::open`] takes
    /// (nonce, ciphertext and tag, in the guard's own layout).
    fn seal(
        &self,
        name: &str,
        plain: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> std::result::Result<Vec<u8>, GuardError>;
    fn open(
        &self,
        name: &str,
        sealed: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, GuardError>;
    /// Removes key `name`; nothing happens if there is none.
    fn delete(&self, name: &str);
}

/// Why a key store operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// The owner closed the prompt; nothing changed.
    Cancelled,
    /// The device reset this key's protection; the .p12 must be added again.
    KeyReset,
    WrongPassword,
    /// Too many wrong passwords: try again in this many seconds.
    Wait(u64),
    /// The key list is hidden and not unlocked.
    Locked,
    /// The key is already stored.
    AlreadyAdded,
    /// This protection is not available on this device.
    Unavailable,
    NoSuchKey,
    Failed(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = match self {
            VaultError::Cancelled => tr("Cancelled."),
            VaultError::KeyReset => tr(
                "This device reset the key's protection (screen lock removed or a new fingerprint added). Add the .p12 file again.",
            ),
            VaultError::WrongPassword => tr("Wrong password."),
            VaultError::Wait(s) => {
                return write!(
                    f,
                    "{}",
                    crate::i18n::trf(
                        "Too many wrong passwords. Try again in {} s.",
                        &[&s.to_string()]
                    )
                );
            }
            VaultError::Locked => tr("kzsigner is locked."),
            VaultError::AlreadyAdded => tr("This key is already added."),
            VaultError::Unavailable => tr("This protection is not available on this device."),
            VaultError::NoSuchKey => tr("The key is no longer in kzsigner."),
            VaultError::Failed(m) => m,
        };
        f.write_str(t)
    }
}

impl std::error::Error for VaultError {}

impl From<GuardError> for VaultError {
    fn from(e: GuardError) -> VaultError {
        match e {
            GuardError::Cancelled => VaultError::Cancelled,
            GuardError::KeyReset => VaultError::KeyReset,
            GuardError::Failed(m) => VaultError::Failed(m),
        }
    }
}

impl From<crate::Error> for VaultError {
    fn from(e: crate::Error) -> VaultError {
        VaultError::Failed(e.0)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Argon2id settings for a password layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    /// Memory in KiB.
    pub memory: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Kdf {
    /// About half a second on a mid-range phone.
    pub const DEFAULT: Kdf = Kdf {
        memory: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    fn derive(&self, password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = argon2::Params::new(self.memory, self.passes, self.lanes, Some(32))
            .map_err(|e| VaultError::Failed(format!("Argon2 settings: {e}")))?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; 32]);
        a.hash_password_into(password.as_bytes(), salt, &mut out[..])
            .map_err(|e| VaultError::Failed(format!("Argon2: {e}")))?;
        Ok(out)
    }
}

/// The password layer of a record: salt and Argon2id settings.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PasswordLayer {
    salt: Vec<u8>,
    kdf: Kdf,
}

/// One stored key.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Random; also the name of its chip key.
    pub id: String,
    pub level: Level,
    pub security: Security,
    /// The key's alias in its .p12 file.
    pub alias: String,
    /// The certificate first, then its issuers.
    pub chain: Vec<Cert>,
    password: Option<PasswordLayer>,
    /// Wrong passwords in a row, and when the last one was (Unix seconds).
    failures: u32,
    last_failure: u64,
    /// The private key, encrypted (see the module notes).
    sealed: Vec<u8>,
}

impl Entry {
    pub fn cert(&self) -> &Cert {
        &self.chain[0]
    }

    fn aad(&self) -> Vec<u8> {
        record_aad(self.cert(), self.level)
    }

    fn to_der(&self) -> Vec<u8> {
        let chain: Vec<u8> = self.chain.iter().flat_map(|c| c.der.clone()).collect();
        let password = match &self.password {
            None => der::null(),
            Some(p) => der::seq(&[
                &der::octets(&p.salt),
                &der::small_int(p.kdf.memory as u64),
                &der::small_int(p.kdf.passes as u64),
                &der::small_int(p.kdf.lanes as u64),
            ]),
        };
        der::seq(&[
            &der::tlv(der::UTF8_STRING, self.id.as_bytes()),
            &der::small_int(self.level.code()),
            &der::small_int(self.security.code()),
            &der::tlv(der::UTF8_STRING, self.alias.as_bytes()),
            &der::tlv(der::SEQUENCE, &chain),
            &password,
            &der::small_int(self.failures as u64),
            &der::small_int(self.last_failure),
            &der::octets(&self.sealed),
        ])
    }

    fn from_der(t: &Tlv) -> crate::Result<Entry> {
        let bad = || crate::Error::new("damaged key store entry");
        let k = t.items(der::SEQUENCE)?;
        let text = |t: &Tlv| -> crate::Result<String> {
            String::from_utf8(t.expect(der::UTF8_STRING)?.content.to_vec()).map_err(|_| bad())
        };
        let small = |t: &Tlv| -> crate::Result<i64> {
            let v = t.small_int()?;
            if v < 0 { Err(bad()) } else { Ok(v) }
        };
        let id = text(&k[0])?;
        let level = Level::from_code(small(&k[1])?).ok_or_else(bad)?;
        let security = Security::from_code(small(&k[2])?).ok_or_else(bad)?;
        let alias = text(&k[3])?;
        let chain = k[4]
            .items(der::SEQUENCE)?
            .iter()
            .map(|c| Cert::parse(c.raw))
            .collect::<crate::Result<Vec<Cert>>>()?;
        if chain.is_empty() {
            return Err(bad());
        }
        let password = if k[5].tag == der::NULL {
            None
        } else {
            let p = k[5].items(der::SEQUENCE)?;
            let num =
                |t: &Tlv| -> crate::Result<u32> { u32::try_from(small(t)?).map_err(|_| bad()) };
            Some(PasswordLayer {
                salt: p[0].expect(der::OCTET_STRING)?.octets()?,
                kdf: Kdf {
                    memory: num(&p[1])?,
                    passes: num(&p[2])?,
                    lanes: num(&p[3])?,
                },
            })
        };
        if password.is_some() != level.needs_password() {
            return Err(bad());
        }
        Ok(Entry {
            id,
            level,
            security,
            alias,
            chain,
            password,
            failures: u32::try_from(small(&k[6])?).map_err(|_| bad())?,
            last_failure: small(&k[7])? as u64,
            sealed: k[8].expect(der::OCTET_STRING)?.octets()?,
        })
    }
}

fn record_aad(cert: &Cert, level: Level) -> Vec<u8> {
    der::cat(&[
        RECORD_AAD,
        &crate::gost::sha256(&cert.der),
        &[level.code() as u8],
    ])
}

/// Seconds to wait before the next password attempt after `failures` wrong ones in a row:
/// none after the first two, then 1, 2, 4 ... up to five minutes.
pub fn wait_after(failures: u32) -> u64 {
    if failures < 3 {
        return 0;
    }
    1u64.checked_shl(failures - 3)
        .unwrap_or(MAX_WAIT)
        .min(MAX_WAIT)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    crate::random(&mut b)?;
    Ok(b)
}

fn random_name() -> Result<String> {
    Ok(format!("kzsigner-{}", crate::hex(&random::<16>()?)))
}

/// AES-256-GCM in software: nonce (12 bytes) then ciphertext and tag.
fn encrypt(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random::<12>()?;
    let c = Aes256Gcm::new(key.into())
        .encrypt(
            &Nonce::from(nonce),
            aes_gcm::aead::Payload { msg: plain, aad },
        )
        .map_err(|_| VaultError::Failed("AES-GCM encryption failed".into()))?;
    Ok(der::cat(&[&nonce, &c]))
}

/// Undoes [`encrypt`]; None when the key, data or associated data do not match.
fn decrypt(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let (nonce, c) = data.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    Aes256Gcm::new(key.into())
        .decrypt(&Nonce::from(nonce), aes_gcm::aead::Payload { msg: c, aad })
        .ok()
        .map(Zeroizing::new)
}

/// The list key while the hidden list is unlocked.
struct Hidden {
    chip_key: String,
    sealed_list_key: Vec<u8>,
    list_key: Option<Zeroizing<[u8; 32]>>,
}

/// The stored keys, in one file.
pub struct Store<G: Guard> {
    path: PathBuf,
    guard: G,
    /// None while the hidden list is locked.
    entries: Option<Vec<Entry>>,
    hidden: Option<Hidden>,
    /// The hidden list as read, kept to unlock it.
    encrypted_list: Vec<u8>,
}

impl<G: Guard> Store<G> {
    /// Reads the store at `path` (an empty store if there is no file). A hidden list starts
    /// locked ([`Store::unlock`]).
    pub fn open(path: &Path, guard: G) -> Result<Store<G>> {
        let mut s = Store {
            path: path.to_path_buf(),
            guard,
            entries: Some(Vec::new()),
            hidden: None,
            encrypted_list: Vec::new(),
        };
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(s),
            Err(e) => return Err(VaultError::Failed(format!("{}: {e}", path.display()))),
        };
        s.read(&data).map_err(|e| {
            VaultError::Failed(format!("{}: {}", tr("The key store is damaged"), e.0))
        })?;
        Ok(s)
    }

    fn read(&mut self, data: &[u8]) -> crate::Result<()> {
        let body = data
            .strip_prefix(MAGIC)
            .ok_or_else(|| crate::Error::new("not a kzsigner key store"))?;
        let (top, _) = der::read(body)?;
        let t = top.items(der::SEQUENCE)?;
        if t[0].small_int()? != VERSION as i64 {
            return Err(crate::Error::new("unknown key store version"));
        }
        match t[1].tag {
            x if x == der::ctx(0) => {
                self.entries = Some(read_index(t[1].content)?);
            }
            x if x == der::ctx(1) => {
                let h = t[1].inner()?.items(der::SEQUENCE)?;
                let name = String::from_utf8(h[0].expect(der::UTF8_STRING)?.content.to_vec())
                    .map_err(|_| crate::Error::new("damaged key store"))?;
                self.hidden = Some(Hidden {
                    chip_key: name,
                    sealed_list_key: h[1].expect(der::OCTET_STRING)?.octets()?,
                    list_key: None,
                });
                self.encrypted_list = h[2].expect(der::OCTET_STRING)?.octets()?;
                self.entries = None;
            }
            _ => return Err(crate::Error::new("damaged key store")),
        }
        Ok(())
    }

    /// Writes the store: to a new file first, then renamed over the old one.
    fn save(&self) -> Result<()> {
        let entries = self.entries.as_ref().ok_or(VaultError::Locked)?;
        let index = Zeroizing::new(der::cat(
            &entries
                .iter()
                .map(Entry::to_der)
                .collect::<Vec<_>>()
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        ));
        let choice = match &self.hidden {
            None => der::tlv(der::ctx(0), &index),
            Some(h) => {
                let key = h.list_key.as_ref().ok_or(VaultError::Locked)?;
                // SEQUENCE OF Entry, padded to whole buckets
                let mut list = Zeroizing::new(der::tlv(der::SEQUENCE, &index));
                // nonce and tag make the encrypted list a whole number of buckets
                let size = (list.len() + 12 + 16).div_ceil(BUCKET) * BUCKET - 12 - 16;
                list.resize(size, 0);
                let enc = encrypt(key, &list, LIST_AAD)?;
                der::tlv(
                    der::ctx(1),
                    &der::seq(&[
                        &der::tlv(der::UTF8_STRING, h.chip_key.as_bytes()),
                        &der::octets(&h.sealed_list_key),
                        &der::octets(&enc),
                    ]),
                )
            }
        };
        let file = der::cat(&[MAGIC, &der::seq(&[&der::small_int(VERSION), &choice])]);
        let tmp = self.path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&file)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        write().map_err(|e| VaultError::Failed(format!("{}: {e}", self.path.display())))
    }

    /// Whether the list is hidden and not unlocked.
    pub fn is_locked(&self) -> bool {
        self.entries.is_none()
    }

    pub fn is_hidden(&self) -> bool {
        self.hidden.is_some()
    }

    /// The stored keys (empty while locked).
    pub fn keys(&self) -> &[Entry] {
        self.entries.as_deref().unwrap_or(&[])
    }

    /// Unlocks a hidden list (one prompt).
    pub fn unlock(&mut self, prompt: &Prompt) -> Result<()> {
        let Some(h) = &mut self.hidden else {
            return Ok(());
        };
        if self.entries.is_some() {
            return Ok(());
        }
        let k = self
            .guard
            .open(&h.chip_key, &h.sealed_list_key, LIST_AAD, prompt)?;
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            k.as_slice()
                .try_into()
                .map_err(|_| VaultError::Failed(tr("The key store is damaged").into()))?,
        );
        let list = decrypt(&key, &self.encrypted_list, LIST_AAD)
            .ok_or_else(|| VaultError::Failed(tr("The key store is damaged").into()))?;
        let (t, _) = der::read(&list).map_err(|e| {
            VaultError::Failed(format!("{}: {}", tr("The key store is damaged"), e.0))
        })?;
        let entries = read_index(t.expect(der::SEQUENCE).map_err(VaultError::from)?.content)
            .map_err(|e| {
                VaultError::Failed(format!("{}: {}", tr("The key store is damaged"), e.0))
            })?;
        h.list_key = Some(key);
        self.entries = Some(entries);
        Ok(())
    }

    /// Forgets the unlocked list and its key (a hidden store only).
    pub fn lock(&mut self) {
        if let Some(h) = &mut self.hidden {
            h.list_key = None;
            self.entries = None;
        }
    }

    /// The level a new key gets without asking: one touch where the device can, otherwise
    /// the password.
    pub fn default_level(&self) -> Level {
        let c = self.guard.capabilities();
        if c.screen_lock && c.hardware {
            Level::Standard
        } else {
            Level::PasswordOnly
        }
    }

    /// Whether `level` works on this device.
    pub fn level_available(&self, level: Level) -> bool {
        let c = self.guard.capabilities();
        match level.chip() {
            ChipAuth::None => true,
            ChipAuth::BiometricOrPin => c.screen_lock && c.hardware,
            ChipAuth::BiometricOnly => c.screen_lock && c.hardware && c.biometric,
        }
    }

    /// Adds the key from a .p12 file at [`Store::default_level`]; a password level uses the
    /// .p12's own password. Returns the new key's id.
    pub fn add(
        &mut self,
        p12_file: &[u8],
        p12_password: &str,
        alias: Option<&str>,
        prompt: &Prompt,
    ) -> Result<String> {
        let level = self.default_level();
        self.add_with(
            p12_file,
            p12_password,
            alias,
            level,
            Some(p12_password),
            Kdf::DEFAULT,
            prompt,
        )
    }

    /// [`Store::add`] with a chosen level; `password` is the new password for a password
    /// level (ignored otherwise).
    #[allow(clippy::too_many_arguments)]
    pub fn add_with(
        &mut self,
        p12_file: &[u8],
        p12_password: &str,
        alias: Option<&str>,
        level: Level,
        password: Option<&str>,
        kdf: Kdf,
        prompt: &Prompt,
    ) -> Result<String> {
        let entries = self.entries.as_ref().ok_or(VaultError::Locked)?;
        let (key, pkcs8) = p12::open_with_pkcs8(p12_file, p12_password, alias)?;
        if entries.iter().any(|e| e.cert().der == key.cert.der) {
            return Err(VaultError::AlreadyAdded);
        }
        let entry = self.seal_new(level, password, kdf, key.alias, key.chain, &pkcs8, prompt)?;
        let id = entry.id.clone();
        self.entries.as_mut().ok_or(VaultError::Locked)?.push(entry);
        if let Err(e) = self.save() {
            self.forget(&id);
            return Err(e);
        }
        Ok(id)
    }

    /// Makes a chip key and a record for a private key.
    #[allow(clippy::too_many_arguments)]
    fn seal_new(
        &self,
        level: Level,
        password: Option<&str>,
        kdf: Kdf,
        alias: String,
        chain: Vec<Cert>,
        pkcs8: &[u8],
        prompt: &Prompt,
    ) -> Result<Entry> {
        if !self.level_available(level) {
            return Err(VaultError::Unavailable);
        }
        let aad = record_aad(&chain[0], level);
        let record = Zeroizing::new(der::seq(&[&der::octets(pkcs8)]));
        let (inner, layer) = if level.needs_password() {
            let password = password
                .filter(|p| !p.is_empty())
                .ok_or(VaultError::WrongPassword)?;
            let salt = random::<16>()?.to_vec();
            let k = kdf.derive(password, &salt)?;
            (
                Zeroizing::new(encrypt(&k, &record, &aad)?),
                Some(PasswordLayer { salt, kdf }),
            )
        } else {
            (record, None)
        };
        let id = random_name()?;
        let security = self.guard.create(&id, level.chip())?;
        let sealed = match self.guard.seal(&id, &inner, &aad, prompt) {
            Ok(s) => s,
            Err(e) => {
                self.guard.delete(&id);
                return Err(e.into());
            }
        };
        Ok(Entry {
            id,
            level,
            security,
            alias,
            chain,
            password: layer,
            failures: 0,
            last_failure: 0,
            sealed,
        })
    }

    fn entry(&self, id: &str) -> Result<&Entry> {
        self.entries
            .as_ref()
            .ok_or(VaultError::Locked)?
            .iter()
            .find(|e| e.id == id)
            .ok_or(VaultError::NoSuchKey)
    }

    fn entry_mut(&mut self, id: &str) -> Result<&mut Entry> {
        self.entries
            .as_mut()
            .ok_or(VaultError::Locked)?
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(VaultError::NoSuchKey)
    }

    /// Seconds until key `id` takes another password attempt.
    pub fn wait(&self, id: &str) -> Result<u64> {
        let e = self.entry(id)?;
        let w = wait_after(e.failures);
        let since = now().saturating_sub(e.last_failure);
        // a clock set back counts as no time passed
        Ok(if now() < e.last_failure {
            w
        } else {
            w.saturating_sub(since)
        })
    }

    /// The private key's PKCS#8, after the prompt and (for a password level) the password.
    fn unseal(
        &mut self,
        id: &str,
        password: Option<&str>,
        prompt: &Prompt,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let e = self.entry(id)?;
        if e.level.needs_password() {
            let w = self.wait(id)?;
            if w > 0 {
                return Err(VaultError::Wait(w));
            }
        }
        let aad = e.aad();
        let inner = self.guard.open(&e.id, &e.sealed, &aad, prompt)?;
        let record = match &e.password {
            None => inner,
            Some(layer) => {
                let k = layer.kdf.derive(password.unwrap_or(""), &layer.salt)?;
                match decrypt(&k, &inner, &aad) {
                    Some(r) => r,
                    None => {
                        let e = self.entry_mut(id)?;
                        e.failures = e.failures.saturating_add(1);
                        e.last_failure = now();
                        self.save()?;
                        return Err(VaultError::WrongPassword);
                    }
                }
            }
        };
        if self.entry(id)?.failures != 0 {
            let e = self.entry_mut(id)?;
            e.failures = 0;
            e.last_failure = 0;
            self.save()?;
        }
        let damaged = || VaultError::Failed(tr("The key store is damaged").into());
        let t = der::parse(&record).map_err(|_| damaged())?;
        let pkcs8 = t
            .items(der::SEQUENCE)
            .and_then(|r| r[0].expect(der::OCTET_STRING)?.octets())
            .map_err(|_| damaged())?;
        Ok(Zeroizing::new(pkcs8))
    }

    /// Key `id`, ready to sign with: shows the prompt, and checks `password` for a password
    /// level.
    pub fn key(&mut self, id: &str, password: Option<&str>, prompt: &Prompt) -> Result<Key> {
        let pkcs8 = self.unseal(id, password, prompt)?;
        let e = self.entry(id)?;
        let damaged = || VaultError::Failed(tr("The key store is damaged").into());
        let private_key = PrivateKey::from_pkcs8(&pkcs8).map_err(|_| damaged())?;
        let public = e.cert().public_key().map_err(|_| damaged())?;
        if !private_key.matches(&public) {
            return Err(damaged());
        }
        Ok(Key {
            alias: e.alias.clone(),
            private_key,
            cert: e.cert().clone(),
            chain: e.chain.clone(),
            other_aliases: Vec::new(),
        })
    }

    /// Moves key `id` to another level, or sets a new password: the key is unlocked with
    /// what it needs now (`password`), then sealed again (`new_password` for a password
    /// level). Shows the prompt for the old level, then for the new one.
    pub fn change(
        &mut self,
        id: &str,
        level: Level,
        password: Option<&str>,
        new_password: Option<&str>,
        prompt: &Prompt,
    ) -> Result<()> {
        if !self.level_available(level) {
            return Err(VaultError::Unavailable);
        }
        let pkcs8 = self.unseal(id, password, prompt)?;
        let e = self.entry(id)?.clone();
        let new = self.seal_new(
            level,
            new_password,
            Kdf::DEFAULT,
            e.alias.clone(),
            e.chain.clone(),
            &pkcs8,
            prompt,
        )?;
        let new_id = new.id.clone();
        *self.entry_mut(id)? = new;
        if let Err(err) = self.save() {
            self.guard.delete(&new_id);
            *self.entry_mut(&new_id)? = e;
            return Err(err);
        }
        self.guard.delete(id);
        Ok(())
    }

    /// Removes key `id` and its chip key.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.entry(id)?;
        let removed = self.forget(id);
        if let Err(e) = self.save() {
            if let (Some(r), Some(v)) = (removed, self.entries.as_mut()) {
                v.push(r);
            }
            return Err(e);
        }
        self.guard.delete(id);
        Ok(())
    }

    fn forget(&mut self, id: &str) -> Option<Entry> {
        let v = self.entries.as_mut()?;
        let i = v.iter().position(|e| e.id == id)?;
        Some(v.remove(i))
    }

    /// Turns "hide my keys" on (the list, certificates included, is then encrypted and needs
    /// one prompt to show) or off. Needs a screen lock.
    pub fn set_hidden(&mut self, hide: bool, prompt: &Prompt) -> Result<()> {
        if self.entries.is_none() {
            return Err(VaultError::Locked);
        }
        if hide == self.hidden.is_some() {
            return Ok(());
        }
        if !hide {
            let old = self.hidden.take();
            if let Err(e) = self.save() {
                self.hidden = old;
                return Err(e);
            }
            if let Some(h) = old {
                self.guard.delete(&h.chip_key);
            }
            return Ok(());
        }
        if !self.level_available(Level::Standard) {
            return Err(VaultError::Unavailable);
        }
        let name = random_name()?;
        self.guard.create(&name, ChipAuth::BiometricOrPin)?;
        let list_key = Zeroizing::new(random::<32>()?);
        let sealed = match self.guard.seal(&name, &list_key[..], LIST_AAD, prompt) {
            Ok(s) => s,
            Err(e) => {
                self.guard.delete(&name);
                return Err(e.into());
            }
        };
        self.hidden = Some(Hidden {
            chip_key: name.clone(),
            sealed_list_key: sealed,
            list_key: Some(list_key),
        });
        if let Err(e) = self.save() {
            self.hidden = None;
            self.guard.delete(&name);
            return Err(e);
        }
        Ok(())
    }
}

fn read_index(content: &[u8]) -> crate::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() && rest[0] != 0 {
        let (t, r) = der::read(rest)?;
        out.push(Entry::from_der(&t)?);
        rest = r;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A software stand-in for the chip: AES keys in memory, and switches for what the owner
    /// does at the prompt.
    #[derive(Default)]
    struct FakeChip {
        keys: Mutex<HashMap<String, ([u8; 32], ChipAuth)>>,
        prompts: Mutex<Vec<String>>,
        cancel: Mutex<bool>,
        no_screen_lock: bool,
    }

    impl Guard for &FakeChip {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                screen_lock: !self.no_screen_lock,
                biometric: !self.no_screen_lock,
                hardware: true,
            }
        }

        fn create(&self, name: &str, auth: ChipAuth) -> std::result::Result<Security, GuardError> {
            let k = random::<32>().unwrap();
            self.keys.lock().unwrap().insert(name.into(), (k, auth));
            Ok(Security::Chip)
        }

        fn seal(
            &self,
            name: &str,
            plain: &[u8],
            aad: &[u8],
            prompt: &Prompt,
        ) -> std::result::Result<Vec<u8>, GuardError> {
            let (k, auth) = *self
                .keys
                .lock()
                .unwrap()
                .get(name)
                .ok_or(GuardError::KeyReset)?;
            self.ask(auth, prompt)?;
            Ok(encrypt(&k, plain, aad).unwrap())
        }

        fn open(
            &self,
            name: &str,
            sealed: &[u8],
            aad: &[u8],
            prompt: &Prompt,
        ) -> std::result::Result<Zeroizing<Vec<u8>>, GuardError> {
            let (k, auth) = *self
                .keys
                .lock()
                .unwrap()
                .get(name)
                .ok_or(GuardError::KeyReset)?;
            self.ask(auth, prompt)?;
            decrypt(&k, sealed, aad).ok_or(GuardError::Failed("bad tag".into()))
        }

        fn delete(&self, name: &str) {
            self.keys.lock().unwrap().remove(name);
        }
    }

    impl FakeChip {
        fn ask(&self, auth: ChipAuth, prompt: &Prompt) -> std::result::Result<(), GuardError> {
            if auth == ChipAuth::None {
                return Ok(());
            }
            self.prompts.lock().unwrap().push(prompt.title.clone());
            if *self.cancel.lock().unwrap() {
                return Err(GuardError::Cancelled);
            }
            Ok(())
        }

        fn prompts(&self) -> usize {
            self.prompts.lock().unwrap().len()
        }

        fn key_count(&self) -> usize {
            self.keys.lock().unwrap().len()
        }
    }

    const FAST: Kdf = Kdf {
        memory: 8,
        passes: 1,
        lanes: 1,
    };

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/keys/{name}.p12",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn dir() -> tempdir::Dir {
        tempdir::Dir::new()
    }

    /// A throwaway folder.
    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                let mut b = [0u8; 8];
                crate::random(&mut b).unwrap();
                let p = std::env::temp_dir().join(format!("kzsigner-vault-{}", crate::hex(&b)));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn file(&self) -> std::path::PathBuf {
                self.0.join("keys.kzs")
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn err<T>(r: Result<T>) -> VaultError {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    fn prompt() -> Prompt {
        Prompt {
            title: "Sign".into(),
            ..Prompt::default()
        }
    }

    fn signs(k: &Key) {
        let s = k.private_key.sign(b"data").unwrap();
        let p = k.cert.public_key().unwrap();
        assert!(
            p.verify(
                k.private_key.sig_oid(),
                Some(k.private_key.digest_oid()),
                b"data",
                &s
            )
            .unwrap()
        );
    }

    #[test]
    fn standard_key_one_touch() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert_eq!(s.default_level(), Level::Standard);
        let id = s
            .add(&fixture("alice_gost2015"), "Qwerty12", None, &prompt())
            .unwrap();
        assert_eq!(chip.prompts(), 1);
        // read back from the file
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert_eq!(s.keys().len(), 1);
        assert_eq!(s.keys()[0].level, Level::Standard);
        let k = s.key(&id, None, &prompt()).unwrap();
        assert_eq!(chip.prompts(), 2);
        signs(&k);
        // the file does not hold the key in clear
        let file = std::fs::read(d.file()).unwrap();
        let (_, pkcs8) =
            p12::open_with_pkcs8(&fixture("alice_gost2015"), "Qwerty12", None).unwrap();
        assert!(!file.windows(pkcs8.len()).any(|w| w == pkcs8.as_slice()));
    }

    #[test]
    fn no_screen_lock_uses_the_p12_password() {
        let chip = FakeChip {
            no_screen_lock: true,
            ..FakeChip::default()
        };
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert_eq!(s.default_level(), Level::PasswordOnly);
        assert!(!s.level_available(Level::Standard));
        let id = s
            .add_with(
                &fixture("alice_rsa"),
                "Qwerty12",
                None,
                Level::PasswordOnly,
                Some("Qwerty12"),
                FAST,
                &prompt(),
            )
            .unwrap();
        assert_eq!(chip.prompts(), 0);
        assert_eq!(
            err(s.key(&id, Some("wrong"), &prompt())),
            VaultError::WrongPassword
        );
        signs(&s.key(&id, Some("Qwerty12"), &prompt()).unwrap());
        assert_eq!(
            s.add_with(
                &fixture("bob_rsa"),
                "Qwerty12",
                None,
                Level::Standard,
                None,
                FAST,
                &prompt()
            )
            .unwrap_err(),
            VaultError::Unavailable
        );
    }

    #[test]
    fn maximum_needs_touch_and_password_and_slows_guessing() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        let id = s
            .add_with(
                &fixture("alice_gost2015"),
                "Qwerty12",
                None,
                Level::Maximum,
                Some("long secret"),
                FAST,
                &prompt(),
            )
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                err(s.key(&id, Some("guess"), &prompt())),
                VaultError::WrongPassword
            );
        }
        // every guess needed a touch
        assert_eq!(chip.prompts(), 4);
        assert!(matches!(
            s.key(&id, Some("long secret"), &prompt()),
            Err(VaultError::Wait(1))
        ));
        // the count survives reopening
        let s2 = Store::open(&d.file(), &chip).unwrap();
        assert!(s2.wait(&id).unwrap() > 0);
        assert_eq!(chip.prompts(), 4);
    }

    #[test]
    fn waits_grow_to_five_minutes() {
        assert_eq!(
            (0..12).map(wait_after).collect::<Vec<_>>(),
            [0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 256]
        );
        assert_eq!(wait_after(12), 300);
        assert_eq!(wait_after(u32::MAX), 300);
    }

    #[test]
    fn cancel_changes_nothing() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        *chip.cancel.lock().unwrap() = true;
        assert_eq!(
            s.add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
                .unwrap_err(),
            VaultError::Cancelled
        );
        assert!(s.keys().is_empty());
        assert_eq!(chip.key_count(), 0);
        assert!(!d.file().exists());
    }

    #[test]
    fn wrong_p12_password_and_duplicates() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert!(matches!(
            s.add(&fixture("alice_rsa"), "nope", None, &prompt()),
            Err(VaultError::Failed(_))
        ));
        s.add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        assert_eq!(
            s.add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
                .unwrap_err(),
            VaultError::AlreadyAdded
        );
    }

    #[test]
    fn tampering_is_refused() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        let a = s
            .add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        let b = s
            .add(&fixture("bob_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        // Bob's record next to Alice's certificate
        let bob_sealed = s.entry(&b).unwrap().sealed.clone();
        s.entry_mut(&a).unwrap().sealed = bob_sealed;
        assert!(s.key(&a, None, &prompt()).is_err());
        // a flipped bit
        let mut s = Store::open(&d.file(), &chip).unwrap();
        s.entry_mut(&a).unwrap().sealed[20] ^= 1;
        assert!(s.key(&a, None, &prompt()).is_err());
        // a level lowered in the file
        let mut s = Store::open(&d.file(), &chip).unwrap();
        s.entry_mut(&a).unwrap().level = Level::Strict;
        assert!(s.key(&a, None, &prompt()).is_err());
        // a damaged file
        let mut f = std::fs::read(d.file()).unwrap();
        f.truncate(f.len() / 2);
        std::fs::write(d.file(), f).unwrap();
        assert!(Store::open(&d.file(), &chip).is_err());
    }

    #[test]
    fn reset_chip_key() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        let id = s
            .add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        (&chip).delete(&id);
        assert_eq!(err(s.key(&id, None, &prompt())), VaultError::KeyReset);
        s.remove(&id).unwrap();
        assert!(Store::open(&d.file(), &chip).unwrap().keys().is_empty());
    }

    #[test]
    fn change_level_and_password() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        let id = s
            .add(&fixture("alice_gost2015"), "Qwerty12", None, &prompt())
            .unwrap();
        s.change(&id, Level::Maximum, None, Some("new secret"), &prompt())
            .unwrap();
        assert_eq!(chip.key_count(), 1);
        let id = s.keys()[0].id.clone();
        assert_eq!(s.keys()[0].level, Level::Maximum);
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert_eq!(err(s.key(&id, None, &prompt())), VaultError::WrongPassword);
        signs(&s.key(&id, Some("new secret"), &prompt()).unwrap());
        s.change(&id, Level::Standard, Some("new secret"), None, &prompt())
            .unwrap();
        let id = s.keys()[0].id.clone();
        signs(&s.key(&id, None, &prompt()).unwrap());
    }

    #[test]
    fn hidden_list() {
        let chip = FakeChip::default();
        let d = dir();
        let mut s = Store::open(&d.file(), &chip).unwrap();
        s.add(&fixture("alice_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        s.set_hidden(true, &prompt()).unwrap();
        let one = std::fs::read(d.file()).unwrap();
        s.add(&fixture("bob_rsa"), "Qwerty12", None, &prompt())
            .unwrap();
        let two = std::fs::read(d.file()).unwrap();
        // same size for one and two keys; no certificate readable
        assert_eq!(one.len(), two.len());
        let cert = s.keys()[0].cert().der.clone();
        assert!(!two.windows(64).any(|w| w == &cert[100..164]));
        // starts locked
        let mut s = Store::open(&d.file(), &chip).unwrap();
        assert!(s.is_locked() && s.keys().is_empty());
        let before = chip.prompts();
        s.unlock(&prompt()).unwrap();
        assert_eq!(chip.prompts(), before + 1);
        assert_eq!(s.keys().len(), 2);
        let id = s.keys()[1].id.clone();
        signs(&s.key(&id, None, &prompt()).unwrap());
        s.lock();
        assert_eq!(err(s.key(&id, None, &prompt())), VaultError::Locked);
        // and off again
        s.unlock(&prompt()).unwrap();
        s.set_hidden(false, &prompt()).unwrap();
        let s = Store::open(&d.file(), &chip).unwrap();
        assert!(!s.is_locked() && s.keys().len() == 2);
        assert_eq!(chip.key_count(), 2);
    }
}
