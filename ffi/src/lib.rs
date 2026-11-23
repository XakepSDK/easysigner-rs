//! The core's calls for the Kotlin app. The core returns facts and codes; the app picks the
//! words (docs/compose-plan.md).
//!
//! The phone's key chip is the app's: [`Chip`] is implemented in Kotlin (Android Keystore and
//! the system's fingerprint/PIN prompt) and called from here, as the egui app's KeyGuard.java
//! is through `src/android.rs`. Its calls block until the owner answers the prompt, so the
//! app calls [`Vault`] off the main thread.

use std::path::Path;
use std::sync::{Arc, Mutex};

use kzsigner::cert::{self, Cert, get, rdns};
use kzsigner::vault::{
    Capabilities, ChipAuth, Guard, GuardError, Level, Prompt, Security, Store, VaultError,
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

mod check;
mod sign;
pub use check::*;
pub use sign::*;

/// Why a call failed.
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// The key vault file can't be read or written.
    VaultFile {
        detail: String,
    },
    /// The owner closed the fingerprint/PIN prompt; nothing changed.
    Cancelled,
    /// The phone reset this key's protection (screen lock removed, a fingerprint added): the
    /// key file has to be added again.
    KeyReset,
    NoSuchKey,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::VaultFile { detail } => write!(f, "key vault: {detail}"),
            CoreError::Cancelled => f.write_str("cancelled"),
            CoreError::KeyReset => f.write_str("the key's protection was reset"),
            CoreError::NoSuchKey => f.write_str("no such key"),
        }
    }
}

impl From<VaultError> for CoreError {
    fn from(e: VaultError) -> CoreError {
        match e {
            VaultError::Cancelled => CoreError::Cancelled,
            VaultError::KeyReset => CoreError::KeyReset,
            VaultError::NoSuchKey => CoreError::NoSuchKey,
            e => CoreError::VaultFile {
                detail: e.to_string(),
            },
        }
    }
}

/// Why a key file was not added.
#[derive(Debug, uniffi::Error)]
pub enum AddKeyError {
    /// The password doesn't open this key file.
    WrongPassword,
    /// The file is not a signature key (.p12) the app can read.
    NotAKey,
    /// The key opens but can't sign documents.
    KeyCantSign {
        reason: CantSign,
        /// The certificate's validity (milliseconds since 1970, UTC), for the dates on screen.
        valid_from_ms: i64,
        expires_ms: i64,
    },
    /// This key is already on the phone.
    AlreadyAdded,
    /// The owner closed the fingerprint/PIN prompt; nothing was added.
    Cancelled,
    Failed {
        detail: String,
    },
}

impl std::fmt::Display for AddKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Why a key can't sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CantSign {
    /// Its certificate has expired (see [`KeyInfo::expires_ms`]).
    Expired,
    /// Its certificate is not valid yet.
    NotYetValid,
    /// A GOST 2004 key: NCA no longer gives its signatures a signing time.
    Gost2004,
    /// NCA says it was revoked (found when signing).
    Revoked,
    /// Not a key from NCA (Kazakhstan's certification authority), or NCA doesn't know it
    /// (found when signing).
    NotRecognized,
}

/// What opens a saved key each time it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Unlock {
    /// The fingerprint (or face), or the screen lock: the app words it after what the phone
    /// has set up.
    FingerprintOrScreenLock,
    /// The fingerprint (or face) only.
    Fingerprint,
    /// The key's password: the phone has no screen lock (or no key chip).
    Password,
    /// Fingerprint, then the password.
    FingerprintAndPassword,
}

impl From<Level> for Unlock {
    fn from(l: Level) -> Unlock {
        match l {
            Level::PasswordOnly => Unlock::Password,
            Level::Standard => Unlock::FingerprintOrScreenLock,
            Level::Strict => Unlock::Fingerprint,
            Level::Maximum => Unlock::FingerprintAndPassword,
        }
    }
}

/// One saved key, as the key lists show it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyInfo {
    pub id: String,
    /// The holder's name.
    pub name: String,
    pub iin: Option<String>,
    /// The organization, for a company key.
    pub company: Option<String>,
    pub bin: Option<String>,
    /// When the certificate expires (milliseconds since 1970, UTC).
    pub expires_ms: i64,
    pub unlock: Unlock,
    /// Why it can't sign, as far as the phone can tell without asking NCA (revocation is
    /// checked when signing).
    pub cant_sign: Option<CantSign>,
}

/// The saved keys.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Keys {
    pub keys: Vec<KeyInfo>,
    /// The list itself is locked (turned on in the egui app): [`Vault::unlock`] shows it.
    pub hidden: bool,
}

/// The texts of the system's fingerprint/PIN prompt, in the app's language.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct ChipPrompt {
    pub title: String,
    pub subtitle: String,
    pub detail: String,
}

impl From<&Prompt> for ChipPrompt {
    fn from(p: &Prompt) -> ChipPrompt {
        ChipPrompt {
            title: p.title.clone(),
            subtitle: p.subtitle.clone(),
            detail: p.detail.clone(),
        }
    }
}

impl From<ChipPrompt> for Prompt {
    fn from(p: ChipPrompt) -> Prompt {
        Prompt {
            title: p.title,
            subtitle: p.subtitle,
            detail: p.detail,
        }
    }
}

/// What the phone offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ChipCaps {
    /// A screen lock (PIN, pattern or password) is set.
    pub screen_lock: bool,
    /// A fingerprint or face is enrolled.
    pub biometric: bool,
    /// Keys can live in hardware.
    pub hardware: bool,
}

/// How the owner unlocks a chip key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChipUnlock {
    None,
    BiometricOrPin,
    BiometricOnly,
}

/// Where a chip key ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ChipSecurity {
    /// A separate security chip (StrongBox).
    Chip,
    /// The processor's protected area (TEE).
    Protected,
    Software,
}

#[derive(Debug, uniffi::Error)]
pub enum ChipError {
    /// The owner closed the prompt.
    Cancelled,
    /// The chip key is gone for good.
    KeyReset,
    Failed {
        detail: String,
    },
}

impl std::fmt::Display for ChipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ChipError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> ChipError {
        ChipError::Failed { detail: e.reason }
    }
}

/// The phone's key chip, implemented by the app: AES-256-GCM keys that never leave it, each
/// use behind the system prompt when the key asks for one. The layouts are the egui app's
/// (KeyGuard.java), so a vault moves between the two: `seal` returns the 12-byte nonce, then
/// the ciphertext and tag; `open` takes the same.
#[uniffi::export(with_foreign)]
pub trait Chip: Send + Sync {
    fn capabilities(&self) -> ChipCaps;
    /// Makes key `name`, unlocked as `unlock` says.
    fn create(&self, name: String, unlock: ChipUnlock) -> Result<ChipSecurity, ChipError>;
    fn seal(
        &self,
        name: String,
        plain: Vec<u8>,
        aad: Vec<u8>,
        prompt: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError>;
    fn open(
        &self,
        name: String,
        sealed: Vec<u8>,
        aad: Vec<u8>,
        prompt: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError>;
    /// Removes key `name`; nothing happens if there is none.
    fn delete(&self, name: String);
    /// Why keys can't live in hardware, when they can't.
    fn problem(&self) -> Option<String>;
}

/// The vault's [`Guard`] over the app's [`Chip`].
struct ChipGuard(Arc<dyn Chip>);

fn guard_error(e: ChipError) -> GuardError {
    match e {
        ChipError::Cancelled => GuardError::Cancelled,
        ChipError::KeyReset => GuardError::KeyReset,
        ChipError::Failed { detail } => GuardError::Failed(detail),
    }
}

impl Guard for ChipGuard {
    fn capabilities(&self) -> Capabilities {
        let c = self.0.capabilities();
        Capabilities {
            screen_lock: c.screen_lock,
            biometric: c.biometric,
            hardware: c.hardware,
        }
    }

    fn create(&self, name: &str, auth: ChipAuth) -> Result<Security, GuardError> {
        let unlock = match auth {
            ChipAuth::None => ChipUnlock::None,
            ChipAuth::BiometricOrPin => ChipUnlock::BiometricOrPin,
            ChipAuth::BiometricOnly => ChipUnlock::BiometricOnly,
        };
        Ok(
            match self.0.create(name.into(), unlock).map_err(guard_error)? {
                ChipSecurity::Chip => Security::Chip,
                ChipSecurity::Protected => Security::Protected,
                ChipSecurity::Software => Security::Software,
            },
        )
    }

    fn seal(
        &self,
        name: &str,
        plain: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> Result<Vec<u8>, GuardError> {
        self.0
            .seal(name.into(), plain.to_vec(), aad.to_vec(), prompt.into())
            .map_err(guard_error)
    }

    fn open(
        &self,
        name: &str,
        sealed: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> Result<Zeroizing<Vec<u8>>, GuardError> {
        self.0
            .open(name.into(), sealed.to_vec(), aad.to_vec(), prompt.into())
            .map(Zeroizing::new)
            .map_err(guard_error)
    }

    fn delete(&self, name: &str) {
        self.0.delete(name.into())
    }

    fn problem(&self) -> Option<String> {
        self.0.problem()
    }
}

/// The core's version.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The saved keys: the vault file (`files/keys.kzs`, as in the egui app) and the phone's chip.
#[derive(uniffi::Object)]
pub struct Vault {
    store: Mutex<Store<ChipGuard>>,
}

impl Vault {
    fn store(&self) -> std::sync::MutexGuard<'_, Store<ChipGuard>> {
        // a panic while holding it leaves nothing half-written on disk (save writes a new file)
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[uniffi::export]
impl Vault {
    /// Reads the vault file at `path` (none yet: no keys). Reading never shows a prompt.
    #[uniffi::constructor]
    pub fn new(path: String, chip: Arc<dyn Chip>) -> Result<Arc<Vault>, CoreError> {
        let store = Store::open(Path::new(&path), ChipGuard(chip))?;
        Ok(Arc::new(Vault {
            store: Mutex::new(store),
        }))
    }

    pub fn keys(&self) -> Keys {
        keys(&self.store(), now())
    }

    /// What will open a key added now: the screen lock when the phone has one, else the
    /// key's own password.
    pub fn new_key_unlock(&self) -> Unlock {
        self.store().default_level().into()
    }

    /// Shows a hidden list (one prompt).
    pub fn unlock(&self, prompt: ChipPrompt) -> Result<Keys, CoreError> {
        let mut s = self.store();
        s.unlock(&prompt.into())?;
        Ok(keys(&s, now()))
    }

    /// Adds the key in `p12` (a .p12 file from NCA or egov.kz) with its password. With a
    /// screen lock, the chip seals it (one prompt) and the password is never kept; without
    /// one, the key's own password guards it. Returns the new key's id.
    pub fn add_key(
        &self,
        nca: Arc<crate::sign::Nca>,
        p12: Vec<u8>,
        password: String,
        prompt: ChipPrompt,
    ) -> Result<String, AddKeyError> {
        let p12 = Zeroizing::new(p12);
        let password = Zeroizing::new(password);
        // checked before the prompt: a key that can't sign is not worth one
        match kzsigner::p12::open(&p12, &password, None) {
            Ok(key) => {
                // expired, GOST 2004, or not from NCA or another CA recognized in Kazakhstan
                // (offline: whether NCA revoked it is asked when signing)
                if let Some(reason) =
                    cant_sign(&key.cert, now()).or_else(|| nca.unrecognized(&key.cert))
                {
                    return Err(AddKeyError::KeyCantSign {
                        reason,
                        valid_from_ms: key.cert.not_before,
                        expires_ms: key.cert.not_after,
                    });
                }
            }
            Err(_) => {
                return Err(match kzsigner::p12::problem(&p12, &password) {
                    Some(kzsigner::p12::Problem::WrongPassword) => AddKeyError::WrongPassword,
                    _ => AddKeyError::NotAKey,
                });
            }
        }
        self.store()
            .add(&p12, &password, None, &prompt.into())
            .map_err(|e| match e {
                VaultError::AlreadyAdded => AddKeyError::AlreadyAdded,
                VaultError::Cancelled => AddKeyError::Cancelled,
                VaultError::WrongPassword => AddKeyError::WrongPassword,
                e => AddKeyError::Failed {
                    detail: e.to_string(),
                },
            })
    }

    /// Removes key `id` from the phone: its record and its chip key. The key file and the
    /// certificate are untouched.
    pub fn remove_key(&self, id: String) -> Result<(), CoreError> {
        Ok(self.store().remove(&id)?)
    }
}

fn now() -> i64 {
    kzsigner::time::now_ms()
}

fn keys<G: Guard>(store: &Store<G>, now: i64) -> Keys {
    Keys {
        keys: store
            .keys()
            .iter()
            .map(|e| {
                let mut k = info(&e.id, e.cert(), now);
                k.unlock = e.level.into();
                k
            })
            .collect(),
        hidden: store.is_hidden() && store.is_locked(),
    }
}

/// Why `c` can't sign at `now` (milliseconds, as the certificate's times), as far as the
/// phone alone can tell.
fn cant_sign(c: &Cert, now: i64) -> Option<CantSign> {
    if c.key_alg() == kzsigner::gost::KEY_GOST2004 {
        Some(CantSign::Gost2004)
    } else if c.not_after < now {
        Some(CantSign::Expired)
    } else if c.not_before > now {
        Some(CantSign::NotYetValid)
    } else {
        None
    }
}

fn info(id: &str, c: &Cert, now: i64) -> KeyInfo {
    let mut sr = kzsigner::report::SignerReport::default();
    cert::describe(&mut sr, c);
    let subject = rdns(&c.subject);
    KeyInfo {
        id: id.to_string(),
        name: sr.name(),
        iin: get(&sr.subject, "IIN").map(str::to_string),
        company: get(&subject, "O").map(str::to_string),
        bin: get(&sr.subject, "BIN").map(str::to_string),
        expires_ms: c.not_after,
        unlock: Unlock::FingerprintOrScreenLock,
        cant_sign: cant_sign(c, now),
    }
}

#[cfg(test)]
mod tests;
