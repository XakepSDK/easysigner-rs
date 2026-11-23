//! The core's calls for the Kotlin app. The core returns facts and codes; the app picks the
//! words (docs/compose-plan.md).

use std::path::Path;

use kzsigner::cert::{self, get, rdns};
use kzsigner::vault::{Guard, SoftwareGuard, Store};

uniffi::setup_scaffolding!();

/// Why a call failed.
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// The key vault file can't be read.
    Vault { detail: String },
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Vault { detail } => write!(f, "key vault: {detail}"),
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
    /// When the certificate expires (Unix seconds).
    pub expires: i64,
}

/// The saved keys.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Keys {
    pub keys: Vec<KeyInfo>,
    /// The list itself is locked: unlocking it needs the device's prompt (phase 2).
    pub hidden: bool,
}

/// The core's version.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The keys in the vault file at `vault_path` (`files/keys.kzs`). Reading the list never
/// asks the device's key chip, unless the list is hidden; then it comes back empty with
/// `hidden` set.
#[uniffi::export]
pub fn list_keys(vault_path: String) -> Result<Keys, CoreError> {
    // Listing never touches the chip, so a guard without one does here; the Kotlin guard
    // (BiometricPrompt) replaces it once keys are added and used from the app.
    keys_with(Path::new(&vault_path), SoftwareGuard::default())
}

fn keys_with<G: Guard>(path: &Path, guard: G) -> Result<Keys, CoreError> {
    let store = Store::open(path, guard).map_err(|e| CoreError::Vault {
        detail: e.to_string(),
    })?;
    Ok(Keys {
        keys: store.keys().iter().map(|e| info(&e.id, e.cert())).collect(),
        hidden: store.is_hidden(),
    })
}

fn info(id: &str, c: &cert::Cert) -> KeyInfo {
    let mut sr = kzsigner::report::SignerReport::default();
    cert::describe(&mut sr, c);
    let subject = rdns(&c.subject);
    KeyInfo {
        id: id.to_string(),
        name: sr.name(),
        iin: get(&sr.subject, "IIN").map(str::to_string),
        company: get(&subject, "O").map(str::to_string),
        bin: get(&sr.subject, "BIN").map(str::to_string),
        expires: c.not_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kzsigner::vault::Prompt;

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/keys")
            .join(name);
        std::fs::read(p).unwrap()
    }

    #[test]
    fn no_vault_file_means_no_keys() {
        let dir = std::env::temp_dir().join(format!("kzsigner-ffi-{}", std::process::id()));
        let k = list_keys(dir.join("none.kzs").to_string_lossy().into()).unwrap();
        assert_eq!(
            k,
            Keys {
                keys: vec![],
                hidden: false
            }
        );
    }

    #[test]
    fn lists_a_saved_key() {
        let dir = std::env::temp_dir().join(format!("kzsigner-ffi-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.kzs");
        let mut store = Store::open(&path, SoftwareGuard::default()).unwrap();
        let id = store
            .add(
                &fixture("alice_rsa.p12"),
                "Qwerty12",
                None,
                &Prompt::default(),
            )
            .unwrap();
        drop(store);
        let k = keys_with(&path, SoftwareGuard::default()).unwrap();
        assert!(!k.hidden);
        assert_eq!(k.keys.len(), 1);
        assert_eq!(k.keys[0].id, id);
        assert!(!k.keys[0].name.is_empty());
        assert!(k.keys[0].expires > 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
