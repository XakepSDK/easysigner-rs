use super::*;
use kzsigner::vault::SoftwareGuard;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/keys")
        .join(name);
    std::fs::read(p).unwrap()
}

/// A fresh folder for one test's vault file.
fn dir(test: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kzsigner-ffi-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The app's chip, played by the vault's in-memory test guard: what Kotlin does on a phone.
struct TestChip(Arc<SoftwareGuard>);

fn chip_error(e: GuardError) -> ChipError {
    match e {
        GuardError::Cancelled => ChipError::Cancelled,
        GuardError::KeyReset => ChipError::KeyReset,
        GuardError::Failed(detail) => ChipError::Failed { detail },
    }
}

impl Chip for TestChip {
    fn capabilities(&self) -> ChipCaps {
        let c = self.0.capabilities();
        ChipCaps {
            screen_lock: c.screen_lock,
            biometric: c.biometric,
            hardware: c.hardware,
        }
    }
    fn create(&self, name: String, unlock: ChipUnlock) -> Result<ChipSecurity, ChipError> {
        let auth = match unlock {
            ChipUnlock::None => ChipAuth::None,
            ChipUnlock::BiometricOrPin => ChipAuth::BiometricOrPin,
            ChipUnlock::BiometricOnly => ChipAuth::BiometricOnly,
        };
        self.0
            .create(&name, auth)
            .map(|_| ChipSecurity::Software)
            .map_err(chip_error)
    }
    fn seal(
        &self,
        name: String,
        plain: Vec<u8>,
        aad: Vec<u8>,
        prompt: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError> {
        self.0
            .seal(&name, &plain, &aad, &prompt.into())
            .map_err(chip_error)
    }
    fn open(
        &self,
        name: String,
        sealed: Vec<u8>,
        aad: Vec<u8>,
        prompt: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError> {
        self.0
            .open(&name, &sealed, &aad, &prompt.into())
            .map(|z| z.to_vec())
            .map_err(chip_error)
    }
    fn delete(&self, name: String) {
        self.0.delete(&name)
    }
    fn problem(&self) -> Option<String> {
        None
    }
}

/// The egui app's side of the same guard, to write a vault as it does.
struct Shared(Arc<SoftwareGuard>);

impl Guard for Shared {
    fn capabilities(&self) -> Capabilities {
        self.0.capabilities()
    }
    fn create(&self, name: &str, auth: ChipAuth) -> Result<Security, GuardError> {
        self.0.create(name, auth)
    }
    fn seal(&self, n: &str, p: &[u8], a: &[u8], pr: &Prompt) -> Result<Vec<u8>, GuardError> {
        self.0.seal(n, p, a, pr)
    }
    fn open(
        &self,
        n: &str,
        s: &[u8],
        a: &[u8],
        pr: &Prompt,
    ) -> Result<Zeroizing<Vec<u8>>, GuardError> {
        self.0.open(n, s, a, pr)
    }
    fn delete(&self, n: &str) {
        self.0.delete(n)
    }
}

fn prompt() -> ChipPrompt {
    ChipPrompt {
        title: "Add your key".into(),
        ..Default::default()
    }
}

fn vault(path: &Path, g: &Arc<SoftwareGuard>) -> Arc<Vault> {
    Vault::new(path.to_string_lossy().into(), Arc::new(TestChip(g.clone()))).unwrap()
}

#[test]
fn no_vault_file_means_no_keys() {
    let d = dir("none");
    let v = vault(&d.join("keys.kzs"), &Arc::default());
    assert_eq!(
        v.keys(),
        Keys {
            keys: vec![],
            hidden: false
        }
    );
}

#[test]
fn adds_lists_and_removes_a_key() {
    let d = dir("add");
    let path = d.join("keys.kzs");
    let g = Arc::new(SoftwareGuard::default());
    let v = vault(&path, &g);
    assert_eq!(v.new_key_unlock(), Unlock::FingerprintOrScreenLock);

    let id = v
        .add_key(fixture("alice_rsa.p12"), "Qwerty12".into(), prompt())
        .unwrap();
    // one prompt, with the app's text
    assert_eq!(g.prompts.lock().unwrap().len(), 1);
    assert_eq!(g.prompts.lock().unwrap()[0].title, "Add your key");

    // read back from the file by a new vault, as after a restart
    let k = vault(&path, &g).keys();
    assert!(!k.hidden);
    assert_eq!(k.keys.len(), 1);
    let k = &k.keys[0];
    assert_eq!(k.id, id);
    assert!(!k.name.is_empty());
    assert!(k.expires_ms > now());
    assert_eq!(k.unlock, Unlock::FingerprintOrScreenLock);
    assert_eq!(k.cant_sign, None);

    assert!(matches!(
        v.add_key(fixture("alice_rsa.p12"), "Qwerty12".into(), prompt()),
        Err(AddKeyError::AlreadyAdded)
    ));

    v.remove_key(id.clone()).unwrap();
    assert!(v.keys().keys.is_empty());
    assert!(vault(&path, &g).keys().keys.is_empty());
    assert_eq!(g.key_count(), 0, "the chip key goes too");
    assert!(matches!(v.remove_key(id), Err(CoreError::NoSuchKey)));
}

#[test]
fn says_why_a_key_was_not_added() {
    let d = dir("why");
    let g = Arc::new(SoftwareGuard::default());
    let v = vault(&d.join("keys.kzs"), &g);
    let add = |file: Vec<u8>, pw: &str| v.add_key(file, pw.into(), prompt()).unwrap_err();

    assert!(matches!(
        add(fixture("alice_rsa.p12"), "Йцукен12"),
        AddKeyError::WrongPassword
    ));
    assert!(matches!(
        add(b"%PDF-1.7".to_vec(), "Qwerty12"),
        AddKeyError::NotAKey
    ));
    assert!(matches!(
        add(fixture("alice_gost2004.p12"), "Qwerty12"),
        AddKeyError::KeyCantSign {
            reason: CantSign::Gost2004,
            ..
        }
    ));
    // none of these asked for the fingerprint, or left anything behind
    assert!(g.prompts.lock().unwrap().is_empty());
    assert_eq!(g.key_count(), 0);

    g.cancel.store(true, Ordering::SeqCst);
    assert!(matches!(
        add(fixture("alice_rsa.p12"), "Qwerty12"),
        AddKeyError::Cancelled
    ));
    assert!(v.keys().keys.is_empty());
    assert_eq!(g.key_count(), 0);
}

#[test]
fn a_phone_without_screen_lock_uses_the_password() {
    let d = dir("nolock");
    let mut sg = SoftwareGuard::default();
    sg.no_screen_lock = true;
    let g = Arc::new(sg);
    let v = vault(&d.join("keys.kzs"), &g);
    assert_eq!(v.new_key_unlock(), Unlock::Password);
    v.add_key(fixture("alice_rsa.p12"), "Qwerty12".into(), prompt())
        .unwrap();
    assert_eq!(v.keys().keys[0].unlock, Unlock::Password);
    assert!(g.prompts.lock().unwrap().is_empty(), "no prompt to show");
}

#[test]
fn expired_and_future_keys_cant_sign() {
    let key = kzsigner::p12::open(&fixture("alice_rsa.p12"), "Qwerty12", None).unwrap();
    let c = &key.cert;
    assert_eq!(cant_sign(c, c.not_before + 1), None);
    assert_eq!(cant_sign(c, c.not_after + 1), Some(CantSign::Expired));
    assert_eq!(cant_sign(c, c.not_before - 1), Some(CantSign::NotYetValid));
}

/// A vault the egui app wrote (same file, same chip) reads and works here: the switch to the
/// Compose app keeps the keys.
#[test]
fn reads_the_egui_apps_vault() {
    let d = dir("egui");
    let path = d.join("keys.kzs");
    let g = Arc::new(SoftwareGuard::default());
    let mut egui = Store::open(&path, Shared(g.clone())).unwrap();
    let id = egui
        .add(
            &fixture("alice_rsa.p12"),
            "Qwerty12",
            None,
            &Prompt::default(),
        )
        .unwrap();
    // and a hidden list, which only the egui app can turn on
    egui.set_hidden(true, &Prompt::default()).unwrap();
    drop(egui);

    let v = vault(&path, &g);
    let k = v.keys();
    assert!(k.hidden);
    assert!(k.keys.is_empty());
    let k = v.unlock(prompt()).unwrap();
    assert!(!k.hidden);
    assert_eq!(k.keys.len(), 1);
    assert_eq!(k.keys[0].id, id);

    // the key itself opens through the app's chip
    let mut s = Store::open(&path, ChipGuard(Arc::new(TestChip(g.clone())))).unwrap();
    s.unlock(&Prompt::default()).unwrap();
    let key = s.key(&id, None, &Prompt::default()).unwrap();
    assert_eq!(key.alias, "alice");
}

mod check;
mod sign;
