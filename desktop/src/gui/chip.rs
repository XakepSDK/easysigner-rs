//! The computer's stand-in for the phone's key chip: AES-256 keys in files in the app's data
//! folder, readable only by this user, with no prompt. The keys added on a computer are
//! kept under their own password (the vault's inner Argon2id layer), so these files only tie
//! the vault to this account; Windows Hello and Touch ID come later (docs/desktop-plan.md).

use std::path::PathBuf;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use kzsigner_ffi::{Chip, ChipCaps, ChipError, ChipPrompt, ChipSecurity, ChipUnlock};
use zeroize::Zeroizing;

pub struct FileChip {
    dir: PathBuf,
}

impl FileChip {
    /// Keys in `dir` (made when the first key is).
    pub fn new(dir: PathBuf) -> FileChip {
        FileChip { dir }
    }

    fn path(&self, name: &str) -> Result<PathBuf, ChipError> {
        // the vault names its keys itself (random hex); anything else is refused
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ChipError::Failed {
                detail: format!("bad key name {name:?}"),
            });
        }
        Ok(self.dir.join(name))
    }

    fn key(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, ChipError> {
        let k = Zeroizing::new(std::fs::read(self.path(name)?).map_err(|_| ChipError::KeyReset)?);
        if k.len() != 32 {
            return Err(ChipError::KeyReset);
        }
        Ok(k)
    }
}

fn failed(e: impl std::fmt::Display) -> ChipError {
    ChipError::Failed {
        detail: e.to_string(),
    }
}

/// Creates `path` readable and writable by this user only.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    use std::io::Write;
    o.open(path)?.write_all(data)
}

impl Chip for FileChip {
    fn capabilities(&self) -> ChipCaps {
        // no screen lock to rely on: keys are kept under their password
        ChipCaps {
            screen_lock: false,
            biometric: false,
            hardware: false,
        }
    }

    fn create(&self, name: String, _unlock: ChipUnlock) -> Result<ChipSecurity, ChipError> {
        let mut k = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut k[..]).map_err(failed)?;
        write_private(&self.path(&name)?, &k[..]).map_err(failed)?;
        Ok(ChipSecurity::Software)
    }

    fn seal(
        &self,
        name: String,
        plain: Vec<u8>,
        aad: Vec<u8>,
        _: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError> {
        let plain = Zeroizing::new(plain);
        let k = self.key(&name)?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(failed)?;
        let c = Aes256Gcm::new_from_slice(&k)
            .map_err(failed)?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(failed)?;
        let mut out = nonce.to_vec();
        out.extend(c);
        Ok(out)
    }

    fn open(
        &self,
        name: String,
        sealed: Vec<u8>,
        aad: Vec<u8>,
        _: ChipPrompt,
    ) -> Result<Vec<u8>, ChipError> {
        let k = self.key(&name)?;
        if sealed.len() < 12 {
            return Err(failed("too short"));
        }
        let (nonce, c) = sealed.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().map_err(failed)?;
        Aes256Gcm::new_from_slice(&k)
            .map_err(failed)?
            .decrypt(&Nonce::from(nonce), Payload { msg: c, aad: &aad })
            .map_err(|_| failed("the key file doesn't open this record"))
    }

    fn delete(&self, name: String) {
        if let Ok(p) = self.path(&name) {
            let _ = std::fs::remove_file(p);
        }
    }

    fn problem(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_only_with_its_key_and_data() {
        let d = std::env::temp_dir().join(format!("kzsigner-chip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let c = FileChip::new(d.clone());
        c.create("k1".into(), ChipUnlock::None).unwrap();
        let s = c
            .seal(
                "k1".into(),
                b"secret".to_vec(),
                b"aad".to_vec(),
                ChipPrompt::default(),
            )
            .unwrap();
        assert_eq!(
            c.open(
                "k1".into(),
                s.clone(),
                b"aad".to_vec(),
                ChipPrompt::default()
            )
            .unwrap(),
            b"secret"
        );
        assert!(
            c.open(
                "k1".into(),
                s.clone(),
                b"other".to_vec(),
                ChipPrompt::default()
            )
            .is_err()
        );
        assert!(c.create("../x".into(), ChipUnlock::None).is_err());
        c.delete("k1".into());
        assert!(matches!(
            c.open("k1".into(), s, b"aad".to_vec(), ChipPrompt::default()),
            Err(ChipError::KeyReset)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
