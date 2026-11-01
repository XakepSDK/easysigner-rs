# Key safety plan (stashed, not implemented)

Goal: people who don't understand keys, pick weak passwords and share their .p12 files
should still end up safe by default.

## Problems seen
- The .p12 password is typed on every signature and is usually weak.
- The .p12 file is copied around (Downloads, USB sticks, chats) and shared with others.
- People don't know what to do when a key may be stolen.

## Options discussed
1. Keep the key unlocked only while kzsigner is open (no storage).
2. "Remember on this computer", opt-in:
   - Windows: Windows Hello (`KeyCredentialManager`). A TPM-held key signs a fixed challenge
     plus a salt; HKDF of the signature gives an AES-256-GCM key that encrypts the secret, and
     the encrypted blob lives in `%APPDATA%\kzsigner`. A Hello prompt (face, fingerprint or PIN)
     is shown for each use. Works with local accounts; a Hello PIN must be set up. Resetting the
     PIN loses the secret. Check on setup that the signature is deterministic (as KeePassXC
     does); refuse to save otherwise. Fallback when Hello is missing: Credential Manager (DPAPI).
   - Linux: Secret Service (GNOME Keyring or KWallet) through the `keyring` crate. There is no
     Hello equivalent (fprintd only gates; TPM2 is possible but fiddly).
3. Import the key into kzsigner (the user's idea of "fully owning" the certificate):
   - Re-encrypt the key with a random 256-bit secret nobody sees, which Hello or the keyring
     protects. Store the encrypted key in kzsigner's folder, NOT in Credential Manager: it hands
     its contents to any program running as the same user without a prompt, and caps a blob at
     about 2.5 KB.
   - Offer to delete the original weak-password .p12 file.
   - Warn that losing the PC or resetting Hello loses the key; NCA reissue is free on egov.kz.
   - "Export a copy" with a new password, for NCALayer and the eGov portal.
4. "My key may be stolen" button: forget the stored key, then open NCA's revocation (pki.gov.kz
   personal account, or a ЦОН office) with instructions. Only NCA can revoke; there is no
   public API, so do not script their site. Check the current NCA flow before building.
5. Later: passkey PRF unlock from a phone (see /mnt/project-files/notes/signing-research.md);
   PKCS#11 tokens (Kaztoken, ID card).

## Limits on every option
- Windows and Linux can't enforce "only kzsigner may use the key": malware running as the same
  user can read the unlocked key from memory. Hello only stops silent use.
- No GOST key can be held in hardware, on any platform; hardware only guards an unlock secret.
