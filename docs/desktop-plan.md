# Desktop app on the simple design: plan

The phone app's simple flow (compose-plan.md, the design's 24 screens and rules note) brought
to the desktop window. Still egui, on Windows, Linux and macOS, over the same core. The
command line (`kzsigner sign`, `verify`, ...) keeps all its options; only the window changes.

Status: proposed, waiting for review. Nothing here is built yet.

## What the desktop window is today

- Start screen: Sign or Check. Sign is one long form: the document, the key file and its
  password (an alias picker for multi-key files), and options: detached .cms, timestamp,
  long-term (B-LTA), visible stamp, sign as .cms / PDF / document card / XML, card QR and
  language. Then a Signed screen, and a Check screen with a report.
- Keys are not kept: the .p12 is chosen and its password typed for every signature. The
  window's "kept key" code (`with_key_store`) was for the removed egui phone build; only a
  test uses it now.
- Text: `tr("English")` with Kazakh and Russian in `src/i18n.rs`, separate from the phone's
  strings, so the two apps word things differently.
- Tests: `tests/gui.rs` drives the window with egui_kittest (sign, check, cards, a kept key).

## Goal

The same app as on the phone, laid out for a window:

- **Home**: "Sign a document" and "Check a signature", the key chip ("Add key" / "Your
  keys"), and the share hint replaced by "or drop a file here". A file dropped or opened
  with kzsigner goes where the phone sends a shared file (a key to Add key, a document to
  Sign, a signed file to Sign with "Add your signature?", a detached .cms to Check).
- **Add key, once**; **Your keys** (remove, language, About). Same refusals before any
  prompt: not recognized in Kazakhstan, GOST 2004, expired, not yet valid.
- **Sign**: document card with "Read it" (the system's viewer; never a gate), who signs,
  what signing makes (output by input: PDF inside with the Who signed page, XML inside,
  .cms joined, anything else a new .cms), and one Sign button. NCA checks the key first:
  revoked / not recognized screens, "No internet" vs "Can't reach NCA" with Try again.
- **Signed**: where the file is, "Show in folder", Done.
- **Check**: the same verdicts, reasons, next steps and Signature details (plain revocation
  words) as the phone; a detached .cms asks for its document.
- No options anywhere in the window. Detached .cms, document cards, levels and stamp
  placement stay in the command line. Existing cards and detached files are still checked.

## Shape

- **One app layer for both apps.** The phone's behaviour lives in the `ffi` crate today
  (`inspect`, `check_file`, `Vault::add_key` / `sign` with `Nca`, `Checked` with reason
  codes). Move it into the core as `kzsigner::app`; `ffi` becomes the UniFFI wrapper over it,
  and the window calls it directly. One place decides what a file is, what signing makes,
  and what a check says, so the two apps can't drift. ffi's tests move with it.
- **Its own words.** The window keeps its own text table (`src/i18n.rs`, Kazakh and
  Russian next to the English), rewritten to say what the phone says, in the window's terms
  ("this computer", "Show in folder"). No build link to the Android string files; the
  native-speaker check reads both.
- **Layout**: one centred column (about 560 px wide) in a resizable window, the phone's
  hierarchy and spacing; keyboard first (Tab order, Enter on the main button, Esc for Back).

## Keys on a computer

The phone keeps the key in its vault behind the fingerprint or screen lock, so a signature is
one touch. The computer equivalent, per system:

| System | Unlock | Notes |
|---|---|---|
| Windows 10/11 | Windows Hello (fingerprint, face or Hello PIN), key in the TPM | `windows` crate, Microsoft Passport key storage provider; falls back to the key's password without Hello |
| macOS | Touch ID or the login password, key in the Keychain / Secure Enclave | needs the app signed with an Apple Developer ID (entitlements); until then the key's password |
| Linux | the key's password each time | no common OS prompt to rely on (polkit, Secret Service and TPM vary by distro) |

The vault file goes in the user's app data folder (`%APPDATA%\kzsigner`, `~/Library/Application
Support/kzsigner`, `~/.local/share/kzsigner`). The password path is the phone's "no screen
lock" path (one action: type the password, Sign). It ships first on every system; Windows
Hello and Touch ID come in their own phase.

## Files

- In: drag and drop onto the window (exists), "Open with kzsigner" / double click (the path
  argument, exists), the file chooser on Home.
- Out: the signed file is saved next to the original under the phone's name (`X-signed.pdf`,
  `X.cms`, `X-signed.xml`), never over an existing file (`X-signed (2).pdf`); when that
  folder can't be written, the save dialog opens. Signed shows the path, "Show in folder"
  and "Save a copy elsewhere".

## Tests

- Core: existing tests; ffi's tests move to `kzsigner::app`.
- Window: egui_kittest walks every flow against the fake NCA servers in-process (as the ffi
  tests do), the same list as the emulator's AppFlows: Home without a key, add (wrong
  password, Russian keyboard hint, GOST 2004, not recognized), sign PDF / text / XML, join a
  .cms and a signed PDF, detached refused, revoked refused, NCA down then Try again; check
  not signed, valid, revoked, kept answer, changed, not recognized, detached alone / with its
  document / with another; remove a key; language; About; text at 200 %.
- Each screen's accessibility tree checked (every control named, keyboard reachable), and a
  screenshot per screen (kittest's wgpu snapshot) on Linux CI for review.
- CI runs them on Windows and Linux (and macOS, if built).

## Phases

1. **App layer**: `kzsigner::app` from ffi; ffi wraps it; all tests green, no visible change.
2. **Words and layout**: the window's texts rewritten, the centred column, Home, Add key,
   Your keys (language, About), the vault in the app data folder with the password unlock.
3. **Sign**: Sign, Signed, the NCA screens, save next to the original; the old Sign form and
   its options removed from the window.
4. **Check**: the phone's verdict screens and details; the old report view removed.
5. **OS unlock**: Windows Hello; Touch ID once there is a signing identity for macOS.
6. **Finish**: accessibility pass (NVDA, Narrator, Orca, VoiceOver where possible, 200 %),
   every flow in kittest with screenshots, docs, a check on a real Windows PC and Linux.

## Decisions for the person

1. **Keep keys on the computer** (recommended, as on the phone) or keep choosing the .p12
   and typing its password for each signature (as NCALayer does)?
2. **Where the signed file goes**: next to the original automatically (recommended, one
   action) or a save dialog each time?
3. **macOS**: build it now (unsigned: macOS warns on first open, and Touch ID waits for an
   Apple Developer ID, $99 a year) or later? Today CI builds Windows and Linux only.

## Self-review

- Risk: moving ffi's logic into the core touches the phone app; phase 1 changes no
  behaviour and the emulator tests guard it.
- Two text tables (phone, window) can drift; each new screen updates both, and the
  native-speaker check covers both.
- No users yet, so the window's options (cards, detached .cms, levels, stamp) go without a
  migration; the command line keeps them, and checking such files stays in the window.
- Not covered: hardware tokens (Kaztoken, eToken) that NCALayer supports; kzsigner doesn't
  read them today. Worth a separate look if people ask.
