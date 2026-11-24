# Desktop app on the simple design: plan

The phone app's simple flow (compose-plan.md, the design's 24 screens and rules note) brought
to the desktop window. Still egui, on Windows, Linux and macOS, over the same core. The
command line (`kzsigner sign`, `verify`, ...) keeps all its options; only the window changes.

Status: reviewed 2026-11-24 (decisions below). Phase 1 done; the desktop screens are
proposed for review before phase 2.

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
- Tests: `desktop/tests/gui.rs` drives the window with egui_kittest (sign, check, cards, a kept key).

## Goal

The phone's rules (one Sign action, output by input, no options, the same refusals,
verdicts and reasons), with screens made for a window: they may differ from the phone's
wherever that makes the desktop easier to use (the person's call, 2026-11-24). The screens
below are the starting point; the desktop design is reviewed before phase 2.

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

- **One app layer for both apps.** The phone's behaviour lives in the `ffi` crate
  (`inspect`, `check_file`, `Vault::add_key` / `sign` with `Nca`, `Checked` with reason
  codes). It is also a plain Rust library, so the window calls it directly (the UniFFI
  attributes cost nothing there). One place decides what a file is, what signing makes and
  what a check says. For that the window and command line moved out of the core into their
  own crate, `desktop/` (the core can't depend on `ffi`, which depends on the core).
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

- Core and app layer: existing tests (`cargo test`, `-p kzsigner-ffi`).
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

1. **Desktop crate** (done): the window and command line in `desktop/`, the core a library;
   all tests green, no visible change.
2. **Words and layout**: the window on the app layer (`kzsigner-ffi`), its texts rewritten, the centred column, Home, Add key,
   Your keys (language, About), the vault in the app data folder with the password unlock.
3. **Sign**: Sign, Signed, the NCA screens, save next to the original; the old Sign form and
   its options removed from the window.
4. **Check**: the phone's verdict screens and details; the old report view removed.
5. **OS unlock**: Windows Hello; Touch ID once there is a signing identity for macOS.
6. **Finish**: accessibility pass (NVDA, Narrator, Orca, VoiceOver where possible, 200 %),
   every flow in kittest with screenshots, docs, a check on a real Windows PC and Linux.

## Decisions (2026-11-24)

1. **Keys are kept on the computer**, as on the phone.
2. **The signed file is saved next to the original** automatically.
3. **macOS later.** CI builds Windows and Linux; Touch ID waits for a Mac build with an
   Apple Developer ID.
4. Texts stay separate from the phone's (no shared string files). No users yet: breaking
   changes and removing features are fine.
5. Desktop screens may differ from the phone's where that's easier to use.

## Self-review

- The window depends on `kzsigner-ffi` and so builds UniFFI's runtime in; a little size,
  no behaviour. If that grows, the app layer can move to its own crate under `ffi`.
- Two text tables (phone, window) can drift; each new screen updates both, and the
  native-speaker check covers both.
- No users yet, so the window's options (cards, detached .cms, levels, stamp) go without a
  migration; the command line keeps them, and checking such files stays in the window.
- Not covered: hardware tokens (Kaztoken, eToken) that NCALayer supports; kzsigner doesn't
  read them today. Worth a separate look if people ask.
