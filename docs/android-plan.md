# Android build: plan (not started)

Status: planned only. Do not implement until asked.

## Goal

The same kzsigner app on Android phones: open a .p12 key, sign and co-sign files, verify and
extract .cms files, with the same three languages and the same NCA timestamp and OCSP checks.
It is distributed as an APK on the GitHub release page, next to the Windows and Linux downloads.

## What carries over unchanged

- Everything under `src/` except the window glue: DER, CMS, GOST and RSA keys, p12, timestamps,
  OCSP, trust roots, i18n. This is plain Rust and builds for `aarch64-linux-android` as it is.
- The egui interface. eframe runs on Android through `android-activity`
  (`android-native-activity` feature), so the screens stay the same code.
- The HTTP client (ureq, plain http to NCA).

## What is Android-specific

1. **Entry point.** `src/lib.rs` gets an `android_main(app: AndroidApp)` that starts the same
   `gui::App`. The crate also builds as a `cdylib` for Android only.
2. **Files.** rfd has no Android picker, and apps can't read arbitrary paths. Files go through
   the Storage Access Framework: `ACTION_OPEN_DOCUMENT` to pick a key or document and
   `ACTION_CREATE_DOCUMENT` to save the .cms file, called over JNI (`jni` + `ndk-context`).
   The bytes are read into memory, so the signing code doesn't change. The editable path
   fields are hidden on Android.
3. **Open with / Share.** Intent filters for .cms and .p12, so a file can be opened from Files,
   Telegram or e-mail straight into kzsigner.
4. **Keyboard.** egui doesn't always show the on-screen keyboard on Android. The password field
   needs a JNI call to show and hide it (`InputMethodManager`).
5. **Network.** Android blocks plain http by default. A network security config allows
   cleartext for `*.pki.gov.kz` only. The `INTERNET` permission is needed; no other permissions.
6. **Layout.** A single column for narrow screens, and larger touch targets. The same code
   switches by window width, so the desktop keeps its layout.
7. **Language.** Taken from the Android locale (`Configuration`), with the same saved-choice
   file in the app's private folder.

## Build and signing

- **Targets:** `aarch64-linux-android` (almost all phones), and `x86_64-linux-android` for the
  emulator in CI. Optionally `armv7-linux-androideabi` for old phones.
- **minSdk:** 30 (Android 11), target 35. Raised from 26 for the key store: per-use
  fingerprint-or-PIN keys (`setUserAuthenticationParameters`) need Android 11.
- **Tooling:** cargo builds the .so (`scripts/apk.sh`), and Gradle (pinned 8.14.3, checked by
  SHA-256; Android Gradle plugin 8.10.1) adds the Java side and signs. Gradle came in with
  GameActivity, which TalkBack support needs (AccessKit's Android adapter reads its view) and
  which is an AndroidX library. The NDK, build-tools, Gradle and Rust versions are pinned so the
  build stays reproducible; CI builds every commit twice and compares the APKs.
- **Signing key:** a release keystore is generated once and stored as GitHub Actions secrets
  (keystore base64 + password). It must never change: Android refuses updates signed with a
  different key. The user keeps an offline backup.
- **Reproducibility:** unsigned APKs from two builds must be byte-identical (checked in CI like
  the desktop builds). APK signature v2/v3 with RSA is deterministic, so signed APKs match too,
  which also keeps the door open for F-Droid's reproducible-build verification.

## CI

- A new `android` job: build the APK, build it again in another folder and compare, then run
  it on an emulator (`reactivecircus/android-emulator-runner`, x86_64, KVM on ubuntu-latest)
  and check that it starts and stays up, like the Windows and Linux window checks.
- Unit and e2e tests keep running on the desktop jobs. The crypto code is shared, so they cover it.
- The release job attaches `kzsigner-X.Y.Z-android.apk` and its line in `SHA256SUMS`.

## Open questions for the user

- Sideload APK only, or also F-Droid or Google Play? Play needs a developer account ($25 once)
  and an AAB upload. F-Droid needs the repository to be public.
- Who holds the backup of the release signing key?
- Is armv7 (old 32-bit phones) worth the extra build?

## Rough order of work

1. Android entry point and an APK that opens the window (emulator check in CI).
2. File open and save through SAF, with the keyboard fix.
3. Network config, layout for narrow screens, intent filters.
4. Release signing, reproducibility check, release asset.

## TODO: a native UI on each platform

Decided for later; the current order of work stays (GameActivity and TalkBack, UI Automator
tests, then the Gradle 9 and dependency upgrades).

egui draws its own widgets, so on a phone every native behaviour has to be glued on by hand:
TalkBack (AccessKit + GameActivity), keyboard input (the edit-box bridge in `src/android.rs`),
screen edges, the back gesture. Autofill, the Material look and native test tools are still
missing. The way out is to keep Rust as the shared core and give each platform its own UI:

- **Core (Rust, unchanged):** signing, the crypto, the key store, the NCA checks, as one
  library with a small API made for a UI to call.
- **Android:** Kotlin + Jetpack Compose. Accessibility, autofill, text input, insets and back
  come from the platform; the fingerprint or PIN prompt is the system's `BiometricPrompt`
  without hand-written JNI; Espresso and UI Automator test the real screens.
- **iOS (later):** SwiftUI on the same core.
- **Bindings:** UniFFI (Mozilla) generates the Kotlin and Swift code that calls Rust.
- **Desktop:** stays on egui for now.

The screens are few (sign, check, keys, settings), so a second UI is a modest amount of work;
the phone app has no users yet, which makes Android the place to start.
