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
- **minSdk:** 26 (Android 8), which covers about 97% of phones in use.
- **Tooling:** `cargo-ndk` builds the .so. A small Gradle-free packaging step (`aapt2` + `zipalign`
  + `apksigner` from the SDK build-tools) makes the APK. The NDK, build-tools and Rust versions
  are pinned so the build stays reproducible, like `scripts/cargo.sh` does on the desktop.
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
