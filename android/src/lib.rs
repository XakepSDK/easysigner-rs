//! The entry point Android calls; see kzsigner's src/android.rs.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: kzsigner::android::AndroidApp) {
    kzsigner::android::main(app);
}
