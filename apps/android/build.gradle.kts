// The Android build: the app is :compose (Kotlin + Compose over the Rust core), its emulator
// tests :uitest. scripts/apk.sh runs it after cargo built the core. Versions are pinned: two
// builds of a commit give the same APK.
plugins {
    id("com.android.application") version "9.5.2" apply false
    id("com.android.test") version "9.5.2" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}
layout.buildDirectory = file("../../target/gradle")
