// The Kotlin + Compose app (docs/compose-plan.md), built next to the egui app until it covers
// every screen: kz.kzsigner, so both install side by side. The Rust core comes from cargo
// (libkzsigner_ffi.so, copied by scripts/apk.sh into -Pkzsigner.ffiLibs) and its Kotlin
// bindings from uniffi-bindgen (-Pkzsigner.ffiKotlin); neither is checked in.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val ffiLibs = providers.gradleProperty("kzsigner.ffiLibs").getOrElse("../../target/android-ffi")
val ffiKotlin = providers.gradleProperty("kzsigner.ffiKotlin").getOrElse("../../target/uniffi-kotlin")
val appVersion = providers.gradleProperty("kzsigner.version").getOrElse("0.0.0-dev")

layout.buildDirectory = file("../../target/gradle-compose")

android {
    namespace = "kz.kzsigner"
    compileSdk = 37
    // Compose 1.13 asks for 37.1 or newer; the whole build uses one platform
    compileSdkMinor = 2
    buildToolsVersion = "37.0.0"

    defaultConfig {
        // the id and signing key of the earlier egui app, so it installs over it and keeps the
        // keys (the same vault file and chip keys, see KeystoreChip.kt)
        applicationId = "kz.kzsigner"
        minSdk = 30
        targetSdk = 35
        versionCode = 2
        versionName = appVersion
        // the architectures the core is built for; JNA's aar carries seven more
        ndk.abiFilters.addAll(listOf("arm64-v8a", "x86_64"))
    }

    sourceSets["main"].apply {
        // the generated bindings (uniffi-bindgen), outside the module
        kotlin.directories.add(ffiKotlin)
        jniLibs.directories.add(ffiLibs)
    }

    signingConfigs {
        create("kzsigner") {
            val ks = System.getenv("KZSIGNER_KEYSTORE")
            if (!ks.isNullOrEmpty()) {
                storeFile = file(ks)
                storePassword = System.getenv("KZSIGNER_KEYSTORE_PASS")
                keyAlias = System.getenv("KZSIGNER_KEY_ALIAS") ?: "kzsigner"
                keyPassword = storePassword
            } else {
                // a development key whose password is public: -dev versions only (apk.sh checks)
                storeFile = file("../dev.keystore")
                storePassword = "kzsigner-dev"
                keyAlias = "kzsigner-dev"
                keyPassword = "kzsigner-dev"
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("kzsigner")
            vcsInfo.include = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        // the release build stops on a call Android 11 doesn't have (the bindings' too)
        checkReleaseBuilds = true
        fatal.add("NewApi")
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.11.01"))
    implementation("androidx.compose.material3:material3:1.5.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.1")
    // the per-app language on Android 11 and 12, and its theme
    implementation("androidx.appcompat:appcompat:1.8.0")
    // the UniFFI bindings call the Rust library through JNA; the aar carries its Android .so
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:2.4.21"))
}
