// kzsigner's APK. The Rust library comes from cargo (scripts/apk.sh copies it into the folder
// given as -Pkzsigner.jniLibs); this only adds the Java side, resources and AndroidX, and signs.
plugins {
    id("com.android.application") version "9.5.2"
    id("com.android.test") version "9.5.2" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}

val jniLibsDir = providers.gradleProperty("kzsigner.jniLibs").getOrElse("../target/android-jni")
val appVersion = providers.gradleProperty("kzsigner.version").getOrElse("0.0.0-dev")

layout.buildDirectory = file("../target/gradle")

android {
    namespace = "kz.kzsigner"
    compileSdk = 37
    // Compose 1.13 asks for 37.1 or newer; the whole build uses one platform
    compileSdkMinor = 2
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "kz.kzsigner"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = appVersion
    }

    sourceSets["main"].apply {
        manifest.srcFile("AndroidManifest.xml")
        java.directories.add("java")
        res.directories.add("res")
        jniLibs.directories.add(jniLibsDir)
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
                storeFile = file("dev.keystore")
                storePassword = "kzsigner-dev"
                keyAlias = "kzsigner-dev"
                keyPassword = "kzsigner-dev"
            }
        }
    }

    buildTypes {
        getByName("release") {
            // drops the unused parts of AndroidX (most of it), see proguard-rules.pro
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("kzsigner")
            // nothing that differs between machines or checkouts goes into the APK
            vcsInfo.include = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // native libraries stay uncompressed and aligned, loaded straight from the APK
        jniLibs.useLegacyPackaging = false
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        checkReleaseBuilds = false
    }
}

dependencies {
    // must match the GameActivity glue in the android-activity crate (see its README)
    implementation("androidx.games:games-activity:4.4.0")
    implementation("androidx.appcompat:appcompat:1.8.0")
    // one Kotlin standard library: AndroidX brings two generations of it
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:2.4.21"))
}
