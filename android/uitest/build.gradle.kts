// The emulator tests (UI Automator), as their own APK: kz.kzsigner.uitest. It runs in its own
// process ("self-instrumenting"), so it keeps going while kzsigner is restarted, uninstalled
// or replaced by the test copy. scripts/android-selftest.sh installs and runs it on CI.
plugins {
    id("com.android.test")
}

layout.buildDirectory = file("../../target/gradle-uitest")

android {
    namespace = "kz.kzsigner.uitest"
    compileSdk = 37
    // Compose 1.13 asks for 37.1 or newer; the whole build uses one platform
    compileSdkMinor = 2
    buildToolsVersion = "37.0.0"
    targetProjectPath = ":"

    defaultConfig {
        minSdk = 30
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets["main"].apply {
        manifest.srcFile("AndroidManifest.xml")
        java.directories.add("java")
        // the test keys (password Qwerty12), served by KeyFiles
        assets.directories.add("../../tests/fixtures/keys")
    }

    signingConfigs {
        create("dev") {
            storeFile = file("../dev.keystore")
            storePassword = "kzsigner-dev"
            keyAlias = "kzsigner-dev"
            keyPassword = "kzsigner-dev"
        }
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("dev")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    experimentalProperties["android.experimental.self-instrumenting"] = true

    lint {
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation("androidx.test:runner:1.7.0")
    implementation("androidx.test.ext:junit:1.3.0")
    implementation("androidx.test.uiautomator:uiautomator:2.4.1")
    implementation("junit:junit:4.13.2")
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:2.4.21"))
}
