// The emulator tests (UI Automator), as their own APK: kz.kzsigner.uitest. It runs in its own
// process ("self-instrumenting"), so it keeps going while kzsigner is restarted, uninstalled
// or replaced by the test copy. scripts/android-selftest.sh installs and runs it on CI.
plugins {
    id("com.android.test")
}

layout.buildDirectory = file("../../target/gradle-uitest")

android {
    namespace = "kz.kzsigner.uitest"
    compileSdk = 35
    buildToolsVersion = "36.0.0"
    targetProjectPath = ":"

    defaultConfig {
        minSdk = 30
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets["main"].java.directories.add("java")

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
    implementation("androidx.test:runner:1.6.2")
    implementation("androidx.test.ext:junit:1.2.1")
    implementation("androidx.test.uiautomator:uiautomator:2.3.0")
    implementation("junit:junit:4.13.2")
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:1.8.22"))
}
