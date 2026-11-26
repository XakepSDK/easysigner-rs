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
        // phones only (arm64): the core is built for nothing else, and JNA's aar carries
        // seven more architectures. The x86_64 emulators run it through ARM translation.
        ndk.abiFilters.addAll(listOf("arm64-v8a"))
    }

    sourceSets["main"].apply {
        // the generated bindings (uniffi-bindgen), outside the module
        kotlin.directories.add(ffiKotlin)
        jniLibs.directories.add(ffiLibs)
    }

    signingConfigs {
        // the public development key, for the emulator tests' build
        create("dev") {
            storeFile = file("../dev.keystore")
            storePassword = "kzsigner-dev"
            keyAlias = "kzsigner-dev"
            keyPassword = "kzsigner-dev"
        }
        create("kzsigner") {
            val ks = System.getenv("KZSIGNER_KEYSTORE")
            if (!ks.isNullOrEmpty()) {
                storeFile = file(ks)
                storePassword = System.getenv("KZSIGNER_KEYSTORE_PASS")
                keyAlias = System.getenv("KZSIGNER_KEY_ALIAS") ?: "kzsigner"
                keyPassword = storePassword
            } else {
                // a development key whose password is public: -dev versions only (apk.sh checks
                // too, but a Gradle run of its own would not)
                if (!appVersion.contains('-')) {
                    throw GradleException("release $appVersion: set KZSIGNER_KEYSTORE (the release signing key)")
                }
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
            buildConfigField("boolean", "TEST_CAS", "false")
        }
        // the emulator tests' build: the release build, plus the test keys' CAs trusted when
        // adding a key (KeysModel.issuers), so the tests can add one. Never released.
        create("uitest") {
            initWith(getByName("release"))
            buildConfigField("boolean", "TEST_CAS", "true")
            signingConfig = signingConfigs.getByName("dev")
            matchingFallbacks += "release"
        }
        getByName("debug") {
            buildConfigField("boolean", "TEST_CAS", "false")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
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

// Pitest, for the pitest task below
val pitest: Configuration by configurations.creating

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

    // JVM unit tests (src/test): plain logic, no phone needed
    testImplementation("junit:junit:4.13.2")
    pitest("org.pitest:pitest-command-line:1.30.2")
}

// Mutation testing of the logic the JVM tests cover (Pitest): `gradle :compose:pitest` changes
// the compiled classes one way at a time and expects a test to fail each time; the report goes
// to target/gradle-compose/reports/pitest. Compose screens and the code that needs a phone or
// the Rust library are left out: the emulator tests (android/uitest) cover those.
val pitestClasses = listOf("kz.kzsigner.CheckFlow*", "kz.kzsigner.SignFlow*", "kz.kzsigner.Files")
tasks.register<JavaExec>("pitest") {
    group = "verification"
    description = "Mutation tests for the JVM-tested logic (Pitest)"
    val unitTests = tasks.named<Test>("testDebugUnitTest")
    dependsOn(unitTests)
    classpath = pitest
    mainClass = "org.pitest.mutationtest.commandline.MutationCoverageReport"
    val report = layout.buildDirectory.dir("reports/pitest")
    doFirst {
        // the app's classes as a folder (the tests' classpath has them as a jar, which Pitest
        // doesn't mutate)
        val main = tasks.named("compileDebugKotlin").get().outputs.files.filter { File(it, "kz/kzsigner").isDirectory }
        val cp = (main.files + unitTests.get().classpath.files.filter { it.exists() }).joinToString(",")
        args(
            "--reportDir", report.get().asFile.path,
            "--targetClasses", pitestClasses.joinToString(","),
            "--targetTests", "kz.kzsigner.*Test",
            "--excludedClasses", "kz.kzsigner.*Test*",
            // what needs a phone (Context, MimeTypeMap): the emulator tests cover it
            "--excludedMethods", "share,send,view,uri",
            // Kotlin's own null checks and coroutine machinery (no test can tell them apart), and
            // the phone's own lists (android.webkit)
            "--avoidCallsTo", "kotlin.jvm.internal,kotlin.ResultKt,kotlin.coroutines.intrinsics,android.webkit",
            "--sourceDirs", file("src/main/kotlin").path,
            "--classPath", cp,
            "--mutableCodePaths", main.asPath.replace(File.pathSeparator, ","),
            "--outputFormats", "HTML,XML",
            "--timestampedReports", "false",
            // the survivors allowed: a suspend function's Unit return replaced with null, which
            // its callers can't see (SignFlow.open, CheckFlow.check twice)
            "--maxSurviving", "3"
        )
    }
}
