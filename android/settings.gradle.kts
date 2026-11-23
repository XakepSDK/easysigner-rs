// The APK's packaging (scripts/apk.sh runs it after cargo built the Rust library).
// Versions are pinned: two builds of a commit give the same APK.
pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "kzsigner"
