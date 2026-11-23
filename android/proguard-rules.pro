# Rust calls into these by name over JNI (src/android.rs): keep them whole.
-keep class kz.kzsigner.** { *; }
# GameActivity's own rules come with its library; its native methods and the fields that
# AccessKit's adapter reads by name (mSurfaceView) must stay too.
-keep class com.google.androidgamesdk.** { *; }
# kzsigner's code is open source: keep names readable in crash reports
-dontobfuscate
