# The UniFFI bindings and JNA find classes, fields and methods by name.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class kz.kzsigner.core.** { *; }
-dontwarn java.awt.**
# kzsigner's code is open source: keep names readable in crash reports
-dontobfuscate
