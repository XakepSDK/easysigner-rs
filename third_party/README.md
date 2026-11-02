# Patched crates

- `jni-macros` 0.22.4 (MIT OR Apache-2.0, https://github.com/jni-rs/jni-rs), used through
  android-activity in the Android app. Its `bind_java_type!` code generation iterated a HashMap
  and a HashSet (`TypeMappings::rust_to_java_iter`, `TypeMappings::rust_types` in
  `src/types.rs`), whose order is random per compiler run, so two builds of the same commit
  gave different Android libraries. The patch sorts both by Rust type path. Nothing else is
  changed. Drop the copy once upstream is deterministic.
