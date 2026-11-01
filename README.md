# kzsigner (Rust)

Sign and verify `.cms` files with Kazakhstan NCA RK keys, locally, without NCALayer. A port of
[kzsigner](https://github.com/XakepSDK/easysigner) (Java) to Rust: the same commands, messages,
checks and window, in one small executable with no runtime.

| | Java native (GraalVM) | Rust |
|---|---|---|
| Linux | 17 MB download (executable + `lib/`) | **5.5 MB** single file (1.7 MB tar.xz) |
| Windows | 20 MB download, 51 MB `.exe` + `lib/` | **6.4 MB** single `.exe` (2.7 MB zip) |
| Without the window (`--no-default-features`) | | 0.8 MB |

It signs, co-signs, verifies and extracts `.cms` files made with GOST 34.10-2015 (512 and 256),
GOST 34.310-2004 and RSA keys, and files made by NCALayer / Kalkan. The network is used only for
an NCA timestamp (`--tsa`) and the NCA revocation check (`--ocsp`).

## Use

Run `kzsigner` with no arguments (or double-click it) for the window, or open a file with it:
`kzsigner document.pdf` starts on the Sign tab, `kzsigner signed.cms` on the Verify tab. Files can
also be dropped on the window. The window is in Kazakh, Russian or English: it starts in the
system's language and the menu at the top right switches (the choice is remembered;
`KZSIGNER_LANG=kk|ru|en` also sets it). The command line stays in English.

On Windows, `kzsigner.exe` is the window and opens without a console. Commands in a terminal
(`kzsigner sign ...` in cmd or PowerShell) run through `kzsigner.com`, a small console launcher
next to it that waits for the result; keep the two files together.

On Linux, `sh install.sh` (in the download) installs kzsigner into `~/.local/bin` with an
applications-menu entry and icon, and offers it in "Open with" for `.cms` and `.p12` files;
`sh install.sh --uninstall` removes it.

```
kzsigner sign document.pdf -k GOSTKNCA_xxx.p12          # -> document.pdf.cms
kzsigner sign document.pdf.cms -k RSA_yyy.p12           # adds a second signature (co-signing)
kzsigner sign document.pdf -k key.p12 --detached --tsa  # detached, with an NCA timestamp
kzsigner verify document.pdf.cms [--ocsp] [--json]      # exit code 0 only if all signatures are valid
kzsigner verify detached.cms --data document.pdf
kzsigner extract document.pdf.cms                       # -> document.pdf
kzsigner info -k key.p12
```

The password comes from `-p`, the `KZSIGNER_PASSWORD` environment variable, or a prompt.
`--trust CA.cer` adds a trusted CA on top of NCA RK's bundled root and issuing certificates.
`kzsigner COMMAND --help` lists every option.

## Build

```
cargo build --release              # target/release/kzsigner
cargo test --release               # unit tests, end-to-end checks, scripted window test
cargo build --release --no-default-features   # command line only
sh scripts/cargo.sh                # reproducible release build (what the downloads are)
```

Release builds are reproducible: `sh scripts/cargo.sh` (Git Bash on Windows) gives byte-identical
executables for the same commit on any machine and in any folder. The compiler version is pinned
in `rust-toolchain.toml`, crates in `Cargo.lock`, and the script keeps build paths and (on
Windows) link times out of the files. To check a download, build the release's tag and compare
with `SHA256SUMS`. CI builds every commit twice, in different folders, and fails if the
executables differ.

On Linux the window needs the GTK 3 development files for the file dialogs (`libgtk-3-dev`), and
at run time X11 or XWayland with OpenGL (Mesa is enough). The Windows `.exe` cross-builds from
Linux with `cargo build --release --target x86_64-pc-windows-gnu` (MinGW); CI builds it natively.

## How it is put together

All of the cryptography that is specific to Kazakhstan is in this repository; generic pieces come
from small RustCrypto crates.

* `gost.rs`: the KZ profiles of the GOST algorithms. GOST 34.311-95 is GOST R 34.11-94 with the
  test S-box (RustCrypto `gost94`), GOST 34.11-2015 is Streebog (`streebog`). GOST 34.10
  signatures on the CryptoPro-A, TC26 256-A and TC26 512-A curves are implemented here (Jacobian
  coordinates on `num-bigint`), with NCA's little-endian conventions for keys and signatures.
* `keys.rs`: KZ GOST and RSA keys; RSA PKCS#1 v1.5 signing (blinded, CRT, self-checked) and
  verification.
* `p12.rs`: PKCS#12 key files as Kalkan writes them (BER, 3DES key bag, RC2-40 certificate bag,
  SHA-1 MAC), and PBES2/AES files.
* `der.rs`: a small ASN.1 reader (DER and BER) and DER writer that keeps raw encodings, so signed
  parts are hashed and copied byte for byte.
* `cms.rs`, `sign.rs`: CAdES-BES signing with the attributes NCALayer writes (content type,
  signing time, signingCertificateV2, message digest), co-signing by merging signers.
* `verify.rs`, `tsp.rs`, `ocsp.rs`, `trust.rs`: signature, signing-certificate binding,
  timestamps (CAdES-T), certificate paths built only from trusted certificates, OCSP.
* `http.rs`: a minimal HTTP/1.1 POST client for the timestamp and OCSP servers.
* `gui.rs`: the window ([egui](https://github.com/emilk/egui)): OpenGL on Linux, Direct3D 12 on
  Windows (which falls back to Windows' software renderer, so it also works in virtual machines
  and over remote desktop). Fonts are a 51 KB subset of Noto Sans with Cyrillic and Kazakh
  letters (`assets/`).
* `main.rs`, `output.rs`: the command line, text and JSON reports. `bin/kzsigner-console.rs`:
  the Windows console launcher (`kzsigner.com`).
* `i18n.rs`: the window's Kazakh and Russian texts, one table. The Kazakh was not written by a
  native speaker; corrections are welcome.
* `assets/kzsigner.ico`, `.png`: the icon, drawn by `packaging/make-icon.py`; `build.rs` puts it
  and the version into the Windows `.exe`. `packaging/linux/`: the menu entry and installer.

## Differences from the Java version

* Timestamp and OCSP URLs must be `http://` (NCA's servers are plain http; the data is signed).
* The OCSP nonce is sent in the RFC 8954 form; both that and the bare form are accepted back.
* A timestamp's signing-certificate reference must match the TSA certificate.
* A file can be given on the command line (or with "Open with") to start the window with it.
* RSA-PSS signatures are not supported (NCA does not use them).
* The big-number arithmetic is not constant-time. Keys never leave the computer, and RSA signing is
  blinded, but this is a difference from Bouncy Castle.

## Tests

`cargo test` runs:

* `tests/e2e.rs`: the end-to-end checks of the Java version's `test/run-tests.sh`, against the
  built executable. It uses throwaway test keys (`tests/fixtures/keys`, made by the Java
  version's `MkKeys`), a fake local timestamp server, and files and keys made by NCA's own Kalkan
  library (`tests/fixtures/kalkan`).
* `tests/gui.rs`: drives the window without a display (egui_kittest): picks a document and key,
  types the password, signs, verifies the result and saves the document back out.
* `tests/p12.rs` and unit tests: key files, curves, hashes, ASN.1, times.

None of the test keys or certificates is a real NCA certificate. The Kalkan fixtures expire on
2027-11-01.
