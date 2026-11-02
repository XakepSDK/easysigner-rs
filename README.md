# kzsigner (Rust)

Sign and verify `.cms` files, signed PDFs and document cards with Kazakhstan NCA RK keys, locally, without NCALayer. A port of
[kzsigner](https://github.com/XakepSDK/easysigner) (Java) to Rust: the same commands, messages,
checks and window, in one small executable with no runtime.

| | Java native (GraalVM) | Rust |
|---|---|---|
| Linux | 17 MB download (executable + `lib/`) | **5.5 MB** single file (1.7 MB tar.xz) |
| Windows | 20 MB download, 51 MB `.exe` + `lib/` | **6.4 MB** single `.exe` (2.7 MB zip) |
| Without the window (`--no-default-features`) | | 0.8 MB |

It signs, co-signs, verifies and extracts `.cms` files made with GOST 34.10-2015 (512 and 256),
GOST 34.310-2004 and RSA keys, and files made by NCALayer / Kalkan. It can also sign without the
`.cms` wrapper, so the result opens like any document:

* **Inside a PDF** (PAdES, `--pdf`): the signature goes into the PDF itself, which still opens in
  any PDF viewer; more signatures are added the same way, each keeping the earlier ones valid.
  `--stamp` also draws a visible stamp on the page (the signer, ИИН/БИН, the certificate and
  the signing time; `--stamp-page N`, `--stamp-at br|bl|tr|tl`, `--stamp-lang kk|ru|en`,
  `--stamp-logo logo.png|.jpg`); the window has it under More options.
* **Document card** (`--card`, карточка электронного документа, the
  [ddcard](https://github.com/kaarkz/ddcard) format SIGEX uses): a PDF that shows the document's
  pages, a page per signature with the signer, certificate, timestamp and revocation answer
  (and, with `--qr`, the signature itself as QR codes), and carries the original document and
  its `.cms` signatures as attachments. Any document can be put in a card, not only a PDF.
  Cards made by kzsigner open in SIGEX's [ddc](https://github.com/sigex-kz/ddc), and kzsigner
  checks and co-signs cards made by SIGEX.

* **Long-term signatures** (ETSI B-LT and B-LTA, `--level LT|LTA`, or `kzsigner extend` on an
  existing file): the CA certificates and NCA's revocation answers go into the signature (a
  .cms's certificates and `crls`, plus the revocationValues and certValues attributes Order
  500 p.8 names; a PDF's document security store), so it can still be checked after the
  certificate expires. LTA adds an archive timestamp over everything (CAdES
  archive-time-stamp-v3, or a PDF document timestamp); running `kzsigner extend` again later
  renews it before the timestamp's own certificate expires. The window makes long-term
  signatures by default when it adds the NCA time.

The network is used only for an NCA timestamp (`--tsa`, always for a card and a long-term
signature), the NCA revocation check (`--ocsp`, always for a card and a long-term signature,
whose signatures keep the answer), and the CAs' revocation lists when OCSP gives no answer.

### What is checked (Order 500/НҚ)

* **Before signing**, the key's own certificate is checked (p.4): it must be in force, its chain
  must lead to a trusted CA, and it must be meant for signing documents. With `--ocsp` (and
  always for a card, and in the window when the revocation check is on) it must also not be
  revoked; when NCA cannot be reached, signing goes ahead with a warning. kzsigner trusts NCA RK
  only, so test keys need their CA added with `--trust`.
* **Purpose** (p.16.4): a CA certificate, a key whose usage allows neither digital signature nor
  non-repudiation, a timestamp or OCSP service key, or a certificate policy outside its CA's
  policy is not accepted for document signatures (`usageError` in `--json`, "Usage" in text).
* **Revocation** (p.18): OCSP first; if it gives no answer, the CA's CRL (with its delta CRL) is
  used instead. An answer kept in a long-term signature counts when it was made at the
  signing time and the online check is off or gets no answer. `revocationSource` in `--json`
  says which answered (`ocsp`, `crl`, `kept-ocsp`, `kept-crl`); `level` gives the ETSI level
  (B-B, B-T, B-LT, B-LTA), with `archiveTimestamps` and a PDF's `documentTimestamps`. Lists are cached until their
  next update (at most an hour), failures for five minutes.
* **Timestamps** (p.17.2): a warning when the timestamp comes from a different CA than the
  signer's (NCA's own CAs count as one).
* **Kept answers** (p.8): card signatures carry the OCSP answer in `crls` and in the
  revocationValues attribute, and the issuer and responder certificates in certValues.
* **Seeing the document** (Digital Code Art. 50): the window has **Open the document**, before
  signing and when checking, which opens it in the system's viewer (on a phone, through the
  app chooser).

## Use

Run `kzsigner` with no arguments (or double-click it) for the window. It starts with two choices,
**Sign a document** and **Check a signed file**, each on a screen of its own in plain words; the
technical details are folded away. A file opened with it (`kzsigner document.pdf`) or dropped on
the window goes where it belongs: a document to signing, a signed file (.cms, signed PDF, card)
to checking, a key file to the key field. On a phone, or in a narrow window, the screens
switch to one column with full-width buttons. Safe by default: signing adds NCA's official time and
checking asks NCA whether the keys were revoked (both need internet; they can be turned off
under More options). When NCA cannot be reached, a check says the signatures are valid but not
checked for revocation, rather than failing. The window is in Kazakh, Russian or English: it starts in the
system's language and the menu at the top right switches (the choice is remembered;
`KZSIGNER_LANG=kk|ru|en` also sets it). The command line stays in English.

On Windows, `kzsigner.exe` is one file for both: a terminal waits for it and gets its output
and exit code, and double-clicking shows only the window. On Windows 11 24H2 and later no
console appears at all (its manifest sets `consoleAllocationPolicy` to `detached`); older
Windows flash a console for a moment before the window opens.

On Linux, `sh install.sh` (in the download) installs kzsigner into `~/.local/bin` with an
applications-menu entry and icon, and offers it in "Open with" for `.cms` and `.p12` files;
`sh install.sh --uninstall` removes it. It uses only the standard freedesktop.org locations, needs
no root, and works the same on GNOME, KDE Plasma and other desktops.

```
kzsigner sign document.pdf -k GOSTKNCA_xxx.p12          # -> document.pdf.cms
kzsigner sign document.pdf.cms -k RSA_yyy.p12           # adds a second signature (co-signing)
kzsigner sign document.pdf -k key.p12 --detached --tsa  # detached, with an NCA timestamp
kzsigner sign document.pdf -k key.p12 --pdf --level LTA # inside the PDF, long-term (B-LTA)
kzsigner extend document.pdf.cms                        # make a .cms long-term, or renew it
kzsigner verify document.pdf.cms [--ocsp] [--json]      # exit code 0 only if all signatures are valid
kzsigner verify detached.cms --data document.pdf
kzsigner extract document.pdf.cms                       # -> document.pdf
kzsigner info -k key.p12

kzsigner sign contract.pdf -k key.p12 --pdf             # -> contract-signed.pdf, signed inside
kzsigner sign contract-signed.pdf -k key2.p12 --pdf     # a second signature inside the PDF
kzsigner sign contract.pdf -k key.p12 --pdf --stamp --stamp-logo logo.png  # with a visible stamp
kzsigner sign contract.docx -k key.p12 --card --qr      # -> contract.docx.card.pdf
kzsigner sign contract.docx.card.pdf -k key2.p12 --card # adds a signature to the card
kzsigner verify contract.docx.card.pdf                  # checks the card's signatures
kzsigner extract contract.docx.card.pdf                 # -> contract.docx, from inside the card
kzsigner verify --qr scans.txt --data contract.docx     # signatures read back from QR codes
```

A card's language is `--lang ru` (default), `kk` or `kk/ru`. For `verify --qr`, `scans.txt` holds
the texts a QR scanner reads from a card's signature pages, one code per line, in any order.

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

CI also signs build provenance for the archives and executables with GitHub artifact attestations,
so a download can be checked without building: `gh attestation verify FILE -R XakepSDK/easysigner-rs`.
GitHub stores attestations only for public repositories, so this step is skipped while the
repository is private.

On Linux the program links nothing beyond the C library, so it runs on any distribution and
desktop (GNOME, KDE Plasma, Xfce, ...). The window runs natively on Wayland or on X11 and needs
OpenGL (Mesa is enough). File dialogs come from the desktop through the XDG desktop portal, so KDE
shows its own dialog and GNOME its own; without a portal, `zenity` is used if installed, and the
path fields can always be typed or pasted into. The Windows `.exe` cross-builds from
Linux with `cargo build --release --target x86_64-pc-windows-gnu` (MinGW); CI builds it natively.

## How it is put together

All of the cryptography that is specific to Kazakhstan is in this repository; everything generic
comes from established crates: RustCrypto for hashes, HMAC, PBKDF2, the PKCS#12 key derivation,
DES/RC2/AES-CBC and RSA (`rsa`, constant-time `crypto-bigint`), `ureq` for HTTP and `base64`.

* `gost.rs`: the KZ profiles of the GOST algorithms. GOST 34.311-95 is GOST R 34.11-94 with the
  test S-box (RustCrypto `gost94`), GOST 34.11-2015 is Streebog (`streebog`). GOST 34.10
  signatures on the CryptoPro-A, TC26 256-A and TC26 512-A curves are implemented here (Jacobian
  coordinates on `num-bigint`), with NCA's little-endian conventions for keys and signatures.
* `keys.rs`: KZ GOST and RSA keys; RSA PKCS#1 v1.5 signing and verification with the `rsa`
  crate.
* `p12.rs`: PKCS#12 key files as Kalkan writes them (BER, 3DES key bag, RC2-40 certificate bag,
  SHA-1 MAC), and PBES2/AES files. The file structure is read here because Kalkan writes BER,
  which the RustCrypto `pkcs12`/`der` crates do not read; the key derivation and ciphers are
  theirs.
* `der.rs`: a small ASN.1 reader (DER and BER) and DER writer that keeps raw encodings, so signed
  parts are hashed and copied byte for byte (NCALayer and Kalkan files are not always strict DER,
  which the `der` crate requires).
* `cms.rs`, `sign.rs`: CAdES-BES signing with the attributes NCALayer writes (content type,
  signing time, signingCertificateV2, message digest), co-signing by merging signers.
* `verify.rs`, `tsp.rs`, `ocsp.rs`, `trust.rs`: signature, signing-certificate binding,
  timestamps (CAdES-T), certificate paths built only from trusted certificates, OCSP.
* `crl.rs`, `cert.rs`: CRLs and delta CRLs (the OCSP fallback), key usage and certificate
  policies.
* `ltv.rs`: long-term validation data (fetching it, keeping it, reading it back) and CAdES
  archive-time-stamp-v3 with its ats-hash-index-v3 (ETSI EN 319 122-1 5.5). PDF document
  timestamps and the DSS are in `pdf/mod.rs`.
* `http.rs`: the POST to the timestamp and OCSP servers and the CRL downloads, with `ureq`
  (plain http, which NCA's servers use; a proxy from the environment is honoured).
* `gui.rs`: the window ([egui](https://github.com/emilk/egui)): OpenGL on Linux, Direct3D 12 on
  Windows (which falls back to Windows' software renderer, so it also works in virtual machines
  and over remote desktop). `icons.rs` draws the icons from SVG path data as vector shapes, so
they stay sharp at any scale with no image files. Fonts are a 51 KB subset of Noto Sans with Cyrillic and Kazakh
  letters (`assets/`).
* `pdf/`: PDF signatures and document cards, on [lopdf](https://github.com/J-F-Liu/lopdf).
  `pdf/mod.rs` signs a PDF as an incremental update (ETSI.CAdES.detached, the `ByteRange`
  covering everything but the signature) and checks every signature in one. A signature only
  passes if every later update just added signatures (new signature fields and widgets, the
  AcroForm entries for them, the DSS); an update that changes a page, the page tree or the
  catalog fails every earlier signature, since the PDF no longer shows what was signed. A PDF
  certified with no changes allowed (DocMDP P=1) is not signed. `pdf/stamp.rs` draws the visible stamp (a widget appearance with the bundled font, an optional JPEG or PNG logo, upright on rotated pages). `pdf/card.rs` builds and reads document cards after ddc's layout and texts
  (MIT licence; its Kazakh texts are reused): the card's signatures are detached CAdES with a
  mime-type attribute, an NCA timestamp, the certificate chain and the OCSP answer kept in
  `crls` (RFC 5940), as the ddcard specification asks. `pdf/qr.rs` turns a signature into QR
  codes (ZIP, Base64, JSON parts; [qrcodegen](https://github.com/nayuki/QR-Code-generator)) and
  back. `pdf/import.rs` shows the document's own pages in the card; `pdf/layout.rs`,
  `pdf/font.rs` draw the pages in an embedded subset of the bundled Noto Sans (`ttf-parser`).
* `main.rs`, `output.rs`: the command line, text and JSON reports.
* `i18n.rs`: the window's Kazakh and Russian texts, one table. The Kazakh was not written by a
  native speaker; corrections are welcome.
* `assets/kzsigner.ico`, `.png`: the icon, drawn by `packaging/make-icon.py`; `build.rs` puts it
  and the version into the Windows `.exe`. `packaging/linux/`: the menu entry and installer.

## Differences from the Java version

* Timestamp and OCSP URLs must be `http://`. NCA's servers take requests only over http (over
  https they answer POST with 405, checked 2026-11-01), as NCALayer uses them; the answers are
  signed and kzsigner checks them: the timestamp token's signature, TSA certificate and nonce
  (also when signing), and the OCSP responder, nonce and freshness. Requests carry NCALayer's
  User-Agent (`Java/1.8.0_492`, the Java default its Kalkan modules send).
* NCA's TSA no longer serves policy 1.2.398.3.3.2.6.1, so GOST 34.310-2004 keys cannot get a
  timestamp (NCA answers "Missing certificate or key error!").
* The OCSP nonce is sent in the RFC 8954 form; both that and the bare form are accepted back.
* A timestamp's signing-certificate reference must match the TSA certificate.
* A file can be given on the command line (or with "Open with") to start the window with it.
* RSA-PSS signatures are not supported (NCA does not use them).
* Long-term signatures follow ETSI EN 319 122-1 / 319 142-1; they were checked by kzsigner's
  own tests, not yet against NCALayer's or the EU DSS validator's reading of them.
* The GOST curve arithmetic is on `num-bigint`, which is not constant-time (no maintained Rust
  crate implements KZ GOST 34.10). Keys never leave the computer. RSA uses the `rsa` crate.

## Tests

`cargo test` runs:

* `tests/e2e.rs`: the end-to-end checks of the Java version's `test/run-tests.sh`, against the
  built executable. It uses throwaway test keys (`tests/fixtures/keys`, made by the Java
  version's `MkKeys`), a fake local timestamp server, and files and keys made by NCA's own Kalkan
  library (`tests/fixtures/kalkan`).
* `tests/e2e.rs` also signs PDFs (RSA, GOST 2015, GOST 2004; co-signing; changed files) and makes,
  co-signs, checks and unpacks document cards, with a fake local OCSP responder for its own test
  CA (`tests/fixtures/ocsp`, made with openssl), QR codes read back, and a revoked certificate
  refused. Test PDFs are in `tests/fixtures/pdf`.
* `tests/gui.rs`: drives the window without a display (egui_kittest): from the start screen picks
  a document and key, types the password, opens the document, signs, checks the result, saves the document back out
  and switches languages; signs a PDF inside, checks it and a card, saves the card's document;
  and opens a signed PDF from the start, which goes to checking.
* `tests/malformed.rs`: damaged files (bytes changed, cut, lengths broken: .cms, .p12, plain and
  signed PDFs), deep nesting, page-tree loops and broken OIDs give errors, never a crash.
* `tests/pdf_changes.rs`: a signed PDF whose page is redrawn by a later update fails, later
  signatures alone keep earlier ones valid, and a no-changes certified PDF is not signed.
* `tests/e2e.rs` `long_term`: B-LTA .cms and PDFs signed, renewed, co-signed and checked
  offline from the kept answers; removed validation data and changed files are caught; a
  detached signature's archive timestamp needs its document.
* `tests/crl.rs`, `tests/policy.rs`: CRL and delta CRL answers, and which certificates may sign
  documents (key usage, service keys, policies against the real NCA CAs).
* `tests/p12.rs` and unit tests: key files, curves, hashes, ASN.1, times, and real exchanges
  with NCA's timestamp server (`tests/fixtures/nca-live`, RSA and GOST 2015 TSA signatures).

None of the test keys or certificates is a real NCA certificate. The Kalkan fixtures expire on
2027-11-01; the OCSP test CA and key on 2046-10-27.

Checked by hand (not in `cargo test`, they need other tools): RSA-signed PDFs pass poppler's
`pdfsig` and pyHanko (neither knows KZ GOST); cards made by kzsigner open with ddc's
`ExtractAttachments` (Go, pdfcpu), and a card ddc builds from kzsigner's signatures verifies,
co-signs and extracts with kzsigner.
