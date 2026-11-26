# kzcrypto

The cryptography of kzsigner on its own: Kazakhstan's NCA RK algorithms and formats, as bytes
in and bytes out. It is a separate crate so that it can be reviewed and certified as one small
unit (СТ РК 1073-2025, see the project's certification notes), and later moved to a repository
of its own.

## What is inside

| Module | What it does |
|---|---|
| `gost` | GOST 34.311-95 and GOST 34.11-2015 (Streebog) hashes as NCA uses them, SHA-1/2; GOST 34.10 signing and checking on the CryptoPro-A, TC26 256-A and 512-A curves, with NCA's little-endian conventions; hedged nonces (RFC 6979 section 3.6) |
| `keys` | KZ GOST and RSA public and private keys; RSA PKCS#1 v1.5 (blinded) |
| `p12` | Opening .p12 key files as Kalkan writes them (BER, 3DES, RC2-40, SHA-1 MAC) and PBES2 (AES) |
| `der`, `time` | ASN.1 reading (DER and Kalkan's BER) and DER writing; ASN.1 times |
| `cert` | X.509 certificates: fields, names, key usage, policies, whether a certificate may sign |
| `cms` | CMS SignedData: reading, writing, CAdES-BES signing as NCALayer does, co-signing |
| `verify` | One signer's signature, signed attributes and signing-certificate binding |
| `trust` | Certificate paths to trusted CAs (NCA RK's root and issuing CAs are built in, `certs/`) |
| `tsp` | Timestamp requests (RFC 3161), checking the answer against the request, checking tokens |
| `ocsp` | OCSP requests (with nonce), checking answers: signature, responder, nonce, freshness |
| `crl` | Revocation lists and delta lists: reading, checking, and what they say about a certificate |
| `text` | Messages for people: an English template and its arguments |

## The boundary

The crate is `#![no_std]` with `alloc` and `#![forbid(unsafe_code)]`. It has no files, network,
clock, threads or operating-system random numbers. CI builds it for a bare-metal ARM target
(`thumbv7em-none-eabihf`) to prove it.

What the caller does:

* **I/O.** It reads key files and documents, sends the timestamp and OCSP requests this crate
  builds (`tsp::Request`, `ocsp::request`), hands the answers back (`tsp::read_answer`,
  `ocsp::read_fresh`), and downloads revocation lists from the addresses `crl::urls` gives.
* **Time.** It passes the current time in, in milliseconds since 1970 (UTC): the signing time,
  the moment to check a certificate path at, and when an OCSP answer arrived.
* **Randomness.** It passes a random source in (the `Rng` trait), used for signature nonces,
  RSA blinding and request nonces. A failing source stops the operation with
  `ErrorKind::Random`; it is never replaced by zeros or by something weaker. GOST nonces are
  hedged: even with a broken source they differ for every message and key, so a signature
  never gives the private key away.
* **Words.** Errors and statuses are `Text` (English template and arguments). The application
  translates the template and shows times in the reader's time zone. `Display` gives English.

Errors carry an `ErrorKind` (`Malformed`, `Unsupported`, `WrongPassword`, `Random`, `Other`) for
programs.

## Size

The release profile uses `opt-level = "z"`, LTO, one codegen unit, `panic = "abort"` and
stripping.

## Known gaps (follow-ups)

* **Panics on malformed input.** Some parsers index slices directly, so a malformed file can
  panic, and with `panic = "abort"` that ends the process. The plan is to deny
  `clippy::indexing_slicing` in this crate and return `ErrorKind::Malformed` instead.
* **Fixtures.** The tests read `../tests/fixtures`. Moving the crate to its own repository means
  copying the keys, CA certificates and NCA captures it uses.
