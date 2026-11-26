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
| `time` | ASN.1 times (including looser forms some CAs write), ISO-8601 |
| `cert` | X.509 certificates: fields, names, key usage, policies |
| `cms` | CMS SignedData: reading, writing, CAdES-BES signing as NCALayer does, co-signing |
| `verify` | One signer's signature, signed attributes and signing-certificate binding |
| `trust` | Certificate paths to the CAs the caller trusts, under a `Policy` (clock skew, OCSP freshness, path length) |
| `tsp` | Timestamp requests (RFC 3161), checking the answer against the request, checking tokens |
| `ocsp` | OCSP requests (with nonce), checking answers: signature, responder, nonce, freshness |
| `crl` | Revocation lists and delta lists: reading, checking, and what they say about a certificate |

It assumes no CA and no national rules. NCA RK's CA certificates, TSA policies, its signing
rules (Order 500) and its tolerances are in `kzcrypto-nca` (`crates/kzcrypto-nca`).

All formats are read and written with RustCrypto's `der`, `x509-cert`, `cms`, `x509-tsp`,
`x509-ocsp` and `pkcs12` (BER where Kalkan writes it). Signed parts are kept exactly as encoded.

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
* **Words.** None in errors. An `Error` is an enum of what went wrong, with data (an OID, a key
  alias, a parser's diagnostic), never a sentence; the application words it in its own
  language. Statuses (`trust::PathStatus`, `ocsp::Status`, `crl::ListStatus`,
  `cert::SigningRefusal`) are enums too.

`Error::kind()` gives the broad class (`Malformed`, `Unsupported`, `WrongPassword`, `Random`,
`Other`) and `Error::code()` a stable number for each variant, for logs and other languages.

## No panics

Malformed input is an error, never a panic: with `panic = "abort"` a panic would end the
caller's process. Library code (this crate, `kzcrypto-nca` and `gost3410`) may not index or
slice, `unwrap`, `expect` or `panic!` (clippy's `indexing_slicing`, `unwrap_used`,
`expect_used` and `panic`, which CI turns into errors). Tests and the `testkit` helpers may.

## Self-tests

`self_test()` runs known-answer tests: GOST 34.311-95, Streebog-256 and -512, SHA-1 and
SHA-256 on standard vectors, and on each of the three GOST curves a signature made elsewhere
(by Kalkan, or by kzcrypto's first, independent GOST code) that must check, and a fixed key
that must sign a fixed hash to a recorded signature. Opening a GOST key runs a pairwise check
(it signs, and its public key checks the signature). A failure is `Error::SelfTestFailed`. The
app runs `self_test()` once, before the first key is opened or anything is signed or checked.

## Size

The release profile uses `opt-level = "z"`, LTO, one codegen unit, `panic = "abort"` and
stripping.

## Known gaps (follow-ups)

* **Fixtures.** The tests read `../tests/fixtures`. Moving the crate to its own repository means
  copying the keys, CA certificates and NCA captures it uses.
