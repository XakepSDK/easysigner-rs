# cms 0.3.0-rc.2, patched

RustCrypto's `cms` crate as published (0.3.0-rc.2), without its tests, with one change in
`src/revocation.rs`: `OtherRevocationInfoFormat.other_format` is an `ObjectIdentifier`, as
RFC 5652 section 10.2.1 has it. Upstream types it as an `AlgorithmIdentifier`, so any CAdES
B-LT/B-LTA signature that keeps an OCSP answer (`[1] OtherRevocationInfoFormat` with
id-ri-ocsp-response) fails to parse. Reported upstream as RustCrypto/formats#2543, with a fix
in progress (#2545). The root `Cargo.toml` points `[patch.crates-io]` here; drop this copy
once a release has the fix.
