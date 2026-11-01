# Live NCA TSP exchanges (captured 2026-11-01, http://tsp.pki.gov.kz/)

Every request was a POST with `Content-Type: application/timestamp-query`. Each `tsr.der` is the raw HTTP response body.
`data.bin` holds the 21 bytes `kzsigner test vector\n`. The generator script is `make_request.py` (it uses asn1crypto and gostcrypto).

- **sha256-policy-6.2/**: policy 1.2.398.3.3.2.6.2. Hash is SHA-256 (2.16.840.1.101.3.4.2.1), digest `2816b969405b2aa272c8251ef223c8d057e51689cbfabd4044320e27304d838c`.
  The reply is Granted. The TSA signed with RSA (sha256WithRSAEncryption) and SHA-256 as the digest algorithm. The serial number is negative.
- **gost2015-policy-6.4/**: policy 1.2.398.3.3.2.6.4. Hash is GOST 34.11-2015 Streebog-512 (1.2.398.3.10.1.3.3), digest
  `0148bde054cad0429f3ca653c658b5b86f77edb3b8102eb176bdb3dc73407ec99bac7318f12f588529c800bf64f87fb1f8f6e984299da7534491c1a66f62796a`
  (computed with gostcrypto `streebog512`, in standard byte order). The reply is Granted. The TSA key is GOST 2015 (1.2.398.3.10.1.1.2.2). The serial number is negative.
  Caveat: the TSA does not check the digest against any data, so this capture does not prove which byte order NCA expects.
- **rejected-policy-6.1/**: policy 1.2.398.3.3.2.6.1. Hash is GOST 34.311 (1.2.398.3.10.1.3.1), with a placeholder all-zero 32-byte digest and no data.bin.
  The reply is **Rejected: "Missing certificate or key error!"**. Policy 6.1 is rejected the same way with SHA-256, so it looks like NCA has retired policy 6.1. Hash OIDs other than 1.2.398.3.10.1.3.1 got "Unrecognized or unsupported Algorithm Identifier!". I tried 1.2.398.3.10.1.3.2, 1.2.643.2.2.9 and 1.3.6.1.4.1.6801.1.1.1.
