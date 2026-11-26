# GOST 34.310-2004 signatures, for checking only

kzsigner no longer signs with GOST 2004 keys (NCA stopped issuing them, and its TSA no longer
stamps them), but documents signed with them years ago must still check. These files were
made by kzsigner itself with `keys/alice_gost2004.p12` and `keys/bob_gost2004.p12` (CA
`keys/ca_gost2004.cer`) on 2026-11-26, just before signing with these keys was turned off:

* `pades.pdf`: `pdf/plain.pdf` signed inside (PAdES) by alice, then bob
* `signed.xml`: `req.xml` signed (XAdES B-B) by alice
* `detached.cms`: a detached signature of `doc.txt` by alice, made from its GOST 34.311 hash

Files Kalkan made with GOST 2004 keys are in `../kalkan/` (`cosigned_gost2004.cms`,
`timestamped_gost2004.cms`).
