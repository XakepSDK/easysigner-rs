# Files the app's emulator tests sign and check

* `act.xml`, `doc.txt`: to sign (an XML file, any other file).
* `contract-signed.pdf`, `act.txt.cms`: signed by carol (`../ocsp/carol.p12`) against the fake NCA
  servers (`tests/common/nca.rs`), with their time stamp and OCSP answer kept inside.
* `act-changed.txt.cms`: `act.txt.cms` with its text changed after signing.
* `doc.txt.cms`: a detached signature of `doc.txt` (a copy of `../kalkan/detached_gost2015.cms`).
* `rsa.txt.cms`: signed with a key whose CA the test build doesn't trust (a copy of
  `../kalkan/timestamped_rsa.cms`).

Made by `cargo test -p kzsigner-ffi make_app_fixtures -- --ignored --nocapture`, which also prints
what checking each gives. Test keys only; nothing here is a real NCA certificate.
