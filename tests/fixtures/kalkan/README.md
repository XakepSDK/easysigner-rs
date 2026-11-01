# Kalkan compatibility fixtures

Throwaway test keys (password `Qwerty12`) and `.cms` files made with NCA RK's own Kalkan library
(kalkancrypt 0.7.8 / knca_provider_util 0.8.8, the crypto NCALayer uses), before kzsigner dropped
it. `test/run-tests.sh` checks that kzsigner still opens these keys and verifies and co-signs these
files. None of this is a real NCA certificate; `ca_*.cer` are test CAs, and the timestamps come from
a fake local test TSA.

* `alice_*.p12`, `bob_*.p12`, `ca_*.cer`: GOST 2015-512, GOST 2004 and RSA test keys and CAs
* `cosigned_*.cms`: `doc.txt` signed by alice then bob (attached)
* `timestamped_*.cms`: signed by alice with a CAdES-T timestamp
* `detached_gost2015.cms`: detached signature of `doc.txt`
