#!/bin/sh
# Copies the test files into the fuzz corpora, as starting points.
set -eu
cd "$(dirname "$0")"
mkdir -p corpus/verify corpus/open_key corpus/extract corpus/cert corpus/crl corpus/ocsp corpus/tsp corpus/cms
find ../tests/fixtures ../desktop/tests -type f \( -name '*.cms' -o -name '*.pdf' -o -name '*.xml' -o -name '*.p7s' \) \
    -size -2M -exec cp {} corpus/verify/ \;
find ../tests/fixtures -type f -name '*.cms' -size -2M -exec cp {} corpus/extract/ \;
find ../tests/fixtures -type f -name '*.p12' -exec cp {} corpus/open_key/ \;
find ../tests/fixtures ../crates/kzcrypto-nca/certs -type f \( -name '*.cer' -o -name '*.crt' -o -name '*.pem' \) \
    -exec cp {} corpus/cert/ \;
find ../tests/fixtures -type f \( -name '*.crl' -o -name '*.der' \) -size -2M -exec cp {} corpus/crl/ \;
find ../tests/fixtures -type f \( -name '*.der' -o -name '*.ocsp' \) -size -2M -exec cp {} corpus/ocsp/ \;
find ../tests/fixtures -type f \( -name 'ts*.der' -o -name '*.tsr' -o -name '*.tsq' \) -exec cp {} corpus/tsp/ \;
find ../tests/fixtures -type f \( -name '*.cms' -o -name '*.p7s' \) -size -2M -exec cp {} corpus/cms/ \;
