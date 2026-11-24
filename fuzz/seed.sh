#!/bin/sh
# Copies the test files into the fuzz corpora, as starting points.
set -eu
cd "$(dirname "$0")"
mkdir -p corpus/verify corpus/open_key corpus/extract
find ../tests/fixtures ../desktop/tests -type f \( -name '*.cms' -o -name '*.pdf' -o -name '*.xml' -o -name '*.p7s' \) \
    -size -2M -exec cp {} corpus/verify/ \;
find ../tests/fixtures -type f -name '*.cms' -size -2M -exec cp {} corpus/extract/ \;
find ../tests/fixtures -type f -name '*.p12' -exec cp {} corpus/open_key/ \;
