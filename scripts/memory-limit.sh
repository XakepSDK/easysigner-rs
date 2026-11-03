#!/bin/sh
# Runs a test binary with at most 4 GB of address space. Under cargo mutants some mutants turn
# a loop into one that never ends and keeps allocating. Without a limit such a test eats all
# of the machine's memory, and the CI runner dies with it. With one, the test aborts and the
# mutant counts as caught.
ulimit -v 4194304
exec "$@"
