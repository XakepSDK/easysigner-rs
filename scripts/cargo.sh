#!/bin/sh
# Runs cargo so that the executables do not depend on where they were built, which makes
# release builds reproducible: the same commit gives byte-identical files on any machine, in
# any folder (with the compiler pinned in rust-toolchain.toml and crates in Cargo.lock).
#
#   sh scripts/cargo.sh                 # = cargo build --release --locked
#   sh scripts/cargo.sh test --release  # any other cargo command, with the same settings
#
# It maps the source and cargo folders to fixed names in the paths the compiler records (panic
# locations), and on Windows (MSVC) asks the linker for a fixed timestamp instead of the time.
# It also hides pkg-config: nothing here links a system library, but some build scripts record
# what they find (x11-dl stores the X11 library folder), which would make the output depend on
# the -dev packages installed on the build machine.
set -eu
cd "$(dirname "$0")/.."
src=$(pwd)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
if command -v cygpath >/dev/null 2>&1; then # Git Bash on Windows: the compiler sees C:\...
    src=$(cygpath -w "$src")
    cargo_home=$(cygpath -w "$cargo_home")
fi
flags="--remap-path-prefix=$cargo_home=/cargo"
flags="$flags$(printf '\037')--remap-path-prefix=$src=/build"
case "$(rustc -vV | sed -n 's/^host: //p')" in
*-windows-msvc) flags="$flags$(printf '\037')-Clink-arg=/Brepro$(printf '\037')-Clink-arg=/PDBALTPATH:%_PDB%" ;;
esac
export CARGO_ENCODED_RUSTFLAGS="$flags"
export PKG_CONFIG_LIBDIR=/nonexistent PKG_CONFIG_PATH= PKG_CONFIG_SYSROOT_DIR=
unset RUSTFLAGS
if [ $# -eq 0 ]; then
    set -- build --release --locked
fi
exec cargo "$@"
