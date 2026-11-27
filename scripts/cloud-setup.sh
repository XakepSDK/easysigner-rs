#!/bin/bash
# Installs the build toolchain for a Claude Code cloud session (also used by the
# SessionStart hook in .claude/settings.json). Mirrors what CI installs
# (.github/workflows/*.yml). Idempotent: every step is skipped when already present.
set -eu
log() { echo "[cloud-setup] $*"; }
export DEBIAN_FRONTEND=noninteractive
SDK=${ANDROID_HOME:-/opt/android-sdk}
NDK_VER=30.0.16248370
GRADLE_VERSION=9.9.2
GRADLE_SHA256=971fcd7150ca4ba04852c0b2ca0d2d0ab9468e14b03473eab19528809914c76b
SUDO=; [ "$(id -u)" -eq 0 ] || SUDO=sudo

# 1. System packages: Windows cross-compiler (MinGW), window-test libraries, unzip
PKGS="mingw-w64 xvfb weston libxkbcommon-x11-0 libgl1-mesa-dri libegl1 libwayland-egl1 unzip"
missing=$(for p in $PKGS; do dpkg -s "$p" >/dev/null 2>&1 || echo "$p"; done)
if [ -n "$missing" ]; then
    log "apt: $missing"
    $SUDO apt-get update -qq || true
    $SUDO apt-get install -y -qq --no-install-recommends $missing >/dev/null
fi

# 2. Rust: the toolchain pinned in rust-toolchain.toml, with CI's targets and components
command -v rustup >/dev/null || {
    log "rustup"
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
}
export PATH=$HOME/.cargo/bin:$PATH
RUST=1.100.0
rustup toolchain list | grep -q "^$RUST-" || { log "rust $RUST"; rustup toolchain install "$RUST" --profile minimal; }
have_t=$(rustup target list --installed --toolchain "$RUST")
for t in x86_64-pc-windows-gnu aarch64-linux-android thumbv7em-none-eabihf; do
    echo "$have_t" | grep -qx "$t" || { log "target $t"; rustup target add --toolchain "$RUST" "$t"; }
done
have_c=$(rustup component list --installed --toolchain "$RUST")
for c in rustfmt clippy llvm-tools; do
    echo "$have_c" | grep -q "^$c" || { log "component $c"; rustup component add --toolchain "$RUST" "$c"; }
done

# 3. Android SDK parts (pinned, as in build.yml)
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
    log "android cmdline-tools"
    tmp=$(mktemp -d)
    curl -sSfL -o "$tmp/c.zip" https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
    $SUDO mkdir -p "$SDK/cmdline-tools"
    $SUDO unzip -q "$tmp/c.zip" -d "$tmp"
    $SUDO mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
    rm -rf "$tmp"
fi
if [ ! -d "$SDK/ndk/$NDK_VER" ] || [ ! -d "$SDK/build-tools/37.0.0" ] || [ ! -d "$SDK/platforms/android-37.0" ]; then
    log "android sdk: ndk $NDK_VER, build-tools 37.0.0, android-37.0"
    yes | $SUDO "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" --licenses >/dev/null || true
    $SUDO "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" \
        "ndk;$NDK_VER" "build-tools;37.0.0" "platforms;android-37.0" "platform-tools" >/dev/null
fi

# 4. Gradle for scripts/apk.sh (same cache folder and checksum as the script)
G=${XDG_CACHE_HOME:-$HOME/.cache}/kzsigner-gradle
if [ ! -x "$G/gradle-$GRADLE_VERSION/bin/gradle" ]; then
    log "gradle $GRADLE_VERSION"
    mkdir -p "$G"
    curl -sSfL -o "$G/g.zip" "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"
    echo "$GRADLE_SHA256  $G/g.zip" | sha256sum -c - >/dev/null
    (cd "$G" && unzip -q -o g.zip && rm g.zip)
fi

# 5. The crates in Cargo.lock, so builds start offline-ready (only inside the repository)
R=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$R/Cargo.lock" ] && (cd "$R" && cargo fetch --locked -q) || true

# 6. The environment for later shells (Claude's Bash tool reads CLAUDE_ENV_FILE in a hook)
ENVS="export ANDROID_HOME=$SDK ANDROID_NDK_ROOT=$SDK/ndk/$NDK_VER"
[ -n "${CLAUDE_ENV_FILE:-}" ] && echo "$ENVS" >> "$CLAUDE_ENV_FILE"
if [ -w /etc/profile.d ] && [ ! -f /etc/profile.d/kzsigner-android.sh ]; then
    echo "$ENVS" > /etc/profile.d/kzsigner-android.sh
fi
log "ready"
