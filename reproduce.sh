#!/bin/sh
# Build ti-verify exactly as a Texas Inference release does (AB-152), then print its SHA-256.
# Linux builds compile C (ring, aws-lc) with the host's musl-gcc, so the reference environment is
# the Ubuntu 24.04 container that ./build-in-docker.sh runs. This script is what runs inside it.
#   ./reproduce.sh x86_64-unknown-linux-musl     (Linux x86_64)
#   ./reproduce.sh aarch64-unknown-linux-musl    (Linux arm64, on an arm64 machine)
#   ./reproduce.sh aarch64-apple-darwin          (macOS on Apple silicon, best effort: the result
#                                                 also depends on the Xcode version in build-*.txt)
# The printed hash must equal the line for that target in the release's SHA256SUMS.
set -eu
target=${1:?usage: ./reproduce.sh TARGET}
here=$(cd "$(dirname "$0")" && pwd -P)
cd "$here"
rustup target add "$target" >/dev/null
# Paths, timestamps and build ids are the only inputs that differ between machines: fix them.
# The platform commit's time, recorded at export, so a clone's own commit time does not matter.
SOURCE_DATE_EPOCH=$(sed -n 's/.*"source_date_epoch": *\([0-9]*\).*/\1/p' .export.json)
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
# Physical paths, so a symlinked folder (macOS /tmp is /private/tmp) still remaps.
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" 2>/dev/null && pwd -P || echo "${CARGO_HOME:-$HOME/.cargo}")
rustup_home=$(cd "${RUSTUP_HOME:-$HOME/.rustup}" 2>/dev/null && pwd -P || echo "${RUSTUP_HOME:-$HOME/.rustup}")
flags="--remap-path-prefix=$here=/ti-verify --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup -C strip=symbols"
case "$target" in
  *-linux-musl) flags="$flags -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none" ;;
  # ld64 records object file paths (OSO) and hashes them into LC_UUID: strip the build folder.
  *-apple-darwin) flags="$flags -C link-arg=-Wl,-oso_prefix,$here/" ;;
esac
export RUSTFLAGS="$flags"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0
cargo build --locked --release -q -p ti-verify --target "$target"
bin="target/$target/release/ti-verify"
if command -v sha256sum >/dev/null; then sum=$(sha256sum "$bin" | cut -d' ' -f1); else sum=$(shasum -a 256 "$bin" | cut -d' ' -f1); fi
echo "$sum  ti-verify-$target"
