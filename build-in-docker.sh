#!/bin/sh
# Build ti-verify for Linux in the reference environment (AB-152): Ubuntu 24.04 in Docker, with the
# Rust toolchain from rust-toolchain.toml. The release workflow and customers run the same script.
#   ./build-in-docker.sh x86_64-unknown-linux-musl      (on an x86_64 machine)
#   ./build-in-docker.sh aarch64-unknown-linux-musl     (on an arm64 machine)
# Packages come from the Ubuntu snapshot archive at a fixed time (TI_APT_SNAPSHOT), and the image
# is pinned by digest (override with TI_BUILD_IMAGE=ubuntu@sha256:...). A rebuild matches a release when both
# equal the values in that release's build-<target>.txt.
# Writes target/<target>/release/ti-verify and build-<target>.txt (image digest, snapshot, gcc,
# binutils, libc6-dev, musl, rustc), and prints the binary's SHA-256. TI_BUILD_HOME and TI_BUILD_MOUNT change the home folder
# and the source path inside the container: the second release build uses both, so a leaked path
# shows up as a hash difference.
set -eu
target=${1:?usage: ./build-in-docker.sh TARGET}
here=$(cd "$(dirname "$0")" && pwd -P)
# Ubuntu 24.04: the multi-arch index digest ubuntu:24.04 resolved to on the x86_64 and arm64 CI
# runners on 22 Nov 2026 (AB-154, read from the build note annotations of PR #41's first run).
image=${TI_BUILD_IMAGE:-ubuntu@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289}
snapshot=${TI_APT_SNAPSHOT:-20261120T000000Z}
home=${TI_BUILD_HOME:-/root}
mount=${TI_BUILD_MOUNT:-/ti-verify}
docker pull -q "$image" >/dev/null
# A digest reference is recorded as given: RepoDigests can list an older digest first when the
# machine already holds the same image under another tag.
case "$image" in
  *@sha256:*) digest=$image ;;
  *) digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image") ;;
esac
toolchain=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$here/rust-toolchain.toml")
docker run --rm -e HOME="$home" -e TARGET="$target" -e TOOLCHAIN="$toolchain" -e DIGEST="$digest" -e SNAPSHOT="$snapshot" \
  -v "$here:$mount" -w "$mount" "$image" sh -euc '
  mkdir -p "$HOME"
  # The snapshot archive is HTTPS only, so CA certificates come first from the image'"'"'s own archive.
  # They do not reach the binary: everything the build compiles with comes from the snapshot.
  apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ca-certificates >/dev/null
  apt-get update -q --snapshot "$SNAPSHOT" >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    --no-install-recommends --snapshot "$SNAPSHOT" ca-certificates curl gcc libc6-dev musl-tools git >/dev/null
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$TOOLCHAIN" >/dev/null
  . "$HOME/.cargo/env"
  rc=0; ./reproduce.sh "$TARGET" || rc=$?
  v() { dpkg-query -W -f "\${Version}" "$1"; }
  { echo "image: $DIGEST"; echo "apt snapshot: $SNAPSHOT"; echo "gcc: $(gcc --version | head -n1)"; echo "binutils: $(v binutils)"; echo "libc6-dev: $(v libc6-dev)"; echo "musl: $(v musl-tools)"; echo "rustc: $(rustc -V)"; } > "build-$TARGET.txt"
  chmod -R a+rX,u+w target "build-$TARGET.txt" 2>/dev/null || true
  exit $rc'
