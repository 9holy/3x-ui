#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
platform=${1:?usage: build-release.sh PLATFORM [OUTPUT]}
output=${2:-dist}
mkdir -p "$output"
output=$(cd "$output" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CGO_ENABLED=1 GOOS=linux GOARCH="$platform"
export CGO_CFLAGS="-O2"
case "$platform" in
  amd64) export CC=gcc ;;
  arm64) export CC=aarch64-linux-gnu-gcc ;;
  386) export CC=i686-linux-gnu-gcc ;;
  armv7)
    export GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc
    export CGO_CFLAGS="-O2 -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard" ;;
  armv6)
    export GOARCH=arm GOARM=6 CC=arm-linux-gnueabi-gcc
    export CGO_CFLAGS="-O2 -march=armv6 -mfloat-abi=soft" ;;
  armv5)
    export GOARCH=arm GOARM=5 CC=arm-linux-gnueabi-gcc
    export CGO_CFLAGS="-O2 -march=armv5te -mfloat-abi=soft" ;;
  s390x) export CC=s390x-linux-gnu-gcc ;;
  *) echo "Unsupported platform: $platform" >&2; exit 1 ;;
esac
# The C tools must use the same ARM ISA as the Go/SQLite panel binary.
export AWG_CC="$CC $CGO_CFLAGS"
mkdir -p "$work/x-ui/bin"
go build -trimpath -tags 'netgo,osusergo,sqlite_omit_load_extension' \
  -ldflags '-s -w -linkmode external -extldflags -static' -o "$work/x-ui/x-ui" .
cp x-ui.sh x-ui.service LICENSE "$work/x-ui/"
chmod 755 "$work/x-ui/x-ui" "$work/x-ui/x-ui.sh"
./DockerInit.sh "$platform" "" "$work/x-ui/bin"
if [ "$GOARCH" = arm ]; then
  cp "$work/x-ui/bin/xray-linux-arm" "$work/x-ui/bin/xray-linux-$platform"
fi
python3 scripts/release.py seal "$work/x-ui" "$platform"
tar --sort=name --owner=0 --group=0 --numeric-owner \
  -czf "$output/x-ui-linux-$platform.tar.gz" -C "$work" x-ui
python3 scripts/release.py verify "$output/x-ui-linux-$platform.tar.gz" "$platform"
