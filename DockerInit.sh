#!/bin/sh
set -eu

# Shared by Docker and release archives. $1 is TARGETARCH (or a release
# platform), $2 is TARGETVARIANT, and $3 optionally overrides build/bin.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
download() {
    python3 "${SCRIPT_DIR}/scripts/download-runtime.py" "$1" "$2"
}

GO_ARM=""
TUIC_TARGET=""
case "${1:-amd64}" in
    amd64 | x86_64)
        PLATFORM="amd64"
        GO_ARCH="amd64"
        XRAY_ZIP="64"
        TUIC_TARGET="x86_64-unknown-linux-musl"
        ;;
    386 | i386 | i686)
        PLATFORM="386"
        GO_ARCH="386"
        XRAY_ZIP="32"
        TUIC_TARGET="i686-unknown-linux-musl"
        ;;
    arm64 | armv8 | aarch64)
        PLATFORM="arm64"
        GO_ARCH="arm64"
        XRAY_ZIP="arm64-v8a"
        TUIC_TARGET="aarch64-unknown-linux-musl"
        ;;
    arm | arm32 | armv7 | armv6 | armv5)
        GO_ARCH="arm"
        case "${1:-arm}:${2:-}" in
            armv5:* | *:v5) GO_ARM="5" ;;
            armv6:* | *:v6) GO_ARM="6" ;;
            armv7:* | arm: | arm32: | *:v7) GO_ARM="7" ;;
            *)
                echo "DockerInit: unsupported ARM variant '${2:-}'" >&2
                exit 1
                ;;
        esac
        PLATFORM="armv${GO_ARM}"
        XRAY_ZIP="arm32-v${GO_ARM}"
        if [ "$GO_ARM" = "7" ]; then
            XRAY_ZIP="arm32-v7a"
            TUIC_TARGET="armv7-unknown-linux-musleabihf"
        fi
        ;;
    s390x)
        PLATFORM="s390x"
        GO_ARCH="s390x"
        XRAY_ZIP="s390x"
        ;;
    *)
        echo "DockerInit: unsupported architecture '${1:-}'" >&2
        exit 1
        ;;
esac

# Keep the protocol core identical in Docker images and release archives.
XRAY_VERSION="v$(cat "${SCRIPT_DIR}/config/xray-version")"
MTG_VERSION="1.16.1"
TUIC_VERSION="1.0.0"
AWG_TOOLS_VERSION="v3.1.20260812"
AWG_GO_VERSION="v3.1.20260828"

mkdir -p "${3:-build/bin}"
BIN_DIR=$(cd "${3:-build/bin}" && pwd)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
cd "$WORK_DIR"

download "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ZIP}.zip" xray.zip
unzip -q xray.zip
cp xray "${BIN_DIR}/xray-linux-${GO_ARCH}"
chmod +x "${BIN_DIR}/xray-linux-${GO_ARCH}"

MTG_PACKAGE="mtg-multi-${MTG_VERSION}-linux-${PLATFORM}"
download "https://github.com/MHSanaei/mtg-multi/releases/download/v${MTG_VERSION}/${MTG_PACKAGE}.tar.gz" mtg.tar.gz
tar -xzf mtg.tar.gz
cp "${MTG_PACKAGE}/mtg-multi" "${BIN_DIR}/mtg-linux-${GO_ARCH}"
chmod +x "${BIN_DIR}/mtg-linux-${GO_ARCH}"

# The TUIC project publishes no armv5, armv6, or s390x runtime. Preserve the
# other protocols on those platforms instead of shipping an incompatible CPU
# binary. The panel reports a missing TUIC runtime if one is requested.
if [ -n "$TUIC_TARGET" ]; then
    download "https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${TUIC_VERSION}/tuic-server-${TUIC_VERSION}-${TUIC_TARGET}" "${BIN_DIR}/tuic-server-linux-${GO_ARCH}"
    chmod +x "${BIN_DIR}/tuic-server-linux-${GO_ARCH}"
else
    rm -f "${BIN_DIR}/tuic-server-linux-${GO_ARCH}"
    echo "DockerInit: TUIC runtime is not available for ${PLATFORM}; install a compatible tuic-server-linux-${GO_ARCH} manually to enable it." >&2
fi

# Build the tools for the selected CPU/libc. The upstream Alpine zip contains
# a single architecture and must not be copied into every target image.
download "https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/${AWG_TOOLS_VERSION}.tar.gz" awg-tools.tar.gz
tar -xzf awg-tools.tar.gz
AWG_TOOLS_DIR="amneziawg-tools-${AWG_TOOLS_VERSION#v}/src"
# The workflow's PLATFORM names a CPU, while this upstream Makefile uses it
# for the operating system and its UAPI include directory.
make -C "$AWG_TOOLS_DIR" PLATFORM=linux CC="${AWG_CC:-${CC:-cc}}" LDFLAGS=-static \
    WIREGUARD_TOOLS_VERSION="${AWG_TOOLS_VERSION#v}" wg
cp "${AWG_TOOLS_DIR}/wg" "${BIN_DIR}/awg"
cp "${AWG_TOOLS_DIR}/wg-quick/linux.bash" "${BIN_DIR}/awg-quick"
chmod +x "${BIN_DIR}/awg" "${BIN_DIR}/awg-quick"

download "https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/${AWG_GO_VERSION}.tar.gz" amneziawg-go.tar.gz
tar -xzf amneziawg-go.tar.gz
(
    cd "amneziawg-go-${AWG_GO_VERSION#v}"
    # Release archives have no .git directory for upstream's Makefile version
    # generation, so record the pinned source tag explicitly.
    printf 'package main\n\nconst Version = "%s"\n' "$AWG_GO_VERSION" > version.go
    GOTOOLCHAIN=go1.25.0+auto GOOS=linux GOARCH="$GO_ARCH" GOARM="$GO_ARM" CGO_ENABLED=0 go build -trimpath -o "${BIN_DIR}/amneziawg-go" .
)
chmod +x "${BIN_DIR}/amneziawg-go"

download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202611072203/geoip.dat" "${BIN_DIR}/geoip.dat"
download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202611072203/geosite.dat" "${BIN_DIR}/geosite.dat"
download "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/download/202611081129/geoip.dat" "${BIN_DIR}/geoip_IR.dat"
download "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/download/202611081129/geosite.dat" "${BIN_DIR}/geosite_IR.dat"
download "https://github.com/vuong2023/vn-v2ray-rules/releases/download/202405010158/geoip.dat" "${BIN_DIR}/geoip_VN.dat"
download "https://github.com/vuong2023/vn-v2ray-rules/releases/download/202405010158/geosite.dat" "${BIN_DIR}/geosite_VN.dat"
