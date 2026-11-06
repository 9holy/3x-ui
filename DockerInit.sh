#!/bin/sh
set -e

download() {
    curl -fL --retry 5 --retry-delay 2 --retry-all-errors -o "$2" "$1"
}
case $1 in
    amd64)
        ARCH="64"
        FNAME="amd64"
        ;;
    i386)
        ARCH="32"
        FNAME="i386"
        ;;
    armv8 | arm64 | aarch64)
        ARCH="arm64-v8a"
        FNAME="arm64"
        ;;
    armv7 | arm | arm32)
        ARCH="arm32-v7a"
        FNAME="arm32"
        ;;
    armv6)
        ARCH="arm32-v6"
        FNAME="armv6"
        ;;
    *)
        ARCH="64"
        FNAME="amd64"
        ;;
esac

case $1 in
    amd64 | "")
        TUIC_TARGET="x86_64-unknown-linux-musl"
        TUIC_BIN="tuic-server-linux-amd64"
        ;;
    i386)
        TUIC_TARGET="i686-unknown-linux-musl"
        TUIC_BIN="tuic-server-linux-386"
        ;;
    armv8 | arm64 | aarch64)
        TUIC_TARGET="aarch64-unknown-linux-musl"
        TUIC_BIN="tuic-server-linux-arm64"
        ;;
    armv7 | arm | arm32)
        TUIC_TARGET="armv7-unknown-linux-musleabihf"
        TUIC_BIN="tuic-server-linux-armv7"
        ;;
    armv6)
        TUIC_TARGET="armv7-unknown-linux-musleabihf"
        TUIC_BIN="tuic-server-linux-armv6"
        ;;
    *)
        TUIC_TARGET="x86_64-unknown-linux-musl"
        TUIC_BIN="tuic-server-linux-amd64"
        ;;
esac

case $1 in
    amd64 | "")
        MTG_PLATFORM="amd64"
        MTG_BIN="mtg-linux-amd64"
        ;;
    i386)
        MTG_PLATFORM="386"
        MTG_BIN="mtg-linux-386"
        ;;
    armv8 | arm64 | aarch64)
        MTG_PLATFORM="arm64"
        MTG_BIN="mtg-linux-arm64"
        ;;
    armv7 | arm | arm32 | armv6)
        MTG_PLATFORM="armv7"
        MTG_BIN="mtg-linux-arm"
        ;;
    *)
        MTG_PLATFORM="amd64"
        MTG_BIN="mtg-linux-amd64"
        ;;
esac

mkdir -p build/bin
cd build/bin
download "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-${ARCH}.zip" "Xray-linux-${ARCH}.zip"
unzip "Xray-linux-${ARCH}.zip"
rm -f "Xray-linux-${ARCH}.zip" geoip.dat geosite.dat
mv xray "xray-linux-${FNAME}"
download "https://github.com/mhsanaei/mtg-multi/releases/download/v1.16.1/mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz" "mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
tar -xzf "mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
mv "mtg-multi-1.16.1-linux-${MTG_PLATFORM}/mtg-multi" "${MTG_BIN}"
rm -rf "mtg-multi-1.16.1-linux-${MTG_PLATFORM}" "mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
chmod +x "${MTG_BIN}"
download "https://github.com/tuic-protocol/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-${TUIC_TARGET}" "${TUIC_BIN}"
chmod +x "${TUIC_BIN}"
download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" geoip.dat
download "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" geosite.dat
download "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat" geoip_IR.dat
download "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat" geosite_IR.dat
download "https://github.com/vuong2023/vn-v2ray-rules/releases/latest/download/geoip.dat" geoip_VN.dat
download "https://github.com/vuong2023/vn-v2ray-rules/releases/latest/download/geosite.dat" geosite_VN.dat
cd ../../
