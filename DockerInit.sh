#!/bin/sh
set -e
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
wget -t 5 -T 30 "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-${ARCH}.zip"
unzip "Xray-linux-${ARCH}.zip"
rm -f "Xray-linux-${ARCH}.zip" geoip.dat geosite.dat
mv xray "xray-linux-${FNAME}"
wget -t 5 -T 30 "https://github.com/mhsanaei/mtg-multi/releases/download/v1.16.1/mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
tar -xzf "mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
mv "mtg-multi-1.16.1-linux-${MTG_PLATFORM}/mtg-multi" "${MTG_BIN}"
rm -rf "mtg-multi-1.16.1-linux-${MTG_PLATFORM}" "mtg-multi-1.16.1-linux-${MTG_PLATFORM}.tar.gz"
chmod +x "${MTG_BIN}"
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
wget -O geoip_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat
wget -O geosite_IR.dat https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat
wget -O geoip_VN.dat https://github.com/vuong2023/vn-v2ray-rules/releases/latest/download/geoip.dat
wget -O geosite_VN.dat https://github.com/vuong2023/vn-v2ray-rules/releases/latest/download/geosite.dat
cd ../../
