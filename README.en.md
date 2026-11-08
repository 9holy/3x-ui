# 3X-UI — 9holy protocol maintenance fork

[中文说明](README.md) · [Stable releases](https://github.com/9holy/3x-ui/releases) · [Protocol audit](docs/protocol-support-audit.md)

This fork retains the aircross Vue panel and SQLite architecture while selectively adapting newer MHSanaei protocols, transports, security settings and subscriptions. Installation and updates use **9holy/3x-ui** releases.

## Install or upgrade

Run as root on a supported Linux system:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/9holy/3x-ui/main/install.sh)
```

Append `v2.4.3` to select that stable version. Existing installations can use `x-ui update` after switching to this fork's installer. The installer checks SHA256 and validates a consistent snapshot of the existing database using the new panel and bundled Xray before stopping the old service. A failed startup restores the previous program, database and running state.

## Docker

Download the matching `3x-ui-docker-linux-{amd64,arm64,armv7}.tar.gz` from the stable release, verify its entry in `SHA256SUMS`, and load it with `gzip -dc <archive> | docker load`. The image tag is `ghcr.io/9holy/3x-ui:2.4.3`; the public archive works without GHCR access. The Chinese README includes complete copyable commands and the Compose setup. A fresh container uses the inherited `admin/admin` login on port 2053; change it after first login. Existing mounted databases are preserved.

## Scope

The release includes Xray 26.10.31, MTG 1.16.1, Rust TUIC server 1.0.0 and AmneziaWG 3.1 tools/runtime. It supports modern XHTTP, Hysteria2, MASQUE, VLESS Encryption, REALITY ML-DSA, TLS ECH/pinning and the existing protocols. TUIC supports authentication, absolute expiration, disabling and reloads, but not per-user accounting/quotas, delayed expiration or Xray routing. AWG manages full interface configurations, not per-peer panel CRUD/accounting/subscriptions. TUN creation is not exposed.

Old H2/QUIC transports and explicitly empty legacy mKCP seeds require migration before upgrading. The detailed audit documents these boundaries. TUIC has no bundled official runtime on armv5, armv6 or s390x; other protocols remain available on those architectures.

Seven native Linux packages and three Docker archives are built and tested. Publishing follows successful architecture/runtime, database, race, browser, installer rollback and Docker reload checks, with all remote release bytes verified before promotion from draft to stable.

## Upstream credits

[aircross/3x-ui](https://github.com/aircross/3x-ui) provides the panel baseline; [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui) provides later protocol references. Thanks also to [alireza0](https://github.com/alireza0), [XTLS](https://github.com/XTLS), [TUIC](https://github.com/tuic-protocol/tuic), [MTG](https://github.com/MHSanaei/mtg-multi) and [AmneziaVPN](https://github.com/amnezia-vpn).

License: [GPL-3.0](LICENSE).
