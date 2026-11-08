# 3X-UI — 9holy 协议维护版

[English](README.en.md) · [正式版本与安装包](https://github.com/9holy/3x-ui/releases) · [协议审核与兼容说明](docs/protocol-support-audit.md)

保留 **aircross/3x-ui 的 Vue 面板、SQLite 数据库和管理方式**，选择性补齐 MHSanaei/3x-ui 后续协议、传输、安全参数和订阅适配。此仓库的安装、升级和发行包统一来自 **9holy/3x-ui**。

## 安装与升级

在受支持的 Linux 主机上，以 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/9holy/3x-ui/main/install.sh)
```

安装指定正式版本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/9holy/3x-ui/main/install.sh) v2.4.3
```

已有安装可执行 `x-ui update`。由其他仓库安装的旧版，请先使用上面的命令切换安装器来源；旧管理脚本仍可能更新回原仓库。

安装器按 CPU 选择发行包并核对 SHA256。升级在停止旧服务前，用新程序和随包核心检查现有 SQLite 数据的一致性副本，包括已提交的 WAL 数据。检查失败保留原服务；替换后启动失败会恢复旧程序、数据库和原运行状态。旧数据库、面板账号、路径和相对路径证书会保留，备份路径会显示在安装日志中。

首次安装会显示生成的登录账号、密码、端口和访问路径。安装后使用 `x-ui` 打开管理菜单，或执行：

```bash
x-ui status
x-ui settings
x-ui restart
x-ui update
```

## Docker 安装

Release 提供已经构建的 Docker 镜像归档，支持 `amd64`、`arm64` 和 `armv7`，无需先从镜像仓库拉取。以下例子用于 **amd64**；其他 CPU 修改 `arch`。

```bash
(
  set -euo pipefail
  version=v2.4.3
  arch=amd64
  base="https://github.com/9holy/3x-ui/releases/download/$version"
  image="3x-ui-docker-linux-$arch.tar.gz"
  curl -fL -o "$image" "$base/$image"
  curl -fL -o SHA256SUMS "$base/SHA256SUMS"
  awk -v name="$image" '$2 == name { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS | sha256sum -c -
  gzip -dc "$image" | docker load
)
```

然后启动：

```bash
mkdir -p /opt/docker/3x-ui /opt/docker/acme.sh
docker run -d \
  --name 3x-ui \
  --network host \
  --restart unless-stopped \
  -v /opt/docker/3x-ui:/etc/x-ui \
  -v /opt/docker/acme.sh:/root/cert \
  ghcr.io/9holy/3x-ui:2.4.3
```

也可以克隆本仓库，加载对应架构的镜像归档后执行 `docker compose up -d`。容器首次启动继承原面板默认 `admin/admin` 和端口 `2053`，请在登录后设置自己的账号和访问路径；已有挂载数据库不会重置。原始 AWG 配置需要 TUN/网络管理能力时，使用仓库的 `docker-compose.tun.yml`：

```bash
docker compose -f docker-compose.yml -f docker-compose.tun.yml up -d
```

## 协议支持

| 功能 | 本版实现 |
| --- | --- |
| VMess、VLESS、Trojan、Shadowsocks | 原面板客户管理、流量统计、限额/到期、分享及订阅 |
| SOCKS、HTTP、Mixed、Tunnel | 配置管理；修正空账户、现代 Tunnel 字段和旧字段迁移 |
| WireGuard | 原有 Peer 配置及分享；修正 Hex/Base64 密钥、IPv6、仅私钥旧 Peer 的公钥派生 |
| XHTTP | 表单/JSON、导入导出、传输参数、订阅及原生核心热添加 |
| VLESS Encryption、REALITY ML-DSA、TLS ECH | 保留对应配置与客户端参数；X25519 密钥生成兼容新核心输出 |
| Hysteria2 | 入/出站、客户管理、TLS、混淆、客户端跳端口、URI 和 Xray JSON 订阅 |
| MASQUE | 入/出站、认证客户、TLS 与 Xray JSON；不生成没有通用标准的 URI |
| MTProto | 随包 MTG、FakeTLS、客户禁用/到期/限额、流量统计、Telegram 链接、变更重启 |
| TUIC v5 | 随包 Rust TUIC 1.0.0、UUID/密码、绝对日期到期、禁用、重载、URI |
| AmneziaWG 3.1 | 随包 AWG 工具与 Go runtime；完整 inline/file 配置、接口启动/停止/更新 |
| FinalMask、XDRIVE | 高级 JSON 与对应客户端配置保留；XDRIVE 使用 JSON |

TUIC 此版没有逐客户流量计量、流量配额、首次流量倒计时或 Xray 路由桥接；AWG 使用完整接口配置，没有面板逐 Peer CRUD/计量/订阅。界面和 API 按实际能力限制设置。TUN 不开放新建入口。详细支持范围与迁移要求见 [协议审核说明](docs/protocol-support-audit.md)。

## 核心与升级兼容性

本版面板 **2.4.3**，随包 Xray **26.10.31**、MTG **1.16.1**、TUIC server **1.0.0**、AmneziaWG tools **3.1.20260812** / Go **3.1.20260828**。

- 旧 H2 和旧 `network: "quic"` 传输已经被随包新核心移除。升级预检会明确提示，需先迁移服务端和客户端。Hysteria2/TUIC 所使用的 QUIC 不受此项影响。
- 旧 mKCP 非空 seed 和缺失 seed 有对应兼容处理；显式空 `seed: ""` 不能透明迁移，需修改并同步客户端。
- 新核心不能靠保留旧 `allowInsecure` 字段来关闭证书验证。使用有效证书或正确的证书固定/验证名。
- 面板内更新核心会校验官方 SHA256、CPU 架构、最低兼容版本和完整配置。新核心启动失败时恢复原核心。

## 发行平台与验证

Linux 原生包：`amd64`、`arm64`、`armv7`、`armv6`、`386`、`armv5`、`s390x`。TUIC 官方仅提供前四种中的 `amd64`/`arm64`/`armv7` 以及 `386`；其他三种包不会混装不兼容的 TUIC 二进制。需要 TUIC 时请选择有官方运行时的平台。

每次 PR/主分支发布流程包含：静态构建、逐文件 SHA256/ELF 架构检查、各架构执行与 SQLite 初始化、Go race、实际核心/MTG/TUIC、旧新 mKCP 通信、协议模型与真实浏览器保存编辑、安装失败回滚，以及三个 Docker 镜像导出后重新加载和 HTTP 启动检查。所有必需检查成功后，主分支才会上传 Release 草稿，重新下载核对全部资产，再发布为正式版本。

Release 内有七个原生包、三个 Docker 归档、`install.sh`、`x-ui.sh`、`release-manifest.json` 和 `SHA256SUMS`。源码提交和依赖版本记录在清单中。

## 感谢上游

- [aircross/3x-ui](https://github.com/aircross/3x-ui)：本分支面板与管理方式的基线。
- [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui)：后续协议支持和实现参考。
- [alireza0](https://github.com/alireza0)、[XTLS/Xray-core](https://github.com/XTLS/Xray-core)、[MTG](https://github.com/MHSanaei/mtg-multi)、[TUIC](https://github.com/tuic-protocol/tuic)、[AmneziaVPN](https://github.com/amnezia-vpn)。

许可证：[GPL-3.0](LICENSE)。
