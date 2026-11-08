# 协议支持审核与修正

审核基线日期：2026-11-07；正式交付修订：2026-11-09，版本 2.4.3。范围是保留 aircross 的面板和 SQLite 架构，选择性补齐协议、传输、安全参数、运行时及订阅链路；不做 MHSanaei 整仓升级。

## 对照基准

| 仓库 | 审核时主分支 | 结论 |
| --- | --- | --- |
| 9holy/3x-ui | `44f42d167b80cc38aa60ca0261c3332efff53b77` | 本次修复的起点 |
| aircross/3x-ui | `e0f9ee1fba6fb42c06b7046e2ea6c4b6d99d8e01` | 是 9holy 主分支祖先，第一阶段已完整继承 |
| MHSanaei/3x-ui | `e535df03745c5ad003ae48e812024eb5fdc2124d` | 用于核对当前协议 schema 和关键修复；不将其新面板、节点同步、其他业务模块整体合并 |

修复前的结论是：**aircross 对齐已完成，后续协议支持不能认定为完成**。原分支添加了协议名称和 JSON 入口，但部分路径会报错、静默丢字段、无法启动、修改不生效或生成错误订阅。

## 已修正的问题

| 问题 | 修正 |
| --- | --- |
| 出站引用不存在的 `xHTTPStreamSettings`，默认构造/导入出站报错 | 补齐 XHTTP 模型、别名迁移、传输字段及行为测试 |
| VLESS 客户端 encryption 被写死为 `none`，REALITY 新字段被丢弃 | 保留 encryption/decryption，区分服务端和客户端字段，补 ML-DSA `pqv`、Vision 适用条件和分享往返 |
| HY2 导入忽略 TLS/SNI、IPv6、编码凭据、混淆及跳端口 | 统一 URI 解析和输出，支持相关 TLS 与 finalmask 字段，校正证书指纹编码 |
| 后端白名单删除 HY2 `auth`，MASQUE 未转换 `password` → `pass` | 保留实际协议凭据，在核心输出边界转换；HY2 两处 version 固定为 2，MASQUE 补默认地址池 |
| 旧版内嵌配置解析器无法识别新版协议，部分字段被静默丢弃 | 热添加调用实际安装的 Xray `api adi`；不再用旧 `infra/conf` 构造新配置；不支持的用户热更新明确触发完整配置更新 |
| 不正确的配置可能在重启时影响所有入站 | 保存时验证相关原生配置，完整重启前执行实际核心 `run -test`，验证失败时保留正在运行的核心 |
| XHTTP、旧 mKCP、HY2/QUIC 调整项在保存或订阅中丢失 | 提供共同的协议兼容处理；mKCP 的旧 seed/header 转换为 finalmask；兼容旧 UDP hop 格式和 mask 顺序 |
| 客户端 UDP hop mask 被错误发送给服务端 | 在核心入站输出时剥离客户端专属 mask；数据库和订阅中保留客户端配置 |
| TUIC 将面板 `clients` 直接传给拒绝未知字段的 Rust runtime | 转换为 runtime 的 `users`、字段名和 duration 格式；配置变更重载并过滤禁用/过期用户 |
| MTProto 对正在运行实例直接跳过，改密钥/端口不生效 | 按实际配置检测变化并重启，移除禁用/过期/超额用户，统计同时更新用户和入站 |
| AmneziaWG 把一次性的 `awg-quick up` 当成常驻服务 | 以接口生命周期处理 up/down，正确处理 inline/file 配置、接口名和变更重载 |
| Sidecar 客户 CRUD 仍按旧 UUID 逻辑查找或丢掉凭据 | 对 HY2、MASQUE、TUIC、MTProto 使用一致的客户标识，补齐旧面板表单与 API 处理 |
| Sidecar JSON 订阅生成只有默认直连出口的配置 | 对无法表示为 Xray outbound 的协议不生成虚假的 JSON 代理配置；保留受支持的标准 URI |
| JSON 订阅可能泄露未激活 TLS/REALITY 块中的服务端私钥 | 输出只构造当前客户端需要的安全参数，移除未激活安全块和服务端证书私钥；增加密钥哨兵回归 |
| External Proxy 循环复用可变 stream，前一个端点影响后一个 | 每个端点单独复制，统一 IPv6、凭据编码、TLS/Flow 参数；订阅请求的地址状态不再共享 |
| Docker 与 release runtime 不一致、部分架构二进制命名错误 | 共同打包入口，按真实架构选择/构建；没有官方 TUIC 资产的架构明确说明，不混放不兼容二进制 |
| 节点管理与同步模块超出“仅协议支持” | 移除这次额外添加的 Node 页面、路由、服务、模型及迁移注册；不删除历史数据库表 |

## 修复后的支持范围

| 能力 | 状态与边界 |
| --- | --- |
| VMess、VLESS、Trojan、Shadowsocks、SOCKS/HTTP、WireGuard 原有模型 | 保留旧面板；针对协议数据往返、订阅和核心生成增加校验。不是对全部客户端/网络环境的端到端认证 |
| Mixed、Tunnel | 增加对应配置入口；旧 SOCKS、dokodemo 名称仍可读取 |
| XHTTP | 表单与高级 JSON、别名、mode/extra、padding、session 参数、客户端/服务端字段区分及订阅支持 |
| VLESS Encryption、REALITY ML-DSA、TLS ECH/证书固定/验证名 | 配置与客户端输出支持；密钥由用户提供，完整客户端组合仍需实际部署验证 |
| FinalMask、XDRIVE | 高级 JSON 保留协议配置；XDRIVE 使用 JSON 配置，不伪造不存在的通用分享 URI |
| Hysteria2 | 原生入站/出站、客户管理、URI、Xray JSON、TLS、混淆、客户端跳端口配置 |
| MASQUE | 原生配置、认证客户、Xray JSON；不宣称存在标准 MASQUE 分享 URI |
| MTProto | MTG sidecar、有效 FakeTLS secret、变更重载、禁用/到期/限额、流量统计与 Telegram URI |
| TUIC | 固定 TUIC v1.0.0 sidecar 的配置适配、认证客户、绝对日期到期禁用、重载、URI。**没有逐用户流量计量和 Xray 路由桥接**；拒绝流量配额及依赖首次流量的延迟计时，不生成虚假 Xray JSON。原生 `users` map 配置使用 JSON 编辑；只有存在 `clients` 数组时开放面板客户 CRUD |
| AmneziaWG | 完整接口配置/配置文件的启动、停止和更新。**没有面板逐 Peer 的客户端 CRUD、流量计量和订阅**；拒绝不具备映射或计量能力的客户端/配额设置 |
| TUN | 不提供新建入口，保留已有配置数据的读取。不能把它与已完整实现的普通入站管理混为一谈 |

这些边界是实际实现差异，不能据此宣称已经复制了 MHSanaei 新架构下的全部协议管理功能。

## 升级与迁移注意事项

1. **旧 H2 与旧 `network: "quic"` 传输已被固定的 Xray 26.10.31 移除。** 新建入口不再提供这两种传输，存量配置保留并显示迁移提示；需同时迁移服务端与客户端到适用的 XHTTP 模式并刷新订阅。这不是 Hysteria2/TUIC 所使用的 QUIC 协议被移除。
2. **mKCP 的缺失 seed 与显式空 seed 不同。** 旧配置缺失 seed 的原始认证方式可转换为相应 legacy mask。旧配置显式 `seed: ""` 无法与新核心空 mask 做透明等价映射，因此明确拒绝静默迁移；设置非空 seed 并同步更新客户端。
3. 旧 TLS `allowInsecure` 不能被当作新版 Xray 已支持的能力。使用有效证书和需要的证书固定/验证名。已保存的服务端密钥不会下发到订阅。
4. TUIC/AWG 的高级运行时适配不能替代上游完整的逐客户计量与路由实现。界面说明和服务端拒绝逻辑一致，避免配置了限制却没有实际执行。
5. AmneziaWG 的真实接口需要运行环境提供网络管理权限及适当的 TUN/内核能力。此修复没有自动修改部署权限。裸机还需要 `bash`、`iproute2`、`iptables`、`resolvconf` 等运行依赖；容器使用者应按自身部署配置能力与设备。

## 打包版本与平台

| 组件 | 固定版本 |
| --- | --- |
| Xray | `v26.10.31` |
| MTG | `v1.16.1` |
| TUIC server | `1.0.0` |
| AmneziaWG tools | `v3.1.20260812` |
| AmneziaWG Go | `v3.1.20260828` |
| 面板 Go 工具链 | `1.23.1`；AWG 单独使用其所需的 Go 1.25 工具链 |

官方 TUIC 资产覆盖 amd64、386、arm64、armv7；armv5、armv6、s390x 不伪装为受支持平台。需要 TUIC 时须自行提供兼容的 `tuic-server-linux-${GOARCH}`。Xray、MTG、AWG 的打包映射保持独立。

已实际执行完整 amd64 runtime 打包，并检查五类运行时的版本。其他平台做了架构选择与文件名逻辑验证，没有把模拟结果当成所有架构实机运行通过。

## 验证方法

普通回归：

```sh
go test -race ./...
node --test scripts/test-protocol-models.js
sh -n DockerInit.sh
git diff --check
```

带真实 runtime 的回归（路径按实际打包目录和架构调整）：

```sh
XUI_TEST_XRAY="$PWD/bin/xray-linux-amd64" \
MTPROTO_TEST_BINARY="$PWD/bin/mtg-linux-amd64" \
TUIC_TEST_BINARY="$PWD/bin/tuic-server-linux-amd64" \
go test -race ./...

XRAY_BINARY="$PWD/bin/xray-linux-amd64" \
node --test scripts/test-protocol-models.js
```

实际验证涵盖：核心配置解析及启动、XHTTP 原生热添加后查询运行态字段、MTG 真实启动与带认证的统计接口、TUIC 真实 QUIC/TLS 握手、SQLite 客户 CRUD/配额状态、订阅凭据与参数、私钥不外泄、旧协议导出回归。AWG 用可控 `awg-quick` 验证生命周期；未在此环境中验证真实内核/TUN 数据转发。

面板验证使用独立数据库：真实 HTTP 登录及入站/Xray 页面返回成功，生产 Vue 编译器和实际返回的模板通过新建/编辑入站、出站导入、四种新协议客户管理及迁移阻断检查。环境限制阻止启动 Chromium，云端浏览器也不能访问隔离容器的 localhost，因此这些属于 HTTP/组件集成验证，不宣称完成浏览器端到端或视觉布局验证。

另已使用旧 Xray 24.9.19 客户端连接新 Xray 26.10.31 服务端，四种 mKCP 组合（非空 seed + none/wechat-video、缺失 seed + none/srtp）均完成本地 SOCKS5 → HTTP 200 往返。删除 original mask 的负对照按预期超时。可用本地二进制复现：

```sh
LEGACY_XRAY_BINARY=/path/to/xray-24.9.19 \
XUI_TEST_XRAY=/path/to/xray-26.10.31 \
python3 scripts/test-kcp-compat.py --go /path/to/go
```

该脚本只访问 localhost，不自动下载核心；Go 模块需要已在本地缓存。

`XUI_TEST_XRAY`、`MTPROTO_TEST_BINARY`、`TUIC_TEST_BINARY`、`XRAY_BINARY` 未指定时，对应的真实 runtime 测试会明确跳过；普通编译通过不等于这些运行测试已经执行。

## 参考源码

- [9holy 审核起点](https://github.com/9holy/3x-ui/commit/44f42d167b80cc38aa60ca0261c3332efff53b77)
- [aircross 对齐基线](https://github.com/aircross/3x-ui/commit/e0f9ee1fba6fb42c06b7046e2ea6c4b6d99d8e01)
- [MHSanaei 对照快照](https://github.com/MHSanaei/3x-ui/commit/e535df03745c5ad003ae48e812024eb5fdc2124d)
- [上游协议 schema](https://github.com/MHSanaei/3x-ui/tree/e535df03745c5ad003ae48e812024eb5fdc2124d/frontend/src/schemas/protocols)
- [上游核心输出转换](https://github.com/MHSanaei/3x-ui/blob/e535df03745c5ad003ae48e812024eb5fdc2124d/internal/database/model/model.go)
- [上游分享链接生成](https://github.com/MHSanaei/3x-ui/blob/e535df03745c5ad003ae48e812024eb5fdc2124d/internal/sub/service.go)
- [上游 JSON 订阅生成](https://github.com/MHSanaei/3x-ui/blob/e535df03745c5ad003ae48e812024eb5fdc2124d/internal/sub/json_service.go)

## 正式交付修订

本轮以 GitHub 上已保存的第一轮修正为基础完成正式发行，不把上次中断时未提交的原生 TUIC/AWG 扩展当作发行能力。上文列出的 Rust TUIC / 完整配置 AWG 边界继续成立。

- 修复 raw 协议普通对象被 `toString()` 转为 `[object Object]` 的真实提交错误，使用统一 `toJson()` 保存，再由真实浏览器验证保存后重新打开。
- 修复 Mixed/HTTP 空账户导入、Tunnel 现代字段和旧字段迁移、WG Hex/Base64 私钥派生与 IPv6 分享、无到期误标及无客户详情弹窗错误。
- Xray 启动同步返回进程错误，停止等待退出，配置文件权限 0600；进程、在线客户和日志状态使用同步保护。
- 核心更新按正确 ARM ISA 下载并验证官方 SHA256，限制最低版本 26.10.31，候选核心预检，启动失败恢复旧程序和运行状态；X25519 输出兼容新版标签并验证格式。
- 安装器、管理脚本、README、Docker 与 Release 全部使用 9holy 仓库。升级前只对一致性 SQLite 副本迁移与检查；失败恢复旧程序、数据库和原启停状态。
- PR 和主分支均运行七架构静态包/QEMU/SQLite、实际 runtime、race、模型/浏览器、旧 mKCP、安装回滚与三架构 Docker 导出重载检查。主分支验证全部14项资产后，将草稿转换为非预发布的正式版本。

实际执行结果以该提交的 GitHub Actions 和 Release 清单为准；工作流中存在测试步骤不等于已经通过。
