# Rustgo

Rustgo V1.0 是一款可自行托管的固定端口 TCP、UDP 和认证 P2P 隧道软件，并可选择启用内嵌可观测功能。私有网络中的客户端（`rustgoc` CLI 或 `rustgoc-gui`）通过 TLS 1.3 连接公网中继服务端（`rustgos`），使用独立的 Ed25519 设备密钥完成认证，并开放明确配置的端口。

V0.4 新增跨平台 GUI 客户端（`rustgoc-gui`），支持实时连接监控、隧道展示、流量图表、P2P 路径显示和受限的资源使用。GUI 与无界面的 `rustgoc` 共用同一个客户端库，无需修改即可连接 V0.1、V0.2 和 V0.3 服务端。在 Windows 上，GUI 提供系统托盘和最小化到托盘功能。

V0.3 新增可选的只读 Web 仪表盘，用于实时监控服务端和客户端、查看主机遥测数据、P2P 路径以及有上限的历史趋势。仪表盘仅监听本机回环地址，可通过反向代理提供 HTTPS，并完全兼容 V0.2 和 V0.1 客户端。

V0.2 引入具名的 `[[exports]]` 和 `[[forwards]]`。对端使用经服务端授权的设备密钥进行认证，从客户端固定端口范围尝试建立 QUIC/UDP 或原生 TCP 直连；策略允许时，直连失败会回退到加密的服务端中继。复杂 NAT 仍可能阻止直连，中继回退是受支持的运行模式，不会绕过认证。

## 构建与验证

安装稳定版 Rust 工具链，然后运行：

```text
cargo build --workspace --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

生成的程序位于 `target/release/rustgos`、`target/release/rustgoc` 和 `target/release/rustgoc-gui`（Windows 下带 `.exe` 后缀）。平台冒烟测试会启动真实的 release 程序，使用临时凭据，并验证两种传输方式：

```text
bash scripts/e2e.sh
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1
```

每个脚本只创建一个私有临时目录，并且只删除该目录。凭据不会写入 Cargo 或 CI 缓存目录。Bash 入口仅支持 Linux，并要求 `/proc/<pid>/stat` 可读、内核支持 `pidfd_open`/`pidfd_send_signal`，且 Python 3.10+ 提供 `os.pidfd_open` 和 `signal.pidfd_send_signal`。每次清理时，脚本会打开一个 pidfd，仅在打开后核对记录的启动时间，并通过同一个进程对象发送 TERM 信号以及有次数限制的 KILL 升级信号。缺少这些能力或无法读取进程身份时，E2E 将直接失败，不会仅根据 PID 发送信号。

## GUI 客户端

GUI 客户端（`rustgoc-gui`）提供：

- 实时连接状态和连接代次显示
- 显示协议和端口信息的实时隧道监控
- 有上限的日志视图（最近 1,000 行）
- 流量总计和网络活动信息
- Windows 系统托盘集成（最小化到托盘、从托盘退出）

运行 GUI：

```text
rustgoc-gui
```

GUI 和 CLI 都读取可执行文件旁的 `client.toml`；两者均不接受 `-c` 或 `--config`。GUI 使用与 CLI 客户端相同的配置格式。使用 `--selfcheck` 验证配置和连接：

```text
rustgoc-gui --selfcheck
```

自检最多等待 30 秒以建立有效连接，输出流量和路径状态快照，成功时以状态码 0 退出。E2E 脚本已集成此命令，用于自动验证。

GUI 管理的所有集合都有数量上限：1,000 行日志、300 个遥测图表数据点和 64 个托盘事件。GUI 启用 `#![forbid(unsafe_code)]`，在 Linux 上不依赖 GTK 或 AppIndicator。

## 发布版本

推送 `v1.0.0` 等版本标签后，工作流会为 Windows x86_64、Linux x86_64 和 Linux ARM64 构建 `rustgoc`、`rustgoc-gui` 和 `rustgos`。GitHub Release 包含：

```text
rustgoc-win-x86-v1.0.0.zip
rustgoc-gui-win-x86-v1.0.0.zip
rustgos-win-x86-v1.0.0.zip
rustgoc-linux-x86-v1.0.0.zip
rustgoc-gui-linux-x86-v1.0.0.zip
rustgos-linux-x86-v1.0.0.zip
rustgoc-linux-arm64-v1.0.0.zip
rustgoc-gui-linux-arm64-v1.0.0.zip
rustgos-linux-arm64-v1.0.0.zip
SHA256SUMS
```

每个 ZIP 包含一个按约定命名的可执行文件及其对应的 `client.toml` 或 `server.toml`。Linux CLI 和服务端 ZIP 还包含 `docker-compose.yaml`，GUI ZIP 不包含 Compose 模板。配置文件是示例，启动前请替换其中的端点。正常启动时，如果配置的两个 TLS 身份文件都不存在，`rustgos` 会自动生成 TLS 证书和私钥。发布产物不会包含生成的凭据。

下载全部十个资产后验证校验和。Linux 上运行：

```text
sha256sum --check SHA256SUMS
```

PowerShell 上运行：

```text
Get-Content SHA256SUMS | ForEach-Object {
    $hash, $name = $_ -split '  ', 2
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant() -ne $hash) {
        throw "Checksum mismatch: $name"
    }
}
```

Compose 部署方式和维护者发布流程请参阅[运维文档](docs/operations.md)。

## 安全启动

在客户端主机上生成密钥对：

```text
rustgoc keygen -o ./keys
```

将 `keys/device.key` 保留在客户端。只把 `keys/device.pub` 交给服务端管理员，并将其中的 `ed25519:...` 值填入对应的服务端授权条目。将 `server.tls_server_name` 配置为客户端实际使用的 DNS 名称。首次启动时，如果配置的两个身份文件均不存在，服务端会生成涵盖该名称的 TLS 身份。通过受保护的通道把生成的证书复制到客户端，核对日志中记录的指纹，并配置相同的 `server_name` 和该显式 CA 证书文件。

复制 [examples/server.toml](examples/server.toml) 和 [examples/client.toml](examples/client.toml)，提供文件中说明的环境变量，然后在不绑定端口或联系对端的情况下进行验证：

```text
rustgos check -c ./server.toml
rustgoc check
```

`check` 使用生产环境的凭据加载器。服务端会解析 TLS 证书链中的每张证书，验证 TLS 私钥编码以及叶证书与密钥是否匹配，并拒绝格式错误或强度不足的 Ed25519 授权密钥。客户端会解析每张显式 CA 证书及其 Rustgo 设备私钥。这些检查不会执行绑定或连接操作。

将 `client.toml` 放在每个客户端可执行文件旁。服务端默认读取当前目录中的 `server.toml`，同时也接受 `-c`：

```text
rustgos                 # 也可使用 rustgos -c ./server.toml
rustgoc                 # 读取可执行文件旁的 client.toml
rustgoc-gui             # 读取可执行文件旁的 client.toml
```

程序不会到父目录或平台专用目录中查找配置。CLI 启动需要 `client.toml`；用于审批注册时，缺失或损坏的设备密钥会自动生成。`check` 只验证现有凭据，不会申请访问权限。GUI 的 `--selfcheck` 会建立连接，因此要求设备已经获得授权。

### 审批式注册

启用服务端注册和经过认证的 Web 管理功能后，新客户端会通过已验证的 TLS 自动申请访问权限。管理员核对公钥指纹后批准或拒绝申请。获批的客户端会绑定其密钥并自动连接；待审批的密钥和请求 ID 在重启后仍会保留。此流程要求使用更新后的服务端。

使用 `rustgoc enroll` 申请访问，使用 `rustgoc re-enroll` 复用当前密钥，或使用 `rustgoc re-enroll --confirm-replace-key` 明确申请更换密钥。当前密钥会保留到替换申请获批为止。升级到数据库架构版本 4 前，请备份服务端注册数据库。参阅[审批版本发布说明](deploy/approval-release/README.md)。

证书命令、防火墙、服务重启、日志记录、密钥轮换、故障排查和完整发布检查清单请参阅[运维文档](docs/operations.md)。

## P2P 端口与策略

标准服务端布局使用 `7443/tcp` 承载 TLS 控制和中继流量，使用 `7443/udp` 和 `7444/udp` 进行经过认证的 NAT 观测。每个客户端还需要为配置的 `p2p.udp_port_range` 和 `p2p.tcp_port_range` 开放入站与出站访问；多个客户端共用一台主机时，请选择互不重叠的范围。导出项省略 `allowed_peers` 或将其留空时，会允许所有已认证客户端，并产生 `P2P_EXPORT_ALLOW_ALL` 日志。按照最小权限原则，应设置明确的客户端列表。

易读日志会记录观测、选定路径、路径提升和回退事件。GUI 客户端通过公共路径状态存储实时显示 P2P 路径状态（直连或中继）。

## 安全与诊断

- 生产流量始终使用 TLS 1.3，不提供明文 TOML 配置选项。
- 客户端名称只是别名，不是凭据。名称、已启用的授权、公钥、签名和挑战记录必须全部匹配。
- 日志为易读的单行文本，不支持 JSON 日志。
- 日志可能包含名称、端点、ID 和短指纹，但绝不会包含私钥、完整签名、挑战材料或应用数据载荷。

Rustgo 采用 MIT 或 Apache-2.0 双许可证。
