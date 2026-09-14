# 审批接入版

## 客户端

- Windows：运行 windows-client/rustgoc.exe（CLI）或 rustgoc-gui.exe（GUI）。
- Linux：给 linux-client/rustgoc 添加执行权限后运行。
- CLI 固定读取可执行文件同目录的 client.toml，不支持 -c/--config，也不读取当前工作目录的其他配置。
- 每台设备请配置唯一的 client.name，并确认 server_addr。无需在管理端预先创建客户端。
- 示例沿用现有部署的服务器地址、转发配置，并从其公开证书提取可信指纹。若换服务器或证书，须通过可信渠道更新 server_certificate_fingerprint。
- 新部署不携带设备私钥。客户端有有效密钥时复用；没有或损坏时自动生成。等待审批时不退出，断网后重试。
- 管理端核对客户端显示/日志中的公钥指纹后批准，客户端会自动完成绑定并连接。
- 请求编号和密钥保存在设备本机，重启复用原申请。请保持程序目录可写，不要在等待期间删除 .rustgo-enrollment-pending-* 目录或 client.enrollment-pending.toml。
- 单独申请：rustgoc enroll；复用密钥重新申请：rustgoc re-enroll；明确更换密钥：rustgoc re-enroll --confirm-replace-key。
- 更新已有客户端时保留该设备自己的 client.toml、device.key 和待审批文件，不要将这些运行后产生的密钥再打包分发给其他设备。

## 服务端

- Windows 服务端：windows-server/rustgos.exe；Linux 服务端：linux-server/rustgos。
- 服务端必须同步更新到本包版本才能处理新的申请；本次未更新远程运行中的服务。
- 沿用服务端现有 server.toml、TLS 证书/私钥及 enrollment 数据库；服务端仍支持 -c 指定配置文件。
- 确保 enrollment.enabled=true，且管理 Web 已启用。启动会将 enrollment 数据库迁移到版本 4；更新前备份数据库，更新后不要直接降级旧二进制。
- 管理页面只展示申请审批/拒绝和客户端删除，不再需要手动创建客户端或分发接入密钥。旧管理 API 和长密钥处理保留兼容用途。

此发布目录未包含任何设备私钥、服务器私钥或运行时数据库。

## 2026-09-14 本地收尾验证

- Windows 三个程序已重新构建，启动检查、GUI 自检、TCP/UDP 回显及 P2P 直连/中继冒烟通过。
- GUI 已修复认证拒绝后申请审批、隐藏到托盘时审批完成自动连接、从其他目录启动时查找凭据的问题。
- Linux 两个程序保留此前交叉编译产物，本次未做 Linux 运行验证；本包没有 Linux GUI 程序。
- `SHA256SUMS.txt` 覆盖本目录说明、示例配置和二进制；正式升级前请核对校验和并备份服务端数据库。
