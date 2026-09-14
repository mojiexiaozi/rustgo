# 2026-09-14 审批接入版收尾

## 本次范围

- 同步 README、运维说明、Web 说明及发布说明中的客户端配置路径和审批流程。
- 修复 Windows/Linux 冒烟脚本仍传入 `-c` 的问题；在隔离临时目录复制客户端及配置，从不同工作目录启动验证配置定位。
- 修复 Linux GUI 冒烟阶段过期的服务端 TOML 字段、未定义公钥变量及启动日志读取。
- 同步 Docker 客户端命令和配置挂载位置；说明只读模板用于已有授权凭据。
- 修复 UDP 过期测试对异步日志顺序的错误假设：等待丢包日志前，过期日志可能已经被消费；保留对会话归零的断言。
- 清理审批客户端的 Clippy 条件写法。
- 修复 GUI 认证拒绝后未进入审批恢复、隐藏到托盘后审批完成不自动连接，以及运行时凭据路径依赖工作目录的问题。
- 更新 Web 静态资源断言，验证当前审批/删除入口存在、旧手工管理入口不再出现在界面脚本中。

## 本次验证结果

- `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`git diff --check`：通过。
- 核心工作区测试（排除 GUI 和 observability）：517 项通过，1 项 Web 旧断言失败；修复后 `cargo test -p rustgos --test web_assets -- --test-threads=1` 的 2 项全部通过。UDP 日志顺序测试已在本轮完整核心测试中通过。
- `cargo test -p rustgoc-gui -- --test-threads=1`：80 项通过，含 2 项真实 TLS 审批回归。首次受沙箱限制的临时注册表测试已在沙箱外复验；未修改实际开机启动项。
- `cargo test -p rustgo-observability --lib --test host_sampling --test snapshot_flow -- --test-threads=1`：9 项通过，遵循 Windows CI 的可移植测试范围。
- `node --test crates/rustgos/tests/web_management.test.cjs`：3 项通过。
- `scripts/e2e.ps1`：通过，包含 Windows release 构建、客户端配置检查、两种服务端启动方式、GUI 自检、TCP/UDP 回显和 P2P 直连/中继。
- Windows 三个发布程序已更新到 `deploy/approval-release`。Linux 两个程序保留之前的交叉编译产物。

## 提交前复验

- 再次执行 Windows 工作区测试（排除 observability）：597 项通过，16 MiB TCP 流测试出现一次 Windows `NotConnected`（10057）。单项复验通过；增加读写/半关闭错误上下文后，完整 TCP 测试组 10 项全部通过。没有屏蔽错误或放宽断言，首次偶发失败根因尚未确定。
- 可移植 observability 9 项、Web 管理 3 项、格式及 Clippy 检查再次通过。
- 补齐 Linux GUI 冒烟配置的 heartbeat 和 limits 必填字段，提取该脚本配置并通过实际 `rustgos check` 校验。
- 网络命名空间测试和当前 live relay 脚本按独立配置目录复制并启动客户端；明确绑定旧 v0.2 二进制的历史脚本保持原状。
- 临时配置校验目录的清理被执行策略拦截，保留在已忽略的 `test-results/closeout-2026-09-14/linux-config-check`；不会纳入源码提交。
- 本地分支：`codex/approval-closeout-20260914`。源码与必要说明纳入提交，本机配置、设备凭据和发布二进制使用忽略规则留在本地。

## 后续验证边界

本机为 Windows。Linux 运行测试、网络命名空间测试和 Linux 脚本执行需要 Linux CI。仓库既有本机配置、密钥目录和旧打包文件不属于可直接发布的源码集合。

分支已推送并触发 CI；GitHub 集成创建草稿 PR 返回 403，尚未创建 PR。未执行远程部署、服务替换或版本标签发布。Cargo 工作区版本仍为 0.3.0；文档中的 V0.4 为功能阶段，正式发布标签必须与 Cargo 版本统一。

首次 Linux CI 在 Clippy 阶段发现 Windows 托盘功能在非 Windows 平台留下未使用项。已关闭非 Windows 的发送端、移除未使用的占位构造函数，并限定托盘事件枚举的非 Windows dead-code 例外。Windows Clippy 和托盘测试通过，Linux 结果以新提交的 CI 为准。
