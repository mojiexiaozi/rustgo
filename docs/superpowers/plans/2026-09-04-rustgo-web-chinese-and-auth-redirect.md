# Rustgo Web 中文化与未鉴权跳转 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 Rustgo 嵌入式 Web 仪表盘改为仅简体中文，并让未鉴权浏览器访问 `/` 时以 302 跳转登录页，同时保持 API 的 401 JSON 契约。

**Architecture:** 保持现有嵌入式静态资源结构，在 HTML 和 JavaScript 展示层直接使用中文，不引入国际化框架。页面入口和 API 继续使用不同的鉴权失败响应：`assets::index` 返回明确的 302，API 路由保持现有 401 JSON。

**Tech Stack:** Rust、Axum、嵌入式 HTML/CSS/原生 JavaScript、Cargo 功能测试

**Design:** `docs/superpowers/specs/2026-09-04-rustgo-web-chinese-and-auth-redirect-design.md`

**Constraints:** 仅中文界面；`/` 未鉴权精确返回 `302 + Location: /login`；API 保持 `401` JSON；不引入国际化框架；不改布局、认证和 API 数据；不触碰无关脏文件；编写过程中不运行测试，最终只运行对应功能测试。

---

## 文件职责

- `crates/rustgos/src/web/assets.rs`：仪表盘页面资源及页面入口鉴权响应。
- `crates/rustgos/web/login.html`：中文登录页固定结构和文案。
- `crates/rustgos/web/index.html`：中文仪表盘固定结构、标签和初始状态。
- `crates/rustgos/web/login.js`：中文登录过程和失败提示。
- `crates/rustgos/web/app.js`：中文动态状态、枚举映射、时间及图表文案。
- `crates/rustgos/tests/web_assets.rs`：真实路由与嵌入资源的功能契约。
- `crates/rustgos/tests/web_auth.rs`：页面跳转和认证会话功能契约。
- `crates/rustgos/tests/web_api.rs`：未鉴权 API 的 401 JSON 回归契约。

### Task 1: 更新页面鉴权功能契约

**Files:**
- Modify: `crates/rustgos/tests/web_assets.rs`
- Modify: `crates/rustgos/tests/web_auth.rs`
- Modify: `crates/rustgos/tests/web_api.rs`

- [ ] **Step 1: 更新未鉴权页面断言**

在现有真实 Web 测试服务器分别用缺失、无效和过期 Cookie 请求 `/`，断言状态为 `302`、`Location` 精确为 `/login`，响应不再被当作 API JSON。保留并确认 `/login` 及公开静态资源仍可匿名访问。

- [ ] **Step 2: 保留 API 鉴权断言**

确认 `web_api.rs` 中未鉴权 `/api/v1/overview`、`/api` 和未知 `/api/**` 路径均断言 `401` 和 `authentication_required`；若覆盖不足，只扩展现有功能场景，不创建单元测试。

- [ ] **Step 3: 暂不运行测试**

遵循 `AGENTS.md`，编写过程中不运行测试；记录最终验收命令为：

```powershell
cargo test -p rustgos --test web_assets
cargo test -p rustgos --test web_auth
cargo test -p rustgos --test web_api
```

### Task 2: 实现页面入口 302 跳转

**Files:**
- Modify: `crates/rustgos/src/web/assets.rs`

- [ ] **Step 1: 添加明确的页面重定向响应**

在 `index` 的 Cookie 鉴权失败分支构造 `StatusCode::FOUND` 响应，并写入 `Location: /login`。不要使用返回 307 的 `Redirect::temporary`，不要改动 API 路由或认证状态。

- [ ] **Step 2: 检查安全响应头兼容性**

确认响应仍经过全局 `response_security_headers` 中间件，且重定向不携带认证细节或用户输入。

- [ ] **Step 3: 暂不运行测试**

只执行静态代码检查，不启动服务、不运行 Cargo 测试。

### Task 3: 中文化固定页面内容

**Files:**
- Modify: `crates/rustgos/web/login.html`
- Modify: `crates/rustgos/web/index.html`

- [ ] **Step 1: 中文化登录页**

将 `lang` 改为 `zh-CN`，并翻译页面标题、主标题、说明、用户名、密码、登录按钮以及面向辅助技术的标签。保留 Rustgo 产品名。

- [ ] **Step 2: 中文化仪表盘骨架**

将 `lang` 改为 `zh-CN`，翻译导航、退出、总览、历史范围、服务指标、图表、客户端列表、搜索排序、详情、会话筛选、表头、空状态及所有 `aria-label`。保留 CPU、TCP、UDP、P2P、QUIC 和标准单位。

- [ ] **Step 3: 暂不运行测试**

使用文本检索盘点残留的用户可见英文，不把 HTML 标签、属性、元素 ID、CSS 类或协议缩写误判为界面文案。

### Task 4: 中文化动态界面内容

**Files:**
- Modify: `crates/rustgos/web/login.js`
- Modify: `crates/rustgos/web/app.js`

- [ ] **Step 1: 中文化登录交互**

翻译“正在登录”和通用登录失败提示，不细分凭据错误、限流或来源校验失败。

- [ ] **Step 2: 中文化格式化与状态文案**

翻译不可用、刚刚、秒/分钟/小时前、采样、陈旧、时钟偏差、连接状态、服务健康、历史状态、请求失败及退出失败等动态文字；日期使用 `toLocaleString("zh-CN")`。

- [ ] **Step 3: 中文化有限枚举**

新增局部展示映射，将 `active`、`closed`、在线状态以及精确的路径值 `relay`、`p2p-direct`、`p2p-fallback` 映射为中文。映射必须同时用于客户端详情和会话表；TCP、UDP、P2P、QUIC 等协议缩写和设备名、隧道名、会话短 ID 等动态身份值原样显示。不得修改 API 数据或筛选请求参数。

- [ ] **Step 4: 中文化动态卡片和图表**

翻译客户端摘要、指标卡、清单、路径与会话、表格空状态、历史加载/不可用和 SVG 图表辅助文本。确保通过 `textContent` 或现有安全 DOM 构造写入动态值。

- [ ] **Step 5: 暂不运行测试**

使用文本检索复核残留英文，只允许技术名词、单位、代码标识和非展示错误字符串存在。

### Task 5: 更新资源功能断言并统一验收

**Files:**
- Modify: `crates/rustgos/tests/web_assets.rs`
- Modify: `crates/rustgos/tests/web_auth.rs`
- Modify: `crates/rustgos/tests/web_api.rs`

- [ ] **Step 1: 更新中文资源断言**

把既有英文页面文案断言替换为代表性的中文断言，并增加 `lang="zh-CN"`、中文动态提示及必要的枚举映射检查。测试关注用户可见契约，不复制全部实现文本。

- [ ] **Step 2: 运行格式与差异检查**

```powershell
cargo fmt --all -- --check
git diff --check
```

预期：两条命令退出码均为 0，且不改动无关脏文件。

- [ ] **Step 3: 运行对应 Web 功能测试**

依次运行并要求每条退出码为 0：

```powershell
cargo test -p rustgos --test web_assets
cargo test -p rustgos --test web_auth
cargo test -p rustgos --test web_api
```

- [ ] **Step 4: 审核最终差异**

确认只有计划列出的 Web、测试和文档文件属于本次改动；确认 `/` 是 302、API 是 401 JSON、全部可见界面为中文，且用户已有 GUI、部署和其他未提交内容保持不变。

- [ ] **Step 5: 提交实现**

只暂存本计划列出的实现及测试文件：

```powershell
git add crates/rustgos/src/web/assets.rs crates/rustgos/web/login.html crates/rustgos/web/index.html crates/rustgos/web/login.js crates/rustgos/web/app.js crates/rustgos/tests/web_assets.rs crates/rustgos/tests/web_auth.rs crates/rustgos/tests/web_api.rs
git commit -m "fix: localize dashboard and redirect unauthenticated pages"
```
