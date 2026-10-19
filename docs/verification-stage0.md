# 阶段 0 验证记录

记录日期：2026-10-17（北京时间）。

## 原理与实现

桌面进程由 Go/Wails 启动，内嵌 Vite 构建后的静态文件，WebView2 展示 React 页面。当前页面明确标注为构建验证页，不执行探测。依赖分别由 `go.mod`/`go.sum`、`package.json`/`package-lock.json` 固定；Wails CLI 安装指定 v2.15.0。

`scripts/dev.ps1` 在当前 PowerShell 进程设定 Go 的 PATH、仓库内的 GOBIN 和 GOPROXY；不修改 Windows 的永久环境变量。脚本先构建前端，再运行 Go 检查，因为 Go 的 `embed` 需要 `frontend/dist`。

## 本地证据

- Windows 11、Go 1.27.2、Node 24.20.0、npm 11.19.0、Git 2.53.0。
- `dev.ps1 -Task check`：版本检查通过。
- `dev.ps1 -Task test`：`npm ci`、TypeScript 检查、Vite 构建、`go test ./...` 通过。当前 Go 包尚无测试文件。
- `dev.ps1 -Task build`：Wails CLI v2.15.0 将应用构建为 `build/bin/NetEvidence.exe`，Windows amd64，构建完成。
- 在未保留 `build/` 资源文件的情况下再次构建通过；Wails 会生成阶段 0 的默认资源，仓库无需提交模板图标。
- 当时私有开发仓库的 GitHub Actions Windows CI：前端依赖安装、TypeScript 检查、前端构建、Go 检查、Wails CLI 安装和 Windows 桌面构建全部成功。原始运行记录不在公开预览仓库中。

## 剩余风险

- 此阶段没有真实 DNS/TCP/TLS/HTTP 探测，不能用构建结果证明诊断正确。
- 分享报告与脱敏尚未实现，原始诊断数据不应作为公开工单附件。
- 当前 Go 包没有测试文件。阶段 1 应用本地假服务器和错误场景测试探测逻辑。
