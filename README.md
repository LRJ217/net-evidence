# NetEvidence

Windows 本地网络故障证据工具。输入 URL、域名或 `host:port`，按 DNS、TCP、TLS、HTTP 和本机环境分层探测；将原始证据、带依据的“可能原因”和脱敏报告交给用户。

> 当前处于阶段 0：构建与文档基线。诊断引擎及报告尚未实现，桌面界面只是构建验证页。

## 目标与技术

NetEvidence 解决“用户只说打不开、支持人员难以复现”的问题。探测在本机执行，不需要账号、服务器、管理员权限或驱动。使用 Wails v2.15.0、Go 1.27.2、React、TypeScript；首版历史使用本地 JSON。

完整范围见 [需求](docs/requirements.md)、[架构](docs/architecture.md) 和 [路线图](docs/roadmap.md)。

## 本地开发

需要 Windows 11、Node.js 24、npm 11、Go 1.27.2、WebView2 Runtime。脚本仅调整当前进程及其子进程，不写永久系统设置。

```powershell
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task check
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task test
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task build
```

若 `go` 已在 PATH 中，可省略 `-GoExe`。默认 `GOPROXY=https://goproxy.cn,direct`，可用 `-GoProxy` 覆盖。第一次构建需下载依赖。

## 阶段

| 阶段 | 主要交付 |
| --- | --- |
| 0 | Git 工作区、环境脚本、需求与架构、CI 和构建骨架 |
| 1 | 独立 Go 探测引擎与 CLI |
| 2 | 规则、脱敏和 JSON/HTML/GitHub Issue Markdown 报告 |
| 3 | Wails 交互、进度、详情、历史与对比 |
| 4 | Windows 打包、场景演示与课程材料 |

原始诊断可能含敏感信息。分享功能完成前，请勿直接将原始记录贴到公开工单。仓库当前保持私有。
