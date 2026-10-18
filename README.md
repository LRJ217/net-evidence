# NetEvidence

Windows 本地网络故障证据工具。输入 URL、域名或 `host:port`，按 DNS、TCP、TLS、HTTP 和本机环境分层探测；将原始证据、带依据的“可能原因”和脱敏报告交给用户。

> 阶段 3 已接入桌面诊断、逐层进度与取消、分层详情、报告预览、本机历史和两次诊断对比。

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

## 命令行诊断

`-Task build` 会生成 `build/bin/net-evidence-cli.exe` 和桌面应用。CLI 默认输出脱敏 JSON，示例：

```powershell
.\build\bin\net-evidence-cli.exe -timeout 15s 'https://example.com/path'
.\build\bin\net-evidence-cli.exe 'example.com'
.\build\bin\net-evidence-cli.exe '127.0.0.1:8080'
.\build\bin\net-evidence-cli.exe -format html -out 'report.html' 'https://example.com/private?token=secret'
.\build\bin\net-evidence-cli.exe -format issue -out 'issue.md' 'example.com'
.\build\bin\net-evidence-cli.exe -format raw-json -out 'local-evidence.json' 'example.com'
```

裸域名默认使用 HTTPS 443；`host:port` 的 443 使用 HTTPS，其他端口默认 HTTP。自定义 TLS 端口请明确写 `https://host:port`。某层探测失败仍会输出报告；输入不合法则退出码为 2。`-out` 只创建新文件，不覆盖已有文件。

默认的 JSON、HTML 和 Issue Markdown 报告都只读取脱敏后的证据，并把“可能原因”与其依据 ID 分开呈现。分享版会移除 URL 路径与查询值、IP、MAC、代理详情、证书名称和原始错误文本；发送前仍应预览。`-format raw-json` 是未脱敏的本机原始证据，可能包含 URL Token、代理、本机 IP 和 MAC，请勿直接公开。HTTP 请求当前直连目标，系统代理只采集为证据。

## 桌面应用

运行 `build/bin/NetEvidence.exe`，输入 URL、域名或 `host:port`，选择总超时后开始诊断。界面会逐层更新状态与耗时；运行中可取消，已取得的证据仍保留，取消中的层显示“已取消”。TCP 分别探测 DNS 结果中 IPv4、IPv6 的首个地址，桌面界面显示本机实际尝试的 IP；分享报告会隐藏 IP。后续直连 TLS 和目标站点的 HTTP 请求使用成功的 TCP 地址，重定向到其他站点时重新解析。桌面端还会并行尝试当前用户配置的系统手动代理，以区分直连超时与代理可访问；代理探测是独立的 HTTP 请求，不代表浏览器的完整网络路径。完成后可展开脱敏的分层详情，查看可能原因，预览 JSON、HTML 或 Issue Markdown，并将当前格式另存为新文件。

总超时是整次诊断的上限；默认 DNS/TCP 单层各 3 秒、TLS/代理访问单层各 5 秒。当前仅自动使用 Windows 手动系统代理（HTTP/HTTPS/SOCKS5）；PAC 自动配置、浏览器扩展代理及代理绕过规则不会被复现，界面会标明无法探测的路径。CLI 仍只进行直连诊断。

历史记录保存在当前用户的 `%LOCALAPPDATA%\NetEvidence\history`，包含本机原始诊断数据，请按敏感文件管理。侧栏只展示脱敏摘要、文件数和占用空间；打开历史会重新生成脱敏报告。用户可删除当前记录，或按 30、90、180 天保留期限手动清理旧记录，操作前会确认；程序不会自动删除。对比页可选择两次诊断，查看各层状态与耗时变化。当前只列出最近 100 条，损坏的历史文件会跳过并提示，也不会被期限清理删除。桌面导出仅提供脱敏格式，且不会覆盖已有文件。

各阶段的实现边界及测试证据见 [探测验证](docs/verification-stage1.md)、[分享验证](docs/verification-stage2.md) 与 [桌面验证](docs/verification-stage3.md)。

## 阶段

| 阶段 | 主要交付 |
| --- | --- |
| 0 | Git 工作区、环境脚本、需求与架构、CI 和构建骨架 |
| 1 | 独立 Go 探测引擎与 CLI |
| 2 | 规则、脱敏和 JSON/HTML/GitHub Issue Markdown 报告 |
| 3 | Wails 交互、进度、详情、历史与对比 |
| 4 | Windows 打包、场景演示与课程材料 |

原始诊断可能含敏感信息，请勿直接将 `raw-json` 贴到公开工单。仓库当前保持私有。
