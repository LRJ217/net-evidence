# NetEvidence

Windows 本地网络故障证据工具。输入 URL、域名或 `host:port`，按 DNS、TCP、TLS、HTTP 和本机环境分层探测；将原始证据、带依据的“可能原因”和脱敏报告交给用户。

> **预览版（0.1.0）**：适合愿意反馈问题的 Windows 用户和开发者试用。诊断结论是排查线索，不保证确定故障根因。公开源码采用 [MIT 许可证](LICENSE)；安全与隐私问题见 [报告说明](SECURITY.md)。

> 桌面版已接入单次诊断、连续采样、四种网址入口对比、浏览器 HAR 分析、脱敏报告、本机历史和环境变化对比。

## 目标与技术

NetEvidence 解决“用户只说打不开、支持人员难以复现”的问题。探测在本机执行，不需要账号、服务器、管理员权限或驱动。使用 Wails v2.15.0、Go 1.27.2、React、TypeScript；首版历史使用本地 JSON。

完整范围见 [需求](docs/requirements.md)、[架构](docs/architecture.md) 和 [路线图](docs/roadmap.md)。

## 本地开发

需要 Windows 11、Node.js 24、npm 11、Go 1.27.2、WebView2 Runtime。脚本仅调整当前进程及其子进程，不写永久系统设置。

```powershell
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task check
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task test
.\scripts\dev.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -Task build
.\scripts\package.ps1 -GoExe 'C:\path\to\go1.27.2\go\bin\go.exe' -NSISBin 'D:\path\to\NSIS\Bin'
```

若 `go` 已在 PATH 中，可省略 `-GoExe`。默认 `GOPROXY=https://goproxy.cn,direct`，可用 `-GoProxy` 覆盖。第一次构建需下载依赖。

`package.ps1` 另需 NSIS，生成当前用户安装范围的 `build/bin/NetEvidence-amd64-installer.exe`，不要求管理员权限。安装包尚未签名，也未公开发布。

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

运行 `build/bin/NetEvidence.exe`，输入 URL、域名或 `host:port`，选择总超时后开始诊断。界面会逐层更新状态与耗时；运行中可取消，已取得的证据仍保留，取消中的层显示“已取消”。字面量 IP 目标会跳过域名解析，并继续 TCP 探测。TCP 按解析器返回的顺序，分别探测 IPv4、IPv6 最多 3 个地址；桌面界面显示本机实际尝试的 IP，分享报告隐藏 IP，但保留私有、回环、链路本地等地址类型统计。后续直连 TLS 和目标站点的 HTTP 请求使用成功的 TCP 地址，重定向到其他站点时重新解析。桌面端还会并行尝试当前用户配置的系统手动代理，以区分直连超时与代理可访问；目标匹配手动代理绕过规则时会跳过这条路径。代理探测是独立的 HTTP 请求，不代表浏览器的完整网络路径。完成后可展开脱敏的分层详情，查看可能原因，预览 JSON、HTML 或 Issue Markdown；当前格式可复制到剪贴板或另存为文件。

总超时是整次诊断的上限；默认 DNS/TCP 单层各 3 秒、TLS/代理访问单层各 5 秒。当前仅自动使用 Windows 手动系统代理（HTTP/HTTPS/SOCKS5），并识别其 `ProxyOverride` 绕过规则中的主机名、`*` 通配符及 `<local>`。PAC 自动配置和浏览器扩展代理不会执行；环境变量代理只显示是否存在。CLI 仍只进行直连诊断。

历史记录保存在当前用户的 `%LOCALAPPDATA%\NetEvidence\history`，包含本机原始诊断数据，请按敏感文件管理。侧栏只展示脱敏摘要、文件数和占用空间；打开历史会重新生成脱敏报告。历史按每页 40 条加载，可继续查看更早记录；文件数和占用空间统计全部 JSON 文件。用户可删除当前记录，或按 30、90、180 天保留期限手动清理旧记录，操作前会确认；程序不会自动删除。对比页可选择已加载的两次诊断，查看各层状态与耗时变化。已加载页面中的损坏历史会跳过并提示，也不会被期限清理删除。桌面导出仅提供脱敏格式；在系统保存对话框确认替换后可覆盖已有文件。CLI 的 `-out` 仍只创建新文件。

“连续采样”按 10/30/60 秒间隔持续 5/10/30 分钟，展示成功率、首次异常和故障层，只保留异常与首个成功样本到本机历史；“网址入口对比”并行检查主域名和 `www` 的 HTTP/HTTPS 首页，输入路径和查询不会带入四个请求。历史对比还显示代理、网卡及 DNS 答案是否变化，不输出这些配置的原始值。完整操作见 [使用说明](docs/user-guide.md)，可重复的四入口命令行检查见 `scripts/verify-site.ps1`。

“浏览器记录”可导入不超过 20 MiB 的 HAR 文件，归纳无 HTTP 响应、4xx/5xx 和耗时超过 3 秒的资源请求，并按主机汇总；可选择同站点的本机诊断记录并排对照。HAR 仅在内存中分析，不写入历史；界面只接收脱敏 URL、状态与耗时，不接收请求头、Cookie、请求体或响应体。演示文件见 [模拟浏览器故障 HAR](docs/samples/browser-failure.har)。

各阶段的实现边界及测试证据见 [探测验证](docs/verification-stage1.md)、[分享验证](docs/verification-stage2.md)、[桌面验证](docs/verification-stage3.md)、[交付验证](docs/verification-stage4.md) 与 [HAR 验证](docs/verification-stage5.md)。

## 阶段

| 阶段 | 主要交付 |
| --- | --- |
| 0 | Git 工作区、环境脚本、需求与架构、CI 和构建骨架 |
| 1 | 独立 Go 探测引擎与 CLI |
| 2 | 规则、脱敏和 JSON/HTML/GitHub Issue Markdown 报告 |
| 3 | Wails 交互、进度、详情、历史与对比 |
| 4 | Windows 打包、场景演示与课程材料 |
| 5 | 浏览器 HAR 的本地脱敏分析与诊断对照 |

原始诊断可能含敏感信息，请勿直接将 `raw-json` 贴到公开工单。公开预览版的已知边界和发布检查见 [发布准备](docs/release-readiness.md)。
