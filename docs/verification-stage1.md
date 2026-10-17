# 阶段 1 验证记录

记录日期：2026-10-17（北京时间）。

## 原理与实现

`internal/diagnostic` 独立于 Wails。输入规范化后依次执行 DNS、TCP、TLS、HTTP；每层返回稳定 ID、状态、耗时、结构化值及错误类别。失败后的依赖层标注“跳过”及原因，避免把未探测误写成成功。Windows 系统代理和网卡信息单独采集。

TLS 使用一条仅用于诊断的连接读取证书，再由 `x509.Verify` 检查证书链、域名和有效期。只有验证通过才发送 HTTP 请求。HTTP 直连并记录有限的重定向链，不读取响应体。

CLI 将结果编码为 JSON；它不是分享报告，当前没有脱敏。

## 验证证据

- `go test ./... -count=1`：本地假服务器覆盖 HTTP 成功与重定向、TLS 可信与不可信证书、错误域名和过期证书、TCP 拒绝、HTTP 超时、取消及重定向上限。注入的解析器覆盖 DNS 失败与后续跳过。
- `go vet ./...`：通过。
- `go build -o build/bin/net-evidence-cli.exe ./cmd/net-evidence`：Windows CLI 构建通过。
- CLI 本机关闭端口实测：DNS 成功，TCP 返回 `connection_refused`，TLS 与 HTTP 均标注跳过。
- [阶段 1 核心提交的 GitHub Actions](https://github.com/LRJ217/net-evidence/actions/runs/39042973662)：Go 测试、前端检查及 Windows 桌面构建通过。
- 更新后的 `dev.ps1 -Task build`：本机再次通过前端检查、Go 测试、Go vet、CLI 和 Wails 桌面构建。

## 剩余风险

- 输出包含原始 URL、代理设置、本机地址及 MAC；阶段 2 完成脱敏前不可直接分享。
- HTTP 当前绕过系统代理。需要代理才能上网的环境可能显示直连失败；代理设置仍作为环境证据保留。
- DNS、TCP、TLS、HTTP 使用独立连接，地址选择可能不同。结果需按层解释，不代表同一条连接的完整轨迹。
- 当前错误分类覆盖主要场景，少见的 Windows 网络错误仍可能归入 `unknown`。
- 桌面界面尚未调用引擎，历史、规则与报告仍待后续阶段。
