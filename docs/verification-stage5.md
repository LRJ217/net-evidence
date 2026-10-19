# 阶段 5 验证记录：浏览器 HAR 分析

记录日期：2026-10-19（北京时间）。

## 已验证

- `go test ./... -count=1`、`go vet ./...`、`npm run check` 及完整 Windows Wails 构建通过。
- 解析器与桌面导入函数读取 [模拟 HAR](samples/browser-failure.har)：4 条 HTTP(S) 请求中，首个 HTML 为 200，另有 1 条 503、1 条无 HTTP 响应、1 条耗时 3.8 秒。非 HTTP(S) 请求会被忽略。
- 隐私测试在 HAR 中放入用户信息、Cookie、URL Token、请求体、响应体、浏览器错误文本和本机 IP，序列化后的分析结果均未包含这些原始值。错误消息不回显无效 JSON；超过 20 MiB 的文件会被拒绝。
- 桌面程序中的“浏览器记录”页面和 Windows HAR 文件选择框可打开。2026-10-19 用户提供的桌面截图显示，导入仓库附带的模拟 HAR 后，页面统计为 4 条 HTTP(S) 请求、1 条无 HTTP 响应、1 条 4xx/5xx 和 1 条慢请求，与样例数据一致。截图包含本机历史记录，未收入仓库；真实浏览器导出的 HAR 仍待验证。
- `scripts/package.ps1` 生成当前用户安装范围的 `build/bin/NetEvidence-amd64-installer.exe`，大小为 6,947,150 字节，SHA-256 为 `A0D0660F7E772C2191EB4BC661FAFDEA0BC97D6E27558CB4F16BAE1F31AE4227`。

## 解释边界

- HAR 的 HTTP 状态 0 只表示未记录到 HTTP 响应，可能是取消、拦截或记录不完整。4xx 也可能是正常的权限挑战。
- 页面主机取首个 HTML 请求，缺少 HTML 时取首条 HTTP(S) 请求；不保证总是用户地址栏中的站点。与本机诊断的主机和时间对照只提供线索。
- HAR 从本机文件读取后仅在内存中分析。请求头、请求体与响应体未进入前端；分析结果不写入历史或分享报告。安装包仍未签名；安装与卸载已在现有 WebView2 的开发电脑上验证，详见[发布准备](release-readiness.md)。
