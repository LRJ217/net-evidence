# 阶段 4 验证记录

记录日期：2026-10-18（北京时间）。

## 功能与本地检查

- 连续采样限制为 10/30/60 秒间隔、5/10/30 分钟时长，串行执行，可取消。单元测试验证 3 次采样只保存首个成功与失败样本、取消不保存未完成样本、事件不泄露原始 URL Token 或本机 IP。
- 四入口对比只接受主域名及其 `www` 域名的标准 HTTP/HTTPS 端口。单元测试验证路径与查询被丢弃、非标准端口和其他子域名被拒绝、结果中的跳转地址仍被脱敏。
- 历史对比增加代理启用、手动代理、绕过规则、PAC、环境变量代理存在性、网卡与 DNS 答案变化标志。单元测试验证比较 JSON 不含原始代理、网卡名称和 IP。
- `scripts/dev.ps1 -Task build` 的 Go 测试、Go vet、TypeScript 检查、前端构建与 Windows Wails 编译通过。

## 真实与模拟场景

- `scripts/verify-site.ps1 -Domain dazidazi.com -TimeoutSeconds 15` 实测四个入口均完成 DNS、TCP、HTTP；HTTPS 两个入口的 TLS 也通过，HTTP 状态码均为 200。耗时约 724–810 ms。这仅是当时的快照，不代表该站长期可用。
- 桌面界面实测四入口对比：四个入口的 HTTP 均为 200；两个 HTTP 入口的直连成功，但系统代理探测失败，因此明确显示为“直连可访问，代理异常”。不同时间的探测结果会波动，不能把一次结果当作长期结论。
- 本机临时选取未监听的回环端口：DNS 为 `literal_ip` 跳过，TCP 为 `connection_refused`，TLS 与 HTTP 跳过，推断为 `tcp_refused`。

## 打包

- NSIS 3.13 安装在 D 盘的工具目录，不写入项目依赖。`scripts/package.ps1` 运行完整构建后生成 `build/bin/NetEvidence-amd64-installer.exe`，安装范围为当前用户。
- 本机构建的安装包大小为 6,923,513 字节，SHA-256 为 `BC27DA951185FF0389017B95F9C022FA4078F7AA8F8CB38FAC7C98EC2F9CDA07`。
- 安装包未签名、未公开发布；尚未执行安装和卸载的端到端验证。用户可继续直接运行桌面 EXE。
