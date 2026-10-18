# 架构

```text
React/TypeScript 界面
        │ Wails 绑定
        ▼
应用服务：任务、取消、进度、历史
        ├── Go 探测引擎：输入 → DNS → TCP → TLS → HTTP → 本机环境
        ├── 规则引擎：证据 ID → 可能原因
        ├── 分享管线：脱敏 → JSON / HTML / Issue Markdown
        └── 本地 JSON 历史
```

阶段 1 的探测引擎和 CLI 不依赖 Wails 或 React，可单独测试。每层输出结构化证据，包括 ID、状态、耗时、值和错误类别；未执行步骤也有状态和原因。规则读取证据，输出推断及依据 ID，不覆盖事实字段。

当前引擎按 DNS、TCP、TLS、HTTP 顺序直连探测。TLS 诊断连接先获取对端证书，再用系统或指定的根证书执行独立验证；验证失败时保留证书证据并跳过 HTTP。HTTP 只读取响应头，记录逐跳状态与耗时，限制跳转次数。每层有独立超时，另有总超时与取消信号。

Windows 代理信息来自当前用户的 Internet Settings 注册表，网卡信息来自 Go 网络接口 API。DNS、TCP、TLS、HTTP 四层保持直连，桌面端另外并行执行一次经手动系统代理的 HTTP 请求。代理层支持手动配置的 HTTP、HTTPS、SOCKS5 地址；当目标匹配 `ProxyOverride` 的主机名、`*` 通配符或 `<local>` 时跳过手动代理请求并保留原因。PAC 自动配置和浏览器扩展代理不执行，环境变量代理仅记录是否存在。代理响应与直连结果分别记录，避免把直连超时误写成网站不可访问。CLI 仍仅使用直连路径。绕过规则参考 [Microsoft WinINet 文档](https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality)。

桌面服务一次只运行一项诊断。探测层完成时通过 Wails 事件推送状态与耗时；取消信号经 Go context 传递，完成事件包含已获得的证据。原始结果以带版本号的 JSON 文件保存在当前用户的 `%LOCALAPPDATA%\NetEvidence\history`，先写临时文件再改名；读取时检查 ID、版本和大小，列表最多展示最近 100 条。历史摘要和桌面报告均从原始记录重新构建脱敏投影。对比只输出两次诊断的脱敏目标、各层状态与耗时、HTTP 状态码。

分享时复制数据、先脱敏再渲染，且用户可预览。HTML 预览放在禁用脚本的沙箱 iframe 中。桌面导出只支持脱敏格式；系统保存对话框确认替换后，以同目录临时文件写入并替换目标。CLI 输出文件仍使用只创建模式。限制超时、重定向次数与 HTTP 读取量。凭据、URL 查询参数、代理信息、本机地址和路径均视为敏感内容。

目录：`cmd/` 放 CLI，`internal/` 放探测、规则、脱敏、报告与存储，`frontend/` 放桌面界面，`scripts/` 放开发脚本，`docs/` 放课程证据。
