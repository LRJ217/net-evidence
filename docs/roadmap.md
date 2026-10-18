# 实施路线图

每阶段完成后记录原理、实现、验证证据和剩余风险；以可验证的小里程碑同步私有仓库。

## 阶段 0：项目基线

- [x] 与远端历史一致的 Git 工作区
- [x] 仅当前进程生效的环境脚本
- [x] README、需求、架构与路线图
- [x] 固定 Go/Wails 与前端依赖
- [x] Go 测试、前端检查及 Windows 构建 CI

验收：本地检查与 [GitHub Actions Windows CI](https://github.com/LRJ217/net-evidence/actions/runs/39041219065) 通过；仓库仍私有。具体证据见 [阶段 0 验证记录](verification-stage0.md)。

## 阶段 1：探测引擎和 CLI

- [x] 目标与证据模型、输入规范化
- [x] DNS、TCP、TLS、HTTP 和本机环境探测
- [x] 超时、取消、错误分类、跳过状态与 JSON CLI
- [x] 本地服务器覆盖成功、拒绝、超时、重定向和证书错误

验收：本地测试与 [阶段 1 核心提交的 Windows CI](https://github.com/LRJ217/net-evidence/actions/runs/39042973662) 通过。详细证据及局限见 [阶段 1 验证记录](verification-stage1.md)。

## 阶段 2：解释与分享

- [x] 规则以证据 ID 解释可能原因，区分事实与推断
- [x] 显式投影分享字段，移除 URL 路径与查询、IP、MAC、代理、证书名称及原始错误文本
- [x] 生成 JSON、HTML、Issue Markdown，CLI 默认分享版并支持预览文件
- [x] 隐私回归测试覆盖路径、用户、Cookie、Authorization、Token 和本机地址

验收：本地 Go 测试、静态检查、CLI 三种格式实测通过。具体证据与局限见 [阶段 2 验证记录](verification-stage2.md)。

## 阶段 3：桌面体验

- [x] 目标输入、总超时、逐层进度与取消
- [x] 分层详情、可能原因与三种脱敏报告预览和导出
- [x] 本机 JSON 历史、损坏记录提示与两次诊断对比

验收：Go 测试、静态检查、前端检查及 Windows Wails 构建通过；桌面端手动验证诊断、历史、报告预览和对比。详见 [阶段 3 验证记录](verification-stage3.md)。

## 阶段 4：交付与课程展示

完成 Windows 打包、真实与模拟故障场景、使用手册、架构说明和演示材料。公开发布另行决定。
