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

规则以证据 ID 解释可能原因。脱敏路径、用户、私网地址、MAC、Cookie、Authorization 和 URL Token。生成 JSON、HTML、Issue Markdown；通过隐私回归测试。

## 阶段 3：桌面体验

接入输入、进度、取消、分层详情、报告预览、JSON 历史和两次诊断对比。

## 阶段 4：交付与课程展示

完成 Windows 打包、真实与模拟故障场景、使用手册、架构说明和演示材料。公开发布另行决定。
