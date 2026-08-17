# 组织安全扫描 Workflow 部署 SOP（大纲）

> 状态：大纲已确认，完整内容待编写

---

## 1. 概述
- 1.1 目标：统一接入安全扫描（SCA + SAST），质量门结果直接阻断不符合要求的合并
- 1.2 架构总览（一图说明：业务仓库 → 调用中央 workflow → Trivy / SonarQube / 钉钉）
- 1.3 涉及团队与角色分工（Security / GitHub Admin / DevOps / 开发团队）

## 2. 前置准备（一次性，Security + Admin 完成）
- 2.1 SonarQube 平台准备
  - 创建 Organization & Token
  - Quality Gate 配置说明（默认 `gate.pass = 0 new issues`，可调整）
  - 项目自动创建机制（workflow 中 `Ensure SonarQube Project Exists` 步骤说明）
- 2.2 GitHub App 创建
  - 权限要求（`contents: read`，`metadata: read`）
  - 安装到 Organization 并授权所有仓库
  - 获取 `APP_ID` + `APP_PRIVATE_KEY`
- 2.3 GitHub Organization Rulesets 配置
  - 创建 Ruleset 的步骤（Settings → Rules → Rulesets）
  - 必须关联的 Status Check：`SAST Code Scan (SonarQube)` 和 `SCA Security Scan (Trivy)`
  - 作用范围：所有仓库 / 排除特定仓库（如模板仓库、文档仓库）
  - 阻断策略：`Block` 模式（Status Check 失败时禁止合并）
- 2.4 Secrets 配置层级
  - **Organization Secrets**（所有仓库可见）：`SONAR_HOST_URL`、`SONAR_TOKEN`、`DINGTALK_WEBHOOK`、`DINGTALK_SECRET`
  - **Central 仓库 Secrets**（仅 sec-workflows 仓库）：`APP_ID`、`APP_PRIVATE_KEY`（用于 auto-inject）

## 3. 部署中央安全门禁仓库
- 3.1 将 `sec-workflows` 部署到 Organization（Fork 或直接创建）
- 3.2 配置 Central 仓库 Secrets（GitHub App 凭证：`APP_ID`、`APP_PRIVATE_KEY`）
- 3.3 验证 `security-check.yml` 可被 `workflow_call` 调用（手动触发 `workflow_dispatch` 测试）
- 3.4 验证钉钉通知：发送测试消息确认签名与 Webhook 正常

## 4. 各业务仓库接入
- 4.1 接入原理（轻量 wrapper `hkvax_security.yml`，`secrets: inherit` 透传 Organization Secrets）
- 4.2 方式一：手动创建 `hkvax_security.yml`（适用于少量仓库或特殊分支配置）
  - 文件路径与内容模板
  - 需要根据仓库实际情况修改的参数（分支名、SonarQube Project Key/Name）
- 4.3 方式二：自动注入（通过 `auto-inject-workflow.yml`）
  - scan 模式运行说明（仅识别 + 钉钉告警，不修改仓库）
  - inject 模式运行说明（自动创建 `hkvax_security.yml`）
  - `force_update` 参数说明
- 4.4 新仓库接入流程（新建仓库后自动触发 / 手动触发 inject）

## 5. 自动巡检与告警
- 5.1 定时任务说明（每天北京时间 09:00 自动执行 scan）
- 5.2 钉钉通知内容说明
  - 巡检结果（缺失仓库列表，含可点击链接）
  - 注入结果（成功/失败明细）
- 5.3 质量门失败时的钉钉告警（SCA/SAST 分类状态展示）

## 6. 日常运维
- 7.1 中央 Workflow 版本更新（业务仓库通过 `@main` 自动跟随）
- 7.2 排除特定仓库不执行安全扫描（从 Ruleset 范围移除）
- 7.3 质量门阈值调整（`trivy_severity`、`quality_gate_fail` 参数）
- 7.4 SonarQube Dashboard 查看路径（Job Summary 中的链接说明）
- 7.5 常见故障排查
  - Trivy 扫描器故障（网络/DB 下载问题）
  - SonarQube 连接失败（认证/服务不可用）
  - `secrets: inherit` 不生效（检查 Org Secrets 配置）

## 7. 各团队操作清单（Checklist）
- GitHub Admin：Rulesets + GitHub App + Org Secrets
- DevOps：部署 Central 仓库 + 配置 Central Secrets + 验证
- 开发团队：无需操作（自动注入或手动创建 wrapper 文件）；PR 被阻断时查看 Job Summary
