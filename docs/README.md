# API Manager 文档索引

更新日期：2026-08-04

本文档是仓库文档的统一入口。若设计稿与实现状态冲突，以
[`REQUIREMENTS_V2.md`](../REQUIREMENTS_V2.md)、
[`PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) 和当前代码为准。

## 首次使用

- [`ai_access.md`](ai_access.md)：API Key、AI 导航和可安装的 `authcheck` 客户端；外部 AI 日常操作优先使用此入口。
- [`START.md`](../START.md)：安装、启动、导入、排队、授权矩阵和复测的最短路径。
- [`CONFIGURATION.md`](../CONFIGURATION.md)：环境变量、私有数据目录、MongoDB、Redis、
  本地登录和可选外部工具。
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md)：当前命令、Web 页面、HTTP API、网络副作用和
  迁移工具分类。
- [`DATA_GOVERNANCE.md`](../DATA_GOVERNANCE.md)：公开仓库的数据边界和提交门禁。

## 当前产品与架构

- [`PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md)：当前数据流、四进程边界和复核队列来源。
- [`REQUIREMENTS_V2.md`](../REQUIREMENTS_V2.md)：当前产品需求和验收基线。
- [`api_manager_v2_domain_architecture.md`](api_manager_v2_domain_architecture.md)：领域对象、
  生命周期和迁移决策。
- [`authorization_matrix.md`](authorization_matrix.md)：N 身份授权矩阵、选择器、预算、
  判断和修复复测。
- [`execution_scheduler.md`](execution_scheduler.md)：持久化执行、租约、并发、重试和取消。
- [`account_context.md`](account_context.md)：认证引用和运行期秘密边界。
- [`project_execution_center.md`](project_execution_center.md)：项目执行中心页面与状态转换。

## 导入、认证与接口知识

- [`data_source_routing_center.md`](data_source_routing_center.md)：来源、ImportRun 和项目路由。
- [`auth_import.md`](auth_import.md)：认证 Recipe 导入。
- [`auth_realm_workbench_design.md`](auth_realm_workbench_design.md)：认证 Realm/Profile 修复工作台。
- [`parameter_relation_validation.md`](parameter_relation_validation.md)：参数关系的受控验证。
- [`abstract_rule_analysis_framework.md`](abstract_rule_analysis_framework.md)：抽象规则协议、
  已实现的离线 P0、早期公式修正、实施阶段和新会话必读上下文。
- [`ai_cli_access_and_approval_design.md`](ai_cli_access_and_approval_design.md)：AI-only CLI、
  分级访问、询问策略、完全访问和模型/执行评测设计。
- [`idor_parameter_construction_design.md`](idor_parameter_construction_design.md)：IDOR 参数构造
  的设计来源；当前执行仍以授权矩阵和 scheduler 文档为准。

## 安全与治理参考

- [`internal_high_risk_security_testing_roe.md`](internal_high_risk_security_testing_roe.md)：授权范围模型、
  强度策略、动作分级（A1–A4）、读回与清理要求。2026-09-18 起强度上限已移除。
- [`legacy_api_security_design.md`](legacy_api_security_design.md)：原始 DOCX 的脱敏 Markdown
  摘要和概念到 V2 的映射，仅作为历史设计来源。

## 历史或被替代的文档

以下文档保留演进依据，不作为当前操作手册：

- [`../API_TEST_BASE_ROADMAP.md`](../API_TEST_BASE_ROADMAP.md)：早期基座路线图。
- [`../REQUEST_ASSET_MODEL.md`](../REQUEST_ASSET_MODEL.md)：早期请求资产/快照设计参考。
- [`api_project_context_architecture.md`](api_project_context_architecture.md)：2026-07-16 项目上下文迁移快照。
- [`security_result_management.md`](security_result_management.md)：早期结果模型草案。
- [`legacy_api_security_design.md`](legacy_api_security_design.md)：原始需求的公开、元数据无关版本。
- [`../apiAnalysis/需求符合性差异报告.md`](../apiAnalysis/需求符合性差异报告.md)：早期差异报告。

历史文档中的“尚未实现”、旧页面、旧 Workspace、旧 privilege task、直接重放或兼容
重定向描述都不代表当前实现。
