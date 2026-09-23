# Internal Security Testing Rules Of Engagement

This document defines how to run authorized internal security testing with
api_manger and local methodology libraries such as Claude-BugHunter.

The goal is to find and fix serious risks internally before external discovery,
while keeping tests attributable, reversible where they change state, and
auditable.

修订 2026-09-18：本文此前把测试强度当成待定事项来限制（low request volume、
one target at a time、no mass scanning），前提是"授权尚未确定"。现在授权按环境授予，
这些上限已移除。强度不再是政策问题，见 §2。

## 1. Scope Model

授权单位是**环境**，不是单个主机。

- 资产 owner 提供该环境的授权资产清单（域名、IP、应用、API、租户、账号、环境）。
- 清单内全部在范围内。**不需要**对单个目标再申请批准。
- 清单外全部不在范围内。测它不是一个"治理偏差"，而是未授权入侵。
  这是唯一不让步的一条线。

范围内适用三条约束：

| 约束 | 管什么 | 为什么 |
| --- | --- | --- |
| **Scope** | 测哪些资产 | 区分内部测试与未授权入侵 |
| **Reversibility** | 只约束改状态的操作 | 破坏性操作同时毁掉证据和服务可用性 |
| **Evidence determinism** | 结论怎么推导 | 让发现能被工程复现 |

强度**不在**这个列表里，见 §2。

## 2. Intensity Policy

**在授权环境内，广度是默认姿态。** 批量执行、高并发、无人值守/过夜运行、
同类目标批量验证是预期模式，不是例外。

理由：不对称不在我们这边。攻击者不受变更窗口、预算评审和人力约束。
防守方如果比攻击者更保守，不会变安全，只会更晚发现——通常是从外部发现。

授权范围内具体表现为：

- 不限制请求量、目标数、执行窗口。
- 同类目标批量验证（通杀）已启用，且是跨环境发现同类缺陷的首选方式。
- 枚举、参数 fuzz、payload 列表是常规技术，不需要为此辩解。
- 允许无人值守运行，不需要人盯着。

仍然适用：

- 改状态的操作需要回滚/清理路径和最终回读（§3 A3、§7）。
- 会影响真实用户服务可用性的操作需要有健康度考量，这是运维问题不是政策问题。
- 请求始终留在授权清单内。

**预算属于运维手段，不是政治手段。** Worker 轮次上限、并发上限、LLM 花费上限
只用于发现失控 agent 和控制成本。为了跑完任务而调高是正常的调优动作。

## 3. Action Classes

等级按**可逆性与影响半径**对动作分类，用于判断需要什么处理。
它们不是权限门禁——环境授权后，A4 以下默认全部在范围内。

### A1: Passive And Readonly

示例：

- Apifox/OpenAPI 资产导入
- 端点盘点、参数与 schema 分析
- 基于已有数据的源码/文档/配置审查
- 使用已批准测试账号的只读 API 请求
- 不改数据的 IDOR / 列表隔离检查

处理：除范围与证据规则外无额外要求，按最大广度跑。

### A2: Authenticated Functional Security Tests

示例：

- 水平与垂直授权检查
- 角色/权限对比
- SSO / 会话过期行为
- 租户边界检查
- 只读数据暴露验证
- 使用无效、缺失或畸形认证的负向测试

处理：

- 使用已批准测试账号，保证结果可归因、可复现。
- 记录 owner/attacker 账号角色与构造链路。
- 枚举标识符、遍历角色是预期动作。只需留意会影响真实账号的锁定期与速率阈值。

### A3: State-Changing Tests

示例：

- 创建/删除配对测试
- 更新后还原测试
- 用一次性资源做绑定/解绑
- 用无害测试文件做有限上传
- mass assignment 与权限变更验证

处理（重点是**可逆**，不是许可）：

- 使用唯一测试对象前缀，或带一次性数据的测试账号。
- 执行前先确定清理端点。
- 记录清理状态并做最终回读。
- 清理连续失败两次或出现未知副作用时停止。
- 优先用测试账号和测试租户。若必须涉及真实客户对象，回滚路径要先建立。

### A4: High Blast Radius Single-Point Validation

示例：

- 云 IAM 权限链验证
- SSO / 身份提供方边界用例验证
- 外网边界设备 CVE 暴露确认
- 对已批准构建的 APK 动态插桩
- 供应链暴露验证
- 高影响业务逻辑变更

处理：

- 一次只做一项。这是**运维选择**，为了让失败可诊断、可归因，
  不是为了走审批。
- 建议执行前人工过一遍方案，但不作为门禁。
- 不建立持久化。不做破坏性利用。要有明确回滚或安全停止路径。
- 动作可能可见或有噪声时通知基础设施 owner。

### L5: Out Of Scope For This Workflow

以下不是漏洞发现技术，本工作流不执行，需要另行、另范围的授权：

- 恶意软件开发
- C2 命令控制
- 持久化
- EDR/AV 绕过
- 凭证窃取、LSASS dump
- 横向移动
- 域名接管动作
- 破坏性利用
- 超出最小证明的数据外带
- 对授权清单之外的资产做测试

这些领域可以协助编写治理方案、桌面推演场景、检测逻辑或安全的人工检查清单，
但不执行、不提供可用于滥用的操作步骤。

排除它们的理由不是"测试要胆小"，而是它们**超出本工作流的用途**：
它们不产出漏洞发现，破坏可归因性，且影响半径不可逆。

## 4. Authorization Record

每轮开始前记录：

- 项目名称
- 业务 owner
- 安全 owner
- 批准的操作人
- 日期与时间窗
- 授权环境名称与资产清单引用
- 正式域名是否通过本地 hosts 映射到测试/预发后端
- 明确禁止的动作
- 应急联系人与停止流程
- 证据存放路径

存放位置：

- RoE 摘要：`docs\security_profiles\` 或项目文档
- 秘密与原始证据：`$env:API_MANAGER_DATA_DIR`
- 持久结论：`security_test_run`、`security_test_result`

## 5. Domain-Specific Guidance

### API And Web Authz

默认工具：

- api_manger Apifox 导入
- `parameter_archive`
- `idor_parameter_candidate`
- `idor_construction_trace`
- 只读 IDOR / 列表隔离 runner
- 受控 mutation runner

有用的 Claude-BugHunter 参考：

- `hunt-idor`
- `hunt-auth-bypass`
- `hunt-business-logic`
- `hunt-api-misconfig`
- `hunt-session`
- `triage-validation`
- `evidence-hygiene`

允许：

- 用 attacker 认证重放 owner 资源
- 用已批准账号做租户边界检查
- 清理路径已知的创建/删除配对
- 幂等配置更新与还原
- 在授权清单内枚举标识符、跨账号遍历

留意：

- 枚举真实客户数据：尽量用测试账号；无法避免时先建立回滚路径，样本保持最小。
- 对真实客户数据做无界删除/更新。

### SSO And Identity

记录：

- 目标身份提供方或 SSO 流程
- 测试账号与角色
- MFA/2FA 处理规则
- 锁定期与速率阈值，避免锁掉真实用户

允许：

- 会话过期检查
- 角色切换验证
- 受控客户端的 redirect URI 验证
- token audience/scope 审查
- 敏感操作的第二因素强制检查
- 使用专用测试账号做 MFA 绕过测试

留意：

- 影响真实用户的账号锁定与速率限制——这是可用性与归因问题。
- 收集或复用真实用户凭证。

### APK / Client Testing

记录：

- 已批准的应用包或构建
- 允许的静态/动态分析范围
- 后端/API 范围
- 是否允许插桩

允许：

- 静态提取密钥/配置/API 端点
- 证书固定（pinning）审查
- 导出组件审查
- 在测试设备/账号上做本地存储审查
- 对已批准构建抓取动态流量

留意：

- 篡改生产应用分发
- hook 用户设备或第三方应用
- 提取与测试目标无关的密钥

### Cloud IAM

记录：

- 云账号/项目/订阅
- 已批准的身份/角色
- 允许的服务

允许：

- IAM 策略审查
- 公开 bucket/object 审查
- 在给定仓库中发现暴露密钥
- 用已批准账号做 assume-role 路径分析
- 最小权限与 confused deputy 审查

留意：

- 超出最小证明访问客户数据
- 建立持久化
- 无变更记录地修改生产 IAM——会影响真实用户
- 枚举无关云账号

### External Perimeter And Appliances

记录：

- 授权环境内的精确 IP/域名清单
- 扫描速率
- 允许的端口/协议
- CVE 验证策略
- 主动探测可能有干扰时的维护窗口

允许：

- 版本/banner 审查
- 配置暴露检查
- 用已批准账号审查管理后台
- 非破坏性 CVE 前置条件验证
- 在授权清单内全速扫描

留意：

- 扫描清单之外的网段
- 压测或打挂服务
- 隐蔽与规避技术——它们破坏可归因性

### Supply Chain

记录：

- 组织内仓库
- 包命名空间
- CI/CD 系统
- 容器镜像仓库
- 第三方边界

允许：

- 依赖混淆风险分析
- GitHub Actions workflow 审查
- 公司仓库内的暴露密钥扫描
- 包命名空间归属审查
- 制品可见性审查

留意：

- 发布仿冒包
- 入侵上游项目
- 访问私有第三方仓库
- 在验证与轮换流程之外使用真实密钥

## 6. Execution Checklist

执行前：

- 范围已归档，资产清单是唯一事实来源。
- 动作等级已判定（A1-A4）。
- 账号与角色已知。
- 预期副作用已理解。
- A3/A4 的回滚或清理方案已定。
- 证据路径已选。

执行中：

- 按环境允许的广度跑，不要自我限制。
- 记录命令、工具与版本。
- 原始证据私密存放。
- 留意 token 过期与路由错配。
- 出现非预期副作用时停止并诊断。
- 及时清理测试对象。

执行后：

- 确认清理状态。
- 按目标和结论汇总，**并给出分母**。
- 标记 `potential_vuln` 待验证，不自动升级。
- 记录跳过的用例与缺失前置条件。
- 验证通过后才出可修复的报告。

## 7. Evidence Rules

私密证据可包含：

- 完整请求/响应体
- 真实资源 ID
- owner/attacker 账号索引
- 原始错误响应体
- 清理响应

私密证据必须留在 `.secrets` 下。

报告与文档应包含：

- 端点方法与路径
- 脱敏后的请求形态
- 账号角色关系
- 状态码
- 业务错误摘要
- 影响说明
- 清理结果
- 证据引用

报告与文档不应包含：

- 密码
- Bearer token
- Cookie
- 原始私有客户数据
- 无关 PII
- 完整 HAR 文件

身份、去重 key、覆盖分母与定级由确定性代码计算，绝不由模型给出。
见 `docs/deterministic_vs_model_boundary.md`。这条与测试强度**正交**：
它约束结论的推导方式，不约束目标被测试的力度。

## 8. Validation Gate For Findings

这条门禁用于把**结果升级为漏洞**，不是执行门禁，不得用来阻断测试。

1. 目标在授权环境清单内吗？
2. 能否从全新会话复现？
3. attacker 账号是否本不应访问或修改该资源？
4. 响应或变更是有业务影响的，而不只是 HTTP `200`？
5. 该行为是否不是这个角色的文档化预期行为？
6. 证据是否足够让工程复现？
7. 清理是否完成，或残留状态是否已记录？

任一项为否则保持 `need_review` 或 `not_evaluable`。

## 9. How To Use Claude-BugHunter

当作参考库使用：

- API/Web 授权：`hunt-idor`、`hunt-auth-bypass`、`hunt-business-logic`
- 证据：`evidence-hygiene`
- 验证：`triage-validation`
- 报告：`report-writing`、`redteam-report-template`
- APK：`apk-redteam-pipeline`
- 云/身份/边界：适用同样的范围规则

不要用作：

- 扩大授权资产清单范围的借口
- 后利用动作的来源

对授权目标做自动化 payload 执行是预期且被支持的。
不可接受的是让工具来决定范围。

## 10. Recommended New-Session Context

```text
This is an authorized internal company security test. Follow
docs\internal_high_risk_security_testing_roe.md. Use api_manger for controlled
execution and result storage. Use Claude-BugHunter only as a local methodology
and checklist library.

The authorized environment and its asset list are the scope; everything inside
is fair game at full breadth. Do not self-limit request volume, concurrency, or
execution window, and do not ask for per-target approval. Keep testing inside
the authorized list, keep state-changing actions reversible with a final
read-back, and keep secrets and raw evidence under the external directory
configured by `API_MANAGER_DATA_DIR`. Identity, dedup keys, coverage
denominators, and severity come from deterministic code, not from a model.
```
