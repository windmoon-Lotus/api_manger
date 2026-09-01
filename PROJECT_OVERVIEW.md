# AuthCheck API Manager 项目总览

## 项目定位

这是一个面向 API 资产治理、参数依赖分析和授权边界验证的个人开源项目。
核心价值不是“发送一批 HTTP 请求”，而是把每次测试固化成可解释、可复现、
可复测的证据链。

当前运行原则：

1. 导入只解析和归档，不发送业务请求。
2. 所有网络执行都必须先生成不可变快照，再进入统一调度队列。
3. Web 管理配置和队列；worker 执行业务 API 测试；scheduler 只做恢复和维护。
4. 认证秘密不进入 Mongo、日志、fixture、结果摘要或 Git。
5. 候选关系不等于已验证关系；只有调度执行证据或显式人工信任才能提升状态。

## 当前数据流

```text
HAR / OpenAPI / Postman / Apifox
              |
              v
        import.v1 导入契约
              |
              v
  API 资产 + 参数事实 + 候选关系
              |
              v
  人工选择策略、主体、环境、fixture
              |
              v
   不可变请求快照 + security_test_run
              |
              v
       execution worker 执行
              |
              v
  统一结果 + 证据摘要 + 复核/漏洞闭环
```

导入和验证故意分成两步。导入阶段保留历史观测、参数位置和资源链候选，
但不会根据历史状态码把候选关系标成 `verified`。验证阶段才会使用选定环境和
认证主体发请求，并把状态码、资源身份匹配、快照引用和原因码写入统一结果契约。

## 四个独立进程

- Web：`python tools/run_web_server.py`
- 执行 worker：`python tools/run_execution_worker.py --poll-seconds 5`
- 参数关系 worker：`python tools/run_relation_analysis_worker.py --poll-seconds 5`
- 维护 scheduler：`python tools/run_maintenance_scheduler.py --poll-seconds 30`

Flask 应用工厂不会启动线程、worker 或定时器。旧 Workspace 捕获、同步重放和
旧 privilege task 运行链已经退出当前运行时；历史模型只用于显式数据迁移。

## 导入契约

Web 和 CLI 都调用 `ImportRequest -> execute_import -> ImportOutcome`：

- 每次导入只有一个 `ImportRun` 生命周期；
- 只处理本批次产生的 raw ID/path ID；
- 空批次不会回退成全库分析；
- 参数归档是离线、批次限定的数据转换；
- OpenAPI、Postman 和 Apifox 文档导入必须绑定项目。

示例：

```powershell
python -m apiAnalysis.main `
  --format har `
  --input .\capture.har `
  --project-id <project-id> `
  --env-id test `
  --parameter-disassemble
```

## 参数关系验证

候选关系描述“响应中的资源值可能被另一个请求消费”。验证时：

1. 冻结 source/consumer 端点、typed locator、fixture revision 和认证 profile revision；
2. 使用 source 主体发送只读请求并临时提取真实值；
3. 将值注入 consumer 请求的 Path/Query/Header/Cookie/Body 精确位置；
4. 使用 consumer 主体发送请求；
5. 丢弃原始值，仅持久化摘要、状态、指纹、原因码和快照引用；
6. 结果不确定时保持待复核，不能自动冒充验证成功。

批量请求受自动预算、人工批准预算和环境 mutation policy 约束。

## 可扩展授权矩阵

授权模型不是固定双账号，也不是固定“管理员/普通用户”两级。项目可以定义任意数量
的 `AuthorizationPrincipal`，每个主体绑定一个认证 profile，并携带：

- `role_key`：角色；
- `privilege_rank`：可选的序关系维度；
- `scope_key`：租户、组织、部门或区域；
- `labels`：任意集合标签；
- `attributes`：项目自定义非敏感属性。

版本化策略通过 selector 组合这些维度，生成：

```text
资源拥有者 × 访问主体 × 资源链 × 动作
```

完整矩阵不会静默截断。若 N 个主体、不含 self case、R 个资源组，则需要
`N × (N - 1) × R` 个 case；超过策略预算会显式拒绝调度。新增主体、角色、层级、
scope 或属性只需新增数据和规则，不需要修改矩阵核心代码。

详细设计见 `docs/authorization_matrix.md`。

## Fixture 与证据复测

- fixture 只保存非认证业务输入，并使用不可变 revision；
- fixture 可以切换历史 revision、停用和归档，归档后不可复活；
- Bearer、Cookie、token、密码、私钥等内容会被拒绝；
- 漏洞修复后只能调度原证据快照复测；
- 全部明确通过才进入 `verified_fixed`；重新命中会 `reopened`；不确定结果保持待验证。

## 复核队列来源

复核队列读取 MongoDB `securityTestResult` 集合，由
`apiAnalysis/tool/result_review.py` 做结果投影、去重和 supersession，再由
`apiAnalysis/web/views_review_finding.py` 提供页面操作。

## 关键入口

- 应用工厂：`apiAnalysis/__init__.py`
- 导入契约：`apiAnalysis/import_pipeline.py`
- 执行契约：`apiAnalysis/tool/execution_contract.py`
- 调度与 worker：`apiAnalysis/tool/execution_scheduler.py`
- 参数验证：`apiAnalysis/tool/parameter_validation.py`
- 授权策略：`apiAnalysis/tool/authorization_policy.py`
- 授权矩阵：`apiAnalysis/tool/authorization_matrix.py`
- fixture：`apiAnalysis/tool/request_fixture.py`
- 复核队列：`apiAnalysis/tool/result_review.py`
- 修复复测：`apiAnalysis/tool/vulnerability_lifecycle.py`
