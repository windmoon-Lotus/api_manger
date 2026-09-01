# API Manager 需求基线 V2

更新日期：2026-08-04

## 1. 产品定位

API Manager 是面向内部授权场景的 API 测试资产与安全测试编排基座。
系统负责沉淀接口定义和真实请求样本、维护项目/环境/账号上下文、生成可复现请求、
编排安全测试、归档证据并支持人工复核与复测。

系统不以自研所有通用漏洞扫描器为目标。SQL 注入、契约测试、模板扫描和 DAST
优先通过成熟工具适配；越权、业务对象链和账号数据隔离是项目重点自研能力。

## 2. 核心边界

核心数据链路必须保持为：

```text
导入批次
-> API 资产（抽象定义 / 具体样本）
-> 参数事实与关系
-> 账号和环境上下文
-> 不可变请求快照
-> 安全任务与执行
-> 证据、结论、漏洞和复测
```

- OpenAPI/Apifox 主要提供抽象定义，HAR/flow/Postman 提供具体执行样本。
- 每次导入必须具有独立批次范围；空批次不得退化为全库分析。
- 参数值必须区分项目、环境、账号和角色，禁止跨上下文静默复用。
- 所有真实重放和工具执行必须消费 `request_snapshot` 或其标准请求载荷。
- HTTP 2xx/204 只表示请求被接受，不足以单独证明越权或状态变更。
- 写操作必须记录执行前状态、访问主体操作、资源归属主体读回以及清理/恢复结果。
- AI 只用于接口说明、任务推荐、证据归类和人工复核辅助，不直接判定漏洞成立。

## 3. 当前已经具备的能力

以下能力已经存在，不应作为新功能重复开发：

- OpenAPI、Apifox、HAR、Postman、mitmproxy flow 导入。
- 抽象接口与具体流量样本分离，并通过签名和 `source_meta` 关联项目来源。
- 请求/响应参数位置、类型、必填属性、参数关系、账号参数归档和人工角色维护。
- 请求样本、标准请求载荷、不可变 `request_snapshot` 和持久化 worker 重放入口。
- 未授权、多身份水平/垂直授权矩阵、对象 ID 互换、作用域隔离和依赖参数构造能力。
- `security_test_run` / `security_test_result` 运行批次与标准结果归档。
- 授权矩阵中的资源归属主体取值、访问主体只读访问及资源身份匹配；写入类 action
  必须另行实现回读、补偿/清理适配器，当前不会借用只读链执行。
- `potential_vuln`、`no_vuln`、`need_review`、`not_evaluable`、`error` 等结论，
  以及人工处置、提升漏洞、修复状态和证据引用页面。
- API 版本、漏洞、测试用例、参数中心、参数关系和接口链管理模型及页面。
- Python/Mongo/Redis/上传目录/外部工具自检和现有回归测试。

## 4. 已实现但需要统一或补强

这些不是功能缺失，而是现有实现的一致性和验收增强：

- 新数据已显式传递项目、环境、数据源和导入批次；历史无法证明归属的
  `raw_data/request_sample` 保持未归属并进入路由待处理，不使用默认项目补齐。
- 导入批次已持久化为 `ImportRun`；空导入不会触发全库分析，失败批次也不会
  覆盖上一次成功来源版本。
- 新运行统一消费不可变快照并进入持久化调度器；Web 和统一导入 CLI 不直接发送
  业务请求。旧同步 runner 已从当前运行时删除，历史集合只由显式迁移工具读取。
- `security_test_run/result` 已经承担任务运行和结果职责。后续优先在现有模型上补充
  适配器、快照引用、重试/父执行关系等必要字段，不再为名称一致重复创建
  `security_task/security_execution` 两套表。
- 写操作读回和清理规则已在成熟链路中实现；新 runner 接入时继续执行同一规范。
- 现有结论使用 `potential_vuln`，确认后通过人工处置或漏洞状态表达 `confirmed`，
  无需强制迁移历史结论名称。
- 当前自动化测试以核心纯函数和回归测试为主，导入批次已有单测，Web 已做冒烟；
  仍可增加使用临时数据库的端到端导入、任务和页面测试。
- Web 默认密码、Debug、固定密钥和默认 CORS 已收紧；数据源、路由、认证和
  执行生命周期修改均使用 manager 权限与 CSRF，其他旧修改页面仍按模块迁移核对。

## 5. 下一阶段增强项

### P0：统一性和安全加固

1. 增加轻量 `import_run` 审计记录，并把项目、环境、来源批次稳定传递到资产和快照。
2. 复用 `security_test_run/result`，定义统一 runner/adapter 输入输出协议；逐步让新执行
   自动记录快照引用，历史专项 runner 不做无收益重写。
3. 为修改类 Web 路由补齐 CSRF 和 manager 权限矩阵。
4. 增加脱敏 OpenAPI/Postman/HAR 样本及临时数据库/Web/任务生命周期集成测试。

### P1：外部能力闭环

- Schemathesis 统一适配、API 版本差异回归、漏洞复测和覆盖质量报告。
- 根据实际收益再接 sqlmap、nuclei、ZAP、ffuf；外部工具统一使用标准请求载荷、
  授权范围和结果证据模型。

## 6. 当前数据基线

2026-07-10 本机只读核验：2348 条 API 资产、501 条参数关系、2 条持久化请求快照、
135 次安全测试运行和 3440 条安全结果。快照数量少表示专项 runner 更多使用标准
请求载荷和私有证据文件，不表示越权测试、读回清理或结果归档能力尚未实现。

## 7. 2026-07-16 ApiProject P0 实施状态

已建立稳定内部 `ApiProject`、来源绑定、ImportRun、真实请求观察/路由决策和项目资产关联；
资产、参数、快照、运行及结果已具备明确项目上下文。Apifox 批量导入已接入项目/ImportRun，
通用 `ExecutionContext` 已复用现有请求拼接和 request_snapshot 链，并增加显式匿名认证隔离。

HAR/mitm 和 Workspace 已接入脱敏 RequestObservation；HAR 支持显式项目绑定或逐请求自动路由，
OpenAPI/Postman 强制选择项目/环境并创建来源与 ImportRun。持久化调度队列、AccountContext
provider、认证工作台和独立数据源/路由 UI 均已完成。详细边界及迁移结果见
`docs/api_project_context_architecture.md` 与 `docs/data_source_routing_center.md`。

## 8. 2026-07-16 Persistent scheduler status

The persistent execution lifecycle is now implemented over the existing
`security_test_run/security_test_result` backbone. MongoDB owns queue, lease,
heartbeat, cancellation, retry, Host state, and per-snapshot checkpoints;
Redis is a wake-up signal only. The generic adapter has no fixed endpoint-count
cap, applies configurable global/per-Host concurrency, and rejects mutation
methods unless explicitly acknowledged. Legacy runs/results are not rewritten.
See `docs/execution_scheduler.md`. The explicit AccountContext provider and
`authenticated_snapshot_batch` contract are now implemented: credentials are
resolved from a private-file or callback provider, validated by project,
environment, account, expiry and Host, held only in memory, and unavailable
contexts pause before requests. See `docs/account_context.md`. The local
execution center now only owns runs, checkpoints, results and scheduler-native
cancel/resume controls. Data sources, import runs, source bindings and
append-only routing correction live in `/data-sources`; see
`docs/project_execution_center.md` and `docs/data_source_routing_center.md`.
Versioned test plans, result review events, the vulnerability lifecycle and
immutable finding retests are implemented. New adapters must use the same
snapshot/execution/result contracts.

## 9. 2026-07-20 参数与认证 P0 实施状态

参数事实已从用于恢复请求的扁平键升级为“原始路径 + schema 路径 + 展示路径 + typed locator”。
数组下标、schema `[]`、动态对象键及数字对象键不再混淆；Path、Query、Header、Cookie 和 Body
作为五种一等请求位置处理。流量 Cookie 只沉淀名称，不把 Cookie 值复制到参数事实。

新增 `ProjectEnvironment`、`ProjectAccountBinding`、`ProjectAuthProfile` 及“项目环境与认证”页面。
一个项目/环境可绑定多个内部测试账号，并为同一账号建立 Bearer、Cookie 或 mixed 多套方案。
worker 在执行时使用现有 SSO 流程自动刷新 Token/Cookie，凭据只存在内存；任务和结果只保存
项目、环境、账号别名、方案引用、Host 范围及脱敏健康状态。

参数关系验证已移除 Web 直连请求，改为复用持久化调度器。一次人工操作最多把 10 条关系放入
同一个轻量批次；来源 JSON 与来源提取值只在进程内使用，结果仅含摘要、类型和长度；可选人工
覆盖值仅保存在 7 天过期的异步计划快照中。临时计划快照、
运行、检查点、通用结果和参数验证结果统一设置 7 天 TTL。真实数据迁移后，325 条关系具有
精确来源/目标位置并可入队；176 条缺失来源接口或参数事实的历史候选明确标记为“位置待补数据”，
不会混入批量执行。非空参数事实的 locator 已全部回填，历史参数优先级/经验数据已迁移到稳定项目 ID。

## 10. 2026-07-24 数据源与项目路由 P1-A 实施状态

已增加稳定 `DataSource`，并把来源、项目、环境、认证和执行拆成独立引用。
OpenAPI/Postman/HAR 文件导入均创建不可变 `ImportRun`；OpenAPI/Postman 必须
显式选择项目，未指定项目的混合流量只生成脱敏观察。

3 个 Apifox 来源绑定和 2 个实时采集空间已迁移为 DataSource。106 个历史未归属
样本与 22 个无样本资产形成 128 条待路由观察；机器没有足够项目证据，因此全部
保持 `unassigned`，没有按 Host 猜测。页面支持同来源 + Host 批量确认、逐条纠偏、
忽略非业务流量、精确接口结构学习，以及来源绑定新增/停用。人工最终结论通过
追加记录修改，重复采集不会覆盖人工结论。

项目执行中心已移除来源绑定和路由表单，只保留运行、检查点、结果、恢复和安全取消。
旧 `/import-data` 已删除；版本化测试计划与结果复核现已完成，
不会恢复旧的 Workspace = 项目 + 流量 + 认证模型。

## 11. 2026-08-04 统一契约与多身份授权实施状态

所有文件导入已统一到 `import.v1`，所有新业务执行进入 Mongo 调度队列，所有机器结论
通过 `result.v1` 写入。Web、execution worker、relation worker 和 maintenance
scheduler 已拆分为独立进程；旧 Workspace Web、捕获和同步重放入口已删除。

授权测试使用 N 身份矩阵，不固定账号数量或角色层数。一个不可变策略版本可组合角色、
等级区间、组织作用域、标签和非敏感自定义属性，并完整生成
`访问主体 × 资源归属主体 × 资源组`。超出显式预算时失败，不截断。策略激活冻结身份
认证版本和已验证参数关系指纹；漂移后创建下一版本。详见
`docs/authorization_matrix.md`。

请求 Fixture 具有稳定对象、不可变 Revision 和追加式 Event。漏洞修复后只重放关联
机器结果的不可变快照：全部明确通过才关闭、候选复现才重新打开、不完整证据继续待验证。
