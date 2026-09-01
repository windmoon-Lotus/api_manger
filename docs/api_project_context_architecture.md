# ApiProject 与执行上下文架构

更新日期：2026-07-16

> 状态：历史迁移快照。本文中的 Workspace 兼容、旧 runner 和“尚未完成”清单不代表
> 2026-08-04 当前实现。现行领域模型和完成状态见
> `api_manager_v2_domain_architecture.md`、`../PROJECT_OVERVIEW.md` 和 `README.md`。

## 目标

把旧系统中隐含在 Workspace、Apifox `source_meta`、参数表和专项 runner 里的“项目”
显式化，同时保留现有请求拼接、参数分析、快照、越权 runner 和结果模型。

核心关系：

```text
ApiProject
  -> ProjectSourceBinding (Apifox/OpenAPI/HAR/Workspace)
  -> ImportRun
  -> raw_data / ProjectAssetLink
  -> RequestObservation / ObservationRoutingDecision
  -> parameter facts and relations
  -> request_snapshot
  -> security_test_run / security_test_result
```

Workspace 是流量和认证上下文来源，不再被当作项目边界。混合 Workspace/HAR 中的每条
请求由 `project_routing.route_observation()` 单独判断；精确签名和 Host/Method/Path 可以自动
归属，同分候选保留为 `ambiguous`，只有 Host 的弱证据保留为 `unassigned`。

## 已实现的 P0 纵向切片

- 新增 `ApiProject`、`ProjectSourceBinding`、`ImportRun`、`RequestObservation`、
  `ObservationRoutingDecision` 和 `ProjectAssetLink`。
- `raw_data`、参数归档/关系、IDOR 参数候选、快照、样本、安全运行和结果增加项目上下文。
- Apifox 批量导入自动解析来源项目、创建/复用内部项目并记录未来 ImportRun。
- 新项目上下文存在时，参数构造不再静默回退到其他项目/环境的归档值。
- `request_snapshot` 支持 `anonymous/account/inherit`；匿名重放强制移除 Authorization、
  Cookie、Proxy-Authorization 和 API-key Header，也不读取本机认证环境变量。
- `ExecutionContext` 是通用编排契约，只调用现有 `create_request_snapshot()`，不重写请求拼接。
- 锁定批次可以通过 `record_locked_snapshot_batch.py` 将快照引用和脱敏结果归档到现有
  `security_test_run/result`，而不重新发送请求。
- HAR/mitm 导入现在先创建可跨项目的 ImportRun，再对每条请求执行项目路由；显式选择项目时
  具体资产身份加入项目 scope，避免共享 Host/Path 的跨项目样本合并。真实值仍进入既有
  request_sample，RequestObservation 只保存 Header 名、Body shape、状态、长度和哈希。
- 旧 Workspace 实时请求在保留 PacketRecord 流程的同时写入脱敏 RequestObservation；观察失败
  不影响原请求和旧工作空间功能。
- Web 导入中心支持选择 ApiProject 和 environment；不选择时 HAR 进入自动路由。

## 本地迁移验收

迁移脚本必须先 dry-run，并只回填能够由来源绑定唯一证明的项目归属。无法唯一
归属的记录保持未分配，禁止按 Host、名称或“第一条记录”猜测。验收至少确认：

- 导入资产创建稳定的 `ProjectSourceBinding` 与 `ProjectAssetLink`；
- 参数归档、参数关系、候选项、快照、运行和结果只回填唯一可证明的项目；
- 跨项目记录保持待人工拆分；
- `interfaceChainFeedback.family` 的唯一性限定在项目、环境和资源族内；
- 迁移归档阶段不重新发送任何业务请求。

具体项目 ID、数据量和真实验证记录保存在仓库外的迁移报告中。

## 尚未完成

1. OpenAPI/Postman 可在导入后显式绑定项目，但还未像 Apifox 一样自动创建来源绑定和 ImportRun。
2. 持久化调度已完成：Mongo 维护 run/lease/heartbeat/cancel/retry 和逐快照 checkpoint，Redis 仅作唤醒；默认无固定接口数上限并按 Host 控制并发、速率和熔断。详见 `execution_scheduler.md`。
3. `account` 模式仍兼容本机短期认证环境变量；后续应接显式 AccountContext provider。
4. 项目/环境/账号管理 UI、ambiguous/unassigned 确认页和 ImportRun 页面尚未实现。
5. 20 个跨项目参数归档需要拆分为项目级事实，不能直接补一个项目 ID。
6. Workspace 目前记录观察但不自动生成 raw_data/request_sample；需要确认哪些工作空间流量应晋升
   为资产样本，避免把扫描/认证辅助流量全部污染参数中心。

## 兼容和迁移规则

- 旧记录允许项目字段为空；读取时显式字段优先，必要时兼容 `source_meta.internal_project_id`。
- 不重写历史专项 runner；新执行和有价值的旧证据逐步接入通用执行契约。
- `tools/migrate_project_context_v1.py` 默认 dry-run，`--apply` 幂等回填唯一可证明的数据。
- 不把 Apifox Project ID 当内部主键；它只是 ProjectSourceBinding 的外部来源 ID。
