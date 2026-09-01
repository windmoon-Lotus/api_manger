# 数据源与项目路由中心

## 目标

`/data-sources` 是文档、流量和项目资产之间的唯一人工工作台。它回答两个问题：

1. 数据从哪个稳定来源、哪个导入批次产生；
2. 该观察属于哪个项目和环境。

认证方案、测试执行和接口知识不在这里编辑，只消费已经归属的项目资产。

## 对象与职责

```text
DataSource
-> ImportRun / RequestObservation
-> ObservationRoutingDecision
-> ProjectSourceBinding
-> raw_data / request_sample / ProjectAssetLink
```

- `DataSource` 保存稳定来源身份和非秘密配置。
- `ImportRun` 保存一次不可变导入的状态和计数。
- `RequestObservation` 只保存路径、Header/Query 名称、Body 结构和响应摘要；
  URL 查询值、Header 值、Cookie 值和 Body 值不进入路由页面。
- `ObservationRoutingDecision` 保存每次机器或人工结论。人工纠偏追加新记录，
  不覆盖历史记录。
- `ProjectSourceBinding` 保存来源到项目/环境的当前绑定，以及人工确认后学习的
  精确 `method + abstract_signature` 规则。

## 导入规则

- OpenAPI/Postman 必须显式选择项目与环境。
- HAR 可以显式选择项目，也可以逐条进入机器路由。
- 每次导入都创建新的 `ImportRun`；失败不会覆盖上一个成功批次。
- 导入后可执行本地接口知识预处理，但不会因此发送业务请求。
- 未归属的 HAR/流量只形成脱敏观察，不提前写成项目资产或真实样本。

## 路由与人工纠偏

机器路由优先级：

1. 用户显式项目；
2. 同来源已确认的精确接口结构；
3. 项目资产中的方法、抽象签名与 Host；
4. Host + 路径前缀候选；
5. 无充分证据时保持 `unassigned` 或 `ambiguous`。

人工可以：

- 逐条确认项目和环境；
- 一次确认同一来源、同一 Host 的待处理分组；
- 选择是否学习组内每种接口结构；
- 标记非业务流量；
- 对已确认/已忽略结论追加纠偏；
- 新增或停用来源绑定。

纠偏会撤销旧绑定中的对应精确接口学习规则，并保留旧路由决策。停用来源绑定
不会删除历史导入、观察或项目证据。

## 历史数据迁移

运行：

```powershell
py -3.9 tools/migrate_data_sources_v1.py
py -3.9 tools/migrate_data_sources_v1.py --apply
```

迁移默认 dry-run，并且幂等。它会：

- 为旧 Apifox 来源绑定和实时采集 Workspace 创建稳定 `DataSource`；
- 回填 `ProjectSourceBinding`、`ImportRun` 和 `RequestObservation` 的来源引用；
- 删除旧的“来源 + 环境全局唯一”索引，改为“项目 + 来源 + 环境唯一”；
- 将历史未归属样本和资产转换为脱敏观察，进入待路由区；
- 不发送请求、不读取认证凭据、不自动猜测无法证明的项目。

本机 2026-07-24 迁移结果：

- 3 个 Apifox 来源、2 个实时采集来源和 1 个历史待归属来源；
- 3 个旧来源绑定已回填；
- 106 个历史样本和 22 个无样本资产形成 128 条待路由观察；
- 128 条均因缺少可证明项目匹配保持 `unassigned`，未静默归属；
- 第二次 dry-run 为 0 个新来源、0 个来源引用回填。

## 页面职责拆分

- `/data-sources`：来源、导入批次、路由与来源绑定。
- `/project-executions`：持久化运行、检查点、结果、暂停/恢复/取消。
- `/project-auth`：项目环境、测试账号和认证方案。
- 接口知识中心：参数资产、关系验证和链路编排。

旧 `/import-data` 已删除，不再维护第二套导入表单或兼容重定向。
