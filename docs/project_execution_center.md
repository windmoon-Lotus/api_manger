# 项目执行中心

`/project-executions` 是持久化测试运行的全局投影视图。它只管理已经归属项目的
运行、检查点和结果，不再编辑数据源、来源绑定或观察路由。

## 状态所有权

- MongoDB 中现有 `security_test_run`、`security_execution_checkpoint` 和
  `security_test_result` 仍是唯一执行状态，不建立第二套任务状态机。
- 取消和恢复调用调度器状态转换。取消是协作式的，保留运行、检查点和结果；
  恢复只对 `paused` 运行开放，并重新经过 worker 的适配器、认证和 Host 预检。
- 页面不提供通用“重试”按钮。重试可能重新发送请求，必须由具体测试计划或
  适配器根据变更影响、读回和清理规则决定。
- 参数关系页提供的是关系适配器专用恢复，不是执行中心的通用重试：只有结构化
  结果为 `host_scope_approval_required` 时，才按完整授权 Host 集合计算新的
  单接口对硬预算，并要求管理员显式确认。来源阶段仍失败时不会发送消费请求。
- 参数关系批量执行必须先生成只读预览，并冻结有序接口对、方法、路径、Host、
  字段数和预算；确认时范围不一致会拒绝并要求重新预览。预览本身不创建 Run、
  不发送认证或业务请求。
- 只读 HTTP 400 默认仍允许在授权 Host 内切换；只有非通用结构化业务错误才
  停止并进入 Fixture 恢复。共享来源已有明确 Fixture/认证阻塞时，批量选择器
  会跳过所有复用该来源的接口对，避免重复无效请求。
- `/test-plans` 中激活版本的“一键执行”是创建新运行的入口。它重新组合并保存
  本次不可变请求快照，固定计划、认证 Profile/Realm/Adapter Revision，再进入
  现有 Mongo 持久化队列；页面本身不直接发送业务请求。
- 项目卡片只是资产、环境和运行计数投影，不拥有项目配置。

## 与其他页面的边界

- `/data-sources`：来源、导入批次、观察路由、来源绑定和人工纠偏。
- `/project-auth`：项目环境、账号和认证方案。
- `/test-plans`：明确 PathId 范围、认证方案、Adapter、预算和超时，创建新运行。
- 接口知识中心：参数资产、关系验证和链路编排。
- `/project-executions`：运行状态、进度、Host 停止状态、检查点和结果。

这种拆分避免来源路由与执行生命周期在两个页面重复修改。

## 访问与证据边界

- 读取需要本地登录会话。
- 取消和恢复需要 manager 角色与会话 CSRF token。
- 表单携带预期运行状态，过期页面不会覆盖新状态。
- `apiAnalysis.tool.lifecycle_view` 是允许字段投影层。模板只收到标识、状态、
  计数、时间、请求方法/Origin/Path、Query/Header/Cookie 名称、Body 长度、
  TLS/跳转/超时设置、响应类别/长度/集合数量/字段名和脱敏 AccountContext
  健康信息。
- 原始查询值、Header/Cookie 值、Token、响应正文、异常原文和私有证据路径
  不进入模板。
- 参数关系新结果可展示真实 PreparedRequest 的方法、Origin/Path、
  Query/Header/Cookie 名称、Body 字节数、TLS、跳转、超时和认证前置请求数；
  这些都是结构元数据，不包含请求值或响应正文。
- Checkpoint 的“执行效果”只描述是否得到业务响应；Result 的 `verdict` 和
  `outcome_class` 才是安全结论。通用重放成功可以显示“业务响应成功”，同时仍
  保持 `not_evaluable / blocked`，直到专用 Adapter 提供安全判定。

## 验证

- `tests/test_lifecycle_view.py` 覆盖允许字段和脱敏边界。
- `tests/test_project_execution_web_integration.py` 覆盖模块拆分、CSRF、manager
  权限、恢复和安全取消。
- 数据源和路由闭环由 `tests/test_data_source_web_integration.py` 覆盖。
- 浏览器验证使用合成项目和本地替身服务，覆盖计划创建、激活、一键执行和
  最终详情。针对真实目标的授权验证记录只保存在仓库外的私有证据目录。
- 参数关系的全量本地分析、有界批量真实验证、失败提示和 Host 范围恢复见
  `docs/parameter_relation_validation.md`。
