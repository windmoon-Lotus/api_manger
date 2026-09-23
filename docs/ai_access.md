# API Key 与 AI 导航

网页入口 `/api-keys`、`/ai`，首页账号菜单可打开。外部 AI 无需网页会话。

## 首选：已封装的本地 CLI

日常任务复用 `authcheck-cli`，不要再生成 `aikey_*_probe.py` 一类临时调用脚本。
完整安装、参数与退出码见 [客户端说明](../clients/authcheck_cli/README.md)。
专门测试平台协议本身时可以编写测试，业务调用则使用现有命令。

```powershell
python -m pip install -e ./clients/authcheck_cli
authcheck doctor
authcheck projects
authcheck plans --project PROJECT_ID
authcheck readiness PLAN_ID --project PROJECT_ID
authcheck run PLAN_ID --project PROJECT_ID --idempotency-key UNIQUE_OPERATION_KEY --timeout 120
authcheck wait RUN_ID --project PROJECT_ID --timeout 120
authcheck results RUN_ID --project PROJECT_ID
```

配置并复用环境变量中的现有 Key，不读取 `.secrets` 中的网页登录密码，不为每次业务调用创建新 Key。
账号范围 Key 必须明确项目；CLI 不自动选第一个项目或计划。所有 ID 由前一步平台响应提供。
通用参数用 `--arg name=value` 或 JSON 文件，不需要写 Python 脚本。

`run` 自动读取计划、预检、提交、等待和回读；仅执行已激活计划。它不自动创建或激活计划，也不启动 worker。
超时退出 3，继续 `wait` 原 Run。调用状态不确定时，用
`authcheck receipt --idempotency-key SAME_OPERATION_KEY` 查询原回执；重试原命令保持相同键与正文。
失败、暂停、取消退出 4。HTTP 200 和空结果不能结束等待，旧服务端缺少完成字段时直接报告契约缺失。

## 权限

- `read_only`：账号当前允许的查询与预检。
- `account`：继承账号当前业务角色；管理角色可创建、激活、归档、执行计划。
- 默认继承账号可访问的项目范围，创建 Key 时可选一个项目进一步限制。
- 每次请求重新核对账号角色；删除账号、降权、撤销、过期均影响后续调用。
- Key 不认证网页、登录、账号、密码或其他密钥管理接口；这些只能通过网页会话。
- 当前本地账号模型是全局 access/manage 角色，没有额外的用户项目 ACL。Key 沿用这个模型；可选项目绑定只能缩小范围。

服务端只保存 Key 的 SHA-256 摘要。完整 Key 创建时显示一次，页面禁止缓存。
创建与撤销使用会话和 CSRF 校验；不要在提示词、源码、URL、日志中放密钥。

## 接入

从仓库根目录运行。将平台 origin 配置在 `API_MANAGER_URL`，将密钥配置在
`API_MANAGER_ACCESS_KEY`。这是外部客户端访问平台的 Key，与平台调用模型所用的
`API_MANAGER_AI_API_KEY` 不同。远程访问使用 HTTPS；CLI 拒绝重定向。

```powershell
python tools/ai_access_client.py doctor
python tools/ai_access_client.py capabilities
python tools/ai_access_client.py guide
python tools/ai_access_client.py describe project.list
python tools/ai_access_client.py call project.list
python tools/ai_access_client.py describe project.readiness
python tools/ai_access_client.py call project.readiness --json-file arguments.json
python tools/ai_access_client.py calls
```

`arguments.json` 只放工具参数对象。实际项目与计划 ID 从列表读取，不猜测。
账号范围 Key 调用项目工具时传 `project_id`；项目限定 Key 可以省略，但不能指定其他项目。

公开启动说明：`GET /ai?format=markdown`，该入口不消费认证头。
其余入口均需 `Authorization: Bearer <本机 Key>`：

| 入口 | 用途 |
| --- | --- |
| `GET /api/ai/capabilities` | 当前权限下的工具目录与详情链接 |
| `GET /api/ai/guide` | 操作顺序、失败处理与结论边界 |
| `GET /api/ai/tools/<name>` | 当前工具参数、读写属性与幂等要求 |
| `POST /api/ai/tools/<name>` | 正文 `{"arguments": {...}}`，调用实际服务 |
| `GET /api/ai/calls` | 本 Key 最近 20 次已进入执行层的调用回执 |
| `GET /api/ai/receipt` | 携带原 Idempotency-Key，精确回读当前 Key 的原操作，超出 20 条仍可恢复 |

## 当前操作链

1. `project.list`、`project.assets`：发现项目与接口。
2. `project.list_plans`、`project.plan`：检查计划及版本范围。
3. `project.create_plan`、`project.activate_plan`、`project.archive_plan`：管理账号的计划操作。新建默认草稿。
4. `project.readiness`：复用网页的静态前提检查。
5. `project.execute_plan`：复用现有快照构建与调度器；只接受已激活且预检通过的计划。
6. `project.runs`、`project.results`、`project.review_queue`：回读执行、完整机器结果统计、候选复核队列。

`project.run` 按 run_id 精确读取状态，无需遍历最近 50 条。`project.results` 保留原统计字段，
新增 `run`、`execution_complete`、`results_complete`。执行结束与结果完整是两个独立条件，
两者成立仍不构成安全结论。调用回执仅额外保存项目与计划引用，不保存完整请求参数。

所有写工具要求 16–128 位字母、数字、下划线或连字符的 `Idempotency-Key`。
同一 Key 同一幂等键与正文只执行一次；正文改变返回 409。异常后的 pending/unknown
回执不自动重跑，先检查调用和计划/Run 状态。正常执行回执仅保存 plan/run ID 与状态。
后台 worker 仍需正常运行；调度成功不代表请求已完成。

接入自检通过只证明公开导航、认证、能力、参数目录、一次项目查询和调用回读可用。
真实业务效果需要正常基线、对照、证据和最终回读。普通只读预检不开放专用写操作测试。
当前 API 覆盖上述操作，并未将全部网页管理功能自动暴露为接口；新操作应复用原服务并登记权限。

## 验证

```powershell
python -m pip install -e ./clients/authcheck_cli
python -m unittest discover -s tests -p test_ai_access.py
$env:RUN_AI_ACCESS_INTEGRATION='1'
python -m unittest discover -s tests -p test_ai_access.py
```

集成测试使用随机 `ai_access_test_...` 独立数据库和临时 HTTP 服务，完成后删除该测试库。
包含真实 HTTP 自检、计划生命周期、跨项目拒绝、权限变化、撤销、幂等和 CSRF。
安装包的独立进程还会通过真实 HTTP 验证等待及回执恢复；该项用合成 Run 和替代调度函数推进状态，
验证客户端流程，不声称执行了真实业务请求。客户端等待/失败/旧契约测试在 `test_ai_access_cli.py`，
可使用 `python -m unittest discover -s tests -p "test_ai_access*.py"` 一起运行。
调用记录不持久化请求参数或业务响应。独立测试不会向业务系统发送请求。
