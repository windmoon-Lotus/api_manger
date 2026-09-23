# API Manager 调用与命令参考

更新日期：2026-08-04

本文件记录当前稳定入口。所有命令默认在仓库根目录执行，并使用锁定的 Python：

```powershell
.\.venv\Scripts\python.exe -m apiAnalysis.main --doctor
```

真实 HAR、OpenAPI、Postman、认证材料和执行证据必须存放在仓库外。命令中的
`<project-id>`、`<env-id>` 等均为占位符。

## 进程入口

| 进程 | 命令 | 是否直接发送业务请求 |
| --- | --- | --- |
| Web | `python tools/run_web_server.py` | 否；仅显式认证健康检查属于受控例外 |
| 执行 worker | `python tools/run_execution_worker.py` | 是；只执行已排队、已预算的快照 |
| 参数关系 worker | `python tools/run_relation_analysis_worker.py` | 否；分析持久化事实和候选关系 |
| 维护 scheduler | `python tools/run_maintenance_scheduler.py` | 否；恢复租约并归档已完成复测 |

本机临时启动 Web 可使用 `python run_web.py`。Flask 应用工厂和 Web 入口都不会隐式
启动 worker 或 scheduler。

## 运行检查与文件导入

```powershell
# 版本和环境检查
python -m apiAnalysis.main --version
python -m apiAnalysis.main --doctor

# HAR：可先成为待路由观察
python -m apiAnalysis.main -i <traffic.har> -f har `
  --source-id <stable-source-id> -p

# OpenAPI / Postman / Apifox：必须绑定项目
python -m apiAnalysis.main -i <openapi.json> -f openapi `
  --project-id <project-id> --env-id <env-id> --base-url <base-url> -p
python -m apiAnalysis.main -i <collection.json> -f postman `
  --project-id <project-id> --env-id <env-id> -p
python -m apiAnalysis.main -i <apifox-export-directory> -f apifox `
  --project-id <project-id> --env-id <env-id> -p
```

文件导入只解析、归档和生成候选关系，不发送业务请求，也不会把候选关系自动标记为
`verified`。`import.v1` 是内部 Python 契约名称，不是公开 HTTP 接口。

## 普通快照执行

```powershell
python tools/schedule_snapshot_batch.py --name <name> `
  --project-id <project-id> --pathid <pathid>
python tools/run_execution_worker.py --once

# 查看、取消、恢复或重试已有运行
python tools/manage_execution.py <run-id>
python tools/manage_execution.py <run-id> --cancel
python tools/manage_execution.py <run-id> --resume
python tools/manage_execution.py <run-id> --retry --retry-status error
```

调度命令只写队列；真正的网络请求由 execution worker 发送。普通批次默认只允许
`GET`、`HEAD`、`OPTIONS`。已获用户确认的普通快照变更请求可加 `--allow-mutation`；
worker 会真正发送该请求，自动重试次数限制为一次。收到普通业务响应后结果进入
`need_review` 复核队列，并保留状态码和脱敏证据；是否产生预期业务效果，需按接口实际
能力回读或核验残留。限流、服务错误和重定向仍标为 `not_evaluable`。
无需为了执行单独的创建或删除接口强求完整创建与删除配对。若使用版本化测试计划，
需显式设置 `execution_policy.allow_mutation=true`、`mutation_acknowledged=true` 和
`max_dispatch_attempts=1`。无确认仍拒绝发送变更请求。

## 多身份授权矩阵

```powershell
# 查看身份、策略、规则和激活命令
python tools/manage_authorization_policy.py --help

# 激活后调度不可变策略版本
python tools/manage_authorization_policy.py activate <policy-version-id>
python tools/schedule_authorization_matrix.py <policy-version-id>
python tools/run_execution_worker.py --once
```

矩阵可以使用任意数量的身份、角色、等级、scope、标签和非敏感属性。完整配置示例、
预算公式与判定规则见 [`authorization_matrix.md`](authorization_matrix.md)。当前矩阵适配器
只自动执行只读资源访问。

## 认证、结果与证据

| 命令 | 用途 | 网络/写入行为 |
| --- | --- | --- |
| `python tools/verify_auth_profile.py --help` | 验证 Profile/Realm 修复候选 | 会发送显式预算的认证验证请求 |
| `python tools/record_security_result.py --help` | 将私有分析结果写入统一 `result.v1` | 不请求目标；写 Mongo |
| `python tools/record_locked_snapshot_batch.py --help` | 归档锁定快照批次的脱敏结论 | 不请求目标；写 Mongo |
| `python tools/triage_need_review.py --help` | 离线整理待复核证据 | 不请求目标；读写本地文件 |

机器结果不能直接创建漏洞。候选进入 `/review-queue`，人工确认后才形成稳定 finding；
修复复测重放 finding 关联的原始不可变快照。

## Web 页面

| 页面 | 职责 |
| --- | --- |
| `/projects` | 项目入口和项目上下文 |
| `/data-sources` | 来源、导入批次和路由确认 |
| `/rawdata` | 接口资产分类和只读批次排队 |
| `/project-auth`、`/auth-realms/repair`、`/auth-import` | 认证配置、修复和 Recipe 导入 |
| `/parameter-relations`、`/parameter-priority`、`/interface-chains` | 参数和资源链知识工作台 |
| `/test-plans`、`/project-executions` | 测试计划和持久化运行 |
| `/review-queue`、`/findings` | 结果复核、漏洞和证据复测 |
| `/system/version` | 当前应用和 Python 版本 |

旧 Workspace、旧 privilege task、旧漏洞/版本/全局 testcase 页面以及 `/import-data`
兼容入口均不属于当前运行时。

## HTTP API

当前 `/api` 只提供本机管理 UI 使用的小型 session/资产接口，不是面向公网的执行 API：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/login` | 建立本地管理 session |
| `GET` | `/api/logout` | 清除 session |
| `GET` | `/api/rawdata` | 查询最多 100 条接口资产，可按 action/path 过滤 |
| `PUT` | `/api/rawdata/<asset-id>` | 管理员更新资产分类字段 |

导入、认证、调度、结果和 finding 转换不暴露为无状态 HTTP 写接口；它们分别由版本化
服务契约、队列和追加式审计事件负责。

## 数据治理与发布检查

```powershell
python tools/public_repo_guard.py --worktree
python tools/public_repo_guard.py --staged
python tools/public_repo_guard.py --tracked
python tools/public_repo_guard.py --history
python -m unittest discover -s tests -p "test_*.py"
```

## Unified offline RuleSpec analysis

Dry-run only; reads bounded project facts and sends no business request:

```powershell
python tools/run_unified_rule_analysis.py `
  --project-id <project-id> --env-id <env-id> --profile-id <profile-id>
```

Queue the durable local worker only after repeating the exact watermark printed
by dry-run:

```powershell
python tools/run_unified_rule_analysis.py `
  --project-id <project-id> --env-id <env-id> --profile-id <profile-id> `
  --enqueue --expected-input-watermark-sha256 <sha256>
```

The worker writes only machine-owned typed candidate fields and non-executable
test-plan drafts. It does not set `verified`, create findings, snapshots or
execution Runs, and does not send network requests.

门禁只输出规则、路径和行号，不输出命中的秘密值。历史扫描失败不等于当前工作树仍含
秘密，但必须分类确认后才能决定是否重写历史。

## 抽象规则离线比较

合成 P0 回归不连接 Mongo：

```powershell
python tools/eval_abstract_rules_p0.py
```

项目 Shadow Evaluation 只执行固定、带预算的 Mongo 读查询，不写数据库，也不发送认证或
业务 API 请求：

```powershell
python tools/eval_abstract_rules_shadow.py `
  --project-id <project-id> `
  --env-id <env-id> `
  --profile-revision-id <profile-revision-id>
```

参数关系只使用与所选 Profile Revision 对应、具有 project/env/account 完整归属且带
`profile_scoped_request_sample_v1` 来源标记的 `parameter_archive` 值。归属不足时返回 JSON
`status=partial`、关系 `status=blocked` 并以
退出码 3 结束，不会回退到全库或未归属参数值。预算超限同样 fail closed。默认报告只写
stdout；`--output <path>` 是唯一显式文件写入选项。

从已存储的具体请求样本生成上述 Profile-scoped 参数归档时，先运行默认 dry-run：

```powershell
python tools/build_profile_parameter_archive.py `
  --project-id <project-id> `
  --env-id <env-id> `
  --profile-revision-id <profile-revision-id>
```

报告不含参数名、路径、原始值、正文或账号别名。只有审核当前 `plan_sha256` 后才能显式写入：

```powershell
python tools/build_profile_parameter_archive.py `
  --project-id <project-id> `
  --env-id <env-id> `
  --profile-revision-id <profile-revision-id> `
  --apply `
  --expected-plan-sha256 <dry-run-plan-sha256>
```

dry-run 不写 Mongo；apply 也不发送认证或业务请求。退出码 `0` 表示计划完成，`3` 表示上下文、
样本、typed locator、可归档值或计划 hash 不满足要求，`1` 表示本地运行故障，`2` 表示用法错误。

## Apifox 测试环境边导入边实验

已有 Apifox endpoint details 目录时，可通过同一条命令走 `import.v1`，并仅针对本次
`import_run_id` 生成实验计划：

```powershell
py -3.9 tools/import_apifox_and_experiment.py `
  --details-dir <apifox-details-directory> `
  --source-id <stable-apifox-project-id> `
  --project-id <project-id> `
  --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id>
```

默认只导入和 dry-run 规划，不发送业务请求。需要立即入队时显式增加：

```powershell
  --enqueue --max-workers 8 --per-host-workers 4 --min-interval-ms 25
```

也可对数据库中已有的 Apifox 资产单独规划，先审阅值脱敏报告中的 `plan_sha256`，再用同一
hash 入队：

```powershell
py -3.9 tools/run_apifox_test_experiment.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id>

py -3.9 tools/run_apifox_test_experiment.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> `
  --enqueue --expected-plan-sha256 <plan-sha256> `
  --max-workers 8 --per-host-workers 4 --min-interval-ms 25

py -3.9 tools/run_execution_worker.py --once
```

规划器只接受显式标记为 test/development/staging/preproduction 的活动环境，且 Host 必须属于
该环境。GET/HEAD/OPTIONS 与 POST/PUT/PATCH/DELETE 均可进入专用 adapter；并发上限为 64，
每 Host 并发不得高于总并发。队列是 at-least-once，非幂等写接口必须考虑重放可能。

当前 adapter 的目标是采集测试环境事实，不是自动判定业务效果。写方法即使返回 2xx，也只会
得到 `not_evaluable / mutation_response_requires_readback`；证据明确记录尚未完成 before/after
读回和 cleanup。它不会标记验证成功、不会创建漏洞。worker 会将经过边界化处理的有效 JSON
代表样本写入 project/env/account 归属的私有 `request_sample`，供后续参数归档与关系 shadow
使用；认证 Header 不会进入样本。

### Mutation 读回与恢复

先生成严格的生命周期计划：PUT/PATCH 必须有唯一同资源 GET 和结构化 body；POST 必须有
详情 GET、DELETE，以及历史 2xx JSON 中唯一可提取的资源 ID 形状。DELETE 在没有重建契约时
不会自动执行。

```powershell
py -3.9 tools/run_apifox_mutation_lifecycle.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id>
```

建议先执行只读预检。它为每个 PUT/PATCH 候选只发送 before GET，检查能否从响应中唯一构造
恢复体；即使恢复体就绪也绝不发送 mutation：

```powershell
py -3.9 tools/run_apifox_mutation_lifecycle.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> `
  --preflight-only

py -3.9 tools/run_apifox_mutation_lifecycle.py `
  --project-id <project-id> --env-id <test-env-id> `
  --profile-revision-id <profile-revision-id> `
  --preflight-only --enqueue `
  --expected-plan-sha256 <preflight-plan-sha256>
```

对预检通过的单个 pathid，再生成非 preflight hash 并入队。更新闭环最多执行五步：before GET、
mutation、after GET、恢复请求、final GET。before 非 2xx/非 JSON、恢复体不唯一或 mutation 非 2xx
都会提前停止；恢复请求成功后仍必须由 final GET 的字段摘要证明已恢复。创建闭环最多执行
POST、详情 GET、DELETE、最终 GET，最终 404/410 才算清理得到验证。任何清理不确定都会进入
`need_review`，但不会自动创建 finding。

请求组合现在只允许已验证或人工 trusted 的参数关系提供值，且 relation evidence 必须是标量；
发现元数据、解释字典、弱候选和未验证高分关系不能再被渲染进 URL/body。

## 迁移与专项维护工具

以下脚本不是日常启动入口。运行前必须备份数据库、先阅读 `--help`，能 dry-run 的先
dry-run，并在执行后重新运行完整测试：

- `migrate_account_context_v1.py`
- `migrate_data_sources_v1.py`
- `migrate_execution_scheduler_v1.py`
- `migrate_parameter_p0.py`
- `migrate_parameter_relation_workbench.py`
- `migrate_project_context_v1.py`
- `backfill_outcome_class.py`
- `backfill_idor_construction_traces.py`

`pull_apifox_endpoint_details.py` 会调用外部 Apifox 能力；`import_apifox_assets.py`、
`import_openapi_request_schemas.py`、`seed_parameter_archive_from_round.py` 和各类
`build_*` / `eval_*` 脚本属于一次性导入、离线研究或迁移辅助工具。新的常规导入与执行
不应绕过 `import.v1`、scheduler 和 `result.v1`。

## AI CLI（A0 已实现）

`apiAnalysis/ai_cli` 提供纯 AI 调用入口与软策略，入口为
`python -m apiAnalysis.ai_cli`。stdout 只输出 JSON/JSONL，日志走 stderr；
退出码 0 成功、1 运行/策略错误、2 用法错误、10 非交互下需要审批。

子命令：

- `capabilities --json`：列出 providers、tools 与生效策略；
- `policy show|validate [file] --json`：查看/校验策略；策略文件为 JSON，
  TOML 需要 Python 3.11+（tomllib）或 tomli；
- `run`：从 stdin/`--input` 读取单条 JSON 或 JSONL 工具请求并执行；
  也支持 `--provider fake --script <file>` 运行最小 agent loop；
- `task <name>`：外部 Agent 单任务入口（依赖 Mongo，`--dry-run` 不发业务请求）；
- `shell -- <command...>`：以 `provenance=unmanaged` 执行系统命令。

示例（PowerShell）：

```powershell
python -m apiAnalysis.ai_cli capabilities --json
'{ "tool": "fake.echo", "arguments": { "value": "hi" } }' |
  python -m apiAnalysis.ai_cli run --access read-only --approval on-risk
python -m apiAnalysis.ai_cli run --access full-access --approval never --dry-run
python -m apiAnalysis.ai_cli shell --access full-access --approval never -- dir
```

AI CLI 还注册了三个 `filesystem.read`、`network=false`、`writes=false` 的离线
审计工具：`audit.boundary`、`audit.evidence_verify` 和 `audit.coverage`。例如：

```powershell
'{"tool":"audit.boundary","arguments":{"transcript":"<transcript.jsonl>","scope":"<scope.json>"}}' |
  python -m apiAnalysis.ai_cli run --access read-only --approval never
'{"tool":"audit.evidence_verify","arguments":{"evidence":"<evidence.json>"}}' |
  python -m apiAnalysis.ai_cli run --access read-only --approval never
'{"tool":"audit.coverage","arguments":{"total":"<total.json>","candidates":"<candidates.json>","tested":"<tested.json>"}}' |
  python -m apiAnalysis.ai_cli run --access read-only --approval never
```

它们只复核已有文件，不发送业务请求，也不把报告写回磁盘。SQLi 的真实请求仍通过
`project.create_plan` / `project.execute_plan` 和 scheduler 的 SQLi adapter 执行，避免绕过
AccountContext、请求预算、节流、快照和复核链。

### SQLi 独立首轮筛查与事后审计

`tools/whitehat_sqli_screen.py` 是操作员受控的通用 GET 参数首轮筛查器，不是 AI CLI 的
直连网络工具。目标文件只放授权范围内的测试环境 URL；私密 Header 使用仓库外 JSON 文件，
不要放入命令行、仓库或报告：

```powershell
py -3.9 tools/whitehat_sqli_screen.py `
  --targets <targets.json> `
  --headers-file <private-headers.json> `
  --out <private-evidence.json> `
  --max-requests 100 --delay-ms 150

py -3.9 -m tools.audit.evidence_verify --evidence <private-evidence.json>
py -3.9 -m tools.audit.boundary_audit `
  --transcript <transcript.jsonl> --scope <scope.json>
py -3.9 -m tools.audit.coverage_report `
  --total <total.json> --candidates <candidates.json> --tested <private-evidence.json>
```

`no_signal` 只表示这组小型、成对 payload 没有产生信号，不证明参数已安全或漏洞已修复。
覆盖率必须同时给出 total、candidate、tested 三个分母；证据校验失败时不得采用存储结论。

创建对象的轮次还应由操作员执行清理读回。该工具需要访问网络，因此未注册到离线审计
工具面：

```powershell
py -3.9 -m tools.audit.cleanup_audit `
  --config <cleanup-sweeps.json> `
  --headers-file <private-headers.json> `
  --out <private-cleanup-report.json>
```

退出码 `0` 仅表示所有配置的 sweep 均为 `clean`；`1` 表示发现 `residue`；`2` 表示
`not_evaluable`、没有 sweep 或未知结论。非 200、超时和可见性不足不能当作已清理。

访问预设 `read-only/workspace-write/full-access/custom` 与询问偏好
`always/on-risk/never` 独立组合；`full-access + never` 表示用户明确授权完全
自动运行，不附加隐藏阻断。TTY 下高危动作会询问（本次允许/本会话允许/总是允许
此规则/拒绝），非交互下返回 `approval_required` 并以退出码 10 结束。策略可用
JSON 文件（`--policy`）与每工具 fragment（`--policy-dir`，默认
`~/.api_manager/ai_policy.d`）覆盖。详细协议、退出码和实施顺序见
[`ai_cli_access_and_approval_design.md`](ai_cli_access_and_approval_design.md)。
