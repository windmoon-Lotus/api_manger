# AI CLI 开放代理模式与软约束设计

状态：A0（CLI 协议和软策略）已实现，A1-A3 待实施
更新日期：2026-08-05

## 1. 设计立场

`api_manger` 是用户在自己主机上运行的开源个人项目。用户能够修改源码、调用系统
Shell、直接访问数据库和网络，因此项目不应把 CLI 的访问档位包装成不可绕过的安全
边界。

AI CLI 的目标是提供类似 Codex 的操作体验：

- 默认在可能产生明显副作用时询问；
- 用户可以选择只读、工作区写入或完全访问；
- 用户可以选择每次询问、风险时询问或从不询问；
- `full-access + never` 代表真正的全自动模式，不再附加隐藏权限封锁；
- 所有策略均可由用户配置、覆盖或删除；
- 日志和 provenance 帮助用户理解发生了什么，不充当强制沙箱。

项目仍可提供安全默认值、数据脱敏、预算、cleanup 和 scheduler，但这些是推荐能力和
软约束。用户显式选择完全访问时，框架应服从用户，而不是与用户对抗。

## 2. 当前状态

A0 已实现（2026-08-05），新增 `apiAnalysis/ai_cli/` 包：

- `ai_cli` 入口：`python -m apiAnalysis.ai_cli capabilities|policy|run|task|shell`；
- 软访问预设 `read-only/workspace-write/full-access/custom` 与询问偏好
  `always/on-risk/never` 独立组合；`full-access + never` 代表完全自动模式；
- 工具注册表与 JSON schema 校验（`ToolRegistry`/`ToolSpec`），fake provider/tools
  用于离线确定性测试，OpenAI-compatible provider 可接本地/远程 endpoint；
- TTY 询问（本次允许/本会话允许/总是允许此规则/拒绝）与非交互返回
  `approval_required`（退出码 10）；`--yes`、`--dry-run`、policy JSON 文件与
  每工具审批 fragment（默认 `~/.api_manager/ai_policy.d`）；
- `shell` 子命令以 `provenance=unmanaged` 执行系统命令；JSONL 审计日志。

尚未实现（A1-A3 范围）：完整多轮 agent loop、会话恢复/长任务/并行、本地/远程
provider 切换评测、scheduler/worker/review 工具面、unmanaged Shell/HTTP/扫描器
工具注册表。A0 的 `run --provider fake` 提供最小 agent loop 用于端到端协议测试。

## 3. 两个独立的用户选项

访问预设和询问策略相互独立，但都只是用户偏好。

### 3.1 Access preset

| Preset | 默认行为 |
| --- | --- |
| `read-only` | 读取项目、文件、数据库和运行状态；不主动写入或执行测试 |
| `workspace-write` | 允许修改项目配置、规则、fixture、计划和本地文件 |
| `full-access` | 允许文件、数据库、网络、业务请求、外部工具、Shell 和插件 |
| `custom` | 从用户 JSON/TOML 策略加载任意能力组合 |

这些不是固定角色。用户可以给 `read-only` 增加网络能力，也可以从 `full-access` 删除
某个工具。未知能力默认显示提示，但可通过配置允许。

### 3.2 Approval preference

| Preference | 行为 |
| --- | --- |
| `always` | 每个写入、网络或命令动作都询问 |
| `on-risk` | 只在策略认为风险较高时询问，建议作为默认值 |
| `never` | 不询问，按当前 access preset 直接执行 |

典型组合：

- `read-only + on-risk`：默认协作模式；
- `workspace-write + on-risk`：AI 可完成日常开发和规则调整；
- `full-access + on-risk`：能力全部开放，但关键操作仍让用户看一眼；
- `full-access + never`：完全自动模式；
- `custom + never`：用户定义的无人值守任务。

## 4. 软策略而不是硬沙箱

策略中可以描述：

- 文件系统读取/写入路径；
- 允许的命令和外部工具；
- 网络 Origin、Host 和端口；
- API 测试方法、并发、超时和请求预算；
- 是否允许 mutation、上传、扫描器、私有证据和 Shell；
- 哪些动作需要询问；
- 日志、脱敏和证据保存偏好。

默认策略可以保守，但用户可以通过 CLI、环境变量或配置文件覆盖。框架不应加入无法
关闭的 Host allowlist、固定请求上限、禁止 Shell、禁止 mutation 或强制人工审批。

仅保留实现正确性需要的校验，例如 JSON/schema 可解析、数据库对象引用有效、进程没有
崩溃。这些属于程序正确性，不是对用户权限的限制。

## 5. 建议配置格式

```json
{
  "schema_version": "ai.policy.v1",
  "name": "personal-full-auto",
  "access": "full-access",
  "approval": "never",
  "filesystem": {
    "read": ["*"],
    "write": ["*"]
  },
  "network": {
    "origins": ["*"],
    "business_requests": true
  },
  "commands": {
    "shell": true,
    "allow": ["*"]
  },
  "api_testing": {
    "methods": ["*"],
    "request_budget": null,
    "concurrency": null,
    "mutation": true,
    "cleanup_required": false
  },
  "evidence": {
    "include_private": true,
    "redact_stdout": false
  }
}
```

仓库可以同时提供一个建议的 `safe-default` 示例。个人策略和 provider key 应默认放在
仓库外，但用户仍可自行决定存储方式。

## 6. 询问体验

当 approval 为 `always` 或 `on-risk` 时，CLI 展示即将发生的真实动作：

```text
AI 请求执行：
  command: python tools/run_execution_worker.py --once
  project/env: project-a / test
  network: 2 hosts, GET/POST
  estimated requests: 18
  files written: private evidence + Mongo result
  cleanup: adapter provided

[1] 本次允许  [2] 本会话允许  [3] 总是允许此规则  [4] 拒绝
```

用户的选择可以生成本地策略片段。询问的目的在于让用户知情并减少重复确认，不是建立
模型无法绕过的权限系统。

非交互模式遇到需要询问的动作时，可以：

- 返回 `approval_required` JSON 和退出码 10；
- 把动作放入本地审批队列；
- 用户批准后 resume；
- 或由调用方加 `--yes` / `--approval never` 直接继续。

## 7. Full access 的明确语义

`full-access` 应允许 AI 使用工具注册表中的全部能力，包括：

- 读取和修改源码、配置、私有数据及数据库；
- 调用本地或远程模型；
- 执行系统 Shell；
- 启动 Web、worker、scheduler 和外部扫描器；
- 直接发送只读或 mutation 请求；
- 创建、修改和清理测试对象；
- 安装或调用用户允许的插件；
- 生成和处理私有证据。

如果用户配置 `full-access + never`，CLI 不应再因为内部风险等级暂停。操作系统权限、
工具本身错误和用户配置仍可能导致失败，但不存在额外的“AI 不允许”分支。

## 8. Managed 与 unmanaged 路径

完全访问并不要求所有动作都走 scheduler。提供两条路径：

### Managed

- 使用项目模型、fixture、snapshot、scheduler、worker 和 `result.v1`；
- 自动获得重试、预算、审计、复核和复测能力；
- 适合稳定规则和长期运行。

### Unmanaged

- AI 直接调用 Shell、脚本、HTTP 客户端或外部工具；
- 适合探索、调试、一次性验证和用户自定义工作流；
- CLI 记录命令、退出码和可选证据引用，并标记 `provenance=unmanaged`；
- unmanaged 输出不会自动冒充 managed run，除非用户显式导入或转换。

这个区别是事实来源标记，不是权限限制。

## 9. AI CLI 工具面

建议提供统一入口：

```powershell
# 查看可用 provider、工具和当前软策略
python -m apiAnalysis.ai_cli capabilities --json

# 默认询问式会话
python -m apiAnalysis.ai_cli run `
  --project-id <project-id> --access workspace-write --approval on-risk

# 完全自动
python -m apiAnalysis.ai_cli run `
  --project-id <project-id> --access full-access --approval never

# 自定义策略
python -m apiAnalysis.ai_cli run --policy <policy.json>

# 单任务模式，方便其他 Agent 调用
python -m apiAnalysis.ai_cli task analyze-relations --input <context.json> --json
python -m apiAnalysis.ai_cli task build-plan --project-id <project-id> --json
python -m apiAnalysis.ai_cli task execute --plan-id <plan-id> --yes --json

# 直接开放工具/Shell
python -m apiAnalysis.ai_cli shell --approval never -- <command> <args...>
```

对 Agent 友好的基本要求：

- stdin 支持 JSON/JSONL；
- stdout 只输出 JSON/JSONL，日志走 stderr；
- 稳定 schema 和退出码；
- 长任务返回 run/session id，可查询和恢复；
- 支持 `--yes`、`--dry-run`、`--approval` 和 `--policy`；
- 每个工具公开名称、参数 schema、是否写入、是否联网和建议风险等级。

## 10. Provider 与 Agent loop

把旧单用途 judge 扩展成 provider-neutral 接口：

```text
AIProvider.invoke(messages, tools, response_schema, model_profile)
```

首批可支持：

- 本地 OpenAI-compatible endpoint；
- 远程 OpenAI-compatible endpoint；
- 用户自定义 HTTP adapter；
- deterministic fake provider；
- 直接由外部 Agent 调用 CLI，不在项目内运行 agent loop。

项目内 agent loop 负责：

1. 构建上下文；
2. 调用模型；
3. 校验 tool call schema；
4. 依据软策略决定直接执行或询问；
5. 把工具结果返回模型；
6. 在达到用户目标、预算或终止条件时结束。

上下文和工具结果是否脱敏由策略决定。默认脱敏是合理体验，但用户在 full-access 策略中
可以关闭。

## 11. 与抽象规则框架的关系

AI 可以调用规则框架完成：

- 接口 action 分类；
- 参数角色和别名判断；
- 弱关系和资源链分析；
- RuleSpec 建议；
- fixture 和测试计划生成；
- 结果聚类和复核建议。

规则框架是稳定、可解释的工具集合；AI CLI 是选择和编排这些工具的代理层。用户也可以
在 full-access 模式下跳过规则框架，直接调用自定义脚本。

## 12. 纯 AI 测试模式

| 模式 | 说明 |
| --- | --- |
| `offline-eval` | 使用固定语料和 fake/model provider，不发业务请求 |
| `provider-eval` | 比较模型、Prompt、成本、延迟和输出 schema |
| `shadow` | AI 生成规则/计划但不执行，和人工或现有规则比较 |
| `managed-execute` | AI 通过 scheduler 执行并进入 result/review 闭环 |
| `unmanaged-execute` | AI 使用 Shell/HTTP/扫描器自由执行，记录 provenance |
| `full-agent` | 多轮模型 + 工具调用，直到目标完成或用户终止 |

评测至少覆盖：

- JSON/tool call schema 通过率；
- 分类和关系 precision/recall/F1；
- 计划可执行率和实际覆盖率；
- false positive、false negative、`need_review` 比例；
- 模型/Prompt 版本差异；
- token、时间和成本；
- 询问次数、用户批准率和重复询问率；
- managed 与 unmanaged 结果的一致性；
- full-access + never 是否确实不会意外暂停。

## 13. 审计是可选价值，不是强制边界

建议记录：

- session、provider、model、Prompt version；
- 用户选择的 access/approval/policy；
- tool call、命令、目标、退出码和耗时；
- managed run/result 或 unmanaged evidence reference；
- 用户的本次/会话/永久允许选择。

用户可以配置日志级别、关闭部分记录或把完整记录放在私有目录。公开仓库默认只保留
通用代码和合成测试。

## 14. 实施顺序

### A0：CLI 协议和软策略（已实现 2026-08-05）

- `ai_cli` 入口、JSON tool schema、provider interface；✓
- `read-only/workspace-write/full-access/custom` 预设；✓
- `always/on-risk/never` 询问偏好；✓
- `--yes`、policy 文件、TTY 和非交互返回；✓
- fake provider 和 fake tools；✓

### A1：分析工具

- 接口、参数、关系、资源链和 RuleSpec 工具；
- managed context bundle；
- 外部 Agent 可直接调用单任务 CLI。
- 已提供 `project.chains`、`project.analyze_relations`、`project.list_plans`、
  `project.review_queue`，以及只读离线 `audit.boundary`、
  `audit.evidence_verify`、`audit.coverage`；这只是 A1 的部分完成，不代表完整上下文包或
  所有分析能力已经实现。

### A2：执行工具

- scheduler、worker、run status 和 review 工具；
- unmanaged Shell/HTTP/扫描器工具；
- provenance 区分和显式导入。
- 已提供 `project.create_plan` / `project.execute_plan` 连接现有 managed scheduler；
  SQLi 实际请求仍必须走该链。操作员清理 sweep 和独立 SQLi screener 不作为 AI 直连网络
  工具暴露，因此不能据此将 A2 标记为完成。

### A3：完整 Agent

- 多轮 tool calling；
- 会话恢复、长任务和并行任务；
- 本地/远程 provider、模型切换和评测；
- full-access + never 无人值守运行。

## 15. 新会话实现判断

新会话需要先回答：

1. `ai_cli` 是内置 agent loop、外部 Agent 工具面，还是两者同时支持；
2. 如何复用当前 argparse CLI，而不为 AI 重写全部服务；
3. tool registry 的最小 schema；
4. TTY 询问和非交互 approval JSON 如何共用；
5. custom policy 如何合并、覆盖和热更新；
6. managed/unmanaged provenance 如何保存；
7. full-access 是否需要默认包含 Shell，或由安装时启用；
8. fake provider、fake tools 和端到端 agent 测试如何实现。

第一阶段不得重新设计 scheduler 或规则模型；先让 AI 能稳定调用现有能力。

## 16. 最终判断

命令行支持纯 AI 调用和测试非常必要。正确方向不是把开源工具锁死，而是提供透明、
可编辑、默认友好的软策略：普通用户获得询问保护，高级用户可一条参数进入完全访问，
自动化用户可提供 custom policy 无人值守运行。

项目应该帮助用户看清风险和保留证据，但最终权限归用户。
