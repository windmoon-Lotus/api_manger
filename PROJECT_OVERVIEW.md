# 项目介绍与代码导航

## 项目简介
`api_manger` 是一个面向 API 数据治理与安全测试的工具集，提供两类能力：

1. `CLI` 数据处理链路：导入 HAR / mitmproxy / OpenAPI / Postman 数据，完成参数拆解、接口分类、参数归档、弱关联推断、请求组包与越权任务生成/执行。
2. `Web` 管理界面：查看与编辑原始接口数据，执行运维面板操作（导入、重算、任务执行），并管理版本/漏洞/测试用例与账号配置。

项目核心以 Flask + MongoEngine + Redis 组织，入口清晰，便于按“数据流”快速定位代码。

## 顶层入口
- `run_web.py`：Web 启动入口（读取 `HOST/PORT/DEBUG`）。
- `apiAnalysis/main.py`：CLI 入口（参数解析与任务编排）。
- `apiAnalysis/__init__.py`：`create_app()`，Flask 初始化、蓝图注册、Mongo/Redis/定时任务初始化。

## 目录导航（按模块）
- `apiAnalysis/ai/`：AI 研判模块（schema、prompt、HTTP client、judge service）。
- `apiAnalysis/common/`：通用函数、装饰器、国际化等基础能力。
- `apiAnalysis/conf/`：日志与配置项（Mongo/Redis/密钥/AI 配置）。
- `apiAnalysis/core/`：扫描流程、认证识别（`identify/`）与后台任务。
- `apiAnalysis/db/`：MongoEngine 模型定义（`collection.py`）与数据入库/参数拆解（`save.py`）。
- `apiAnalysis/input/`：HAR、mitmproxy 等输入解析器。
- `apiAnalysis/model/`：请求/响应模型与异常定义。
- `apiAnalysis/rule/`：规则层（分类、参数关联、重放验证、越权引擎）。
- `apiAnalysis/tool/`：请求组包、payload 插入、JSON 扁平化等工具。
- `apiAnalysis/web/`：Flask 蓝图与路由实现（`web/api/ws`）。
- `apiAnalysis/templates/`：Jinja2 页面模板。
- `apiAnalysis/static/`：静态资源（CSS/JS/字体等）。

## 代码导航（按业务场景）

### 1) 数据导入与入库
- CLI 调度：`apiAnalysis/main.py`
- 入库函数：
  - `apiAnalysis/db/save.py::data_generate_mongodb`（flow/har）
  - `apiAnalysis/db/save.py::data_generate_openapi`
  - `apiAnalysis/db/save.py::data_generate_postman`
- 输入解析：
  - `apiAnalysis/input/har_capture_reader.py`
  - `apiAnalysis/input/mitmproxy_capture_reader.py`

### 2) 参数拆解、归档与关联
- 参数拆解：`apiAnalysis/db/save.py::parameter_disassemble_mongodb`
- 参数基础数据：`apiAnalysis/db/save.py::parameter_date_mongodb`
- 参数归档：`apiAnalysis/rule/analysis.py::analysis.parameter_archive`
- 弱关联推断（两阶段）：`apiAnalysis/rule/analysis.py::analysis.infer_weak_relations`
  - 阶段1：候选召回（leaf/value overlap/name fallback）
  - 阶段2：评分过滤（`min_relation_score`）
- 值清洗与低信息过滤：`analysis._normalize_relation_values`（含参数黑名单）
- 关联验证：
  - 规则验证：`analysis.verify_weak_relations`
  - 真实重放验证（预算阀门）：`analysis.verify_weak_relations_real(limit, min_score)`

### 2.1) 接口分类（打分版）
- 分类入口：`apiAnalysis/rule/analysis.py::analysis.classify_raw_data`
- 分类器：`analysis.classify_with_score`
- 分类输出：`action + class_confidence + class_reason_codes`
- 规则标识：`raw_data.rule = "path_score_v1"`

### 3) 请求组包与重放
- 组包构建：`apiAnalysis/tool/compose_request.py`
- 组包触发：`apiAnalysis/rule/analysis.py::analysis.build_request_compose`
- Web 端单条重放：`apiAnalysis/web/web.py::rawdata`（包含 replay 处理分支）

### 4) 越权任务链路
- 任务编排入口：`apiAnalysis/rule/analysis.py`
  - `prepare_privilege_tasks`
  - `execute_privilege_tasks`
  - `execute_ai_stub`
  - `execute_ai_http`
- 核心引擎：`apiAnalysis/rule/privilege.py`
  - `TargetFilter`
  - `PrivilegeEngine.prepare_tasks / execute_pending / execute_task`
  - `_judge`（规则证据与评分）
- 规则评分与融合：
  - `apiAnalysis/rule/evidence.py`（证据提取）
  - `apiAnalysis/rule/scoring.py`（规则评分）
  - `apiAnalysis/rule/fusion.py`（规则+AI 融合）
- AI 研判服务：
  - `apiAnalysis/ai/schema.py`（输出规范化）
  - `apiAnalysis/ai/prompts.py`（提示词模板）
  - `apiAnalysis/ai/client.py`（HTTP 调用）
  - `apiAnalysis/ai/judge_service.py`（统一判定入口）

### 5) Web 页面与 API 路由
- 蓝图定义：`apiAnalysis/web/__init__.py`
  - `bp_web`（页面）
  - `bp_api`（`/api/*`）
  - `bp_ws`（`/ws/*`）
- 页面路由：`apiAnalysis/web/web.py`
  - 重点页面：`/`、`/rawdata`、`/import-data`、`/ops`、`/parameter-relations`、`/privilege-tasks`
- API 路由：`apiAnalysis/web/api.py`
  - 重点接口：`/api/rawdata`、`/api/privilege/tasks`、`/api/version`、`/api/vuln`、`/api/testcase`、`/api/sso/account`

### 6) 主要数据模型（Mongo）
位于 `apiAnalysis/db/collection.py`：
- 流量与解析：`PacketData`、`raw_data`、`req_data`、`res_data`
- 参数分析：`parameter_data`、`parameter_archive`、`parameter_relation`
- 分类增强字段（`raw_data`）：`class_confidence`、`class_reason_codes`
- 关联增强字段（`parameter_relation`）：`score`、`reason_codes`
- 越权任务：`privilege_task`、`privilege_config`、`target_whitelist`
- 越权任务增强字段（`privilege_task`）：
  `rule_score`、`ai_score`、`final_score`、`final_result`、
  `rule_reason_codes`、`ai_reason_codes`、`prompt_ver`、`model_ver`
- 业务管理：`api_version`、`vuln_record`、`test_case`
- 安全运行管理：`security_test_run`、`security_test_result`
- 工作区与账号：`Workspace`、`WorkspaceAuth`、`WorkspaceSso`、`SsoAccount`

## 快速运行命令
- 启动 Web：
  ```bash
  python run_web.py
  ```
- 导入 HAR 并执行参数链路：
  ```bash
  python -m apiAnalysis.main -i <file.har> -f har -p --quiet
  ```
- 生成并执行越权任务：
  ```bash
  python -m apiAnalysis.main --privilege-tasks --privilege-exec --privilege-limit 20
  ```
- 真实重放验证弱关联：
  ```bash
  python -m apiAnalysis.main --verify-relations-real --verify-limit 200 --verify-min-score 60
  ```
- 调用 AI 研判并回写：
  ```bash
  python -m apiAnalysis.main --ai-http --ai-url <endpoint> --ai-key <token> --ai-limit 20
  ```
- 控制输出与日志：
  ```bash
  python -m apiAnalysis.main --quiet
  python -m apiAnalysis.main --log-level WARNING
  ```

## 评估工具
- 越权判定评估：`tools/eval_privilege.py`
- 分类与关联评估：`tools/eval_class_relation.py`
- 回归测试：`tests/test_phase2_regression.py`

## 配置提示
- 基础连接配置：`apiAnalysis/conf/secret.py`
- AI 配置：`apiAnalysis/conf/conf.py`（`ai_endpoint`、`ai_api_key`、`ai_timeout`）
- 认证策略：`apiAnalysis/core/identify/`（SSO / Direct）
