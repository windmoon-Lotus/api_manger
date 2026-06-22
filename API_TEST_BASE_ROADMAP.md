# api_manger 接口测试基座逐步实现文档

## 1. 目标定位

`api_manger` 后续不建议定位成“自己实现所有漏洞扫描能力的工具”，而应定位为：

> 内部 API 测试资产与安全测试编排基座。

它的核心价值是沉淀接口资产、维护认证上下文、生成可复用请求、编排测试任务、调用成熟安全工具、归档证据与报告。

通用漏洞能力优先复用现有工具，例如 `sqlmap`、`nuclei`、`OWASP ZAP`、`Schemathesis`、`ffuf`。项目自身重点建设工具适配、任务编排、业务上下文和结果归档。

## 2. 当前现状判断

项目已经具备成为基座的基础：

- 已支持 HAR、mitmproxy flow、OpenAPI、Postman 数据导入。
- 已有接口资产模型：`raw_data`、`req_data`、`res_data`、`parameter_data`、`parameter_archive`、`parameter_relation`。
- 已有请求组包能力：`apiAnalysis/tool/compose_request.py`。
- 已有 Web 管理界面：接口、参数关系、越权任务、漏洞、测试用例、版本等页面。
- 已有越权任务框架：未授权、水平越权、垂直越权。
- 已有 AI 判定预留：规则分数、AI 分数、融合分数。
- 现有回归测试可通过：`py -3.9 -m unittest discover -s tests -p "test*.py"`。

当前主要不足：

- 运行环境、依赖、配置还没有标准化。
- 通用任务模型偏缺失，目前 `privilege_task` 更偏越权场景。
- 外部安全工具尚未形成适配层。
- 请求变异能力不够通用，尚不能服务所有漏洞类型。
- 测试结果、证据、日志、报告还没有统一规范。
- 回归样本和测试覆盖不足，长期演进容易破坏已有能力。

## 3. 总体架构

建议目标架构如下：

```text
数据导入层
OpenAPI / HAR / Postman / mitmproxy flow
        |
        v
接口资产层
接口、参数、响应、版本、环境、账号、标签、风险属性
        |
        v
请求建模层
请求组包、认证上下文、参数变异、请求快照
        |
        v
任务编排层
任务生成、任务队列、执行状态、重试、日志
        |
        v
工具适配层
sqlmap / nuclei / ZAP / Schemathesis / ffuf / custom-idor
        |
        v
证据归档层
漏洞记录、执行结果、原始输出、复测记录、报告
```

## 4. 实施阶段

### 阶段 0：固定运行环境

目标：让项目在本机和后续机器上稳定启动、稳定测试。

要做：

1. 增加 `requirements.txt` 或 `pyproject.toml`。
2. 明确 Python 版本为 3.9。
3. 固化启动命令：

   ```powershell
   py -3.9 .\run_web.py
   ```

4. 固化测试命令：

   ```powershell
   py -3.9 -m unittest discover -s tests -p "test*.py"
   ```

5. 整理 `START.md`、`PROJECT_OVERVIEW.md` 编码为 UTF-8。
6. 增加最小样本数据集：
   - 1 个 OpenAPI 文件
   - 1 个 HAR 文件
   - 1 个 Postman Collection

验收标准：

- 新机器按文档能安装依赖并启动 Web。
- MongoDB、Redis 配置清晰可查。
- 测试命令稳定通过。
- 至少一份 OpenAPI 样本能导入并在 Web 中看到接口资产。

### 阶段 1：配置与启动自检

目标：降低运维成本，避免运行到一半才发现环境问题。

要做：

1. 将配置从 `apiAnalysis/conf/secret.py` 逐步迁移到环境变量或 `.env`：
   - MongoDB
   - Redis
   - Flask secret key
   - Web host/port/debug
   - AI endpoint/API key
   - 外部工具路径

2. 增加启动自检：
   - MongoDB 是否可连接
   - Redis 是否可连接
   - 上传目录是否存在
   - 外部工具是否存在
   - Python 版本是否符合要求

3. 增加 CLI 自检命令：

   ```powershell
   py -3.9 -m apiAnalysis.main --doctor
   ```

验收标准：

- 配置不需要改代码即可切换。
- Web 启动时能明确提示 Mongo/Redis 连接状态。
- 缺依赖、缺工具、缺目录时有清晰错误提示。

### 阶段 2：统一接口资产与请求快照

目标：让所有后续工具都能复用同一套接口资产和请求构造能力。

要做：

1. 梳理接口资产字段，保留现有模型兼容性，新增必要字段：
   - 来源：OpenAPI/HAR/Postman/flow/manual
   - 环境：dev/test/staging/prod-like
   - 版本
   - 标签
   - 最近导入时间
   - 最近执行时间

2. 增加请求快照模型，记录一次可复现请求：

   ```text
   request_snapshot
   - pathid
   - method
   - url
   - headers
   - query
   - body
   - content_type
   - account_id
   - env_id
   - source
   - created_at
   ```

3. 将 `build_request_payload` 输出标准化，作为所有工具适配器的输入。

4. 建立参数变异能力：
   - query 参数替换
   - path 参数替换
   - header 参数替换
   - cookie 参数替换
   - form 参数替换
   - JSON body 嵌套字段替换

验收标准：

- 任意已导入接口能生成一份标准请求快照。
- 请求快照可以复放。
- 参数变异器能对 query、JSON body、form body 至少三类参数生效。

### 阶段 3：统一安全任务模型

目标：不要为每个工具单独建一套业务逻辑，而是统一任务、状态、证据。

建议新增通用模型 `security_task`：

```text
security_task
- id
- tool: sqlmap / nuclei / zap / schemathesis / ffuf / custom
- check_type: sqli / xss / ssrf / leak / contract / idor / auth
- pathid
- parameter
- payload
- request_snapshot_id
- status: init / running / done / failed / skipped
- severity
- confidence
- result: potential_vuln / no_vuln / need_review / error
- evidence
- raw_output_path
- error_message
- created_at
- started_at
- finished_at
```

要做：

1. 新增任务创建接口。
2. 新增任务列表页。
3. 新增任务详情页。
4. 新增任务执行日志。
5. 新增任务结果归档。

验收标准：

- 能为某个接口创建一条 `sqlmap` 类型任务。
- 能查看任务状态。
- 能保存任务执行结果和原始输出路径。
- 失败任务能看到失败原因。

### 阶段 4：接入 sqlmap

目标：快速获得较成熟的 SQL 注入检测能力。

接入方式：

1. 基座根据请求快照生成 raw HTTP request 文件。
2. 调用 `sqlmap` 执行扫描。
3. 保存 sqlmap 输出目录。
4. 解析结果并写回 `security_task`。

建议命令形态：

```powershell
python sqlmap.py -r request.txt --batch --level 2 --risk 1 --output-dir output/sqlmap
```

基座职责：

- 选择接口与参数。
- 生成 raw request。
- 注入认证信息。
- 管理扫描超时。
- 归档 sqlmap 原始结果。
- 解析是否存在注入、数据库类型、参数名、证据摘要。

验收标准：

- Web 中选择一个接口可生成 sqlmap 任务。
- sqlmap 能对该接口执行。
- 任务结束后能在 Web 中看到结果和证据。

### 阶段 5：接入 Schemathesis

目标：基于 OpenAPI 做契约测试、健壮性测试和异常输入测试。

适用场景：

- OpenAPI 规范回归。
- 检查 5xx。
- 检查响应 schema。
- 检查未声明状态码。
- 检查异常参数是否导致服务端错误。

接入方式：

1. 将已导入 OpenAPI 文件作为测试源。
2. 维护认证 header/cookie。
3. 执行 Schemathesis CLI。
4. 将失败 case 归档成 `security_task` 或 `test_case`。

验收标准：

- 能对一份 OpenAPI 执行 Schemathesis。
- 失败用例能回写到平台。
- 失败请求可复放。

### 阶段 6：接入 nuclei

目标：复用模板生态，覆盖通用 Web/API 漏洞。

适用场景：

- 信息泄露。
- 通用 CVE。
- 错误配置。
- 弱服务暴露。
- 部分 XSS、SSRF、文件读取模板。

接入方式：

1. 将接口资产转换为 nuclei 目标。
2. 对需要认证的接口生成 headers/cookies。
3. 使用 JSONL 输出。
4. 将 nuclei 结果映射为统一证据。

建议优先使用模板分类：

- exposures
- misconfiguration
- vulnerabilities
- cves
- technologies

验收标准：

- 能对指定域名或接口集合执行 nuclei。
- 能解析 JSONL 输出。
- 能把结果绑定到接口资产或域名资产。

### 阶段 7：接入 OWASP ZAP

目标：补充 DAST 能力和被动扫描能力。

适用场景：

- 代理流量被动扫描。
- 基础主动扫描。
- API 导入扫描。
- 安全 header、cookie、CORS、泄露类问题。

接入方式：

1. ZAP 以 daemon/API 模式运行。
2. `api_manger` 调用 ZAP API。
3. 将 OpenAPI/HAR 导入 ZAP。
4. 启动 spider/active scan。
5. 拉取 alerts 并归档。

验收标准：

- 能启动一次 ZAP 扫描任务。
- 能获取 alerts。
- 能将 alerts 转换为统一漏洞记录。

### 阶段 8：保留自研越权/IDOR 引擎

目标：越权测试高度依赖业务上下文，应作为项目核心自研能力保留和增强。

要做：

1. 强化账号配置：
   - 未登录
   - 低权限账号
   - 高权限账号
   - 同权限账号 A/B

2. 强化对象参数识别：
   - user_id
   - account_id
   - device_id
   - order_id
   - tenant_id
   - org_id

3. 强化对比判定：
   - 状态码变化
   - JSON key overlap
   - 响应长度差异
   - 业务错误码
   - 敏感字段泄露

4. 将越权任务逐步迁移或映射到 `security_task`。

验收标准：

- 能基于两个账号生成水平越权任务。
- 能基于高低权限账号生成垂直越权任务。
- 每条任务有明确证据和复测入口。

## 5. 工具适配器设计

建议新增目录：

```text
apiAnalysis/security/
  __init__.py
  task.py
  executor.py
  snapshot.py
  mutator.py
  evidence.py
  adapters/
    __init__.py
    base.py
    sqlmap.py
    schemathesis.py
    nuclei.py
    zap.py
    ffuf.py
    custom_idor.py
```

适配器统一接口：

```python
class BaseAdapter:
    tool = ""

    def available(self):
        """检查工具是否可用"""

    def build_inputs(self, task):
        """根据任务生成工具输入文件或参数"""

    def run(self, task):
        """执行外部工具"""

    def parse_result(self, task):
        """解析工具输出"""

    def normalize_evidence(self, raw_result):
        """转换为统一证据结构"""
```

统一证据结构：

```json
{
  "tool": "sqlmap",
  "check_type": "sqli",
  "matched_rule": "boolean_based_blind",
  "parameter": "id",
  "payload": "' OR '1'='1",
  "request": {},
  "response": {},
  "evidence_snippet": "",
  "severity": "high",
  "confidence": 0.9
}
```

## 6. 优先级建议

最推荐的实现顺序：

1. 环境固定、依赖固定、文档修复。
2. 请求快照与参数变异器。
3. 通用 `security_task`。
4. sqlmap 适配器。
5. Schemathesis 适配器。
6. 越权/IDOR 引擎增强。
7. nuclei 适配器。
8. ZAP 适配器。
9. 报告、复测、趋势统计。

原因：

- sqlmap 能最快带来“外部工具接入”的闭环验证。
- Schemathesis 能最快提升接口质量回归能力。
- 越权能力是通用工具很难替代的项目核心价值。
- nuclei/ZAP 能扩展覆盖面，但对编排、降噪和结果归档要求更高。

## 7. 长期运行机制

为了让项目长期运转，建议形成固定任务流：

### 每次接口变更

1. 导入最新 OpenAPI。
2. 做接口差异对比。
3. 对新增/变更接口生成基础测试任务。
4. 执行 Schemathesis。
5. 对高风险接口生成 sqlmap/nuclei/越权任务。
6. 归档结果。

### 每周例行扫描

1. 对全量接口执行轻量 nuclei。
2. 对核心业务接口执行越权回归。
3. 对新增参数执行 SQLi 快速探测。
4. 输出周报。

### 每次漏洞修复后

1. 从漏洞记录中发起复测。
2. 使用原始请求快照重放。
3. 保存复测结果。
4. 关闭或重新打开漏洞。

## 8. 第一版里程碑

第一版不要追求覆盖所有漏洞类型。建议 MVP 如下：

- Web 可启动。
- OpenAPI/HAR 可导入。
- 接口资产可查看。
- 单接口可生成请求快照。
- 单接口可创建 sqlmap 任务。
- sqlmap 结果可回写。
- OpenAPI 可执行 Schemathesis。
- 越权任务能保留现有能力。
- 所有任务有统一状态和结果页。

达到这个程度后，项目就已经从“工具集合”升级为“接口测试基座雏形”。

## 9. 风险与取舍

### 不建议一开始做

- 自己实现完整 XSS/SQLi/SSRF 扫描器。
- 一次性重构所有数据模型。
- 一开始就做复杂队列平台。
- 一开始就追求 AI 自动定级。
- 一开始就接入太多工具。

### 应该优先坚持

- 统一请求快照。
- 统一任务模型。
- 统一证据结构。
- 每个工具先跑通最小闭环。
- 所有能力都能复测。
- 所有结果都能绑定接口资产。

## 10. 结论

`api_manger` 具备成为内部接口测试基座的潜力。它已经有接口资产、参数解析、请求组包、越权任务和 Web 管理的基础。

后续关键不是堆更多自研漏洞检测代码，而是把它升级成：

> API 资产管理 + 请求构造 + 安全任务编排 + 外部工具适配 + 证据归档的平台。

先用 `sqlmap` 和 `Schemathesis` 做第一批工具闭环，再增强越权/IDOR 自研能力，随后接入 `nuclei` 和 `ZAP` 扩展覆盖面，是比较稳妥且人力成本较低的路线。
