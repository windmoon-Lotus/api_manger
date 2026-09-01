# SQLi 粗筛核心执行链改动范围说明

## 目的

本次修复 DeepSeek 在 2026-08-21 新增的 `sqli_payload_screen` 核心执行链，使其继续作为白帽报告 payload 的保守粗筛器，同时避免把传输失败、限流、基线已有错误文本或微小耗时波动误判成 SQLi 信号。多请求适配器的每一次真实请求现在都受现有调度器的限速、取消和主机熔断控制。

本次不把粗筛器扩展成 sqlmap，也不对任何业务目标发送真实请求。

## 已修改

### 1. 适配器执行契约

文件：`apiAnalysis/tool/execution_adapter.py`

- 为 `ExecutionAdapter` 增加 `request_policy_scope`：
  - `checkpoint`：普通单请求适配器继续由调度器在整个 replay 外层控制。
  - `request`：多请求适配器由调度器控制 replay 内的每一次真实请求。
- 注册时校验 scope 只能是 `checkpoint` 或 `request`。
- 增加 `ExecutionRequestBlocked`，单独表达取消、主机熔断等本地策略停止，不再把它伪装成网络错误。
- SQLi 适配器声明 `supports_mutation=True` 和 `request_policy_scope="request"`。

`supports_mutation=True` 只表示适配器具备能力，不等于自动授权非只读请求。

### 2. 调度器逐请求控制

文件：`apiAnalysis/tool/execution_scheduler.py`

- 新增受控 request executor，每次真实请求都会：
  1. 检查取消和主机停止状态；
  2. 获取 per-host permit 并执行 pacing；
  3. 执行请求；
  4. 从 evidence 字典或 `(evidence, captured_json)` 的第一项记录真实结果；
  5. 更新 transport/429/5xx 熔断计数；
  6. 在 `finally` 中释放 permit。
- `request` scope 适配器不再持有 replay 外层 permit，避免一个 SQLi checkpoint 内的 baseline 和全部 probe 绕过逐请求策略。
- SQLi 聚合 evidence 不再重复刷新主机熔断状态。
- 某次 probe 打开熔断后，下一次 probe 会在发出前被 `ExecutionRequestBlocked` 停止。
- 策略停止沿用 checkpoint 的 PENDING/SKIPPED/CANCELLED 收尾语义，不制造 SQLi 传输误报。
- 等待已占用的 host permit 改为 100 ms 超时轮询；取消发生时无需等在途请求释放 permit 才能停止。
- 显式复用 `idempotency_key` 时，如果既有 run 的 `snapshot_ids` 与本次请求不一致，立即拒绝，避免在 PREPARING 并发窗口混入不同 checkpoint 并破坏进度计数。

### 3. 非 GET 方法改为显式确认门禁

文件：`apiAnalysis/tool/sqli_screen.py`、`apiAnalysis/tool/execution_scheduler.py`

- `_targets()` 不再因为方法是 POST/PUT/PATCH/DELETE 而永久跳过 query/body 参数。
- 非只读方法是否可以执行由调度策略决定：必须同时满足 `allow_mutation=True` 和 `mutation_acknowledged=True`。
- HTTP 方法不是授权结论；环境、业务范围和操作者确认才是门禁。
- 删除会造成虚假覆盖口径的 adapter 内部 mutation 跳过语义。

### 4. baseline 与 probe 的保守判定

文件：`apiAnalysis/tool/sqli_screen.py`

- 没有可达目标参数时不发 baseline 请求。
- baseline 出现以下情况时直接停止，不继续发送 12 个 payload：
  - 传输异常或缺少状态码；
  - 401/403；
  - 429；
  - 404、重定向、5xx；
  - replay 明确标记为非预期状态。
- probe 保留 `None` 状态和真实 `error_type`，不再把失败转换为状态 `0`。
- transport error、401/403、429 优先标记为污染，不参与真假状态差、正文差或强信号判断。
- 错误 marker 只在相对 baseline 新出现时产生信号；baseline 已有的 `Exception`、`Warning` 等不再重复报警。
- 报告真假锚点使用：
  - true：`0)or len(user)>1-- A`
  - false：`0)or len(user)>100-- A`
- 强状态签名仅接受 true=500 且 false 与有效 baseline 一致的方向；任意两个不同状态不会自动提升为 strong。
- 增加同为 2xx 时的正文差异：hash 不同、长度差同时达到 32 bytes 和 10%，并要求仅一侧与 baseline 匹配。
- WAITFOR 必须同时满足至少 3 倍耗时和至少 2500 ms 绝对增量；`1 ms → 4 ms` 不再报警。
- 参数级结果统一为 `INTEREST`、`NOT_EVALUABLE`、`BLOCKED`、`CLEAN`。
- 只有全部已评估参数完整执行且无信号时，最终 judge 才返回低置信度 `no_vuln`，reason 明确限定为 `no_sqli_signal_in_payload_screen`。

### 5. 本地回归测试

文件：

- `tests/test_sqli_screen.py`
- `tests/test_execution_adapter.py`
- `tests/test_execution_scheduler.py`

覆盖：

- 非 GET query/body 参数在明确确认后可执行；
- baseline transport error/404 短路；
- probe timeout 和 429 不形成真假或强信号；
- marker 相对 baseline 判断；
- timing 倍率与绝对门槛；
- 报告方向的 500/200 强签名；
- 200/200 有意义正文差和小幅动态差异；
- BLOCKED 不映射成无漏洞；
- request executor 每次 acquire/record/release；
- 熔断和取消阻止后续请求；
- 等待 host permit 时仍能及时取消；
- 同一显式幂等键不能绑定不同 snapshot 集合。

## 明确未修改

- 未修改 SQLi Manifest 生成、路由模板或 host 提取规则。
- 未修改 snapshot replay 的签名、认证、TLS、请求组装和实际 HTTP 实现。
- 未扩大为 headers、cookies、任意嵌套 JSON 等新的参数发现面；body 仍只处理当前支持的顶层字典参数。
- payload 总数仍为 12，没有增加 sqlmap 式 DBMS、编码、tamper、union 列数或 OOB payload 矩阵。
- 未修改普通 `checkpoint` scope 适配器的外层 permit 行为。
- 未修改 Mongo 文档 schema、迁移脚本、Web 页面或 Manifest/host 数据模型。
- 未执行真实业务请求、WAF 探测或漏洞验证。
- 未创建 git commit，也未处理仓库中其他既有修改或未跟踪文件。

## 授权与副作用边界

- adapter capability、调度授权和业务授权是三件独立的事。
- SQLi adapter 声明支持非只读方法，只解决“能力上可以执行”。
- 调度时仍必须显式设置 mutation acknowledgement；未确认则拒绝创建批次。
- 本次实现和验证没有使用 acknowledgement 对任何真实接口执行请求。
- 每次运行必须继续按实际授权范围报告 tested/skipped 分母，不能把未执行或 BLOCKED 参数描述为 clean。

## 验证结果

以下命令均从仓库根目录执行：

```bash
PYTHONPATH=. ./.venv/Scripts/python.exe -m unittest discover -s tests -p "test_sqli_screen.py"
```

```bash
PYTHONPATH=. ./.venv/Scripts/python.exe -m unittest discover -s tests -p "test_execution*.py"
```

```bash
PYTHONPATH=. ./.venv/Scripts/python.exe -m unittest discover -s tests
```

```bash
PYTHONPATH=. ./.venv/Scripts/python.exe -m py_compile apiAnalysis/tool/execution_adapter.py apiAnalysis/tool/execution_scheduler.py apiAnalysis/tool/sqli_screen.py
```

### 定向测试

- SQLi：12 run，12 passed，0 skipped，0 failed。
- execution：30 run，24 passed，6 MongoDB/Redis integration skipped，0 failed。
- 合计：42 run，36 passed，6 skipped，0 failed。

### 完整本地套件

- 408 run
- 371 passed
- 37 skipped
- 0 failed
- 耗时约 19.3 秒

37 个 skipped 由既有环境或可选集成测试条件产生，不计为通过。

### 其他检查

- `execution_adapter.py`、`execution_scheduler.py`、`sqli_screen.py` 均通过 `py_compile`。
- 新增和定向测试均使用 stub/mock evidence，不发送真实 HTTP 请求。

## 仍未验证

- 需要 MongoDB/Redis 的 execution worker 端到端集成测试在当前环境中被跳过。
- 未验证真实 WAF、限流、动态正文、网络抖动和服务端延迟下的阈值表现。
- 未做高并发或长批次性能测试。
- 本 payload 族只能提供“本粗筛未观察到信号”的有限结论，不能替代完整 SQL 注入测试。
