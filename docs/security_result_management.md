# 安全测试结果管理

> 状态：历史结果模型草案。当前实现已将机器结果、追加式人工复核、稳定 finding 和
> 原证据修复复测分离；现行定义见 `api_manager_v2_domain_architecture.md` 与
> `../PROJECT_OVERVIEW.md`。

`api_manger` 作为安全测试基座，需要记录三类事实：

- 资产事实：有哪些接口、参数、环境、账号角色。
- 执行事实：哪一天、用哪个画像、哪些账号角色、哪些域名和 hosts 模式跑过。
- 结论事实：每条用例的自动判定、证据摘要、置信度、是否需要复测或转漏洞。

## 数据层

新增建议模型：

- `security_test_run`：一次测试批次，例如“向日葵只读 IDOR 初筛 2026-06-11”。
- `security_test_result`：批次里的单条结论，例如“B 账号访问 A 的 remote detail 返回空结果”。

这些模型只存脱敏摘要：

- 可以存：接口名、方法、路径模板、状态码、响应长度、业务码摘要、JSON key overlap、自动结论。
- 不存：账号密码、Bearer、Cookie、真实资源 ID、原始响应体。
- 私密证据用 `evidence_ref` 指向本地 `.private.json` 文件。

## 结论枚举

建议统一使用：

- `potential_vuln`：自动证据足够强，应进入漏洞记录或人工复核前置。
- `need_review`：自动证据不足但值得人工看。
- `no_vuln`：阻断明确或业务空结果明确。
- `not_evaluable`：数据不足、账号无资源、接口不适用。
- `error`：测试失败，不代表安全结论。

## 判定映射

IDOR 分析矩阵的中间判定可映射为：

- `blocked_http` -> `no_vuln`
- `blocked_not_found` -> `no_vuln`
- `blocked_empty` -> `no_vuln`
- `not_evaluable_no_owner_data` -> `not_evaluable`
- `weak_or_empty_signal` -> `no_vuln` 或 `not_evaluable`
- `needs_review` -> `need_review`
- `potential_idor` -> `potential_vuln`

## 转漏洞条件

满足以下条件之一时，才从 `security_test_result` 转为 `vuln_record`：

- attacker 账号用 victim 资源 ID 取得非空业务对象。
- 响应包含敏感字段，且 owner/attacker 字段高度重叠。
- 业务状态码显示成功，而不是空列表、无权限、资源不存在。
- 二次复测仍可稳定复现。
