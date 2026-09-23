# AuthCheck CLI

独立、零第三方运行依赖的本地客户端，支持 Python 3.9+。只通过 HTTP 调用平台封装工具，
不导入服务端代码，不连接 Mongo/Redis，不读取网页登录密码，也不自动创建 Key。

从接口测试仓库根目录安装到当前 Python 环境：

```powershell
python -m pip install -e ./clients/authcheck_cli
authcheck --version
```

也可以安装本目录的 wheel，或 `python -m authcheck_cli` 执行。未安装时，仓库内的
`python tools/ai_access_client.py` 是同一实现的兼容入口。
在不同工作目录调用已安装的 `authcheck` 不依赖仓库当前目录。

使用已配置的 `API_MANAGER_URL` 与 `API_MANAGER_ACCESS_KEY`。不要将 Key 放在命令行、参数文件或提示词中。
若尚未配置，由用户在平台 `/api-keys` 创建并配置到客户端环境；CLI 不代为登录或发放凭据。

```powershell
authcheck doctor
authcheck capabilities
authcheck guide
authcheck projects
authcheck plans --project PROJECT_ID
authcheck assets --project PROJECT_ID --page 1
authcheck readiness PLAN_ID --project PROJECT_ID
authcheck run PLAN_ID --project PROJECT_ID --idempotency-key UNIQUE_OPERATION_KEY --timeout 120
authcheck wait RUN_ID --project PROJECT_ID --timeout 120
authcheck results RUN_ID --project PROJECT_ID
authcheck status RUN_ID --project PROJECT_ID
authcheck receipt --idempotency-key SAME_OPERATION_KEY
```

占位 ID 用平台返回的真实值替换。项目限定 Key 可省略 `--project`，账号范围 Key 需明确项目。
每个新写操作使用独立的 16–128 字符幂等键；重试同一个操作时保留原键与原参数。
`run` 先查询原回执，有已完成提交时恢复原 Run；pending/unknown 时停止并提示检查。
只有没有原回执时才读取计划、预检并提交。它不会创建/激活计划、扩大范围或启动 worker。
worker 不在线时会超时；之后继续 `wait`，不要换键重复发起 `run`。

通用工具不需要另写脚本：

```powershell
authcheck describe project.plan
authcheck call project.plan --project PROJECT_ID --arg plan_id=PLAN_ID
authcheck describe project.create_plan
authcheck call project.create_plan --json-file arguments.json --idempotency-key UNIQUE_OPERATION_KEY
```

`--arg name=value` 可重复；值按 JSON 解析，非 JSON 则作为字符串。包含空格的整个参数需使用 shell 引号。
复杂参数用 JSON 文件，内容是参数对象而非 `{"arguments": ...}`。禁止重复或冲突参数。

输出为一个 JSON 对象。HTTP 200 仅表示接口成功；`run`/`wait` 以服务端终态和完整结果计数判定流程结束。
旧服务端没有完成状态契约时明确报错，不从空结果猜测成功。执行结束不等于接口安全或漏洞修复。

| 退出码 | 意义 |
| --- | --- |
| 0 | 命令成功；`run --no-wait` 仅表示提交成功，默认 run/wait 表示执行及回读完成 |
| 1 | 认证、网络、参数文件、接口或契约错误 |
| 2 | 命令行用法错误，或 run 的计划/预检阻塞 |
| 3 | 等待超时、结果不完整或提交状态不确定 |
| 4 | Run 失败、暂停或取消 |
| 130 | 用户中断；先回读原回执或任务 |

远程地址必须使用 HTTPS。客户端拒绝跳转，错误输出不回显代理/服务器原始正文。
`authcheck-cli` 是外部 HTTP 客户端，与平台的模型驱动 `apiAnalysis.ai_cli` 是不同入口。
