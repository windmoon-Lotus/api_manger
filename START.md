# API Manager 快速启动

完整文档状态和调用入口见 [`docs/README.md`](docs/README.md) 与
[`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md)。

## 1. 环境与依赖

- Python 3.9
- MongoDB（默认 `127.0.0.1:27017`）
- Redis（默认 `127.0.0.1:6379`）

```powershell
py -3.9 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m apiAnalysis.main --doctor
```

`requirements.txt` 是完整锁文件，`requirements.in` 只维护直接依赖。只有读取旧
mitmproxy flow 时才安装 `requirements-capture.txt`。

配置使用环境变量或仓库外的 `..\.secrets` 文件，不要把真实账号、Token、Cookie、
流量包或内部接口导出放进 Git。边界见 [`DATA_GOVERNANCE.md`](DATA_GOVERNANCE.md)。

## 2. 启动四个独立进程

Web 不包含 worker、定时任务或业务请求执行。实际持续运行时分别启动：

```powershell
# 管理页面
.\.venv\Scripts\python.exe .\tools\run_web_server.py

# Mongo 持久化执行队列
.\.venv\Scripts\python.exe .\tools\run_execution_worker.py

# 参数关系分析队列（本身不发送业务请求）
.\.venv\Scripts\python.exe .\tools\run_relation_analysis_worker.py

# 过期租约恢复与漏洞复测归档
.\.venv\Scripts\python.exe .\tools\run_maintenance_scheduler.py
```

本机临时启动 Web 也可以使用 `run_web.py`；它只是 Web 启动器，不会在同一进程嵌入
worker。默认页面为 `http://127.0.0.1:5000`。

首次启动且没有显式管理员密码时，启动器会生成本地密码与 Flask 密钥并保存到
`..\.secrets\api-manager-web.local.env`。密码仅首次显示。显式环境变量始终优先：

```powershell
$env:API_MANAGER_SECRET_KEY="replace-with-a-long-random-value"
$env:API_MANAGER_ADMIN_PASSWORD="replace-with-a-strong-local-password"
```

## 3. 统一导入契约

所有格式都通过 `import.v1`，一次导入只产生一个 `ImportRun` 生命周期。文档类来源
必须绑定项目；HAR 可以先成为待路由观察，再在“数据源”页面明确分配。

```powershell
# HAR / 浏览器流量
python -m apiAnalysis.main -i <traffic.har> -f har `
  --source-id <stable-source-id> -p

# OpenAPI
python -m apiAnalysis.main -i <openapi.json> -f openapi `
  --project-id <project-id> --env-id <env-id> --base-url <base-url> -p

# Postman
python -m apiAnalysis.main -i <collection.json> -f postman `
  --project-id <project-id> --env-id <env-id> -p

# Apifox 导出
python -m apiAnalysis.main -i <apifox-export-directory> -f apifox `
  --project-id <project-id> --env-id <env-id> -p
```

导入命令不发送业务请求。旧 `Workspace` 捕获、同步重放、旧 privilege task 和直接
AI/真实重放 CLI 已退出运行链。

## 4. 执行与结果

普通只读批次先排队，再由 worker 执行：

```powershell
python tools/schedule_snapshot_batch.py --name <name> `
  --project-id <project-id> --pathid <pathid>
python tools/run_execution_worker.py --once
```

所有机器结论只通过 `result.v1` 写入。Web 只展示运行、复核队列和漏洞状态，不直接
重放请求，也不会因状态码不同自动创建漏洞。

## 5. 多身份授权矩阵

授权模型支持任意数量身份，不固定为两个账号。身份可包含角色、项目自定义等级、
组织作用域、标签和非敏感属性；策略按 `访问主体 × 资源归属主体 × 资源组` 展开。

```powershell
python tools/manage_authorization_policy.py --help
python tools/schedule_authorization_matrix.py <policy-version-id>
python tools/run_execution_worker.py --once
```

完整配置、预算和判断规则见
[`docs/authorization_matrix.md`](docs/authorization_matrix.md)。策略或认证/关系指纹变化
后需要克隆并激活新版本，不会修改历史运行。

## 6. 漏洞复测

在漏洞详情中先进入“修复中”，再选择“按原始证据安排复测”。系统重放漏洞关联结果
的不可变快照：全部明确通过才关闭；再次出现候选证据则重新打开；认证、传输或判断
不完整时保持待验证。maintenance scheduler 会自动归档已完成复测，也可在详情页手动
触发归档。

## 7. 常见问题

- `ModuleNotFoundError`：确认使用 `.venv` 的 Python 并重新安装锁文件。
- MongoDB/Redis 连接失败：运行 `python -m apiAnalysis.main --doctor`。
- 运行一直排队：确认 execution worker 已独立启动。
- 运行暂停：在项目认证页修复并验证被固定的 Profile Revision，再恢复或创建新运行。
- 授权矩阵超过预算：缩小身份/资源范围，或创建经过复核的新策略版本并提高显式预算。
