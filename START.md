# API Manager 快速启动（Web 优先）

## 1. 环境要求

- Python 3.9
- MongoDB（默认：`127.0.0.1:27017`）
- Redis（默认配置在 `apiAnalysis/conf/secret.py`）

## 2. 安装依赖

```powershell
pip install redis apscheduler flask flask-cors flask-paginate mongoengine pymongo mitmproxy openpyxl json5 pandas pyjwt requests
```

## 3. 修改配置

编辑：`apiAnalysis/conf/secret.py`

至少确认这些字段可连通：

- `mongo_database`
- `mongo_host`
- `mongo_port`
- `mongo_user`
- `mongo_password`
- `redis_host`
- `redis_port`
- `redis_db`
- `redis_password`

注意：仓库默认 `redis_host='127.0.0.1'`，通常要改为你本机或实际 Redis 地址。

## 4. 启动 Web（推荐）

在项目根目录 `D:\gitlib\api_manger` 执行：

```powershell
python .\run_web.py
```

默认访问地址：

- `http://127.0.0.1:5000`

默认登录账号（代码内置）：

- `admin / admin123`
- `normal / normal123`

可选环境变量：

```powershell
$env:HOST="0.0.0.0"
$env:PORT="5000"
$env:DEBUG="1"
python .\run_web.py
```

## 5. 数据导入（CLI 补充）

Web 主要做管理和查看，流量/文档导入用 CLI：

### 5.1 导入 HAR 并参数拆解

```powershell
python -m apiAnalysis.main -i .\apiAnalysis\console.example.com.har -f har -p
```

### 5.2 导入 OpenAPI

```powershell
python -m apiAnalysis.main -i <openapi.json> -f openapi -p
```

### 5.3 导入 Postman

```powershell
python -m apiAnalysis.main -i <collection.json> -f postman -p
```

## 6. 常用任务命令

```powershell
# 生成并执行越权任务
python -m apiAnalysis.main --privilege-tasks --privilege-exec --privilege-limit 20

# AI 回填
python -m apiAnalysis.main --ai-http --ai-url <endpoint> --ai-key <token> --ai-limit 20

# 真实重放验证弱关联
python -m apiAnalysis.main --verify-relations-real
```

## 7. 常见问题

- `ModuleNotFoundError: redis`：依赖未安装，先执行第 2 节。
- Mongo/Redis 连接失败：检查第 3 节配置和服务状态。
- 导入无数据：确认 `-i` 路径正确，且 `-f` 与文件格式一致。
