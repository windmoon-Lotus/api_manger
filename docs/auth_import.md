# 认证快捷导入与多登录功能点

`/auth-import` 面向个人部署提供三条快捷认证接入路径：

1. 复用已有 Token URL；
2. 一键导入声明式 Recipe；
3. 运行管理员提供的可信 Python 代码。

它们最终都生成同一种运行引用：

```text
ProjectAuthProfile
  -> ProjectAuthProfileRevision
  -> AuthRealmRevision
  -> AuthAdapterVersion
```

执行器仍然只消费短期、进程内的 `AccountContext`，不会把 Token、Cookie
或运行响应保存到任务和结果中。

## 一个项目允许多个登录方案

项目没有唯一的“当前 Recipe”。同一项目和环境可以同时启用多个登录
Profile，例如：

```text
admin-console / admin / password / admin-account
member-web    / member / sms      / member-account
partner-api   / partner / sso     / partner-account
```

一个 Profile 槽位由以下四个业务维度区分：

- 登录功能点 `login_scene`；
- 角色 `role_key`；
- 登录模式 `login_mode`；
- 项目账号别名 `account_key`。

显示名称只是给人看的标签，不用于判断两个登录功能点是否相同。不同槽位
可以同时处于启用状态，并分别使用 Recipe、Token URL 或可信代码 Provider。

## Recipe Key 与不可变版本

不可变的是已经执行过的 Recipe 内容版本，不是登录功能不能修改。

- `recipe_key` 是 Recipe 的稳定身份；
- 相同 `recipe_key` 和相同内容会复用已有 Adapter Version；
- 相同 `recipe_key`、内容变化会新增 Adapter Version；
- 不同 `recipe_key` 表示不同 Recipe，可以同时存在；
- 一键更新只切换当前 Profile 的 Revision，其他 Profile 仍固定引用原版本；
- 历史运行继续引用当时的 Profile/Realm/Adapter Revision。

快捷导入会在本地完成 JSON、秘密引用、认证 Origin 和业务 Origin 静态校验，
然后立即激活所选 Profile，不增加候选审批步骤，也不会为了导入主动发送登录
或业务请求。高级“认证域修复”工作台仍采用候选、显式验证和 CAS 激活流程，
用于替换已经在运行的故障配置。

## Token URL：复用已有登录方案

Token URL 适用于已经有脚本、浏览器插件、OTP/MFA 工具或本地服务负责登录的
情况。API Manager 只在需要认证时调用配置的 HTTP(S) URL。

支持：

- `GET` 或 `POST`；
- 不传凭据，或把绑定账号的用户名/密码放到 Query、JSON Body、受控 Header；
- 使用点路径提取 JSON Token，例如 `data.access_token`；
- 从响应 Cookie 构造 Cookie 认证上下文；
- 默认严格 TLS（可按版本关闭）、禁止自动跳转、30 秒以内超时；
- Token URL 必须属于版本化 Realm 的认证 Origin。

响应示例：

```json
{
  "access_token": "short-lived-token"
}
```

Token 和 Cookie 只进入内存 `AccountContext`。

## RSA 密码转换与二验接收器

Recipe 的 `rsa_encrypt` 本地变换支持 2048 位及以上 RSA 公钥、PKCS#1 v1.5、
OAEP-SHA1、OAEP-SHA256，以及 Base64/Hex 输出。公钥应通过
`{{secret.login_rsa_public_key}}` 之类的 Realm 版本化键引用。需要
`password + 分隔符 + timestamp` 的协议，先用 `unix_time` 和 `concat` 形成明文，
再执行 `rsa_encrypt`。密码明文、密文和最终 Token 均不得进入 Recipe、诊断或日志。

`mfa_receive` 支持：

- `pull`：测试或预发环境主动访问明确允许的验证码接收服务；拉取请求计入最多
  6 次认证请求预算，Origin、TLS、超时和响应提取仍受 Recipe 边界约束；
  JSON 数组可使用 `list_path`、`match_path`、`match_value` 和 `path` 按场景精确
  选择验证码，最多检查前 100 项；
- `push`：认证运行时创建短期事务，受信工具通过 MFA Receiver API 获取待处理
  `transaction_id` 并推送验证码；默认单进程模式只存在于内存，配置共享 Redis 后
  可跨 Web/Worker 进程传递，单次消费，最长等待 300 秒；
- 拉取或推送失败统一返回 `MFA_OR_INTERACTION_REQUIRED`，不会把验证码、响应正文
  或挑战秘密写入认证健康记录。

推送接口必须配置至少 16 字符的 `API_MANAGER_MFA_RECEIVER_TOKEN`，并使用 Bearer
认证。多进程部署还需在 Web 与执行 Worker 中配置相同的
`API_MANAGER_MFA_RECEIVER_REDIS_URL`。Redis 中只保存短期事务元数据和 AES-GCM
密文，密钥由 Receiver Token 派生且不写入 Redis；建议使用独立 DB/账号。

典型核心链路为：RSA 变换 → 首次登录提取 challenge → 可选触发发码 HTTP 步骤
→ `mfa_receive` → 二验提交 → 提取最终 access token → `AccountContext`。只有最终
token/cookie 会进入业务请求。RSA 明文是否拼接时间戳由具体协议决定，不强制添加。

## 证书校验开关

Recipe、Token URL 和管理员可信代码三个快捷导入表单都提供“严格校验 TLS
证书”开关，默认开启。该设置写入不可变 Realm Revision，并由当前 Profile
Revision 固定引用：

- 开启时，认证请求和随后使用该认证上下文的业务请求都执行证书校验；
- 关闭时，只对这一认证方案版本关闭，不修改全局 `requests` 行为；
- 外部调用者不能通过执行参数临时传入 `verify=False` 绕过 Realm 边界；
- 执行中心会在每个 Checkpoint 的发送摘要中明确显示“TLS 校验开启/关闭”；
- 历史 Run 继续显示并使用当时固定版本的设置。

仅在测试环境使用自签名证书且暂时无法配置 CA Bundle 时关闭。关闭后仍有 HTTPS
加密，但无法验证服务端身份，存在中间人风险；正式环境应保持开启。

## 管理员可信代码

可信代码必须定义：

```python
def get_auth(username, password):
    return {
        "headers": {"Authorization": "Bearer ..."},
        "cookies": {},
        "expires_in": 1800,
    }
```

这是“管理员安装本地插件”的信任模型，不是用来执行不可信用户或 AI 代码的
通用沙箱。只有管理员可以通过带 CSRF 防护的页面写入代码。

当前低成本防护包括：

- 独立 Python 子进程和最长 30 秒超时；
- 受限导入与 AST 危险名称检查；
- 注入的 `requests` 只允许 `GET/POST`；
- 最多 6 次认证请求；
- 只能访问页面显式填写的认证 Origin；
- 禁止自动跳转，使用当前 Realm Revision 的 TLS 开关；
- 单响应和最终结果均限制为 1 MiB；
- 子进程只接收当前账号凭据和本次运行所需配置。

这些措施不能抵御精心构造的敌对 Python。若代码来源不可信，应保持功能关闭，
等待后续容器/操作系统级隔离。可以显式禁用：

```powershell
$env:API_MANAGER_ALLOW_TRUSTED_AUTH_CODE="0"
```

默认值为 `1`，符合个人项目“管理员即插件作者”的边界。

## Web 监听地址

默认只监听：

```powershell
$env:HOST="127.0.0.1"
```

需要局域网访问时可手动改为：

```powershell
$env:HOST="0.0.0.0"
```

`0.0.0.0` 会把管理页面暴露给可到达本机端口的其他设备。此时必须使用强管理
员密码、关闭 `DEBUG`、限制防火墙来源，并只允许可信管理员使用代码导入。
