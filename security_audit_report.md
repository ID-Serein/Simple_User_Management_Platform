# Flask 用户管理平台代码审计漏洞报告

## 1. 报告信息

| 项目 | 内容 |
| --- | --- |
| 项目名称 | Simple_User_Management_Platform |
| 审计对象 | Flask Web 应用源码 |
| 审计日期 | 2026-07-07 |
| 审计方式 | 白盒代码审计 + Flask test client 轻量验证 |
| 审计范围 | `app.py`、`templates/*.html`、`static/css/style.css`、仓库依赖/配置文件 |
| 风险分级 | 严重、 高危、 中危、 低危 |

![image-20260707185826305](C:\Users\Serei\AppData\Roaming\Typora\typora-user-images\image-20260707185826305.png)

## 2. 执行摘要

本次审计发现该 Flask 项目存在多处认证与配置类安全问题，其中最严重的问题是硬编码 Flask `secret_key`、默认管理员账号密码泄露、明文密码存储和调试模式对外监听。攻击者在无需合法账号的情况下，可以通过登录页 HTML 注释获取默认管理员密码，或基于源码中的 `secret_key` 伪造 Flask session cookie，从而直接冒充管理员访问敏感信息。

项目当前不建议直接部署到公网或生产环境。应优先处理会话密钥、默认凭据、密码存储、Debug 模式和登录防护问题，并在修复后重新进行安全验证。

## 3. 风险总览

| 编号 | 漏洞名称 | 等级 | OWASP Top 10 | 影响 |
| --- | --- | --- | --- | --- |
| VULN-001 | Flask `secret_key` 硬编码导致 session 可伪造 | 严重 | A01 访问控制失效 / A02 加密机制失效 | 可绕过登录冒充管理员 |
| VULN-002 | 默认管理员账号密码泄露到客户端 HTML | 严重 | A05 安全配置错误 / A07 身份认证失败 | 未授权用户可获取管理员凭据 |
| VULN-003 | 明文密码硬编码、存储并在页面回显 | 高危 | A02 加密机制失效 | 账号凭据泄露，撞库风险扩大 |
| VULN-004 | Debug 模式开启且监听 `0.0.0.0` | 高危 | A05 安全配置错误 | 可能泄露堆栈信息，极端情况下导致远程代码执行 |
| VULN-005 | 登录接口缺少暴力破解防护 | 中危 | A07 身份认证失败 | 可被密码爆破或凭据填充攻击 |
| VULN-006 | 缺少 CSRF 防护且登出使用 GET 请求 | 中危 | A01 访问控制失效 | 可被跨站请求强制登出，后续功能易扩展出更高风险 |
| VULN-007 | 缺少安全响应头和生产 Cookie 加固配置 | 中危 | A05 安全配置错误 | 增加点击劫持、MIME 嗅探、会话窃取风险 |
| VULN-008 | 缺少依赖清单和版本锁定 | 低危 | A06 易受攻击和过时组件 | 无法稳定复现和审计依赖漏洞 |

## 4. 漏洞详情

### VULN-001 Flask `secret_key` 硬编码导致 session 可伪造

**风险等级：严重**

**漏洞类型：** 会话伪造、认证绕过、敏感信息泄露  
**OWASP 分类：** A01:2021 Broken Access Control、A02:2021 Cryptographic Failures  
**影响文件：**

- `app.py:4`
- `app.py:28-32`
- `app.py:40-42`
- `templates/index.html:32`

**问题描述：**

应用在源码中硬编码了 Flask 会话签名密钥：

```python
app.secret_key = "dev-key-2025"
```

Flask 默认 session 是客户端签名 Cookie。签名密钥一旦泄露或可预测，攻击者可以自行构造合法 session 数据。当前应用仅根据 `session["username"]` 判断当前用户身份，因此攻击者可以伪造 `{"username": "admin"}` 的 session cookie，直接冒充管理员。

**验证结果：**

使用当前源码中的 `secret_key` 生成管理员 session 后，请求首页返回 `200`，并包含管理员邮箱、密码和余额等信息。

```text
forged_cookie=eyJ1c2VybmFtZSI6ImFkbWluIn0.akzEiw.0i6SxwAMac4ZObmxEiHcPqDxceI
status= 200
contains_admin_email= True
contains_admin_password= True
contains_admin_balance= True
```

**攻击影响：**

- 绕过登录流程，直接冒充任意存在于 `USERS` 字典中的用户。
- 可读取管理员邮箱、手机号、余额、密码等敏感数据。
- 如果后续增加管理员功能，该问题会直接升级为后台完全接管。

**修复建议：**

1. 从环境变量或密钥管理服务读取高强度随机密钥，不要写入源码。
2. 立即轮换当前密钥，并使旧 session 全部失效。
3. 生产环境建议使用服务端 session 或 Flask-Login 等成熟认证方案。
4. 不要仅信任客户端 session 中的用户名，应在服务端重新加载用户并做权限校验。

示例：

```python
import os

app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
```

---

### VULN-002 默认管理员账号密码泄露到客户端 HTML

**风险等级：严重**

**漏洞类型：** 默认凭据泄露、敏感信息泄露  
**OWASP 分类：** A05:2021 Security Misconfiguration、A07:2021 Identification and Authentication Failures  
**影响文件：**

- `templates/login.html:10`
- `app.py:7-10`

**问题描述：**

登录页模板包含 HTML 注释，直接写出了默认管理员账号和密码：

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

HTML 注释会随响应发送给浏览器。任何未登录用户只需访问 `/login` 并查看页面源代码，即可获取管理员凭据。

**验证结果：**

访问 `/login` 后，响应中包含默认管理员账号密码注释。

```text
status= 200
leaks_default_admin_comment= True
```

使用该默认账号密码提交登录请求后，登录成功并返回管理员信息。

```text
status= 200
login_succeeds_with_default_admin= True
password_rendered= True
```

**攻击影响：**

- 未认证攻击者可直接获取管理员账号密码。
- 若该密码在其他系统复用，会造成横向扩散风险。
- 默认凭据可能被自动化扫描器批量探测并利用。

**修复建议：**

1. 删除所有包含账号、密码、Token、密钥的 HTML 注释和调试信息。
2. 禁止在源码中保留默认管理员密码。
3. 首次部署时通过安全初始化流程创建管理员账号，并强制修改初始密码。
4. 立即更换已泄露的管理员密码。

---

### VULN-003 明文密码硬编码、存储并在页面回显

**风险等级：高危**

**漏洞类型：** 明文密码存储、敏感信息回显  
**OWASP 分类：** A02:2021 Cryptographic Failures  
**影响文件：**

- `app.py:6-22`
- `app.py:40`
- `templates/index.html:31-32`

**问题描述：**

用户数据直接保存在源码字典中，密码以明文形式存储：

```python
"password": "admin123"
```

登录验证时直接比较明文密码，并且用户登录后页面会渲染 `user_info.password`，导致密码出现在 HTML 响应中。

**攻击影响：**

- 源码泄露即等同于账号密码泄露。
- 任何能访问页面响应、浏览器历史、代理日志、截图或前端监控数据的人都可能看到密码。
- 明文密码无法满足基本合规要求，不利于追责和泄露后的风险控制。

**修复建议：**

1. 使用数据库保存用户信息，密码只保存哈希值。
2. 使用 `werkzeug.security.generate_password_hash` 和 `check_password_hash` 或 Argon2/bcrypt。
3. 页面、日志、接口响应中禁止输出密码字段。
4. 对已泄露的账号强制重置密码。

示例：

```python
from werkzeug.security import generate_password_hash, check_password_hash

password_hash = generate_password_hash(password)

if check_password_hash(user.password_hash, password):
    session["username"] = user.username
```

---

### VULN-004 Debug 模式开启且监听 `0.0.0.0`

**风险等级：高危**

**漏洞类型：** 安全配置错误、调试接口暴露  
**OWASP 分类：** A05:2021 Security Misconfiguration  
**影响文件：**

- `app.py:53-54`

**问题描述：**

应用启动时开启了 Flask Debug 模式，并绑定到所有网卡：

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

Debug 模式会暴露详细异常栈、环境信息和交互式调试能力。虽然 Werkzeug 调试器通常有 PIN 保护，但在真实部署、代理转发、日志泄露或弱隔离环境中仍可能被利用，严重时可导致远程代码执行。

**攻击影响：**

- 异常时泄露路径、配置、依赖版本、环境变量等信息。
- 暴露调试控制台，存在进一步执行代码的风险。
- 绑定 `0.0.0.0` 会让同网络内其他主机可访问开发服务。

**修复建议：**

1. 生产环境禁止使用 `app.run(debug=True)`。
2. 使用 Gunicorn、uWSGI、Waitress 等 WSGI Server 部署。
3. 只在本地开发时绑定 `127.0.0.1` 并开启 Debug。
4. 通过环境变量区分开发和生产配置。

示例：

```python
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
```

---

### VULN-005 登录接口缺少暴力破解防护

**风险等级：中危**

**漏洞类型：** 暴力破解、凭据填充  
**OWASP 分类：** A07:2021 Identification and Authentication Failures  
**影响文件：**

- `app.py:35-43`

**问题描述：**

`/login` 接口没有验证码、IP 限速、账号锁定、失败次数记录或审计日志。攻击者可以对用户名和密码进行自动化爆破。结合默认账号、弱密码和密码泄露问题，该风险会显著放大。

**攻击影响：**

- 攻击者可高频尝试密码，直到登录成功。
- 无审计日志时难以及时发现账号攻击。
- 可与泄露密码库结合进行凭据填充攻击。

![image-20260707180144621](C:\Users\Serei\AppData\Roaming\Typora\typora-user-images\image-20260707180144621.png)

![image-20260707180055213](C:\Users\Serei\AppData\Roaming\Typora\typora-user-images\image-20260707180055213.png)

**修复建议：**

1. 使用 Flask-Limiter 对 `/login` 增加 IP 和账号维度限速。
2. 对连续失败的账号增加短时锁定或指数退避。
3. 增加登录失败审计日志和告警。
4. 强制使用更高强度的密码策略。

示例策略：

```text
同一 IP：5 次 / 分钟
同一账号：10 次失败后锁定 15 分钟
管理员账号：失败告警
```

---

### VULN-006 缺少 CSRF 防护且登出使用 GET 请求

**风险等级：中危**

**漏洞类型：** CSRF、状态变更接口设计不当  
**OWASP 分类：** A01:2021 Broken Access Control  
**影响文件：**

- `templates/login.html:23`
- `app.py:47-50`
- `templates/index.html:15`
- `templates/index.html:52`

**问题描述：**

登录表单未包含 CSRF Token，应用也没有启用全局 CSRF 防护。同时 `/logout` 使用 GET 请求完成状态变更：

```python
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
```

攻击者可诱导已登录用户访问恶意页面，从而自动触发登出请求。当前功能较少，因此影响主要是强制登出；但如果后续继续沿用该模式到修改资料、转账、删除用户等接口，风险会快速升级。

**攻击影响：**

- 可跨站强制用户登出。
- 登录 CSRF 可能导致用户被登录到攻击者控制的低权限账号。
- 为后续状态变更接口埋下通用 CSRF 风险。

**修复建议：**

1. 使用 Flask-WTF `CSRFProtect` 开启全局 CSRF 防护。
2. 所有状态变更操作使用 POST/PUT/DELETE，不使用 GET。
3. `/logout` 改为 POST，并校验 CSRF Token。
4. Cookie 配置 `SameSite=Lax` 或更严格策略。

---

### VULN-007 缺少安全响应头和生产 Cookie 加固配置

**风险等级：中危**

**漏洞类型：** 安全头缺失、Cookie 配置不足  
**OWASP 分类：** A05:2021 Security Misconfiguration  
**影响文件：**

- `app.py`

**问题描述：**

项目中未看到安全响应头配置，也未显式设置生产环境 Cookie 安全属性。当前缺少的典型安全控制包括：

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options` 或 CSP `frame-ancestors`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `SESSION_COOKIE_SECURE=True`
- `SESSION_COOKIE_SAMESITE=Lax/Strict`

**攻击影响：**

- 页面可能被第三方站点嵌入，增加点击劫持风险。
- 缺少 CSP 会降低 XSS 后的缓解能力。
- 未强制 HTTPS Cookie 时，会话在非 HTTPS 场景下更容易被窃取。

**修复建议：**

1. 使用 Flask-Talisman 或 `after_request` 统一添加安全响应头。
2. 生产环境启用 HTTPS 和 HSTS。
3. 显式设置 session cookie 安全属性。

示例：

```python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

---

### VULN-008 缺少依赖清单和版本锁定

**风险等级：低危**

**漏洞类型：** 依赖治理不足  
**OWASP 分类：** A06:2021 Vulnerable and Outdated Components  
**影响文件：**

- 仓库根目录

**问题描述：**

仓库中未发现 `requirements.txt`、`pyproject.toml`、`Pipfile` 或锁文件。缺少依赖清单会导致部署环境不可复现，也无法稳定执行依赖漏洞扫描。

**攻击影响：**

- 不同环境可能安装不同版本的 Flask/Werkzeug/Jinja2。
- 无法判断是否使用了存在 CVE 的依赖版本。
- CI/CD 难以自动执行依赖安全检查。

**修复建议：**

1. 添加依赖文件并固定版本范围。
2. 使用 `pip-audit`、`safety` 或 Dependabot 定期扫描依赖。
3. 在 CI 中加入依赖漏洞检查。

示例：

```text
Flask==3.1.3
Werkzeug==3.1.3
```

## 5. 复现证据汇总

### 5.1 伪造管理员 session

审计过程中使用 Flask 内置 session serializer 基于硬编码密钥生成管理员 Cookie，访问 `/` 后可读取管理员信息。

```text
status= 200
contains_admin_email= True
contains_admin_password= True
contains_admin_balance= True
```

### 5.2 登录页泄露默认管理员凭据

访问 `/login` 后响应 HTML 包含默认管理员账号密码注释。

```text
status= 200
leaks_default_admin_comment= True
```

### 5.3 默认管理员账号可直接登录

使用源码和 HTML 注释中的默认凭据提交 `/login`，页面返回管理员信息。

```text
status= 200
login_succeeds_with_default_admin= True
password_rendered= True
```

## 6. 未发现或暂未覆盖的风险

| 检查项 | 结论 |
| --- | --- |
| SQL 注入 | 当前项目未发现数据库访问和 SQL 拼接代码 |
| 命令注入 | 当前项目未发现系统命令执行代码 |
| 文件上传漏洞 | 当前项目未发现文件上传功能 |
| 模板 XSS | 当前模板使用 Jinja2 默认转义，未发现直接 `safe` 或关闭转义用法 |
| 依赖 CVE | 因缺少依赖清单，未进行稳定依赖漏洞判定 |

## 7. 修复优先级建议

1. **立即修复：** 删除默认管理员凭据泄露、轮换管理员密码、移除源码中的明文密码。
2. **立即修复：** 更换 Flask `secret_key`，使用环境变量管理，并使旧 session 失效。
3. **立即修复：** 关闭生产 Debug 模式，禁止开发服务器对公网监听。
4. **短期修复：** 引入密码哈希、数据库用户表、登录限速和审计日志。
5. **短期修复：** 启用 CSRF 防护，登出改为 POST。
6. **中期修复：** 添加安全响应头、HTTPS/HSTS、Cookie 加固配置。
7. **中期修复：** 增加依赖清单、版本锁定、依赖漏洞扫描和基础安全测试。

## 8. 结论

该项目目前具备教学或本地演示性质，但不满足生产环境的基本安全要求。最主要风险集中在认证会话、默认凭据、密码保护和调试配置四个方面。建议完成上述高优先级修复后，再进行一次回归审计，重点验证：

- 旧 session 是否全部失效；
- 默认管理员密码是否已删除并重置；
- 密码是否只以哈希形式存储；
- Debug 模式是否在生产环境彻底关闭；
- `/login` 是否具备限速和审计能力；
- 所有状态变更请求是否具备 CSRF 防护。
