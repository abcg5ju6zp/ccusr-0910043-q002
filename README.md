# Sanic 服务框架

本项目提供异步 HTTP 服务、路由、蓝图、中间件、信号、后台任务和工作进程管理能力。生产源码位于 `sanic/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install --break-system-packages --no-build-isolation -e '.[test]'`

## 测试

`python3 -m pytest -q`

## 构建

`python3 -m compileall -q sanic`

`python3 -m build --wheel --no-isolation`

## 使用

应用通过 `Sanic` 创建服务，可使用本地测试客户端验证请求、响应和生命周期行为。

## 代理链裁决（Proxy Chain Adjudication）

接入两层及以上反向代理后，`Forwarded` 与 `X-Forwarded-*` 头可能被请求方
自行写入，框架通过 `sanic.proxy` 提供逐跳裁决，计算唯一有效来源。

### 策略登记

可信跳点按 *应用近端 → 边缘远端* 登记（depth 0 为直连应用的一跳），
可限制每个跳点授权的头部族与可选秘密值，并设置 X 族 → Forwarded 的
迁移期限：

```python
app.configure_proxy_chain({
    "hops": [
        {"cidr": "10.0.0.0/8",
         "families": ["forwarded", "x-forwarded"],
         "secret": "inner-secret"},
        {"cidr": "10.1.0.0/16",
         "families": ["forwarded", "x-forwarded"]},
    ],
    "families": ["forwarded", "x-forwarded"],   # 全局授权头部族
    "real_ip_header": "X-Real-IP",              # 可选
    "migration": {                              # 可选迁移窗口
        "active_from": "2026-10-01T00:00:00Z",
        "grace_until": "2026-11-01T00:00:00Z",
    },
})
```

也可通过 `config.PROXY_CHAIN` 在启动时装配；`app.reload_proxy_policy(source)`
支持热更新，源失败时保留旧版本。每个请求在受理时绑定不可变策略快照，
处理期间不受热更新影响。发布新版本后会派发
`proxy.policy.reloaded` 信号（上下文为 `version`，处理器签名为
`async def handler(version): ...`）。

### 裁决结论

`request.proxy_verdict` 返回可解释结论（`request.remote_addr` /
`client_ip` / `scheme` / `host` 等据此计算）：

| verdict | 含义 | 有效来源 |
| --- | --- | --- |
| `trusted` | 链上跳点全部通过网段、头部族、秘密值校验 | 最左声明地址 |
| `unknown_hop` | 遇到未登记的中间跳点 | 该跳点（右侧已验证跳点的真实观察） |
| `chain_truncated` | 登记链短于头部声明链 | 截断边界地址 |
| `conflict` | 两族并存且不一致、头部族未授权或已过迁移期限 | 直连对端（拒绝全部声明） |
| `malformed` | 转发头无法解析 | 直连对端 |
| `migration_grace` | 宽限期内收到旧族头，结论可接受但留痕 | 声明地址 |
| `direct` | 无转发头 | 直连对端 |

`verdict.original_chain` 保留逐跳原始声明供审计，
`verdict.validated_chain` 仅含经担保的链段，`verdict.explain()` 给出
单行结论。策略加载或裁决异常时失败闭合，绝不回退采信转发头。

### 日志授权

访问日志只暴露被授权的地址信息：默认输出有效来源、结论与已验证跳数；
`PROXY_LOG_ADDRESSES=False` 时地址以 `redacted` 呈现；完整原始链必须同时
由策略版本（`log_full_chain: true`）与 `PROXY_LOG_FULL_CHAIN=True` 授权
才会记录，未通过担保的左侧声明默认不进日志。

未登记策略时沿用 `PROXIES_COUNT` / `REAL_IP_HEADER` /
`FORWARDED_SECRET` 的旧版行为，两者互不影响。

