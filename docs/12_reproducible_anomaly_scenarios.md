# 可复现异常检测场景（v1）

## 范围

本场景集验证异常检测 A 模块的最小闭环：脱敏日志输入由 `RuleEngine` 处理，输出遵循 `AnomalyEvent` 数据契约，并通过 `GET /api/v1/anomalies` 的 FastAPI 响应模型返回。

数据源是 `tests/fixtures/reproducible_anomaly_scenarios_v1.json`。文件中所有账号、资源、消息、时间和 IP 都是合成数据；IP 使用 TEST-NET 保留网段，不含真实用户或企业日志。

## 场景与预期

| 场景 | 输入 | 预期命中 |
| --- | --- | --- |
| `failed-login-user-spike` | 5 次同账号失败登录 | `failed_login_spike` / high |
| `failed-login-ip-spike` | 8 次同来源失败登录 | `failed_login_spike` / high |
| `credential-stuffing` | 同来源尝试 4 个账号 | `credential_stuffing_pattern` / high |
| `high-api-rate` | 1 分钟内 80 次 API 调用 | `high_api_rate` / medium |
| `sensitive-resource-burst` | 5 次敏感资源访问 | `sensitive_resource_access` / medium |
| `ordinary-user-admin-resource` | 普通账号访问 admin 资源 | `admin_resource_access` / high |
| `new-source-sensitive-chain` | 新来源登录后访问配置资源 | `new_source_then_sensitive_access` / critical |
| `new-source-sensitive-export-chain` | 新来源登录后访问导出资源 | `new_source_then_sensitive_access` / critical |
| `normal-known-source-login` | 工作时段、已知来源登录 | 无异常 / low |
| `normal-low-rate-api` | 3 次普通 API 调用 | 无异常 / low |

`related_event_ids` 至少包含触发当前异常的源事件；攻击链场景还会关联前序登录事件。JSON 中的 `target_anomaly_count` 是表中指定目标异常的数量；规则可能同时生成附带异常，例如新来源登录本身，这不改变目标异常的验证。

## 运行

```bash
docker compose run --rm tester pytest -q tests/test_reproducible_anomaly_scenarios.py
```

测试不连接真实日志、数据库或外部模型服务。它验证固定样例是否仍能产生约定的风险等级、原因码、证据和关联事件，并验证现有 FastAPI 查询响应能接受对应的 `AnomalyEvent`。它不是准确率、召回率或业务效果评测。
