# 异常检测 A 模块验收报告（v1）

## 范围与边界

本报告只覆盖我负责的异常检测 A 模块：标准化安全日志进入 `RuleEngine`，生成 `AnomalyEvent`，并按 FastAPI 的 `GET /api/v1/anomalies` 响应契约返回。Kafka、Flink、ClickHouse 部署和 React 工作台属于团队全链路，不应据此归为个人独立成果。

所有场景来源于 `tests/fixtures/reproducible_anomaly_scenarios_v1.json`。其中的账号、资源、消息与 IP 均为合成数据，IP 使用 TEST-NET 保留网段。

## 场景验收

| 场景 | 目标风险 | 目标 reason codes | 关键 evidence / 关联 |
| --- | --- | --- | --- |
| `failed-login-user-spike` | high | `failed_login_spike` | `user_id`、5 分钟失败数、触发源事件 |
| `failed-login-ip-spike` | high | `failed_login_spike` | `src_ip`、5 分钟失败数、触发源事件 |
| `credential-stuffing` | high | `credential_stuffing_pattern` | `src_ip`、尝试账号数、触发源事件 |
| `high-api-rate` | medium | `high_api_rate` | `user_id`、1 分钟 API 次数、触发源事件 |
| `sensitive-resource-burst` | medium | `sensitive_resource_access` | `user_id`、敏感访问数、资源、触发源事件 |
| `ordinary-user-admin-resource` | high | `admin_resource_access` | 普通账号、admin 资源、触发源事件 |
| `new-source-sensitive-chain` | critical | `new_source_then_sensitive_access`、`sensitive_resource_access` | 用户、来源、资源、前序登录与当前事件 |
| `new-source-sensitive-export-chain` | critical | `new_source_then_sensitive_access`、`sensitive_resource_access` | 用户、来源、导出资源、前序登录与当前事件 |
| `normal-known-source-login` | low | 无 | 工作时段已知来源，无异常事件 |
| `normal-low-rate-api` | low | 无 | 低于阈值的 API 调用，无异常事件 |

执行 `docker compose run --rm tester pytest -q tests/test_reproducible_anomaly_scenarios.py` 时，场景目录检查与 10 个场景共通过 11 项测试。每个异常场景断言风险等级、原因码、关键证据和关联事件；测试通过真实 `RuleEngine` 生成事件，并使用 FastAPI 测试客户端请求 `GET /api/v1/anomalies`。

## 稳定性与增量验证

| 约束 | 已验证的行为 | 覆盖测试 |
| --- | --- | --- |
| 稳定异常 ID | 同一源日志、规则与原因码会生成相同 `anom-*` ID；不同 worker 重跑得到相同 ID。 | `test_event_id_seed_generates_stable_event_id`、`test_worker_uses_stable_event_ids_for_detected_anomalies` |
| 增量读取 | 首轮检测记录最大事件时间；下一轮从该检查点继续，已处理日志不再读入。 | `test_worker_run_once_inserts_detected_anomalies_and_advances_checkpoint` |
| lookback warmup | 启动回看仅恢复滑动窗口与已见 ID，不写入 warmup 历史异常；后续新日志可命中阈值。 | `test_worker_recovers_recent_window_state_without_reinserting_warmup_anomalies` |
| 批内去重 | 同一源事件在同一批次重复投递时只写入一个异常事件。 | `test_worker_deduplicates_replayed_source_event_within_a_batch` |
| 重启后去重 | worker 会查询已有异常 ID，稳定 ID 已落库时不再次插入。 | `test_worker_deduplicates_stable_ids_already_persisted_by_a_previous_worker`、`test_existing_anomaly_ids_queries_only_requested_ids` |

## 已验证命令与限制

```bash
docker compose run --rm tester pytest -q tests/test_reproducible_anomaly_scenarios.py
docker compose run --rm tester pytest -q tests/test_anomaly_builder.py::test_event_id_seed_generates_stable_event_id tests/test_anomaly_detector_worker.py::test_worker_uses_stable_event_ids_for_detected_anomalies tests/test_anomaly_detector_worker.py::test_worker_run_once_inserts_detected_anomalies_and_advances_checkpoint tests/test_anomaly_detector_worker.py::test_worker_recovers_recent_window_state_without_reinserting_warmup_anomalies tests/test_anomaly_detector_worker.py::test_worker_deduplicates_replayed_source_event_within_a_batch
docker compose run --rm tester
```

本报告不提供模型准确率、召回率、真实企业攻击检出率或生产吞吐结论。场景与持久化 ID 查询通过 Docker 测试容器中的规则、FastAPI 契约和 ClickHouse 客户端替身验证；尚未替代真实 Kafka/Flink/ClickHouse 集群的长时间联调与负载测试。
