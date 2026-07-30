# 异常检测模块面试演示

时长目标：3 分钟。仅使用固定合成日志，不需要 API Key、Kafka、Flink 或真实企业日志。

## 1. 启动与输入（约 1 分钟）

```bash
docker compose build tester
docker compose run --rm tester python scripts/run_anomaly_demo.py
```

输入来自 `tests/fixtures/reproducible_anomaly_scenarios_v1.json`。依次指出 `failed-login-user-spike`、`credential-stuffing`、`high-api-rate` 和 `normal-known-source-login`；其中账号、资源和 IP 都是虚构/TEST-NET 数据。

## 2. 预期看到的结果（约 1 分钟）

- 登录失败突增：5 条输入，输出高风险异常、`failed_login_spike`、稳定 `anomaly_id` 与失败数证据；
- 凭证填充：输出 `credential_stuffing_pattern` 和不同账号数证据；
- 高频 API：80 条输入，输出中风险 `high_api_rate`；
- 正常对照：没有异常 ID 和证据；
- 末尾 `deduplication` 显示重复回放后的唯一异常 ID 数量。

报告调用实际 `RuleEngine`、`AnomalyEvent` 和 FastAPI 查询模型，输出为 JSON，便于追问字段含义。

## 3. 个人贡献说明（约 1 分钟）

我负责团队项目中的异常检测 A 模块：规则检测、异常事件建模、稳定 ID/去重与可解释证据。日志采集、Kafka、Flink、ClickHouse、前端和 AI 研判属于团队整体链路；我不会把它们表述为个人独立开发。

可复现输出见 [`evidence/anomaly-demo-v1.md`](evidence/anomaly-demo-v1.md)。
