# 合成异常场景终端证据

执行时间：2026-07-30。命令只读取仓库中的合成 fixture，不产生运行时文件。

```bash
docker compose run --rm tester python -c 'from src.detection.demo import run_demo; r=run_demo(); selected={x["scenario_id"]: x for x in r["scenarios"]}; print({"scenario_count": len(r["scenarios"]), "failed_login": selected["failed-login-user-spike"]["anomaly_ids"], "credential_reason": selected["credential-stuffing"]["reason_codes"], "api_risk": selected["high-api-rate"]["risk_levels"], "normal_count": len(selected["normal-known-source-login"]["anomaly_ids"]), "deduplication": r["deduplication"]})'
```

实际输出：

```text
{'scenario_count': 10, 'failed_login': ['anom-9613110a562f1e4aea6139d8067bd669'], 'credential_reason': [['credential_stuffing_pattern']], 'api_risk': ['medium'], 'normal_count': 0, 'deduplication': {'replayed_anomaly_count': 30, 'unique_anomaly_count': 15, 'deduplicated': True}}
```

这是固定规则样例的回归证据，不代表检测准确率、真实企业数据效果或生产性能。
