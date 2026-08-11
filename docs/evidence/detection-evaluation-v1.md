# 异常检测统一回放终端证据

执行时间：2026-08-09。命令只读取仓库内 10 条固定、脱敏的场景 fixture，不调用外部 API，也不读取线上日志或密钥。

```bash
docker compose build tester
docker compose run --rm tester python scripts/run_detection_evaluation.py
```

实际输出摘要：

```text
summary={'case_count': 10, 'passed_case_count': 10, 'failed_case_count': 0}
trace_ids=['detection-eval-v1-failed-login-user-spike', 'detection-eval-v1-failed-login-ip-spike']
deduplicated=True
```

每个 JSON case 记录输入事件数、期望/实际规则、风险等级、稳定异常 ID、原因码、结构化证据、逐场景重放去重结果和通过状态。该回放是固定规则约束，不代表检测准确率、真实攻击检出率或生产性能。
