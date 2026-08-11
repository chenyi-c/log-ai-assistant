# Investigation Interview Demo Evidence

Command executed in the Docker tester image:

```bash
docker compose run --rm tester python scripts/run_interview_investigation_demo.py --format markdown
```

Observed synthetic-only output excerpt:

```text
failed-login-user-spike
- Input events: 5
- Deduplicated replay: True
- Anomaly ID: anom-9613110a562f1e4aea6139d8067bd669
- Rule hits: failed_login_spike
- ATT&CK references: T1110
- API review replay: pending -> confirmed

credential-stuffing
- Input events: 4
- Deduplicated replay: True
- ATT&CK references: T1110.004
- Sanitized evidence: {'src_ip': '203.0.***.***', 'distinct_users_5m': ['d***a', 'd***b', 'd***c', 'd***d'], 'count': 4}

normal-known-source-login
- Input events: 1
- Result: normal control; no anomaly emitted.
```

This is a fixed synthetic replay, not an accuracy measurement or a claim of complete SOC/SIEM capability.
