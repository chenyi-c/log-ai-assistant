# Investigation Pack Terminal Evidence

Command actually run in the Docker tester image:

```text
docker compose build tester
docker compose run --rm tester python scripts/run_investigation_pack.py --format markdown
```

Observed output excerpt (synthetic inputs only):

```text
## failed-login-user-spike
- Input events: 5
- Deduplicated replay: True
- Anomaly ID: anom-9613110a562f1e4aea6139d8067bd669
- Risk / reasons: high / failed_login_spike
- ATT&CK references: T1110
- Review status: pending

## credential-stuffing
- Input events: 4
- Deduplicated replay: True
- Anomaly ID: anom-a6ee1adbc26316f4b1e22d487142222f
- Risk / reasons: high / credential_stuffing_pattern
- ATT&CK references: T1110.004

## normal-known-source-login
- Input events: 1
- Deduplicated replay: True
- Result: no anomaly expected and none emitted.
```

The complete command output covered ten fixed synthetic scenarios, with eight expected investigation records and two expected normal controls. It is a replay regression result, not a detection-accuracy measurement.
