# Investigation Interview Demo

Fixed synthetic replay; not a SOC/SIEM or accuracy claim.

## failed-login-user-spike
- Input events: 5
- Deduplicated replay: True
- Anomaly ID: anom-9613110a562f1e4aea6139d8067bd669
- Rule hits: failed_login_spike
- ATT&CK references: T1110
- Sanitized evidence: {'user_id': 'd***t', 'failed_count_5m': 5}
- API review replay: pending -> confirmed

## credential-stuffing
- Input events: 4
- Deduplicated replay: True
- Anomaly ID: anom-a6ee1adbc26316f4b1e22d487142222f
- Rule hits: credential_stuffing_pattern
- ATT&CK references: T1110.004
- Sanitized evidence: {'src_ip': '203.0.***.***', 'distinct_users_5m': ['d***a', 'd***b', 'd***c', 'd***d'], 'count': 4}

## high-api-rate
- Input events: 80
- Deduplicated replay: True
- Anomaly ID: anom-9159951ea5aab04842f3434ac2bd1ebc
- Rule hits: high_api_rate
- ATT&CK references: No ATT&CK mapping asserted
- Sanitized evidence: {'user_id': 'a***t', 'api_calls_1m': 80}

## normal-known-source-login
- Input events: 1
- Deduplicated replay: True
- Result: normal control; no anomaly emitted.

## normal-low-rate-api
- Input events: 3
- Deduplicated replay: True
- Result: normal control; no anomaly emitted.
