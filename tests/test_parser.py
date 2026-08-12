from src.parser.log_parser import normalize_raw_record


def test_parse_generator_json_line() -> None:
    line = (
        '{"timestamp": "2026-04-01 09:40:16", "username": "wang.jian", "dept": "运维部", '
        '"role": "ops", "src_ip": "101.89.15.190", "src_country": "中国", "src_city": "上海", '
        '"vpn_gateway": "vpn-gw-bj01", "dst_internal_ip": "10.2.140.10", "event_type": "LOGIN_SUCCESS", '
        '"protocol": "IPSec", "auth_method": "password+OTP", "client_software": "GlobalProtect 6.1", '
        '"session_id": "639174A3-EB41-4B", "result": "SUCCESS", "fail_reason": null, '
        '"session_duration_sec": 4265, "bytes_sent": 6098105, "bytes_recv": 190737046, '
        '"is_off_hours": false, "is_unusual_ip": false, "risk_score": 0, "risk_tags": "正常"}'
    )

    out = normalize_raw_record(line)
    assert out.source_type == "vpn"
    assert out.user_id == "wang.jian"
    assert out.action == "login"
    assert out.result == "success"
    assert out.src_ip == "101.89.15.190"
    assert out.dst_ip == "10.2.140.10"
    assert out.trace_id == "639174A3-EB41-4B"
    assert out.risk_tags == []


def test_preserves_upstream_event_id_and_source_type() -> None:
    line = (
        '{"event_id": "evt-fixed-1", "timestamp": "2026-04-01 09:40:16", '
        '"tenant_id": "default", "source_type": "api", "log_type": "api_access", '
        '"user_id": "svc.report", "src_ip": "10.10.1.8", "action": "api_call", '
        '"resource": "/api/reports/export", "result": "success", "message": "api export"}'
    )

    out = normalize_raw_record(line, source_type_hint="vpn")

    assert out.event_id == "evt-fixed-1"
    assert out.source_type == "api"
    assert out.log_type == "api_access"
    assert out.action == "api_call"


def test_resource_url_template_and_fingerprint_are_added_to_attrs() -> None:
    first = normalize_raw_record(
        {
            "event_id": "evt-url-1",
            "timestamp": "2026-04-01 09:40:16",
            "tenant_id": "default",
            "source_type": "api",
            "log_type": "api_access",
            "user_id": "alice",
            "src_ip": "10.10.1.8",
            "action": "api_call",
            "resource": "/api/users/123/detail?token=secret&page=1",
            "result": "success",
        },
        source_type_hint="api",
    )
    second = normalize_raw_record(
        {
            "event_id": "evt-url-2",
            "timestamp": "2026-04-01 09:40:17",
            "tenant_id": "default",
            "source_type": "api",
            "log_type": "api_access",
            "user_id": "alice",
            "src_ip": "10.10.1.8",
            "action": "api_call",
            "resource": "/api/users/456/detail?page=2&access_token=secret",
            "result": "success",
        },
        source_type_hint="api",
    )

    assert first.resource == "/api/users/123/detail?token=secret&page=1"
    assert first.attrs["url_template"] == "/api/users/{id}/detail?page={value}"
    assert "token" not in first.attrs["url_template"]
    assert first.attrs["resource_normalization_version"] == "resource-normalization-v1"
    assert first.attrs["resource_fingerprint"] == second.attrs["resource_fingerprint"]


def test_parse_syslog_line() -> None:
    line = (
        "2026-04-01 09:40:16 vpn-gw-bj01 vpnd: event=LOGIN_FAIL user=admin dept=IT部 "
        "src_ip=185.220.101.8 src_geo=荷兰/阿姆斯特丹 proto=IPSec auth=password "
        'client="GlobalProtect 6.1" session=ABC-123 result=FAIL reason=密码错误 '
        'risk_score=70 risk_tags="异常IP地址,境外登录(荷兰),登录失败"'
    )

    out = normalize_raw_record(line)
    assert out.user_id == "admin"
    assert out.result == "fail"
    assert out.action == "login"
    assert out.src_ip == "185.220.101.8"
    assert "境外登录(荷兰)" in out.risk_tags
