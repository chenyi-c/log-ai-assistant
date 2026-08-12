"""
VPN Login Log Generator
生成包含 5W1H 要素和行为基线的 VPN 登录日志
5W1H: Who(用户), What(操作), When(时间), Where(位置/IP), Why(结果/原因), How(协议/方式)
"""

import random
import json
import csv
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional
import uuid

# ─────────────────────────────────────────────
# 基础数据定义
# ─────────────────────────────────────────────

USERS = [
    {
        "username": "zhang.wei",
        "dept": "研发部",
        "role": "developer",
        "usual_hours": (9, 18),
        "usual_days": [0, 1, 2, 3, 4],
    },
    {"username": "li.fang", "dept": "财务部", "role": "finance", "usual_hours": (8, 17), "usual_days": [0, 1, 2, 3, 4]},
    {
        "username": "wang.jian",
        "dept": "运维部",
        "role": "ops",
        "usual_hours": (0, 23),
        "usual_days": [0, 1, 2, 3, 4, 5, 6],
    },
    {
        "username": "chen.xiao",
        "dept": "销售部",
        "role": "sales",
        "usual_hours": (8, 20),
        "usual_days": [0, 1, 2, 3, 4, 5],
    },
    {
        "username": "liu.yang",
        "dept": "研发部",
        "role": "developer",
        "usual_hours": (10, 22),
        "usual_days": [0, 1, 2, 3, 4],
    },
    {"username": "zhao.min", "dept": "HR部", "role": "hr", "usual_hours": (9, 18), "usual_days": [0, 1, 2, 3, 4]},
    {
        "username": "sun.lei",
        "dept": "运维部",
        "role": "ops",
        "usual_hours": (0, 23),
        "usual_days": [0, 1, 2, 3, 4, 5, 6],
    },
    {
        "username": "zhou.ting",
        "dept": "市场部",
        "role": "marketing",
        "usual_hours": (9, 19),
        "usual_days": [0, 1, 2, 3, 4, 5],
    },
    {
        "username": "wu.hao",
        "dept": "研发部",
        "role": "developer",
        "usual_hours": (9, 21),
        "usual_days": [0, 1, 2, 3, 4],
    },
    {"username": "admin", "dept": "IT部", "role": "admin", "usual_hours": (8, 20), "usual_days": [0, 1, 2, 3, 4, 5, 6]},
]

# 常用 IP 段（模拟用户常用地点）
USER_USUAL_IPS = {
    "zhang.wei": ["221.130.45.", "114.242.33."],
    "li.fang": ["60.191.22.", "183.60.11."],
    "wang.jian": ["101.89.15.", "117.136.0."],
    "chen.xiao": ["58.247.8.", "180.168.55."],
    "liu.yang": ["221.130.45.", "36.110.22."],
    "zhao.min": ["60.191.22.", "112.80.248."],
    "sun.lei": ["101.89.15.", "117.136.0."],
    "zhou.ting": ["58.247.8.", "180.168.55."],
    "wu.hao": ["221.130.45.", "114.242.33."],
    "admin": ["10.0.0.", "192.168.1."],
}

# 异常 IP 段（境外/陌生地址）
ANOMALY_IPS = [
    "185.220.101.",
    "45.33.32.",
    "198.199.67.",
    "103.21.244.",
    "91.108.4.",
    "77.88.55.",
]

VPN_PROTOCOLS = ["SSL-VPN", "IPSec", "L2TP", "OpenVPN", "WireGuard"]
VPN_GATEWAYS = ["vpn-gw-bj01", "vpn-gw-sh02", "vpn-gw-gz03", "vpn-gw-cd04"]
AUTH_METHODS = ["password", "password+OTP", "certificate", "LDAP"]
CLIENTS = ["Cisco AnyConnect 4.10", "OpenVPN 2.6", "WireGuard 1.0", "FortiClient 7.2", "GlobalProtect 6.1"]
FAIL_REASONS = ["密码错误", "账号锁定", "证书过期", "OTP验证失败", "账号不存在", "IP黑名单拦截"]

# ─────────────────────────────────────────────
# 数据结构
# ─────────────────────────────────────────────


@dataclass
class VPNLogEntry:
    # Stable ID that should survive Filebeat, Kafka, Flink and ClickHouse.
    event_id: str
    # When
    timestamp: str
    # Who
    username: str
    dept: str
    role: str
    # Where (src)
    src_ip: str
    src_country: str
    src_city: str
    # Where (dst)
    vpn_gateway: str
    dst_internal_ip: str
    # What
    event_type: str  # LOGIN_SUCCESS / LOGIN_FAIL / LOGOUT / SESSION_TIMEOUT
    # How
    protocol: str
    auth_method: str
    client_software: str
    session_id: str
    # Why / Result
    result: str
    fail_reason: Optional[str]
    # Behavior baseline fields
    session_duration_sec: Optional[int]
    bytes_sent: Optional[int]
    bytes_recv: Optional[int]
    is_off_hours: bool
    is_unusual_ip: bool
    risk_score: int  # 0-100
    risk_tags: str  # comma-separated anomaly tags


# ─────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────


def random_ip(prefix: str) -> str:
    return prefix + str(random.randint(1, 254))


def ip_to_geo(ip: str):
    """简单映射：根据 IP 前缀返回地理信息"""
    geo_map = {
        "221.130": ("中国", "北京"),
        "114.242": ("中国", "北京"),
        "60.191": ("中国", "杭州"),
        "183.60": ("中国", "广州"),
        "101.89": ("中国", "上海"),
        "117.136": ("中国", "上海"),
        "58.247": ("中国", "上海"),
        "180.168": ("中国", "上海"),
        "36.110": ("中国", "北京"),
        "112.80": ("中国", "南京"),
        "10.0": ("内网", "总部"),
        "192.168": ("内网", "总部"),
        "185.220": ("荷兰", "阿姆斯特丹"),
        "45.33": ("美国", "弗里蒙特"),
        "198.199": ("美国", "纽约"),
        "103.21": ("新加坡", "新加坡"),
        "91.108": ("德国", "法兰克福"),
        "77.88": ("俄罗斯", "莫斯科"),
    }
    prefix = ".".join(ip.split(".")[:2])
    return geo_map.get(prefix, ("未知", "未知"))


def gen_session_id() -> str:
    return str(uuid.uuid4()).upper()[:16]


def gen_event_id(prefix: str = "evt") -> str:
    return f"{prefix}-{uuid.uuid4()}"


def is_off_hours(dt: datetime, user: dict) -> bool:
    h_start, h_end = user["usual_hours"]
    if dt.weekday() not in user["usual_days"]:
        return True
    return not (h_start <= dt.hour < h_end)


def is_unusual_ip(username: str, ip: str) -> bool:
    usual_prefixes = USER_USUAL_IPS.get(username, [])
    return not any(ip.startswith(p) for p in usual_prefixes)


def calc_risk(entry_dict: dict) -> tuple[int, list[str]]:
    """基于行为基线计算风险分和标签"""
    score = 0
    tags = []

    if entry_dict["is_off_hours"]:
        score += 20
        tags.append("非工作时间登录")

    if entry_dict["is_unusual_ip"]:
        score += 25
        tags.append("异常IP地址")

    country = entry_dict["src_country"]
    if country not in ("中国", "内网"):
        score += 30
        tags.append(f"境外登录({country})")

    if entry_dict["event_type"] == "LOGIN_FAIL":
        score += 15
        tags.append("登录失败")

    # 超大流量
    recv = entry_dict.get("bytes_recv") or 0
    if recv > 500 * 1024 * 1024:  # >500MB
        score += 20
        tags.append("大量数据下载")

    # 超短会话后立即重连（此处简化：会话<30s 视为可疑）
    dur = entry_dict.get("session_duration_sec") or 0
    if 0 < dur < 30:
        score += 10
        tags.append("会话时长异常短")

    return min(score, 100), tags


# ─────────────────────────────────────────────
# 核心生成逻辑
# ─────────────────────────────────────────────


def gen_normal_login(user: dict, dt: datetime) -> VPNLogEntry:
    """生成正常登录事件（含 SUCCESS + LOGOUT 对）"""
    usual_prefixes = USER_USUAL_IPS[user["username"]]
    src_ip = random_ip(random.choice(usual_prefixes))
    country, city = ip_to_geo(src_ip)
    protocol = random.choice(VPN_PROTOCOLS[:3])
    auth = random.choice(AUTH_METHODS[:2])
    client = random.choice(CLIENTS)
    gw = random.choice(VPN_GATEWAYS)
    sid = gen_session_id()
    duration = random.randint(600, 28800)  # 10min ~ 8h
    sent = random.randint(1 * 1024 * 1024, 50 * 1024 * 1024)
    recv = random.randint(5 * 1024 * 1024, 200 * 1024 * 1024)
    dst_ip = f"10.{random.randint(1, 5)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    off = is_off_hours(dt, user)
    unu = is_unusual_ip(user["username"], src_ip)

    base = dict(
        event_id=gen_event_id("vpn"),
        timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
        username=user["username"],
        dept=user["dept"],
        role=user["role"],
        src_ip=src_ip,
        src_country=country,
        src_city=city,
        vpn_gateway=gw,
        dst_internal_ip=dst_ip,
        event_type="LOGIN_SUCCESS",
        protocol=protocol,
        auth_method=auth,
        client_software=client,
        session_id=sid,
        result="SUCCESS",
        fail_reason=None,
        session_duration_sec=duration,
        bytes_sent=sent,
        bytes_recv=recv,
        is_off_hours=off,
        is_unusual_ip=unu,
        risk_score=0,
        risk_tags="",
    )
    score, tags = calc_risk(base)
    base["risk_score"] = score
    base["risk_tags"] = ",".join(tags) if tags else "正常"
    return VPNLogEntry(**base)


def gen_failed_login(user: dict, dt: datetime, anomaly_ip=False) -> VPNLogEntry:
    """生成登录失败事件"""
    if anomaly_ip:
        src_ip = random_ip(random.choice(ANOMALY_IPS))
    else:
        usual_prefixes = USER_USUAL_IPS[user["username"]]
        src_ip = random_ip(random.choice(usual_prefixes))

    country, city = ip_to_geo(src_ip)
    protocol = random.choice(VPN_PROTOCOLS)
    auth = random.choice(AUTH_METHODS)
    client = random.choice(CLIENTS)
    gw = random.choice(VPN_GATEWAYS)
    sid = gen_session_id()
    reason = random.choice(FAIL_REASONS)

    off = is_off_hours(dt, user)
    unu = is_unusual_ip(user["username"], src_ip)

    base = dict(
        event_id=gen_event_id("vpn"),
        timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
        username=user["username"],
        dept=user["dept"],
        role=user["role"],
        src_ip=src_ip,
        src_country=country,
        src_city=city,
        vpn_gateway=gw,
        dst_internal_ip="N/A",
        event_type="LOGIN_FAIL",
        protocol=protocol,
        auth_method=auth,
        client_software=client,
        session_id=sid,
        result="FAIL",
        fail_reason=reason,
        session_duration_sec=None,
        bytes_sent=None,
        bytes_recv=None,
        is_off_hours=off,
        is_unusual_ip=unu,
        risk_score=0,
        risk_tags="",
    )
    score, tags = calc_risk(base)
    base["risk_score"] = score
    base["risk_tags"] = ",".join(tags) if tags else "正常"
    return VPNLogEntry(**base)


def gen_anomaly_large_download(user: dict, dt: datetime) -> VPNLogEntry:
    """异常：大量数据下载"""
    usual_prefixes = USER_USUAL_IPS[user["username"]]
    src_ip = random_ip(random.choice(usual_prefixes))
    country, city = ip_to_geo(src_ip)
    gw = random.choice(VPN_GATEWAYS)
    sid = gen_session_id()
    duration = random.randint(3600, 14400)
    sent = random.randint(1 * 1024 * 1024, 10 * 1024 * 1024)
    recv = random.randint(600 * 1024 * 1024, 2 * 1024 * 1024 * 1024)  # 600MB~2GB
    dst_ip = f"10.{random.randint(1, 5)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    off = is_off_hours(dt, user)
    unu = is_unusual_ip(user["username"], src_ip)

    base = dict(
        event_id=gen_event_id("vpn"),
        timestamp=dt.strftime("%Y-%m-%d %H:%M:%S"),
        username=user["username"],
        dept=user["dept"],
        role=user["role"],
        src_ip=src_ip,
        src_country=country,
        src_city=city,
        vpn_gateway=gw,
        dst_internal_ip=dst_ip,
        event_type="LOGIN_SUCCESS",
        protocol=random.choice(VPN_PROTOCOLS[:3]),
        auth_method=random.choice(AUTH_METHODS[:2]),
        client_software=random.choice(CLIENTS),
        session_id=sid,
        result="SUCCESS",
        fail_reason=None,
        session_duration_sec=duration,
        bytes_sent=sent,
        bytes_recv=recv,
        is_off_hours=off,
        is_unusual_ip=unu,
        risk_score=0,
        risk_tags="",
    )
    score, tags = calc_risk(base)
    base["risk_score"] = score
    base["risk_tags"] = ",".join(tags) if tags else "正常"
    return VPNLogEntry(**base)


# ─────────────────────────────────────────────
# 主生成入口
# ─────────────────────────────────────────────


def generate_logs(
    start_date: datetime,
    days: int = 7,
    normal_per_day: int = 40,
    fail_ratio: float = 0.08,
    anomaly_ratio: float = 0.03,
) -> list[VPNLogEntry]:
    logs = []
    end_date = start_date + timedelta(days=days)
    current = start_date

    while current < end_date:
        # 工作日流量更高
        is_weekday = current.weekday() < 5
        day_normal = normal_per_day if is_weekday else int(normal_per_day * 0.3)

        for _ in range(day_normal):
            user = random.choice(USERS)
            # 工作时间内随机时刻（高斯分布模拟上班高峰）
            h_start, h_end = user["usual_hours"]
            hour = int(random.gauss((h_start + h_end) / 2, 2))
            hour = max(h_start, min(h_end - 1, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            dt = current.replace(hour=hour, minute=minute, second=second)
            logs.append(gen_normal_login(user, dt))

        # 登录失败
        fail_count = max(1, int(day_normal * fail_ratio))
        for _ in range(fail_count):
            user = random.choice(USERS)
            hour = random.randint(0, 23)
            dt = current.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
            logs.append(gen_failed_login(user, dt, anomaly_ip=random.random() < 0.4))

        # 异常事件
        anomaly_count = max(0, int(day_normal * anomaly_ratio))
        for _ in range(anomaly_count):
            user = random.choice(USERS)
            # 偏向非工作时间
            hour = random.choice([0, 1, 2, 3, 22, 23])
            dt = current.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
            choice = random.random()
            if choice < 0.5:
                logs.append(gen_failed_login(user, dt, anomaly_ip=True))
            else:
                logs.append(gen_anomaly_large_download(user, dt))

        current += timedelta(days=1)

    # 按时间排序
    logs.sort(key=lambda x: x.timestamp)
    return logs


# ─────────────────────────────────────────────
# 输出函数
# ─────────────────────────────────────────────


def to_csv(logs: list[VPNLogEntry], path: str):
    if not logs:
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=asdict(logs[0]).keys())
        writer.writeheader()
        for log in logs:
            writer.writerow(asdict(log))
    print(f"[CSV] 已写入 {len(logs)} 条 -> {path}")


def to_jsonl(logs: list[VPNLogEntry], path: str):
    with open(path, "w", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(asdict(log), ensure_ascii=False) + "\n")
    print(f"[JSONL] 已写入 {len(logs)} 条 -> {path}")


def to_syslog(logs: list[VPNLogEntry], path: str):
    """模拟 syslog 格式输出"""
    with open(path, "w", encoding="utf-8") as f:
        for log in logs:
            d = asdict(log)
            line = (
                f"{d['timestamp']} {d['vpn_gateway']} vpnd: "
                f"event_id={d['event_id']} event={d['event_type']} user={d['username']} dept={d['dept']} "
                f"src_ip={d['src_ip']} src_geo={d['src_country']}/{d['src_city']} "
                f"proto={d['protocol']} auth={d['auth_method']} "
                f'client="{d["client_software"]}" session={d["session_id"]} '
                f"result={d['result']}"
            )
            if d["fail_reason"]:
                line += f" reason={d['fail_reason']}"
            if d["session_duration_sec"]:
                line += f" duration={d['session_duration_sec']}s"
            if d["bytes_recv"]:
                line += f" bytes_recv={d['bytes_recv']} bytes_sent={d['bytes_sent']}"
            line += f' risk_score={d["risk_score"]} risk_tags="{d["risk_tags"]}"'
            f.write(line + "\n")
    print(f"[Syslog] 已写入 {len(logs)} 条 -> {path}")


def print_stats(logs: list[VPNLogEntry]):
    total = len(logs)
    success = sum(1 for log in logs if log.event_type == "LOGIN_SUCCESS")
    fail = sum(1 for log in logs if log.event_type == "LOGIN_FAIL")
    high_risk = sum(1 for log in logs if log.risk_score >= 50)
    off_hours = sum(1 for log in logs if log.is_off_hours)
    unusual_ip = sum(1 for log in logs if log.is_unusual_ip)

    print("\n========== 日志统计 ==========")
    print(f"总条数       : {total}")
    print(f"登录成功     : {success} ({success / total * 100:.1f}%)")
    print(f"登录失败     : {fail}    ({fail / total * 100:.1f}%)")
    print(f"高风险(≥50) : {high_risk} ({high_risk / total * 100:.1f}%)")
    print(f"非工作时间   : {off_hours} ({off_hours / total * 100:.1f}%)")
    print(f"异常IP       : {unusual_ip} ({unusual_ip / total * 100:.1f}%)")
    print("================================\n")


# ─────────────────────────────────────────────
# 入口
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="VPN 登录日志生成器")
    parser.add_argument("--start", default="2026-04-01", help="起始日期 YYYY-MM-DD")
    parser.add_argument("--days", type=int, default=7, help="生成天数")
    parser.add_argument("--count", type=int, default=50, help="每天正常登录条数")
    parser.add_argument("--outdir", default=".", help="输出目录")
    parser.add_argument("--format", default="all", choices=["csv", "jsonl", "syslog", "all"])
    parser.add_argument("--seed", type=int, default=42, help="随机种子（可复现）")
    args = parser.parse_args()

    random.seed(args.seed)
    start_dt = datetime.strptime(args.start, "%Y-%m-%d")
    os.makedirs(args.outdir, exist_ok=True)

    print(f"生成 {args.days} 天 VPN 日志，起始: {args.start}，每天约 {args.count} 条正常登录...")
    logs = generate_logs(start_dt, days=args.days, normal_per_day=args.count)
    print_stats(logs)

    if args.format in ("csv", "all"):
        to_csv(logs, os.path.join(args.outdir, "vpn_logs.csv"))
    if args.format in ("jsonl", "all"):
        to_jsonl(logs, os.path.join(args.outdir, "vpn_logs.jsonl"))
    if args.format in ("syslog", "all"):
        to_syslog(logs, os.path.join(args.outdir, "vpn_logs.log"))
