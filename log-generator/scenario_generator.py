from __future__ import annotations

import json
import random
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


SOURCE_FILES = {
    "vpn": "vpn.log",
    "oa": "oa.log",
    "api": "api.log",
    "system": "system.log",
    "file": "file.log",
    "database": "database.log",
    "security_device": "security_device.log",
}

EXTERNAL_IP_PREFIXES = ("185.220.101.", "45.33.32.", "198.199.67.", "103.21.244.")
INTERNAL_IP_PREFIXES = ("10.12.1.", "10.12.2.", "10.12.3.", "10.21.8.")

DEFAULT_USERS = [
    {
        "user_id": "zhang.wei",
        "department": "研发部",
        "user_role": "developer",
        "account_type": "employee",
        "usual_src_ips": ["221.130.45.21", "114.242.33.18"],
        "usual_hosts": ["dev-laptop-01"],
    },
    {
        "user_id": "li.fang",
        "department": "财务部",
        "user_role": "finance",
        "account_type": "employee",
        "usual_src_ips": ["60.191.22.19", "183.60.11.44"],
        "usual_hosts": ["fin-laptop-03"],
    },
    {
        "user_id": "wang.jian",
        "department": "运维部",
        "user_role": "ops",
        "account_type": "employee",
        "usual_src_ips": ["101.89.15.90", "117.136.0.88"],
        "usual_hosts": ["ops-admin-01"],
    },
    {
        "user_id": "svc.report",
        "department": "平台部",
        "user_role": "service",
        "account_type": "service",
        "usual_src_ips": ["10.12.1.10"],
        "usual_hosts": ["batch-runner-01"],
    },
    {
        "user_id": "admin",
        "department": "IT部",
        "user_role": "admin",
        "account_type": "admin",
        "usual_src_ips": ["10.0.0.12"],
        "usual_hosts": ["admin-console-01"],
    },
]


@dataclass(frozen=True)
class GeneratedRecord:
    record: dict[str, Any]
    raw_line: str
    output_file: str


def load_config(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = Path(__file__).resolve().parent / "scenarios" / "default.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


class ScenarioGenerator:
    def __init__(self, config: dict[str, Any] | None = None, *, seed: int | None = None) -> None:
        self.config = config or {}
        self.random = random.Random(seed)
        self.tenant_id = str(self.config.get("tenant_id") or "default")
        self.users = list(self.config.get("users") or DEFAULT_USERS)
        self.normal_workload = dict(self.config.get("normal_workload") or {})
        self.source_mix = dict(self.normal_workload.get("source_mix") or {"vpn": 1.0})
        self.anomaly_patterns = [
            pattern for pattern in self.config.get("anomaly_patterns", []) if pattern.get("enabled", True)
        ]
        self.stream = dict(self.config.get("stream") or {})

    def generate_window(
        self,
        *,
        start_time: datetime,
        duration_minutes: int,
        rate_per_minute: int,
    ) -> list[GeneratedRecord]:
        records: list[GeneratedRecord] = []
        total = max(0, int(duration_minutes) * int(rate_per_minute))
        for index in range(total):
            offset_seconds = int((index / max(1, rate_per_minute)) * 60)
            records.append(self._normal_record(start_time + timedelta(seconds=offset_seconds)))

        for pattern in self.anomaly_patterns:
            chains = int(pattern.get("chains_per_window") or 0)
            for _ in range(max(0, chains)):
                max_offset = max(0, duration_minutes * 60 - 60)
                chain_start = start_time + timedelta(seconds=self.random.randint(0, max_offset))
                records.extend(self._attack_chain(pattern, chain_start))

        return sorted(records, key=lambda item: str(item.record.get("timestamp") or ""))

    def generate_batch(self, *, now: datetime, batch_size: int) -> list[GeneratedRecord]:
        records = [self._normal_record(now + timedelta(seconds=i)) for i in range(max(0, batch_size))]
        probability = float(self.stream.get("anomaly_chain_probability") or 0)
        if self.anomaly_patterns and self.random.random() < probability:
            pattern = self.random.choice(self.anomaly_patterns)
            records.extend(self._attack_chain(pattern, now + timedelta(seconds=batch_size + 1)))
        return records

    def _normal_record(self, timestamp: datetime) -> GeneratedRecord:
        source_type = self._weighted_source()
        user = self.random.choice(self.users)
        return self._wrap_record(
            self._base_record(
                source_type=source_type,
                timestamp=timestamp,
                user=user,
                src_ip=self.random.choice(user.get("usual_src_ips") or ["10.0.0.10"]),
                host=self.random.choice(user.get("usual_hosts") or ["workstation-01"]),
                injected_label="normal",
            )
        )

    def _attack_chain(self, pattern: dict[str, Any], start_time: datetime) -> list[GeneratedRecord]:
        chain_id = f"chain-{uuid.uuid4()}"
        scenario_id = f"{pattern.get('name') or pattern.get('type')}-{uuid.uuid4().hex[:8]}"
        scenario_type = str(pattern.get("type") or pattern.get("name") or "unknown")
        target_users = self._select_users(pattern)
        attacker_ip = self._random_ip(EXTERNAL_IP_PREFIXES)
        source_ip = attacker_ip
        records: list[GeneratedRecord] = []
        step_index = 1

        for step in pattern.get("steps", []):
            repeat = max(1, int(step.get("repeat") or 1))
            for repeat_index in range(repeat):
                user = self._step_user(step, target_users, repeat_index)
                if step.get("src_ip_mode") == "usual":
                    source_ip = self.random.choice(user.get("usual_src_ips") or ["10.0.0.10"])
                elif step.get("src_ip_mode") == "internal":
                    source_ip = self._random_ip(INTERNAL_IP_PREFIXES)
                elif step.get("src_ip_mode") in {"attacker", "unusual", "same_as_chain"}:
                    source_ip = attacker_ip

                timestamp = start_time + timedelta(
                    seconds=int(step.get("offset_seconds") or 0) + repeat_index * int(step.get("spacing_seconds") or 5)
                )
                record = self._base_record(
                    source_type=str(step.get("source_type") or "vpn"),
                    timestamp=timestamp,
                    user=user,
                    src_ip=source_ip,
                    host=str(step.get("host") or self.random.choice(user.get("usual_hosts") or ["workstation-01"])),
                    injected_label=str(step.get("injected_label") or scenario_type),
                )
                record.update(
                    {
                        "scenario_id": scenario_id,
                        "scenario_type": scenario_type,
                        "attack_chain_id": chain_id,
                        "step_index": step_index,
                    }
                )
                for key, value in step.items():
                    if key in {
                        "repeat",
                        "spacing_seconds",
                        "offset_seconds",
                        "source_type",
                        "src_ip_mode",
                        "user_mode",
                        "target_account_type",
                        "injected_label",
                    }:
                        continue
                    record[key] = value
                records.append(self._wrap_record(record))
                step_index += 1

        return records

    def _base_record(
        self,
        *,
        source_type: str,
        timestamp: datetime,
        user: dict[str, Any],
        src_ip: str,
        host: str,
        injected_label: str,
    ) -> dict[str, Any]:
        template = _normal_template(source_type, self.random)
        record = {
            "event_id": f"evt-{uuid.uuid4()}",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "tenant_id": self.tenant_id,
            "source_type": source_type,
            "log_type": template["log_type"],
            "user_id": user.get("user_id"),
            "account_type": user.get("account_type") or "unknown",
            "department": user.get("department") or "",
            "user_role": user.get("user_role") or "",
            "host": host,
            "src_ip": src_ip,
            "dst_ip": template.get("dst_ip") or self._random_ip(INTERNAL_IP_PREFIXES),
            "action": template["action"],
            "object_type": template.get("object_type") or "",
            "object_id": template.get("object_id") or "",
            "resource": template["resource"],
            "result": template["result"],
            "severity": template["severity"],
            "protocol": template.get("protocol") or "",
            "auth_method": template.get("auth_method") or "",
            "user_agent": template.get("user_agent") or "",
            "session_id": f"sess-{uuid.uuid4().hex[:16]}",
            "message": template["message"],
            "risk_tags": template.get("risk_tags") or [],
            "scenario_id": "",
            "scenario_type": "",
            "attack_chain_id": "",
            "step_index": None,
            "injected_label": injected_label,
        }
        return record

    def _wrap_record(self, record: dict[str, Any]) -> GeneratedRecord:
        source_type = str(record.get("source_type") or "vpn")
        raw_line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        return GeneratedRecord(
            record=record,
            raw_line=raw_line,
            output_file=SOURCE_FILES.get(source_type, f"{source_type}.log"),
        )

    def _weighted_source(self) -> str:
        items = [(source, float(weight)) for source, weight in self.source_mix.items() if float(weight) > 0]
        if not items:
            return "vpn"
        total = sum(weight for _, weight in items)
        roll = self.random.random() * total
        upto = 0.0
        for source, weight in items:
            upto += weight
            if roll <= upto:
                return source
        return items[-1][0]

    def _select_users(self, pattern: dict[str, Any]) -> list[dict[str, Any]]:
        account_type = pattern.get("target_account_type")
        candidates = [user for user in self.users if not account_type or user.get("account_type") == account_type]
        if not candidates:
            candidates = self.users
        count = max(1, int(pattern.get("target_user_count") or 1))
        if count >= len(candidates):
            return list(candidates)
        return self.random.sample(candidates, count)

    def _step_user(self, step: dict[str, Any], users: list[dict[str, Any]], repeat_index: int) -> dict[str, Any]:
        if step.get("user_mode") == "rotate":
            return users[repeat_index % len(users)]
        if step.get("target_account_type"):
            matching = [user for user in self.users if user.get("account_type") == step.get("target_account_type")]
            if matching:
                return self.random.choice(matching)
        return users[0]

    def _random_ip(self, prefixes: tuple[str, ...]) -> str:
        return self.random.choice(prefixes) + str(self.random.randint(1, 254))


def write_records(
    records: list[GeneratedRecord], output_dir: Path, manifest_path: Path | None = None
) -> dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = defaultdict(int)
    manifest_rows: list[str] = []

    handles: dict[str, Any] = {}
    try:
        for item in records:
            path = output_dir / item.output_file
            handle = handles.get(item.output_file)
            if handle is None:
                handle = path.open("a", encoding="utf-8")
                handles[item.output_file] = handle
            handle.write(item.raw_line + "\n")
            counts[str(item.record.get("source_type") or "unknown")] += 1

            if manifest_path:
                manifest_rows.append(
                    json.dumps(
                        _manifest_row(item, path),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
    finally:
        for handle in handles.values():
            handle.close()

    if manifest_path and manifest_rows:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("a", encoding="utf-8") as f:
            for row in manifest_rows:
                f.write(row + "\n")

    return dict(counts)


def _manifest_row(item: GeneratedRecord, raw_path: Path) -> dict[str, Any]:
    record = item.record
    return {
        "event_id": record.get("event_id"),
        "timestamp": record.get("timestamp"),
        "tenant_id": record.get("tenant_id") or "default",
        "source_type": record.get("source_type"),
        "raw_file": str(raw_path),
        "raw_size_bytes": len((item.raw_line + "\n").encode("utf-8")),
        "scenario_id": record.get("scenario_id") or "",
        "scenario_type": record.get("scenario_type") or "",
        "attack_chain_id": record.get("attack_chain_id") or "",
        "step_index": record.get("step_index"),
        "injected_label": record.get("injected_label") or "",
    }


def _normal_template(source_type: str, rng: random.Random) -> dict[str, Any]:
    templates = {
        "vpn": {
            "log_type": "vpn_login",
            "action": "login",
            "result": "success",
            "resource": "vpn-gw-bj01",
            "severity": 1,
            "protocol": rng.choice(["SSL-VPN", "IPSec", "WireGuard"]),
            "auth_method": rng.choice(["password+OTP", "certificate"]),
            "user_agent": rng.choice(["GlobalProtect 6.1", "FortiClient 7.2"]),
            "message": "VPN login success",
        },
        "oa": {
            "log_type": "oa_access",
            "action": "access",
            "result": "success",
            "resource": rng.choice(["/oa/home", "/oa/approval/list", "/oa/wiki"]),
            "severity": 1,
            "protocol": "https",
            "user_agent": "Chrome",
            "message": "OA page access",
        },
        "api": {
            "log_type": "api_access",
            "action": "api_call",
            "result": "success",
            "resource": rng.choice(["/api/orders/list", "/api/profile/me", "/api/report/summary"]),
            "severity": 1,
            "protocol": "https",
            "user_agent": "internal-sdk",
            "message": "API request success",
        },
        "system": {
            "log_type": "system_login",
            "action": "ssh_login",
            "result": "success",
            "resource": rng.choice(["host:app-01", "host:db-01", "host:ops-01"]),
            "severity": 2,
            "protocol": "ssh",
            "message": "SSH login success",
        },
        "file": {
            "log_type": "file_access",
            "action": "file_read",
            "result": "success",
            "resource": rng.choice(["/share/docs/policy.pdf", "/share/project/readme.md"]),
            "object_type": "file",
            "severity": 1,
            "protocol": "smb",
            "message": "File read success",
        },
        "database": {
            "log_type": "database_query",
            "action": "query",
            "result": "success",
            "resource": rng.choice(["db://erp/customer", "db://finance/report"]),
            "object_type": "database",
            "severity": 1,
            "protocol": "mysql",
            "message": "Database query success",
        },
        "security_device": {
            "log_type": "firewall_event",
            "action": "block",
            "result": "denied",
            "resource": "firewall:wan",
            "severity": 3,
            "protocol": "tcp",
            "message": "Firewall denied suspicious connection",
        },
    }
    return dict(templates.get(source_type, templates["vpn"]))


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Generate multi-source scenario logs and manifest.")
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent / "scenarios" / "default.json"))
    parser.add_argument("--outdir", default="logs")
    parser.add_argument("--manifest", default="logs/manifest.jsonl")
    parser.add_argument("--start", default=None, help="Start time, e.g. 2026-05-31T10:00:00")
    parser.add_argument("--duration-minutes", type=int, default=10)
    parser.add_argument("--rate-per-minute", type=int, default=60)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    start_time = datetime.fromisoformat(args.start) if args.start else datetime.now()
    generator = ScenarioGenerator(load_config(Path(args.config)), seed=args.seed)
    records = generator.generate_window(
        start_time=start_time,
        duration_minutes=args.duration_minutes,
        rate_per_minute=args.rate_per_minute,
    )
    counts = write_records(records, Path(args.outdir), Path(args.manifest))
    print(json.dumps({"generated_count": len(records), "by_source": counts}, ensure_ascii=False))


if __name__ == "__main__":
    main()
