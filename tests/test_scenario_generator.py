from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


GENERATOR_DIR = Path(__file__).resolve().parents[1] / "log-generator"
if str(GENERATOR_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATOR_DIR))

from scenario_generator import ScenarioGenerator, write_records  # noqa: E402


def test_configurable_generator_outputs_multi_source_attack_chain() -> None:
    config = {
        "tenant_id": "default",
        "normal_workload": {"source_mix": {"vpn": 1.0}},
        "anomaly_patterns": [
            {
                "name": "takeover",
                "type": "account_takeover",
                "chains_per_window": 1,
                "target_user_count": 1,
                "steps": [
                    {
                        "source_type": "vpn",
                        "src_ip_mode": "attacker",
                        "action": "login",
                        "result": "success",
                        "resource": "vpn-gw-bj01",
                        "injected_label": "attack_account_takeover",
                    },
                    {
                        "source_type": "api",
                        "offset_seconds": 30,
                        "src_ip_mode": "same_as_chain",
                        "action": "api_call",
                        "result": "success",
                        "resource": "/api/admin/export",
                        "injected_label": "attack_account_takeover",
                    },
                ],
            }
        ],
    }

    generator = ScenarioGenerator(config, seed=7)
    records = generator.generate_window(
        start_time=datetime(2026, 5, 31, 10, 0, 0),
        duration_minutes=1,
        rate_per_minute=2,
    )

    attack_records = [item.record for item in records if item.record["attack_chain_id"]]
    assert len(attack_records) == 2
    assert {item["source_type"] for item in attack_records} == {"vpn", "api"}
    assert len({item["attack_chain_id"] for item in attack_records}) == 1
    assert [item["step_index"] for item in attack_records] == [1, 2]
    assert all(item.record["event_id"].startswith("evt-") for item in records)


def test_write_records_splits_by_source_and_writes_manifest(tmp_path: Path) -> None:
    generator = ScenarioGenerator({"normal_workload": {"source_mix": {"api": 1.0}}}, seed=9)
    records = generator.generate_batch(now=datetime(2026, 5, 31, 10, 0, 0), batch_size=3)
    manifest = tmp_path / "manifest.jsonl"

    counts = write_records(records, tmp_path, manifest)

    assert counts == {"api": 3}
    assert (tmp_path / "api.log").exists()
    raw_lines = (tmp_path / "api.log").read_text(encoding="utf-8").splitlines()
    manifest_rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
    assert len(raw_lines) == 3
    assert [json.loads(line)["event_id"] for line in raw_lines] == [row["event_id"] for row in manifest_rows]
    assert all(row["raw_size_bytes"] > 0 for row in manifest_rows)
