"""Print the synthetic anomaly-detection acceptance report as JSON."""

from __future__ import annotations

import json

from src.detection.demo import run_demo


if __name__ == "__main__":
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2, default=str))
