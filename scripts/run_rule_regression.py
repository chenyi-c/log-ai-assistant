"""Print the synthetic rule-regression report as JSON."""

from __future__ import annotations

import json

from src.detection.regression import run_rule_regression


if __name__ == "__main__":
    print(json.dumps(run_rule_regression(), ensure_ascii=False, indent=2, default=str))
