"""Print the unified synthetic anomaly replay evaluation as JSON."""

from __future__ import annotations

import json

from src.detection.evaluation import run_detection_evaluation


if __name__ == "__main__":
    print(json.dumps(run_detection_evaluation(), ensure_ascii=False, indent=2, default=str))
