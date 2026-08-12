"""Print the synthetic Investigation Pack as JSON or compact Markdown."""

from __future__ import annotations

import argparse
import json

from src.detection.investigation import render_investigation_pack_markdown, run_investigation_pack


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    arguments = parser.parse_args()
    report = run_investigation_pack()
    print(render_investigation_pack_markdown(report) if arguments.format == "markdown" else json.dumps(report, ensure_ascii=False, indent=2))
