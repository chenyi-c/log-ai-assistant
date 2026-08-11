"""Run the privacy-safe interview replay without an external API key."""

from __future__ import annotations

import argparse
import json

from src.detection.interview_demo import (
    render_interview_investigation_demo_markdown,
    run_interview_investigation_demo,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    arguments = parser.parse_args()
    report = run_interview_investigation_demo()
    if arguments.format == "markdown":
        print(render_interview_investigation_demo_markdown(report), end="")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
