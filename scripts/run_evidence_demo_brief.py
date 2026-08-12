"""Print the local synthetic anomaly evidence briefing as Markdown."""

from __future__ import annotations

from src.detection.evidence_demo_brief import (
    build_evidence_demo_brief,
    render_evidence_demo_brief_markdown,
)


if __name__ == "__main__":
    print(render_evidence_demo_brief_markdown(build_evidence_demo_brief()), end="")
