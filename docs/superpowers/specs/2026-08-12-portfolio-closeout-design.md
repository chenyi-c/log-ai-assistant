# Log AI Assistant Portfolio Closeout Design

## Goal

Combine the existing replayable investigation demo with the current engineering-quality checkpoint, then reduce three oversized boundaries without changing public API behavior.

## Scope

- Integrate checkpoint commit `39c0c8e` into the evidence-demo branch.
- Preserve the deterministic investigation demo, redaction rules, stable identifiers, and stored evidence chain.
- Extract pure ClickHouse helpers, FastAPI investigation-support helpers, and shared React presentation components into focused modules.
- Make CI, Ruff, Mypy, pre-commit, frontend build, and dependency audit configuration tracked and internally consistent.
- Commit generated Markdown and JSON examples from the one-command investigation demo.

## Non-goals

- No replacement of ClickHouse, Kafka, Flink, or the Docker-first architecture.
- No broad repository rewrite and no new detection algorithms.
- No claim that local fallback tests prove the full streaming stack.

## Verification

Run the deterministic demo and compare its redacted output with the committed examples. Run Docker-first backend tests when Docker is available; otherwise report the local fallback separately. Ruff, Ruff format, Mypy, frontend build, Compose validation, and `git diff --check` must pass before publication.

## Publication

Push `agent/portfolio-closeout-20260812` to `chenyi-c/log-ai-assistant` and open a draft pull request against the personal repository default branch. Do not target the upstream team repository.
