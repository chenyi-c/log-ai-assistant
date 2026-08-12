# Log AI Assistant Portfolio Closeout Implementation Plan

> **Execution note:** Execute task-by-task with regression tests before moving code and separate Docker-backed evidence from local fallback evidence.

**Goal:** Integrate the existing engineering-quality checkpoint, reduce three oversized module boundaries, and publish a one-command, redacted investigation demo with structured evidence.

**Architecture:** Preserve the deterministic tool-first investigation pipeline and current FastAPI/ClickHouse/React deployment. Refactoring extracts pure query construction, investigation support, and shared presentation helpers without changing routes or persistence contracts.

**Tech Stack:** Python, FastAPI, ClickHouse, React, TypeScript, Vite, pytest, Ruff, Mypy, Vitest, Docker Compose, GitHub Actions.

---

### Task 1: Integrate the authorized quality checkpoint

**Files:**
- Integrate commit: `39c0c8e`
- Preserve: `scripts/run_interview_investigation_demo.py`
- Preserve: `scripts/run_evidence_demo_brief.py`

**Step 1: Cherry-pick the checkpoint**

Run: `git cherry-pick 39c0c8e`

Expected: the quality governance files and tests are integrated. Resolve overlaps in favor of retaining both the newer demo/evidence behavior and the stricter quality configuration.

**Step 2: Run the focused regression baseline**

Run: `$env:PYTHONPATH='.'; pytest -q`

Expected: all Python tests pass before structural extraction.

**Step 3: Validate configuration**

Run: `docker compose config --quiet`

Expected: exit 0 even if the Docker daemon is unavailable.

### Task 2: Extract pure ClickHouse query helpers

**Files:**
- Create: `src/storage/clickhouse_helpers.py`
- Create: `tests/test_clickhouse_helpers.py`
- Modify: `src/storage/clickhouse_client.py`

**Step 1: Write failing import and behavior tests**

Test representative helpers such as filter composition, pagination normalization, ClickHouse type mapping, and column SQL rendering:

```python
from src.storage.clickhouse_helpers import normalize_limit

def test_normalize_limit_caps_large_values():
    assert normalize_limit(50_000, default=100, maximum=1_000) == 1_000
```

Run: `$env:PYTHONPATH='.'; pytest -q tests/test_clickhouse_helpers.py`

Expected: FAIL because the module does not yet exist.

**Step 2: Move only pure helpers**

Keep connection ownership and query execution in `ClickHouseClient`. Move functions that require no client state and import them back explicitly.

**Step 3: Re-run focused and storage tests**

Run: `$env:PYTHONPATH='.'; pytest -q tests/test_clickhouse_helpers.py tests/test_clickhouse_client.py`

Expected: PASS with unchanged query semantics.

### Task 3: Extract investigation support from the API module

**Files:**
- Create: `src/api/investigation_support.py`
- Create: `tests/test_investigation_support.py`
- Modify: `src/api/app.py`

**Step 1: Write failing pure-function tests**

Cover feedback row construction, evidence-chain assembly, risk-reason derivation, baseline-deviation extraction, and window statistics.

Run: `$env:PYTHONPATH='.'; pytest -q tests/test_investigation_support.py`

Expected: FAIL because the extracted module does not yet exist.

**Step 2: Move cohesive pure/support functions**

Routes remain in `app.py`; the extracted module receives explicit inputs and returns data structures. Do not introduce a service container or speculative class hierarchy.

**Step 3: Re-run API regressions**

Run: `$env:PYTHONPATH='.'; pytest -q tests/test_investigation_support.py tests/test_alert_detail_api.py tests/test_alert_analyze_api.py tests/test_anomaly_investigation_api.py`

Expected: PASS with unchanged response contracts.

### Task 4: Extract shared frontend presentation helpers

**Files:**
- Create: `frontend/src/components/common.tsx`
- Create: `frontend/src/components/common.test.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`

**Step 1: Add a failing rendered-component test**

Use Vitest and `react-dom/server` to cover a stable component such as `StatusPill` and a formatter:

```tsx
expect(renderToStaticMarkup(<StatusPill value="high" />)).toContain("high");
```

Run: `npm test -- --run` from `frontend`.

Expected: FAIL until the shared module and test command exist.

**Step 2: Extract shared components and formatters**

Move only `PaginationControls`, `PageHeader`, `ServiceCard`, `Metric`, `StatusPill`, `ErrorBanner`, `EmptyState`, `TableSkeleton`, and stateless formatters. Keep page composition and data fetching in `App.tsx`.

**Step 3: Re-run tests and build**

Run from `frontend`: `npm test -- --run` then `npm run build`.

Expected: PASS and successful production build.

### Task 5: Generate and document structured demo evidence

**Files:**
- Modify: `docs/12_engineering_quality_audit.md`
- Modify: `README.md`
- Create or refresh: `docs/evidence/interview-investigation-demo.md`
- Create or refresh: `docs/evidence/interview-investigation-demo.json`

**Step 1: Run the one-command deterministic demo**

Run the repository’s interview investigation demo entry point with its redacted fixture mode.

Expected: Markdown and JSON contain the same correlation ID, rule evidence, model/fallback status, and redacted log fields.

**Step 2: Add an evidence consistency test if missing**

Assert JSON/Markdown share the same identifiers and that configured secrets or raw sensitive values do not appear.

Run: `$env:PYTHONPATH='.'; pytest -q tests/test_interview_investigation_demo.py tests/test_evidence_demo_brief.py`

Expected: PASS.

**Step 3: Update quality claims**

Mark only verified gates as complete. Clearly label Docker-backed commands that were not runnable if the daemon remains unavailable.

### Task 6: Full verification and publication readiness

**Files:**
- Verify: all changed files

**Step 1: Run local quality gates**

```powershell
$env:PYTHONPATH='.'
pytest -q
ruff check src tests
mypy src/operations/runner.py src/ueba/baseline.py
Push-Location frontend
npm ci
npm test -- --run
npm run build
Pop-Location
docker compose config --quiet
git diff --check
```

Expected: all available commands exit 0.

**Step 2: Attempt the official Docker test path**

Run: `docker compose run --rm tester`

Expected: PASS when Docker is available; otherwise record the daemon error separately and rely only on the explicitly reported local fallback result.

**Step 3: Commit, push, and draft PR**

Commit the refactor/evidence changes, push `agent/portfolio-closeout-20260812` to the personal remote, and open a draft PR against the personal repository default branch with exact command evidence.
