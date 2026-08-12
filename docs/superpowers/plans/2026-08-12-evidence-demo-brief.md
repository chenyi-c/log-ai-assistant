# Evidence Demo Brief Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one deterministic, no-key Markdown/JSON briefing command for the existing synthetic anomaly-detection and investigation replay.

**Architecture:** A pure summary module composes the existing synthetic detection evaluation and interview investigation replay. It reports scenario coverage and limitations without calling external services, requiring a real key, or making accuracy claims. A small script prints the Markdown briefing; a FastAPI endpoint exposes the same structured summary for a local demo.

**Tech Stack:** Python, FastAPI, pytest.

---

### Task 1: Build a pure local demo summary

**Files:**
- Create: `src/detection/evidence_demo_brief.py`
- Test: `tests/test_evidence_demo_brief.py`

- [x] **Step 1: Write failing summary tests**

```python
def test_summary_reports_only_synthetic_coverage_and_limitations() -> None:
    report = build_evidence_demo_brief()
    assert report["requires_external_api_key"] is False
    assert report["is_accuracy_metric"] is False
    assert "synthetic" in report["limitations"][0].lower()
```

- [x] **Step 2: Run the test and observe the missing-module failure**

Run: `docker compose run --rm tester pytest -q tests/test_evidence_demo_brief.py`

- [x] **Step 3: Implement the minimal composition and Markdown renderer**

The implementation invokes only existing local replay functions, includes selected scenario counts, rule-hit coverage, normal-control counts, and limitations, and omits raw log bodies.

- [x] **Step 4: Re-run the focused test**

Run: `docker compose run --rm tester pytest -q tests/test_evidence_demo_brief.py`

### Task 2: Add explicit local CLI/API access

**Files:**
- Create: `scripts/run_evidence_demo_brief.py`
- Modify: `src/api/app.py`
- Modify: `README.md`
- Modify: `tests/test_evidence_demo_brief.py`

- [x] **Step 1: Add a failing FastAPI endpoint test**

```python
def test_demo_brief_api_returns_no_key_summary(client: TestClient) -> None:
    response = client.get("/api/v1/demo/evidence-brief")
    assert response.status_code == 200
    assert response.json()["requires_external_api_key"] is False
```

- [x] **Step 2: Run the test and observe the missing-route failure**

Run: `docker compose run --rm tester pytest -q tests/test_evidence_demo_brief.py`

- [x] **Step 3: Implement the endpoint and CLI script**

Both use the same pure summary module. README documents the command and explicitly states that output is a synthetic replay demonstration, not a real production-data or accuracy claim.

- [x] **Step 4: Run full local pytest fallback and commit locally**

Docker Desktop was not running on this Windows machine (`dockerDesktopLinuxEngine` pipe unavailable), so `docker compose run --rm tester` could not execute. The existing local virtual environment was used for the full 201-test fallback after the Windows lock/import repair.

Run: `docker compose run --rm tester`

Commit: `feat: add local evidence demo brief`
