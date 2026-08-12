# Engineering quality audit

_Log AI Assistant · 2026-08-12 · Portfolio closeout verification_

---

## 📋 Executive summary

The closeout keeps the deterministic investigation behavior while splitting pure ClickHouse, investigation-support, and React presentation helpers behind characterization tests. The verified local fallback suite has 216 passing tests, Ruff lint and the planned Mypy scope pass, the frontend unit test and production build pass, and `npm audit --omit=dev` reports zero production vulnerabilities. Docker Compose configuration validates, but Docker-backed tests could not run because the Docker Desktop daemon was unavailable. Python dependency audit is advisory because the current pins report 13 known vulnerabilities across 5 packages; this closeout does not bundle dependency upgrades.

| Area | Current state | Priority |
| --- | --- | --- |
| Backend tests | 216 passing locally with `PYTHONPATH=.` | Maintain |
| Frontend test/build | 2 Vitest tests pass; type check and Vite build pass | Maintain |
| Production npm audit | 0 vulnerabilities | Maintain |
| Python dependency audit | 13 known vulnerabilities in 5 pinned packages | Advisory; upgrade separately |
| Python lint | `ruff check src tests log-generator` passes | Maintain |
| Python types | Planned core-module Mypy scope passes | Expand incrementally |
| CI and pre-commit | Tracked incremental required gates | Maintain |
| Ruff formatting | 6 untouched legacy files remain after formatting closeout-touched Python files | Separate mechanical PR |
| Logging | CLI `print` calls and few module loggers | Medium |
| Large modules | Storage 2,423 lines; API 1,745; UI 2,168 after focused extraction | Medium risk |

## 🎯 Completed in this audit

| Item | Change | Verification |
| --- | --- | --- |
| Windows test compatibility | Replaced the unconditional Unix-only `fcntl` import with a standard-library Windows file-lock fallback | New lock regression test passes |
| Deterministic baseline test | Added optional `end_date` injection with the existing UTC-today default unchanged | Formerly date-sensitive baseline test passes |
| Baseline validation | Re-ran the complete local fallback backend suite | `216 passed` |
| Boundary extraction | Moved pure storage, API support, and shared React presentation helpers | Focused Python/API tests and Vitest pass |
| Evidence publication | Refreshed deterministic JSON and Markdown evidence and checked redaction/ID consistency | `5 passed` evidence regressions |

## ⚠️ Prioritized technical-debt register

### High risk

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | Frontend dependency audit | Full `npm audit` reports 0 vulnerabilities after the tracked Vite toolchain update | Keep audit required and review future advisories | Completed |
| SEC-02 | Python dependency pins have published advisories | `python-dotenv 1.0.1`, `kafka-python 2.0.2`, `requests 2.32.3`, `pytest 8.2.2`, and `starlette 0.37.2` produce 13 `pip-audit` findings | Upgrade in a dedicated dependency change with Docker regressions; keep CI audit visible and non-blocking meanwhile | Advisory |
| REL-01 | Required gates need an honest incremental baseline | CI and pre-commit now run reproducible Ruff/Mypy/test/build/audit checks | Expand only after the repository passes the added gate | Completed |
| TYP-01 | Whole-repository type coverage remains incomplete | Planned Mypy scope passes for operations runner and baseline modules | Expand module-by-module | Incremental |

### High return, low behavior risk

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| LINT-01 | Required Ruff lint baseline | `ruff check src tests log-generator` passes | Keep as a required CI/pre-commit gate | Completed |
| FORMAT-01 | Whole-repository formatter baseline is not clean | Locked Ruff 0.15.22 reports 6 remaining untouched legacy files after formatting all closeout-touched Python files | Use one separate formatting-only PR; do not hide files with excludes | Deferred |
| DOC-01 | Contributor quality commands | README lists the verified incremental gates and formatting limitation | Keep current | Completed |
| DOC-02 | Release history | `CHANGELOG.md` is tracked | Keep current | Completed |
| CFG-01 | Quality tool versions | `requirements/dev.txt`, `pyproject.toml`, CI, and pre-commit are tracked | Keep current | Completed |

### Medium risk or larger refactoring scope

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| LOG-01 | Runtime diagnostics are inconsistent | `print` is used by CLI/worker paths; only three modules initialize loggers | Introduce a shared logging configuration, then migrate module-by-module without changing CLI output contracts | Deferred until guardrails exist |
| MOD-01 | ClickHouse storage boundary remains large | Pure filters, pagination, type mapping, and normalization helpers were extracted | Continue only behind characterization tests | Incremental |
| MOD-02 | API route and UI composition boundaries remain large | Investigation support and shared stateless React presentation code were extracted; routes and data fetching stayed in place | Continue feature-by-feature | Incremental |
| TYPE-02 | Domain values use broad `dict[str, Any]` at boundaries | Static scan shows extensive unstructured payload use | Introduce narrow `TypedDict` or Pydantic response types at one boundary per change | Deferred: incremental migration |

## 📍 Remediation order

1. Keep the repaired test baseline green.
2. Remove mechanically dead code and make Ruff clean.
3. Add project-owned lint, formatting, type-check, pre-commit and CI guardrails.
4. Upgrade the vulnerable frontend build chain only after confirming its Node and plugin compatibility.
5. Reduce concrete Mypy errors and improve exception/logging boundaries.
6. Split large modules only when a characterization test protects the extracted behavior.

## 🔗 Verification commands

```powershell
# Preferred Docker-first backend check
docker compose run --rm tester

# Local fallback when Docker Desktop is unavailable
$env:PYTHONPATH = "."; pytest -q

# Required Python quality gates
ruff check src tests log-generator
mypy src/operations/runner.py src/ueba/baseline.py

# Frontend validation
Set-Location frontend
npm ci
npm test -- --run
npm run build
npm audit --omit=dev
```

> **Environment note:** `docker compose config --quiet` passed. `docker compose run --rm tester` was attempted but the `dockerDesktopLinuxEngine` named pipe was missing, so no Docker-backed test result is claimed. The recorded backend result is the explicit local fallback.

> **Formatting baseline:** After formatting every Python file changed by this closeout with locked Ruff 0.15.22, `ruff format --check src tests log-generator` reports exactly 6 remaining untouched legacy files: `src/detection/demo.py`, `src/detection/evidence_demo_brief.py`, `src/detection/interview_demo.py`, `src/detection/investigation.py`, `src/detection/regression.py`, and `tests/test_investigation_pack.py`. The check is intentionally not required yet and no exclude hides this debt. Resolve those files in a separate formatting-only PR, then promote the command to required.

> **Dependency-audit boundary:** `pip-audit -r requirements/backend.txt -r requirements/test.txt` currently exits 1 with 13 findings in 5 pinned packages. CI retains it as a named advisory step with `continue-on-error`; no passing Python dependency-audit claim is made. Dependency upgrades are intentionally left for a dedicated, Docker-verified change.
