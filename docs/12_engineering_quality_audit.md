# Engineering quality audit

_Log AI Assistant · 2026-08-11 · Baseline for technical-debt remediation_

---

## 📋 Executive summary

The functional baseline is healthy after two targeted fixes: the backend suite has 169 passing tests and the frontend production build passes. The repository has no production frontend dependency vulnerabilities, but its development dependency tree has five known vulnerabilities, including three high-severity findings. The main quality gaps are missing automated guardrails, incomplete type checking, inconsistent runtime diagnostics, and a small number of oversized boundary modules.

| Area | Current state | Priority |
| --- | --- | --- |
| Backend tests | 169 passing locally | Maintain |
| Frontend build | Type check and Vite build pass | Maintain |
| Production npm audit | 0 vulnerabilities | Maintain |
| Development npm audit | 5 vulnerabilities, 3 high | High risk |
| Python lint | 51 Ruff findings | High return |
| Python types | 30+ Mypy findings | High return |
| CI and pre-commit | Not configured | High return |
| Logging | CLI `print` calls and few module loggers | Medium |
| Large modules | Storage 2,549 lines; API 1,977; UI 2,462 | Medium risk |

## 🎯 Completed in this audit

| Item | Change | Verification |
| --- | --- | --- |
| Windows test compatibility | Replaced the unconditional Unix-only `fcntl` import with a standard-library Windows file-lock fallback | New lock regression test passes |
| Deterministic baseline test | Added optional `end_date` injection with the existing UTC-today default unchanged | Formerly date-sensitive baseline test passes |
| Baseline validation | Re-ran the complete backend suite | `169 passed` |

## ⚠️ Prioritized technical-debt register

### High risk

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | Frontend development dependency vulnerabilities | `npm audit`: Vite 5 chain exposes Babel, esbuild, nanoid and PostCSS advisories | Upgrade Vite and compatible React plugin/Node base; run lint, type-check and build | Planned |
| REL-01 | No CI or local commit gate | No `.github/workflows` or `.pre-commit-config.yaml` | Add reproducible Python and frontend checks plus dependency audit | Planned |
| TYP-01 | Type checker has unresolved errors and unstable local incremental cache | Mypy finds 30+ errors and crashes writing cache under the local Python 3.13 environment | Pin CI to Python 3.11, run Mypy without incremental cache locally, repair concrete annotations | Planned |

### High return, low behavior risk

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| LINT-01 | Unused imports and local variables | 11 Ruff findings are auto-fixable | Apply safe fixes, then address the remaining import-layout findings deliberately | Planned |
| LINT-02 | No committed formatter/linter configuration | No `pyproject.toml`, ESLint or Prettier configuration | Add Ruff, Mypy, ESLint and Prettier configuration with explicit scripts | Planned |
| DOC-01 | README lacks contributor quality commands and security policy | README documents runtime but not local quality workflow | Document exact validation commands and supported toolchain | Planned |
| DOC-02 | No release history | No `CHANGELOG.md` | Add Keep-a-Changelog compatible starting history | Planned |
| CFG-01 | Quality tool versions are not project-pinned | Only runtime/test requirements are committed | Add dev-quality dependency definitions used by CI and pre-commit | Planned |

### Medium risk or larger refactoring scope

| ID | Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- | --- |
| LOG-01 | Runtime diagnostics are inconsistent | `print` is used by CLI/worker paths; only three modules initialize loggers | Introduce a shared logging configuration, then migrate module-by-module without changing CLI output contracts | Deferred until guardrails exist |
| MOD-01 | ClickHouse storage boundary is oversized | `src/storage/clickhouse_client.py` has 2,549 lines | Split query, serialization and schema responsibilities behind tested public methods | Deferred: behavior-sensitive |
| MOD-02 | API route and UI composition modules are oversized | `src/api/app.py` has 1,977 lines; `frontend/src/App.tsx` has 2,462 lines | Extract cohesive route/UI feature groups only after characterization tests | Deferred: behavior-sensitive |
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

# Frontend validation
Set-Location frontend
npm ci
npm run build
npm audit --omit=dev
```

> 📌 **Environment note:** Docker Compose is installed on the audit workstation, but its Docker Desktop daemon was not running. Local Python fallback was therefore used for the recorded backend result.
