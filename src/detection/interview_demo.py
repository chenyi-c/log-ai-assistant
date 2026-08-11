"""No-key replay that joins the synthetic detector output to the FastAPI review API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.detection.investigation import run_investigation_pack


_SELECTED_SCENARIOS = {
    "failed-login-user-spike",
    "credential-stuffing",
    "high-api-rate",
    "normal-known-source-login",
    "normal-low-rate-api",
}


class _DemoStorage:
    """Expose one synthetic anomaly through the same storage contract as the API."""

    def __init__(self, anomaly: dict[str, Any]) -> None:
        self._anomaly = anomaly

    def get_anomaly(self, event_id: str) -> dict[str, Any] | None:
        return self._anomaly if event_id == self._anomaly["event_id"] else None


def run_interview_investigation_demo() -> dict[str, Any]:
    """Replay selected synthetic cases and exercise the real investigation/review routes."""
    report = run_investigation_pack()
    cases = []
    for case in report["cases"]:
        if case["scenarioName"] not in _SELECTED_SCENARIOS:
            continue
        investigation = case["investigation"]
        item: dict[str, Any] = {
            "scenarioName": case["scenarioName"],
            "inputEventCount": case["inputEventCount"],
            "deduplicated": case["deduplicated"],
            "normalControl": investigation is None,
            "anomalyId": investigation["anomalyId"] if investigation else None,
            "reasonCodes": investigation["reasonCodes"] if investigation else [],
            "sanitizedEvidence": investigation["sanitizedEvidence"] if investigation else {},
            "attackTechniques": investigation["attackTechniques"] if investigation else [],
            "apiReplay": _replay_api(investigation) if investigation and case["scenarioName"] == "failed-login-user-spike" else None,
        }
        cases.append(item)
    return {
        "version": "v1",
        "requiresExternalApiKey": False,
        "summary": {"selectedCaseCount": len(cases), "apiReviewReplayCount": 1},
        "cases": cases,
    }


def render_interview_investigation_demo_markdown(report: dict[str, Any]) -> str:
    """Render a compact terminal artifact without synthetic raw event bodies."""
    lines = ["# Investigation Interview Demo", "", "Fixed synthetic replay; not a SOC/SIEM or accuracy claim.", ""]
    for case in report["cases"]:
        lines.extend([
            f"## {case['scenarioName']}",
            f"- Input events: {case['inputEventCount']}",
            f"- Deduplicated replay: {case['deduplicated']}",
        ])
        if case["normalControl"]:
            lines.append("- Result: normal control; no anomaly emitted.")
        else:
            techniques = ", ".join(item["techniqueId"] for item in case["attackTechniques"]) or "No ATT&CK mapping asserted"
            lines.extend([
                f"- Anomaly ID: {case['anomalyId']}",
                f"- Rule hits: {', '.join(case['reasonCodes'])}",
                f"- ATT&CK references: {techniques}",
                f"- Sanitized evidence: {case['sanitizedEvidence']}",
            ])
        if case["apiReplay"]:
            lines.append(
                "- API review replay: "
                f"{case['apiReplay']['beforeReviewStatus']} -> {case['apiReplay']['afterReviewStatus']}"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _replay_api(investigation: dict[str, Any]) -> dict[str, Any]:
    """Use FastAPI's real route handlers with an isolated, synthetic storage dependency."""
    from fastapi.testclient import TestClient

    from src.api.app import app, get_anomaly_review_store, get_storage
    from src.detection.review import AnomalyReviewStore

    anomaly_id = investigation["anomalyId"]
    storage = _DemoStorage(
        {
            "event_id": anomaly_id,
            "risk_level": investigation["riskLevel"],
            "reason_codes": investigation["reasonCodes"],
            "evidence": investigation["sanitizedEvidence"],
            "related_event_ids": investigation["whyMatched"]["relatedEventIds"],
        }
    )
    reviews = AnomalyReviewStore(clock=lambda: datetime(2026, 8, 11, tzinfo=timezone.utc))
    app.dependency_overrides[get_storage] = lambda: storage
    app.dependency_overrides[get_anomaly_review_store] = lambda: reviews
    try:
        with TestClient(app) as client:
            before = client.get(f"/api/v1/anomalies/{anomaly_id}/investigation")
            update = client.post(
                f"/api/v1/anomalies/{anomaly_id}/review",
                json={"status": "confirmed", "reviewer_note": "Synthetic interview replay."},
            )
            after = client.get(f"/api/v1/anomalies/{anomaly_id}/investigation")
    finally:
        app.dependency_overrides.pop(get_storage, None)
        app.dependency_overrides.pop(get_anomaly_review_store, None)
    if before.status_code != 200 or update.status_code != 200 or after.status_code != 200:
        raise RuntimeError("synthetic investigation API replay did not complete")
    return {
        "beforeReviewStatus": before.json()["reviewStatus"],
        "afterReviewStatus": after.json()["reviewStatus"],
        "investigation": after.json(),
    }
