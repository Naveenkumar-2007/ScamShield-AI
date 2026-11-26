"""Bridge to the companion safety engine with a reliable local fallback."""
import os
import requests

from app.services.safety_analyzer import analyze_payment_safety, analyze_sender_trust, analyze_account_protection


def evaluate(tool: str, payload: dict) -> dict:
    base_url = os.environ.get("SAFETY_ENGINE_URL", "").rstrip("/")
    if base_url:
        try:
            response = requests.post(f"{base_url}/api/safety/{tool}", json=payload, timeout=3)
            response.raise_for_status()
            data = response.json()
            if data.get("success"):
                return data
        except requests.RequestException:
            # The UI must remain usable if the companion service is restarting.
            pass

    if tool == "payment":
        return analyze_payment_safety(payload.get("upi_id", ""), payload.get("phone", ""), payload.get("message", ""))
    if tool == "sender":
        return analyze_sender_trust(payload.get("organization", ""), payload.get("sender", ""), payload.get("website", ""))
    return analyze_account_protection(payload.get("incident_type", "unknown"), payload.get("details", ""))
