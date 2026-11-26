"""Safety tools shared by the Flask UI and the optional Java safety service.

The local implementation keeps the Scanner usable when the companion safety
service is not running.  In deployment, Flask may delegate the same request to
the Java service through SAFETY_ENGINE_URL.
"""
import re
from typing import Any, Dict, List

from app.services.risk_engine import compute_composite_risk


def _evidence(kind: str, description: str, severity: str) -> Dict[str, str]:
    return {"evidence_type": kind, "evidence_description": description, "severity": severity}


def _result(input_type: str, category: str, preview: str, evidence: List[Dict[str, str]], recommendations: List[str]) -> Dict[str, Any]:
    likelihood = min(0.95, 0.10 + len(evidence) * 0.18)
    result = compute_composite_risk(likelihood, evidence, input_type, category)
    result.update({
        "success": True,
        "input_preview": preview[:500],
        "evidence": evidence,
        "recommendations": recommendations,
        "explanation": (
            f"This {input_type.replace('_', ' ')} assessment is {result['risk_level'].lower()} "
            f"({result['risk_score']}/100). "
            + ("The detected signals need careful verification before you act." if evidence else "No major fraud signals were found in the supplied details.")
        ),
    })
    return result


def analyze_payment_safety(upi_id: str, phone: str, message: str) -> Dict[str, Any]:
    combined = f"{upi_id} {phone} {message}".strip()
    evidence: List[Dict[str, str]] = []
    if upi_id and not re.fullmatch(r"[a-zA-Z0-9._-]{2,256}@[a-zA-Z][a-zA-Z0-9._-]{1,63}", upi_id):
        evidence.append(_evidence("upi_format", "The UPI ID format appears invalid or incomplete.", "medium"))
    if phone and not re.fullmatch(r"(?:\+91[\s-]?)?[6-9]\d{9}", re.sub(r"[\s-]", "", phone)):
        evidence.append(_evidence("phone_format", "The supplied mobile number is not a standard Indian mobile number.", "low"))

    lowered = message.lower()
    if any(term in lowered for term in ("upi pin", "share otp", "enter otp", "cvv", "card pin")):
        evidence.append(_evidence("credential_request", "The message asks for a PIN, OTP, CVV, or other payment credential.", "critical"))
    if any(term in lowered for term in ("cashback", "reward", "scratch card", "prize", "won ", "lottery")):
        evidence.append(_evidence("reward_bait", "A reward or cashback offer is being used to encourage a payment action.", "high"))
    if any(term in lowered for term in ("immediately", "urgent", "within 24", "today", "account blocked")):
        evidence.append(_evidence("payment_urgency", "The message applies time pressure to make you act quickly.", "medium"))
    if any(term in lowered for term in ("collect request", "scan qr", "approve payment")):
        evidence.append(_evidence("payment_trick", "The message may be trying to make you approve a payment instead of receiving one.", "high"))

    return _result(
        "payment_safety", "Payment and UPI fraud" if evidence else "Payment details appear safe",
        combined,
        evidence,
        ["Never share an OTP, UPI PIN, CVV, or card PIN.", "A UPI PIN is used to pay, never to receive money.", "Verify the recipient in your banking app before approving any payment."] if evidence else ["Continue using normal payment precautions.", "Confirm the recipient name in your banking app before paying."],
    )


def analyze_sender_trust(organization: str, sender: str, website: str) -> Dict[str, Any]:
    combined = f"Organization: {organization}\nSender: {sender}\nWebsite: {website}".strip()
    evidence: List[Dict[str, str]] = []
    sender_domain = sender.lower().split("@")[-1] if "@" in sender else ""
    site_host = re.sub(r"^https?://", "", website.lower()).split("/")[0].split(":")[0]
    brand = organization.lower().strip().replace(" ", "")
    suspicious_tlds = (".xyz", ".top", ".click", ".icu", ".live", ".shop", ".biz")
    if any(sender_domain.endswith(tld) or site_host.endswith(tld) for tld in suspicious_tlds):
        evidence.append(_evidence("suspicious_domain", "The sender or website uses a frequently abused domain extension.", "high"))
    if sender_domain in ("gmail.com", "yahoo.com", "outlook.com") and brand:
        evidence.append(_evidence("free_mail_impersonation", "A public email provider is being used for an organization claim.", "medium"))
    if brand and (brand in sender_domain or brand in site_host) and any(token in sender_domain + site_host for token in ("secure", "verify", "update", "login", "kyc", "support")):
        evidence.append(_evidence("lookalike_domain", "The domain combines a claimed brand with verification or login wording, a common impersonation pattern.", "high"))
    if website and not website.lower().startswith("https://"):
        evidence.append(_evidence("insecure_link", "The website does not use HTTPS.", "medium"))
    if sender and "@" not in sender:
        evidence.append(_evidence("sender_format", "The sender address is incomplete or invalid.", "low"))

    return _result(
        "sender_trust", "Sender impersonation" if evidence else "Sender details appear consistent",
        combined,
        evidence,
        ["Do not use links in unexpected messages.", "Open the organisation's official app or type its known website yourself.", "Call a published customer-care number to verify the request."] if evidence else ["Use the official website or app for sensitive actions.", "Remain cautious with unexpected attachments or payment requests."],
    )


def analyze_account_protection(incident_type: str, details: str) -> Dict[str, Any]:
    incident_labels = {
        "otp_shared": "OTP or banking credential shared",
        "money_sent": "Money sent to a suspicious recipient",
        "malicious_link": "Suspicious link opened or details entered",
        "apk_installed": "Unknown APK or app installed",
        "unknown": "Suspicious contact received",
    }
    label = incident_labels.get(incident_type, incident_labels["unknown"])
    severity = "critical" if incident_type in ("otp_shared", "money_sent", "apk_installed") else "high"
    evidence = [_evidence("incident_report", f"Reported incident: {label}.", severity)]
    return _result(
        "account_protection", "Account protection response", f"{label}: {details}", evidence,
        ["Contact your bank or payment provider immediately and secure the affected account.", "For financial fraud in India, call 1930 immediately and report at cybercrime.gov.in.", "Change passwords from a trusted device and keep screenshots, transaction IDs, numbers, and URLs as evidence.", "Do not delete messages or install any further apps requested by the caller."],
    )
