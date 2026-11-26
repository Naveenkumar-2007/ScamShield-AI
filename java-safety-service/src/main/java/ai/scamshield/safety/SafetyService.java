package ai.scamshield.safety;

import java.util.*;
import org.springframework.stereotype.Service;

@Service
public class SafetyService {
    private Map<String, Object> evidence(String type, String description, String severity) {
        return Map.of("evidence_type", type, "evidence_description", description, "severity", severity);
    }
    private Map<String, Object> result(String inputType, String category, String preview, List<Map<String, Object>> evidence, List<String> actions) {
        int score = Math.min(100, evidence.stream().mapToInt(e -> switch ((String)e.get("severity")) { case "critical" -> 40; case "high" -> 22; case "medium" -> 12; default -> 5; }).sum());
        if (evidence.stream().anyMatch(e -> "critical".equals(e.get("severity")))) score = Math.max(80, score);
        String level = score >= 80 ? "Very High Risk" : score >= 60 ? "High Risk" : score >= 30 ? "Medium Risk" : "Low Risk";
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true); response.put("input_type", inputType); response.put("input_preview", preview); response.put("risk_score", score); response.put("risk_level", level);
        response.put("predicted_category", category); response.put("model_version", "Safety Engine v1.0"); response.put("confidence", Math.min(.95, .15 + evidence.size() * .18));
        response.put("evidence", evidence); response.put("recommendations", actions);
        response.put("explanation", evidence.isEmpty() ? "No major fraud signals were found in the supplied details." : "This assessment found warning signs that should be verified before you act.");
        return response;
    }
    public Map<String, Object> payment(Map<String, String> r) {
        String message = r.getOrDefault("message", "").toLowerCase(); List<Map<String, Object>> e = new ArrayList<>();
        if (message.matches(".*(upi pin|share otp|enter otp|cvv|card pin).*")) e.add(evidence("credential_request", "The message asks for a PIN, OTP, CVV, or other payment credential.", "critical"));
        if (message.matches(".*(cashback|reward|scratch card|prize|lottery).*")) e.add(evidence("reward_bait", "A reward or cashback offer is being used to encourage a payment action.", "high"));
        if (message.matches(".*(immediately|urgent|within 24|today|account blocked).*")) e.add(evidence("payment_urgency", "The message applies time pressure to make you act quickly.", "medium"));
        return result("payment_safety", e.isEmpty() ? "Payment details appear safe" : "Payment and UPI fraud", r.toString(), e, List.of("Never share an OTP, UPI PIN, CVV, or card PIN.", "A UPI PIN is used to pay, never to receive money.", "Verify the recipient in your banking app before approving a payment."));
    }
    public Map<String, Object> sender(Map<String, String> r) {
        String all = (r.getOrDefault("sender", "") + " " + r.getOrDefault("website", "")).toLowerCase(); List<Map<String, Object>> e = new ArrayList<>();
        if (all.matches(".*\\.(xyz|top|click|icu|live|shop|biz)(/|$).*")) e.add(evidence("suspicious_domain", "The sender or website uses a frequently abused domain extension.", "high"));
        if (all.matches(".*(secure|verify|update|login|kyc).*")) e.add(evidence("lookalike_domain", "The sender or website uses verification wording commonly found in impersonation attempts.", "high"));
        if (r.getOrDefault("website", "").startsWith("http://")) e.add(evidence("insecure_link", "The website does not use HTTPS.", "medium"));
        return result("sender_trust", e.isEmpty() ? "Sender details appear consistent" : "Sender impersonation", r.toString(), e, List.of("Use the organisation's official app or type its known website yourself.", "Verify unexpected requests through a published customer-care number."));
    }
    public Map<String, Object> protection(Map<String, String> r) {
        String incident = r.getOrDefault("incident_type", "unknown"); String severity = Set.of("otp_shared", "money_sent", "apk_installed").contains(incident) ? "critical" : "high";
        return result("account_protection", "Account protection response", r.toString(), List.of(evidence("incident_report", "Reported incident: " + incident.replace('_', ' ') + ".", severity)), List.of("Contact your bank or payment provider immediately.", "For financial fraud in India, call 1930 and report at cybercrime.gov.in.", "Change passwords from a trusted device and retain screenshots and transaction IDs."));
    }
}
