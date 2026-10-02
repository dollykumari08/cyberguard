import re
import difflib

TRUSTED_DOMAINS = ["sbi.co.in", "hdfcbank.com", "bput.ac.in", "google.com",
                   "paypal.com", "amazon.in", "microsoft.com"]
AUTHORITY = ["ceo", "director", "principal", "registrar", "manager", "chairman",
             "tax department", "police", "bank"]
MONEY = ["gift card", "wire", "transfer", "payment", "fee", "invoice"]


def analyze_sender(sender_email, display_name, body):
    """Return (score 0-100, reasons)."""
    score, reasons = 0, []
    domain = sender_email.split("@")[-1].lower()

    best, ratio = None, 0
    for t in TRUSTED_DOMAINS:
        r = difflib.SequenceMatcher(None, domain, t).ratio()
        if r > ratio:
            best, ratio = t, r
    if domain not in TRUSTED_DOMAINS and ratio >= 0.75:
        score += 50
        reasons.append(f"Sender domain '{domain}' closely resembles trusted domain '{best}'")

    if re.search(r"gmail|yahoo|outlook|hotmail", domain) and \
            any(a in display_name.lower() for a in AUTHORITY):
        score += 35
        reasons.append(f"Claims authority role ('{display_name}') but uses free email '{domain}'")

    low = body.lower()
    if any(m in low for m in MONEY) and any(u in low for u in ["urgent", "confidential", "asap", "fast"]):
        score += 25
        reasons.append("Requests money or gift cards with urgency and secrecy")
    return min(score, 100), reasons