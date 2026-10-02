import datetime
from engine import phishing, impersonation, login_anomaly, scoring, response, deepfake

_phish = phishing.load()
_login = login_anomaly.load()


def _package(kind, category, score, reasons, target):
    lvl = scoring.level(score)
    if lvl == "Safe":
        category = "None"
    return {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "source": kind,
        "target": target,
        "category": category,
        "score": score,
        "level": lvl,
        "explanation": scoring.explain(lvl, category, reasons),
        "actions": response.recommend(category, lvl),
        "mitre": response.MITRE.get(category, "-"),
        "status": "Open" if lvl != "Safe" else "Closed",
    }


def analyze_message(sender_email, display_name, body, url="", target="user"):
    prob, reasons = phishing.analyze_text(body, _phish)
    text_score = int(prob * 100)
    if text_score >= 50:
        reasons.insert(0, f"ML classifier flags the text as phishing ({text_score}% confidence)")
    url_score = 0
    if url:
        url_score, r = phishing.analyze_url(url)
        reasons += r
    imp_score, r = impersonation.analyze_sender(sender_email, display_name, body)
    reasons += r
    total = scoring.combine([text_score, url_score, imp_score])
    category = "Impersonation" if imp_score >= 50 else "Phishing"
    return _package("Email/SMS", category, total, reasons, target)


def analyze_login(user, hour, country, new_device, failed):
    score, reasons = login_anomaly.analyze_login(hour, country, new_device, failed, _login)
    return _package("Login log", "Account Takeover", score, reasons, user)
def analyze_media(img, target="user"):
    score, reasons = deepfake.analyze_image(img)
    return _package("Image", "Deepfake", score, reasons, target)