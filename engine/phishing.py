import re
import joblib
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

URGENCY = ["urgent", "immediately", "suspended", "within 24 hours", "act now",
           "blocked", "expire", "lose access", "confidential", "fast"]
CREDENTIAL = ["password", "otp", "login", "pan", "aadhaar", "verify", "kyc", "pin"]
BAD_TLDS = {"xyz", "top", "click", "tk", "ml", "gq", "work", "loan"}
BRANDS = ["sbi", "hdfc", "icici", "paypal", "amazon", "google", "microsoft", "bput"]


def train(path="data/messages.csv"):
    df = pd.read_csv(path)
    X_tr, X_te, y_tr, y_te = train_test_split(
        df.text, df.label, test_size=0.25, random_state=1, stratify=df.label)
    model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), lowercase=True),
                          LogisticRegression(max_iter=1000))
    model.fit(X_tr, y_tr)
    print(classification_report(y_te, model.predict(X_te)))
    joblib.dump(model, "models/phish.joblib")


def load():
    return joblib.load("models/phish.joblib")


def analyze_url(url):
    """Return (score 0-100, list of reasons)."""
    score, reasons = 0, []
    ext = tldextract.extract(url)
    domain = ext.domain.lower()
    if ext.suffix in BAD_TLDS:
        score += 30; reasons.append(f"Suspicious top-level domain '.{ext.suffix}'")
    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 35; reasons.append("URL uses a raw IP address instead of a domain")
    if not url.startswith("https"):
        score += 10; reasons.append("Connection is not encrypted (no HTTPS)")
    if domain.count("-") >= 1:
        score += 15; reasons.append("Domain contains hyphens, common in fake sites")
    norm = domain.replace("1", "l").replace("0", "o").replace("3", "e").replace("5", "s")
    for b in BRANDS:
        if b in norm and norm != b:
            score += 35
            reasons.append(f"Look-alike domain: '{domain}' imitates brand '{b}'")
            break
    if any(w in url.lower() for w in ["login", "verify", "secure", "update", "auth"]):
        score += 10; reasons.append("URL contains credential-related keywords")
    return min(score, 100), reasons


def analyze_text(text, model):
    """Return (ml_probability 0-1, reasons)."""
    prob = float(model.predict_proba([text])[0][1])
    low = text.lower()
    reasons = []
    hits = [w for w in URGENCY if w in low]
    if hits:
        reasons.append("Urgency language: " + ", ".join(hits[:3]))
    hits = [w for w in CREDENTIAL if w in low]
    if hits:
        reasons.append("Requests sensitive info: " + ", ".join(hits[:3]))
    return prob, reasons


if __name__ == "__main__":
    train()