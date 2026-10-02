import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = ["hour", "failed_attempts", "new_device", "foreign"]


def prep(df):
    df = df.copy()
    df["foreign"] = (df["country"] != "IN").astype(int)
    return df


def train(path="data/logins.csv"):
    df = prep(pd.read_csv(path))
    normal = df[df.is_attack == 0]
    model = IsolationForest(contamination=0.05, random_state=1)
    model.fit(normal[FEATURES])
    joblib.dump(model, "models/login.joblib")
    pred = (model.predict(df[FEATURES]) == -1).astype(int)
    acc = (pred == df.is_attack).mean()
    print(f"Login anomaly accuracy: {acc:.2%}")


def load():
    return joblib.load("models/login.joblib")


def analyze_login(hour, country, device_new, failed, model):
    """Return (score 0-100, reasons)."""
    reasons, score = [], 0
    row = pd.DataFrame([[hour, failed, int(device_new), int(country != "IN")]], columns=FEATURES)
    if model.predict(row)[0] == -1:
        score += 40
        reasons.append("Behaviour deviates from the user's normal login pattern (Isolation Forest)")
    if failed >= 5:
        score += 25; reasons.append(f"{failed} failed login attempts (possible password spraying)")
    if country != "IN":
        score += 20; reasons.append(f"Login from unusual location: {country}")
    if device_new:
        score += 15; reasons.append("Login from a new, unknown device")
    if hour < 6:
        score += 10; reasons.append(f"Login at unusual hour ({hour}:00)")
    return min(score, 100), reasons
if __name__ == "__main__":
    train()