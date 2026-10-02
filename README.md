# 🛡️ CyberGuard: AI Cyber Threat, Phishing & Digital Impersonation Detection System

Built for the BPUT Hackathon. CyberGuard detects, classifies, scores, explains and recommends a response for cyber threats that target both the technology layer and the human layer.

**Live demo:** https://cyberguard-n4ecxwz48nczbe2zgxkmod.streamlit.app

## What it detects
- **Phishing** in emails and SMS, including malicious URLs
- **Digital impersonation** (look-alike domains, fake authority senders, CEO gift-card scams)
- **Account takeover** (failed logins, unusual location, new device, odd hours)
- **Deepfake images** (baseline forensic check)

## Pipeline
Detection → Classification → Risk score (Safe to Critical) → Explanation → Alert → Recommended response, with MITRE ATT&CK mapping.

## Models and methods
| Module | Method |
|---|---|
| Phishing text | TF-IDF (1-2 grams) + Logistic Regression |
| URL analysis | Rules: suspicious TLDs, raw IPs, look-alike domains, no HTTPS |
| Impersonation | Domain similarity, authority vs free email, money + secrecy cues |
| Account takeover | Isolation Forest + rules |
| Deepfake (baseline) | Metadata, Error Level Analysis, texture noise, generator resolution |
| Scoring | Hybrid: highest signal counts fully, others add 25% each |

## Results
| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Phishing text (9,541 test emails) | 99.5% | 0.99 | 0.99 | 0.99 |
| Login anomaly (simulated logs) | 95% | 0.55 | 1.00 | 0.71 |

## Data
- Phishing: "Phishing and Legit Emails" by Prabhat Amgain (Kaggle, MIT license), 38,164 emails
- Login logs and dashboard events: simulated
- Deepfake events on the dashboard: simulated

## Run locally
```
pip install -r requirements.txt
streamlit run app.py
```

## Project structure
- `app.py`: Streamlit dashboard (Dashboard, Analyze Live, Model Performance)
- `detect.py`: main detection pipeline
- `engine/`: phishing, impersonation, login anomaly, deepfake, scoring, response
- `models/`: trained models
- `data/`: metrics and datasets

## Limitations
- Login data is simulated
- The deepfake module is heuristic, not a trained model
- The phishing dataset is fairly easy, so the next test is AI-written phishing

## Roadmap
- Trained deepfake CNN (FaceForensics++) and voice-clone detection
- FastAPI, Docker and Kafka for scale
- Federated learning for privacy
- Graph-based attack analysis

## Team
Add your team name and member names here.
