MITRE = {
    "Phishing": "T1566 - Phishing",
    "Impersonation": "T1656 - Impersonation",
    "Account Takeover": "T1078 - Valid Accounts / T1110 - Brute Force",
    "Deepfake": "T1656 - Impersonation (synthetic media)",
}


def recommend(category, lvl):
    if lvl == "Safe":
        return ["No action needed"]
    a = []
    if category == "Phishing":
        a = ["Warn the user"]
        if lvl in ("Medium", "High", "Critical"):
            a += ["Quarantine email", "Block suspicious URL"]
        if lvl == "Critical":
            a += ["Notify administrator/SOC"]
    elif category == "Impersonation":
        a = ["Warn the user", "Report impersonation"]
        if lvl in ("High", "Critical"):
            a += ["Quarantine email", "Notify administrator/SOC"]
    elif category == "Account Takeover":
        a = ["Monitor account"]
        if lvl in ("Medium", "High", "Critical"):
            a = ["Require additional authentication"]
        if lvl in ("High", "Critical"):
            a += ["Revoke active session"]
        if lvl == "Critical":
            a += ["Block suspicious IP/device", "Notify administrator/SOC",
                  "Escalate incident for investigation"]
    elif category == "Deepfake":
        a = ["Flag multimedia for manual verification"]
        if lvl in ("Medium", "High", "Critical"):
            a += ["Warn the user"]
        if lvl in ("High", "Critical"):
            a += ["Notify administrator/SOC", "Report impersonation"]        
    return a