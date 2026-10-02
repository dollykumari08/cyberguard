def level(score):
    if score < 20: return "Safe"
    if score < 40: return "Low"
    if score < 60: return "Medium"
    if score < 80: return "High"
    return "Critical"


def combine(scores):
    """Highest signal counts fully; other signals add 25% each."""
    s = sorted([x for x in scores if x > 0], reverse=True)
    if not s:
        return 0
    return int(min(s[0] + sum(x * 0.25 for x in s[1:]), 100))


def explain(lvl, category, reasons):
    if lvl == "Safe" or not reasons:
        return "No significant threat indicators found."
    return f"{lvl} Risk ({category}): " + "; ".join(reasons) + "."