from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import json
from datetime import datetime

app = Flask(__name__)

suspicious_keywords = [
    "login", "verify", "secure", "update", "account",
    "bank", "free", "bonus", "paypal", "signin"
]

stats = {"total":0, "low":0, "medium":0, "high":0}

def analyze_url(url):
    reasons = []
    score = 0

    parsed = urlparse(url)

    if not parsed.scheme in ["http", "https"]:
        reasons.append("Invalid URL scheme")
        score += 2

    if parsed.scheme != "https":
        reasons.append("URL does not use HTTPS")
        score += 1

    domain = parsed.netloc

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        reasons.append("IP address used instead of domain name")
        score += 2

    if len(url) > 75:
        reasons.append("URL length is unusually long")
        score += 1

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            reasons.append(f"Suspicious keyword detected: {keyword}")
            score += 1

    if "@" in url:
        reasons.append("@ symbol found in URL")
        score += 2

    if score >= 5:
        risk = "High Risk"
        stats["high"] += 1
    elif score >= 3:
        risk = "Medium Risk"
        stats["medium"] += 1
    else:
        risk = "Low Risk"
        stats["low"] += 1

    stats["total"] += 1

    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "risk": risk,
        "reasons": reasons
    }

    try:
        with open("urls_log.json", "r") as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []

    logs.append(log_entry)

    with open("urls_log.json", "w") as f:
        json.dump(logs, f, indent=4)

    return risk, reasons

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    reasons = []
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        result, reasons = analyze_url(url)

    return render_template("index.html", result=result, reasons=reasons, url=url, stats=stats)

if __name__ == "__main__":
    app.run(debug=True)