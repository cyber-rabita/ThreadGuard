from flask import Flask, render_template, request
import os
import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)

VT_API_KEY = os.getenv("VT_API_KEY")
def check_url_virustotal(url):
    if not VT_API_KEY:
        return {
            "error": "VirusTotal API key is not configured."
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        # Submit URL to VirusTotal
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return {
                "error": f"VirusTotal API error: {response.status_code}"
            }

        data = response.json()
        analysis_id = data["data"]["id"]

        # Get analysis result
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )

        if analysis_response.status_code != 200:
            return {
                "error": f"Analysis error: {analysis_response.status_code}"
            }

        analysis_data = analysis_response.json()

        attributes = analysis_data.get("data", {}).get("attributes", {})

        stats = attributes.get("stats", {})

        return {
            "status": attributes.get("status", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"VirusTotal connection error: {str(e)}"
        }

    except Exception as e:
        return {
            "error": f"Unexpected VirusTotal error: {str(e)}"
        }
# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():
    return render_template("index.html")


# =========================
# EMAIL ANALYSIS PAGE
# =========================

@app.route("/email")
def email_analysis():
    return render_template("email.html")


# =========================
# EMAIL DETECTION ENGINE
# =========================

def detect_phishing(sender, subject, body):

    score = 0
    indicators = []

    text = f"{sender} {subject} {body}".lower()

    suspicious_words = {
        "urgent": 10,
        "immediately": 10,
        "verify": 10,
        "verification": 10,
        "password": 15,
        "account suspended": 15,
        "click here": 15,
        "confirm your account": 15,
        "login": 10,
        "reset your password": 15
    }

    for word, points in suspicious_words.items():

        if word in text:
            score += points

            indicators.append(
                f"Suspicious phrase detected: {word}"
            )

    score = min(score, 100)

    if score >= 70:
        risk = "CRITICAL"

    elif score >= 50:
        risk = "HIGH"

    elif score >= 30:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return score, risk, indicators


# =========================
# EMAIL ANALYSIS ROUTE
# =========================

@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    sender = request.form.get("sender", "")
    subject = request.form.get("subject", "")
    body = request.form.get("body", "")

    score, risk, indicators = detect_phishing(
        sender,
        subject,
        body
    )

    return render_template(
        "email_result.html",
        sender=sender,
        subject=subject,
        score=score,
        risk=risk,
        indicators=indicators
    )


# =========================
# URL ANALYSIS PAGE
# =========================

@app.route("/url")
def url_analysis():
    return render_template("url.html")


# =========================
# URL DETECTION ENGINE
# =========================

def analyze_url(url):

    score = 0
    indicators = []

    url_lower = url.lower()

    # Check 1: HTTP instead of HTTPS
    if url_lower.startswith("http://"):

        score += 20

        indicators.append(
            "URL is using HTTP instead of HTTPS"
        )

    # Check 2: IP address used instead of domain
    parts = url_lower.split("/")

    if len(parts) > 2:

        domain = parts[2]

        if domain.replace(".", "").isdigit():

            score += 25

            indicators.append(
                "URL appears to use an IP address"
            )

    # Check 3: Suspicious words
    suspicious_words = [
        "login",
        "verify",
        "password",
        "account",
        "secure",
        "update",
        "confirm"
    ]

    for word in suspicious_words:

        if word in url_lower:

            score += 10

            indicators.append(
                f"Suspicious keyword found in URL: {word}"
            )

    # Check 4: Very long URL
    if len(url) > 100:

        score += 15

        indicators.append(
            "URL is unusually long"
        )

    # Check 5: @ symbol
    if "@" in url:

        score += 20

        indicators.append(
            "URL contains an @ symbol"
        )

    # Check 6: Too many subdomains
    parts = url_lower.split("/")

    if len(parts) > 2:

        domain = parts[2]

        if domain.count(".") >= 3:

            score += 15

            indicators.append(
                "URL contains an unusually high number of subdomains"
            )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk classification
    if score >= 70:

        risk = "CRITICAL"

    elif score >= 50:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    return score, risk, indicators


# =========================
# URL ANALYSIS ROUTE
# =========================

@app.route("/analyze-url", methods=["POST"])
def analyze_url_route():
    url = request.form.get("url", "").strip()

    if not url:
        return "Please enter a URL"

    # ThreatGuard local analysis
    score, risk, indicators = analyze_url(url)

    # VirusTotal analysis
    virustotal_result = check_url_virustotal(url)

    return render_template(
        "url_result.html",
        url=url,
        score=score,
        risk=risk,
        indicators=indicators,
        virustotal=virustotal_result
    )
    url = request.form.get("url", "").strip()

    if not url:
        return "Please enter a URL"

    # Local ThreatGuard analysis
    score, risk, indicators = analyze_url(url)

    # VirusTotal analysis
    virustotal_result = check_url_virustotal(url)

    return render_template(
        "url_result.html",
        url=url,
        score=score,
        risk=risk,
        indicators=indicators,
        virustotal=virustotal_result
    )

# =========================
# FILE ANALYSIS PAGE
# =========================

@app.route("/file")
def file_analysis():
    return render_template("file.html")


# =========================
# FILE DETECTION ENGINE
# =========================

def analyze_file(file):

    filename = file.filename
    extension = os.path.splitext(filename)[1].lower()

    score = 0
    indicators = []

    # Check 1: Dangerous executable extensions
    dangerous_extensions = [
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".vbs",
        ".js",
        ".ps1",
        ".msi"
    ]

    if extension in dangerous_extensions:
        score += 50

        indicators.append(
            f"Dangerous file extension detected: {extension}"
        )

    # Check 2: Double extension
    name_parts = filename.lower().split(".")

    if len(name_parts) >= 3:

        score += 25

        indicators.append(
            "File contains multiple extensions"
        )

    # Check 3: Suspicious filename words
    suspicious_words = [
        "password",
        "invoice",
        "payment",
        "urgent",
        "verify",
        "account",
        "login",
        "update"
    ]

    filename_lower = filename.lower()

    for word in suspicious_words:

        if word in filename_lower:

            score += 10

            indicators.append(
                f"Suspicious keyword found in filename: {word}"
            )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk classification
    if score >= 70:

        risk = "CRITICAL"

    elif score >= 50:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    return score, risk, indicators


# =========================
# FILE ANALYSIS ROUTE
# =========================

@app.route("/analyze-file", methods=["POST"])
def analyze_file_route():

    file = request.files.get("file")

    if not file or file.filename == "":
        return "No file selected"

    score, risk, indicators = analyze_file(file)

    return render_template(
        "file_result.html",
        filename=file.filename,
        score=score,
        risk=risk,
        indicators=indicators
    )

# =========================
# START FLASK SERVER
# =========================

if __name__ == "__main__":
    app.run(debug=True)
