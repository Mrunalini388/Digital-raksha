from flask import Flask, request, jsonify
import joblib
import pandas as pd
import requests
from urllib.parse import urlparse
import socket
import spacy

# Load spaCy NLP model
nlp = spacy.load("en_core_web_sm")

app = Flask(__name__)

# Load trained ML model
model = joblib.load('model.joblib')  # Make sure model.joblib exists

# ---- NLP & Threat Detection Logic ----

def extract_text_from_url(url):
    try:
        response = requests.get(url, timeout=5)
        if "text/html" in response.headers.get("Content-Type", ""):
            return response.text
        else:
            return ""
    except:
        return ""

def detect_malware_nlp(text):
    """Very basic NLP-based keyword detection"""
    doc = nlp(text.lower())
    malware_keywords = ["malware", "spyware", "virus", "trojan", "infected"]
    threats = set()

    for token in doc:
        if token.text in malware_keywords:
            threats.add("Malware")

    return threats

def check_redirect(url):
    try:
        response = requests.get(url, timeout=5)
        if response.history:
            return True
        return False
    except:
        return False

# ---- ML Prediction Logic ----

@app.route('/predict', methods=['POST'])
def predict():
    try:
        input_data = request.get_json()
        df = pd.DataFrame([input_data])

        # Drop 'id' if present
        if 'id' in df.columns:
            df = df.drop(columns=['id'])

        prediction = model.predict(df)[0]

        return jsonify({"prediction": int(prediction)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ---- Main URL Threat Check Endpoint ----

@app.route('/predict-url', methods=['POST'])
def predict_url():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({"error": "URL not provided"}), 400

        threats = set()

        # 1. NLP: Analyze page content
        page_text = extract_text_from_url(url)
        threats.update(detect_malware_nlp(page_text))

        # 2. Redirect check
        if check_redirect(url):
            threats.add("Redirect")

        # 3. ML-based phishing check
        # Assume you have a function that converts a URL to feature dict
        features = extract_features_from_url(url)
        df = pd.DataFrame([features])
        if 'id' in df.columns:
            df = df.drop(columns=['id'])
        phishing_pred = model.predict(df)[0]

        if phishing_pred == 1:
            threats.add("Phishing")

        safe = len(threats) == 0

        return jsonify({
            "url": url,
            "safe": safe,
            "threats": list(threats)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- Dummy Feature Extractor (Replace with real logic!) ----
def extract_features_from_url(url):
    parsed = urlparse(url)
    return {
        "NumDots": url.count('.'),
        "SubdomainLevel": len(parsed.hostname.split('.')) - 2 if parsed.hostname else 0,
        "PathLevel": url.count('/'),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "NumDashInHostname": parsed.hostname.count('-') if parsed.hostname else 0,
        "AtSymbol": '@' in url,
        "TildeSymbol": '~' in url,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": len(parsed.query.split('&')) if parsed.query else 0,
        "NumAmpersand": url.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": not url.startswith('https'),
        "RandomString": False,  # Optional NLP logic here
        "IpAddress": is_ip(parsed.hostname),
        "DomainInSubdomains": False,
        "DomainInPaths": False,
        "HttpsInHostname": 'https' in (parsed.hostname or ''),
        "HostnameLength": len(parsed.hostname) if parsed.hostname else 0,
        "PathLength": len(parsed.path),
        "QueryLength": len(parsed.query),
        "DoubleSlashInPath": '//' in parsed.path,
        "NumSensitiveWords": 0,
        "EmbeddedBrandName": False,
        "PctExtHyperlinks": 0,
        "PctExtResourceUrls": 0,
        "ExtFavicon": False,
        "InsecureForms": False,
        "RelativeFormAction": False,
        "ExtFormAction": False,
        "AbnormalFormAction": False,
        "PctNullSelfRedirectHyperlinks": 0,
        "FrequentDomainNameMismatch": False,
        "FakeLinkInStatusBar": False,
        "RightClickDisabled": False,
        "PopUpWindow": False,
        "SubmitInfoToEmail": False,
        "IframeOrFrame": False,
        "MissingTitle": False,
        "ImagesOnlyInForm": False,
        "SubdomainLevelRT": 0,
        "UrlLengthRT": 0,
        "PctExtResourceUrlsRT": 0,
        "AbnormalExtFormActionR": False,
        "ExtMetaScriptLinkRT": 0,
        "PctExtNullSelfRedirectHyperlinksRT": 0,
    }

def is_ip(hostname):
    try:
        socket.inet_aton(hostname)
        return True
    except:
        return False

# ---- Start the App ----
if __name__ == '__main__':
    app.run(debug=True)













