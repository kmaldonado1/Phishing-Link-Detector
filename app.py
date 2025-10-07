import os
import traceback
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import tldextract
import numpy as np
import re

# Initialize Flask app
app = Flask(__name__)

# Load the model
try:
    model_path = os.path.join(os.getcwd(), 'phishing_url_classifier.pkl')
    model = joblib.load(model_path)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    print(traceback.format_exc())

# Function to extract features and identify dangerous elements in a URL
def extract_url_features(url):
    dangerous_chars = ['\\', ';', ' ', '@', "'", ':', '&', '>', '<', '=']
    dangerous_TLDs = ['com', 'net', '', 'it', 'top', 'sh', 'pl', 'ru', 'info', 'br']
    suspicious_keywords = [
        'secure', 'account', 'update', 'login', 'verify', 'signin', 
        'bank', 'notify', 'click', 'inconvenient'
    ]

    # Extract features
    URL_length = len(url)
    Number_of_dots = url.count('.')
    Number_of_slashes = url.count('/')
    Percentage_of_numerical_characters = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    Dangerous_characters = [char for char in dangerous_chars if char in url]
    Dangerous_TLD = tldextract.extract(url).suffix if tldextract.extract(url).suffix in dangerous_TLDs else None
    IP_Address = bool(re.search(r'[0-9]+(?:\.[0-9]+){3}', url))
    Domain_name_length = len(tldextract.extract(url).domain)
    Suspicious_keywords = [word for word in suspicious_keywords if word in url.lower()]
    Repetitions = bool(re.search(r'(.)\1{2,}', tldextract.extract(url).domain))
    Redirections = url.rfind('//') > 7  # Check for multiple "//" after protocol

    # Create feature vector
    features = np.array([[
        URL_length, Number_of_dots, Number_of_slashes, Percentage_of_numerical_characters,
        len(Dangerous_characters) > 0, bool(Dangerous_TLD), IP_Address, Domain_name_length,
        len(Suspicious_keywords) > 0, Repetitions, Redirections
    ]], dtype=float)

    # Return features and identified elements
    return features, {
        "dangerous_chars": Dangerous_characters,
        "dangerous_tld": Dangerous_TLD,
        "suspicious_keywords": Suspicious_keywords
    }

# Function to predict phishing or safe with additional details
def predict_url(url, model, threshold=0.3):
    # Extract features and details
    features, details = extract_url_features(url)
    
    # Predict probabilities using the trained model
    probs = model.predict_proba(features)
    print(f"Predicted probabilities for phishing class (1): {probs[0][1]}")  # Debugging output

    # Determine result based on inverted logic
    # Swap "High Risk" and "Low Risk"
    result = "Safe" if probs[0][1] >= threshold else "Phishing"
    return result, probs[0][1], details


# Webhook endpoint with detailed response for high-risk links
@app.route('/webhook', methods=['POST'])
def dialogflow_webhook():
    try:
        # Parse Dialogflow request
        request_json = request.get_json()
        url = (
            request_json.get('queryResult', {})
            .get('parameters', {})
            .get('url', '')
        )
        
        # Debug: Log extracted URL
        print("Extracted URL:", url)

        if not url:
            return jsonify({"fulfillmentText": "Please provide a valid URL to check."})
        
        # Predict the result using predict_url
        result, probability, details = predict_url(url, model, threshold=0.1)
        
        # Create user-friendly response
        if result == "Phishing":
            # Construct sentence components for dangerous elements
            dangerous_chars_text = f"dangerous characters: {', '.join(details['dangerous_chars'])}" if details["dangerous_chars"] else "no dangerous characters"
            suspicious_keywords_text = f"suspicious words: {', '.join(details['suspicious_keywords'])}" if details["suspicious_keywords"] else "no suspicious keywords"
            dangerous_tld_text = f" dangerous TLD: {details['dangerous_tld']}" if details["dangerous_tld"] else "no dangerous TLDs"
            
            # Full risk message
            risk_message = (
                f"🚨 HIGH RISK: {url} is likely a phishing site! "
                f"The URL contains {dangerous_chars_text}. "
                f"The URL contains {suspicious_keywords_text}. "
                f"The URL contains {dangerous_tld_text}."
            )
        else:
            risk_message = f"✅ LOW RISK: {url} appears safe."
        
        return jsonify({"fulfillmentText": risk_message})
    
    except Exception as e:
        # Handle errors and return error response
        error_message = f"Error checking URL: {str(e)}"
        print(error_message)
        print(traceback.format_exc())
        
        return jsonify({"fulfillmentText": error_message}), 500
# Ensure the app runs on all interfaces and correct port
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)