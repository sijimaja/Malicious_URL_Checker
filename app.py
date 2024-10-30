import joblib
import pandas as pd
from urllib.parse import urlparse
from tld import get_tld
import re
from flask import Flask, request, render_template, jsonify
import pickle

# Load the trained models
feature_extraction = pickle.load(open("feature_extraction.pkl", "rb"))
url_model = joblib.load('rf_model.pkl')

# Load the feature names for URL model
feature_names = joblib.load('feature_names.pkl')

# Create the Flask application
app = Flask(__name__)


def extract_features(url):
    def find_tld(url):
        try:
            tld = get_tld(url, as_object=True, fail_silently=True, fix_protocol=True)
            domain = tld.parsed_url.netloc
        except:
            domain = None
        return domain

    def is_http_secure(url):
        https = urlparse(url).scheme
        return 1 if str(https) == 'https' else 0

    def num_of_letters(url):
        return sum(1 for char in url if char.isalpha())

    def num_of_digits(url):
        return sum(1 for char in url if char.isnumeric())

    special_chars = ['@', '#', '$', '%', '+', '-', '*', '=', '.', '?', '!', '//']

    def url_shortened(domain):
        if domain is None:
            return 0
        url_contains = re.search(r"^(bit\.ly|goo\.gl|...|...|xurl\.es|x\.gd)$", domain)
        return 1 if url_contains else 0

    def contains_ip_address(url):
        url_contains = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)', url)
        return 1 if url_contains else 0

    domain = find_tld(url)
    features = {
        'url_len': len(url),
        'domain_len': len(domain) if domain else 0,
        'https': is_http_secure(url),
        'letters': num_of_letters(url),
        'digits': num_of_digits(url),
    }
    for char in special_chars:
        features[char] = url.count(char)

    features['comma'] = url.count(',')

    features['url_shortened'] = url_shortened(domain)
    features['contains_ip_address'] = contains_ip_address(url)

    # Reorder features to match the order used during training
    features_df = pd.DataFrame([features])
    features_df = features_df[feature_names]

    return features_df


@app.route('/')
def home():
    return render_template('malicious_url.html')


@app.route('/malicious_url', methods=['GET', 'POST'])
def malicious_url():
    result = None
    url = None
    if request.method == 'POST':
        url = request.form["url"]
        features = extract_features(url)
        prediction = url_model.predict(features)
        if prediction[0] == 1:
            result = "Malicious"
        else:
            result = "Safe"
    return render_template('malicious_url.html', result=result, url=url)


if __name__ == '__main__':
    app.run(debug=True)
