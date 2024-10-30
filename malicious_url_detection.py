#!/usr/bin/env python
# coding: utf-8

# Heuristic Method for Malicious URLs Detection Using Machine Learning

# In[28]:


import random

import joblib
import numpy as np
import pandas as pd

from tld import get_tld, is_tld
from urllib.parse import urlparse
import re

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from sklearn.ensemble import RandomForestClassifier

# import xgboost as xgb

# import lightgbm as lgb

# from sklearn.svm import SVC

# from sklearn.linear_model import LogisticRegression

# from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, LSTM

# ##### Load Phishtank Dataset

# In[29]:


# Phishtank Dataset:
df_phishtank = pd.read_csv('Datasets/phishtank_data.csv')

# Display Info
print(df_phishtank.columns)
print(df_phishtank.info())
print(df_phishtank.index.min(), df_phishtank.index.max())
print(df_phishtank.head())

# ##### Load Kaggle Dataset

# In[30]:


# Kaggle Dataset:
df_kaggle = pd.read_csv('Datasets/kaggle_data.csv')

# Display Info
print(df_kaggle.columns)
print(df_kaggle.info())
print(df_kaggle.index.min(), df_kaggle.index.max())
print(df_kaggle.head())
print(df_kaggle.type.value_counts())

# ##### Clean & Merge Data from Datasets

# In[31]:


# We only care about verified & online malicious URLs, so drop all unverified or offline URLs from Phishtank dataset.
df_phishtank = df_phishtank.drop(
    df_phishtank[(df_phishtank['verified'] == 'no') | (df_phishtank['online'] == 'no')].index)

# Also for Phishtank dataset, we only care about URL and type (in this case all are phishing), so drop all other
# columns.
df_phishtank = df_phishtank.drop(
    columns=['phish_id', 'phish_detail_url', 'submission_time', 'verified', 'verification_time', 'online', 'target'])
df_phishtank = df_phishtank.assign(type='phishing')

# Merge datasets
data = pd.concat([df_phishtank, df_kaggle], axis=0)

# Remove 'www.' from URLs (useless info)
data['url'] = data['url'].replace('www.', '', regex=True)

# Display Info
print(data.columns)
print(data.info())
print(data.index.min(), data.index.max())
print(data.head())
print(data.type.value_counts())

# ##### Feature Selection & Extraction

# In[32]:


# Is the URL malicious?
mal = {"malicious": {'benign': 0, 'defacement': 1, 'malware': 1, 'phishing': 1}}
data['malicious'] = data['type']
data = data.replace(mal)

# URL category (based on level of threat to victim)
cat = {"category": {'benign': 0, 'defacement': 1, 'malware': 2, 'phishing': 3}}
data['category'] = data['type']
data = data.replace(cat)

# URL length
data['url_len'] = data['url'].apply(lambda x: len(str(x)))


# Domain
def find_tld(url):
    try:
        tld = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        domain = tld.parsed_url.netloc
    except:
        domain = None
    return domain


data['domain'] = data['url'].apply(lambda x: find_tld(x))

# Domain length
data['domain_len'] = data['domain'].apply(lambda x: len(str(x)))


# URL contains https signature (essential element for a secure URL)
def is_http_secure(url):
    https = urlparse(url).scheme
    if str(https) == 'https':
        return 1
    else:
        return 0


data['https'] = data['url'].apply(lambda x: is_http_secure(x))


# Number of letters in URL
def num_of_letters(url):
    letters = 0
    for char in url:
        if char.isalpha():
            letters = letters + 1
    return letters


data['letters'] = data['url'].apply(lambda x: num_of_letters(x))


# Number of digits in URL
def num_of_digits(url):
    digits = 0
    for char in url:
        if char.isnumeric():
            digits = digits + 1
    return digits


data['digits'] = data['url'].apply(lambda x: num_of_digits(x))

# Number of various special characters in URL
special_chars = ['@', '#', '$', '%', '+', '-', '*', '=', 'comma', '.', '?', '!', '//']
for char in special_chars:
    if char != 'comma':
        data[char] = data['url'].apply(lambda x: x.count(char))
    else:
        data[char] = data['url'].apply(lambda x: x.count(','))


# Presence of a URL shortener
def url_shortened(domain):
    if domain is None:
        return 0
    url_contains = re.search(r"^(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tr\.im|tr\.ee|is\.gd|cli\.gs|"
                             r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
                             r"short\.to|BudURL\.com|ping\.fm|post\.ly|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
                             r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
                             r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
                             r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|cutt\.ly|u\.bb|yourls\.org|"
                             r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
                             r"link\.zip\.net|zrr\.kr|zpr\.io|zip\.pe|ya\.mba|xurl\.es|x\.gd|tiny\.one|shorturl\.at|rb\.gy|"
                             r"lnwlink\.com|urlzs\.com|urlz\.fr|urle\.me|urlbit\.co|url1\.io|url\.in\.th|shorturl\.ac|"
                             r"url\.34782\.ru|uqr\.to|uni\.su|tinu\.be|taplink\.cc|t\.ly|t\.co|surl\.li|sprl\.in|spoo\.me|"
                             r"snip\.ly|snip\.ink|skro\.in|shortu\.be|shorter\.me|short\.im|scnv\.io|sc\.link|s\.yam\.com|"
                             r"s\.id|s\.free\.fr|risu\.io|reurl\.cc|rebrand\.ly|rcl\.ink|qr\.to|qr\.co|qrco\.de|qr1\.be|"
                             r"qr\.paps\.jp|qr\.fm|qr\.de|ppt\.cc|onx\.la|ohw\.tf|o-trim\.co|nx\.tn|lt27\.de|"
                             r"lnkfi\.re|linkr\.it|lihi\.cc|lihi1\.cc|lihi2\.cc|lihi3\.cc|ko\.gl|jii\.li|is\.gd|in\.mt|"
                             r"iiil\.io|idm\.in|i8\.ae|hm\.ru|goo\.su|goo\.gs|goo\.by|go\.ly|gg\.gg|g00.al|f\.yourl\.jp|"
                             r"encr\.pw|e\.vg|dik\.si|d\.yzh\.li|cutl\.pl|clps\.it|cli\.re|cli\.co|blnk.in|"
                             r"bitly\.ws|bitly\.net|bitly\.lc|appurl\.io|2ww\.me|2uuu\.me|2no\.co|2md\.ir|2j\.fr|"
                             r"ok\.uz\.ua|linkby\.tw|inx\.lv)$", domain)

    if url_contains:
        return 1
    else:
        return 0


data['url_shortened'] = data['domain'].apply(lambda x: url_shortened(x))


# Presence of an IP address
def contains_ip_address(url):
    url_contains = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4 with port
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'  # IPv4 in hexadecimal
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # IPv6

    if url_contains:
        return 1
    else:
        return 0


data['contains_ip_address'] = data['url'].apply(lambda x: contains_ip_address(x))

# Display features
data.head(25)

# ##### Random Forest

# In[33]:


# # Split data into train and test sets
X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
y = data['malicious']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Initialize and train the Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(X_train, y_train)


# Save the trained Random Forest model
joblib.dump(rf_classifier, 'rf_model.pkl')

# Save the feature names
joblib.dump(X.columns.tolist(), 'feature_names.pkl')

# # Predict on the test set
y_pred = rf_classifier.predict(X_test)

# # Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
print("Classification Report:")
print(classification_report(y_test, y_pred))

# ##### XGBoost

# In[34]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Initialize and train the XGBoost classifier
# xgb_classifier = xgb.XGBClassifier(learning_rate=0.1, max_depth=3, n_estimators=100, random_state=42)
# xgb_classifier.fit(X_train, y_train)

# # Predict on the test set
# y_pred = xgb_classifier.predict(X_test)

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred))


# ##### LightGBM

# In[35]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Define LightGBM dataset
# train_data = lgb.Dataset(X_train, label=y_train)
# test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

# # Set LightGBM parameters
# params = {
#     'objective': 'binary',
#     'metric': 'binary_error',
#     'verbosity': -1
# }

# # Train the model
# bst = lgb.train(params, train_data, valid_sets=[test_data], callbacks=[lgb.early_stopping(stopping_rounds=10)])

# # Predict on the test set
# y_pred = bst.predict(X_test, num_iteration=bst.best_iteration)
# y_pred_binary = [1 if pred > 0.5 else 0 for pred in y_pred]

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred_binary)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred_binary))


# ##### Support Vector Machine (SVM)

# In[36]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Initialize and train the SVM classifier
# svm_classifier = SVC(kernel='linear', C=0.000000000000000001, random_state=42)
# svm_classifier.fit(X_train, y_train)

# # Predict on the test set
# y_pred = svm_classifier.predict(X_test)

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred))


# ##### Logistic Regression

# In[37]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Initialize and train the Logistic Regression classifier
# logreg_classifier = LogisticRegression(random_state=42, max_iter=1000)
# logreg_classifier.fit(X_train, y_train)

# # Predict on the test set
# y_pred = logreg_classifier.predict(X_test)

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred))


# ##### Convolutional Neural Network (CNN)

# In[38]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Define CNN model
# model = Sequential([
#     Embedding(input_dim=X.shape[0], output_dim=16, input_length=X.shape[1]),
#     Conv1D(128, 5, activation='relu'),
#     GlobalMaxPooling1D(),
#     Dense(64, activation='relu'),
#     Dense(1, activation='sigmoid')
# ])

# # Compile the model
# model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# # Train the model
# model.fit(X_train, y_train, epochs=10, batch_size=16, validation_split=0.2)

# # Evaluate the model
# loss, accuracy = model.evaluate(X_test, y_test)
# print("Test Accuracy:", accuracy)

# # Predict on test data
# y_pred = model.predict(X_test)
# y_pred = [1 if pred > 0.5 else 0 for pred in y_pred]

# # Calculate accuracy
# accuracy = accuracy_score(y_test, y_pred)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred))


# ##### Recurrent Neural Network (RNN)

# In[39]:


# # Split data into train and test sets
# X = data.drop(['url', 'type', 'malicious', 'category', 'domain'], axis=1)
# y = data['malicious']
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Define RNN model
# model = Sequential([
#     Embedding(input_dim=X.shape[0], output_dim=16, input_length=X.shape[1]),
#     LSTM(64),
#     Dense(1, activation='sigmoid')
# ])

# # Compile the model
# model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# # Train the model
# model.fit(X_train, y_train, epochs=10, batch_size=16, validation_split=0.2)

# # Evaluate the model
# loss, accuracy = model.evaluate(X_test, y_test)
# print("Test Accuracy:", accuracy)

# # Predict on test data
# y_pred = model.predict(X_test)
# y_pred = [1 if pred > 0.5 else 0 for pred in y_pred]

# # Calculate accuracy
# accuracy = accuracy_score(y_test, y_pred)
# print("Accuracy:", accuracy)
# print("Classification Report:")
# print(classification_report(y_test, y_pred))
