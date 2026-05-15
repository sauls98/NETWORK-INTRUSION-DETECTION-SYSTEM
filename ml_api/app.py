#!/usr/bin/env python3
"""NIDS ML API v5.1 - Con MinMaxScaler"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import joblib
import os
from datetime import datetime
from collections import Counter

app = Flask(__name__)
CORS(app)

MODEL_PATH = '/app/models/model.joblib'
SCALER_PATH = '/app/models/scaler.joblib'

CLASSES = {
    0: 'Benign', 1: 'DoS-SlowHTTPTest', 2: 'DoS-Hulk', 3: 'DoS-GoldenEye',
    4: 'DoS-Slowloris', 5: 'DDoS-LOIC-UDP', 6: 'DDoS-HOIC', 7: 'DDoS-LOIC-HTTP',
    8: 'Bot', 9: 'FTP-BruteForce', 10: 'SSH-Bruteforce', 11: 'Infilteration',
    12: 'SQL Injection', 13: 'Brute Force-Web', 14: 'Brute Force-XSS'
}

SEVERITY = {
    'Benign': 'info', 'Bot': 'high', 'Brute Force-Web': 'medium',
    'Brute Force-XSS': 'medium', 'DDoS-HOIC': 'critical', 'DDoS-LOIC-HTTP': 'critical',
    'DDoS-LOIC-UDP': 'critical', 'DoS-GoldenEye': 'medium', 'DoS-Hulk': 'high',
    'DoS-SlowHTTPTest': 'medium', 'DoS-Slowloris': 'medium', 'FTP-BruteForce': 'medium',
    'Infilteration': 'critical', 'SQL Injection': 'high', 'SSH-Bruteforce': 'high'
}

MINMAX_MIN = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, -1.0, -1.0, 0.0, 0.0, 0.0, 0.0])
MINMAX_MAX = np.array([65535.0, 1.0, 64440.0, 1460.0, 16529.31, 1460.0, 33879.28, 120000000.0, 120000000.0, 120000000.0, 1.0, 5000000.0, 2000000.0, 1.0, 1.0, 1.0, 65535.0, 65535.0, 48.0, 239934000000.0, 1.0, 1.0])

model = None
scaler = None
stats = {'preds': 0, 'attacks': 0, 'counts': Counter(), 'start': datetime.now()}

def load_models():
    global model, scaler
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("✓ Modelos cargados")

def minmax_transform(features):
    features = np.array(features, dtype=np.float64)
    range_vals = MINMAX_MAX - MINMAX_MIN
    range_vals = np.where(range_vals == 0, 1, range_vals)
    scaled = (features - MINMAX_MIN) / range_vals
    return np.clip(scaled, 0, 1)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'models_loaded': model is not None,
        'predictions_count': stats['preds'],
        'attacks_detected': stats['attacks'],
        'uptime': str(datetime.now() - stats['start'])
    })

@app.route('/predict', methods=['POST'])
def predict():
    global stats
    data = request.get_json()
    features = data.get('features', [])
    
    # MinMax + Standard
    features = minmax_transform(features)
    features = np.array(features).reshape(1, -1)
    features = np.nan_to_num(features, nan=0.0)
    features = scaler.transform(features)
    
    pred = int(model.predict(features)[0])
    proba = model.predict_proba(features)[0]
    conf = float(np.max(proba))
    
    cls = CLASSES.get(pred, 'Unknown')
    is_attack = cls != 'Benign'
    
    stats['preds'] += 1
    stats['counts'][cls] += 1
    if is_attack:
        stats['attacks'] += 1
    
    return jsonify({
        'prediction': cls,
        'attack_code': pred,
        'confidence': conf,
        'is_attack': is_attack,
        'severity': SEVERITY.get(cls, 'low'),
        'uid': data.get('uid', 'unknown')
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({'predictions': stats['preds'], 'attacks': stats['attacks'], 'distribution': dict(stats['counts'])})

if __name__ == '__main__':
    load_models()
    app.run(host='0.0.0.0', port=5000)
