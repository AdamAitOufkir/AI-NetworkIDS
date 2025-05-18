import pandas as pd
import numpy as np
import joblib
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from threading import Thread
import time
import socket
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler,OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
from rich.console import Console
import script  # Import functions from your main script
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Create a Flask app
app = Flask(__name__)

# Create console for rich output
console = Console()

# Email configuration from environment variables
EMAIL_ALERTS_ENABLED = os.getenv('EMAIL_ALERTS_ENABLED', 'true').lower() == 'true'
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS', 'adamoufkir05@gmail.com')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
ATTACK_THRESHOLD = int(os.getenv('ATTACK_THRESHOLD', 15))
EMAIL_COOLDOWN = int(os.getenv('EMAIL_COOLDOWN', 5))

# Log email configuration (without password)
console.log(f"[blue]Email alerts enabled: {EMAIL_ALERTS_ENABLED}[/blue]")
console.log(f"[blue]Email destination: {EMAIL_ADDRESS}[/blue]")
console.log(f"[blue]Attack threshold: {ATTACK_THRESHOLD}[/blue]")
console.log(f"[blue]Email cooldown: {EMAIL_COOLDOWN} minutes[/blue]")

# Track email sending status
last_email_time = None
attack_count_since_last_email = 0

# Global variables to store traffic data and predictions
captured_packets = []
predictions = []
running = True
connection_stats = {}  # Track connection statistics
service_stats = {}     # Track service statistics

# Load trained models and preprocessors
console.log("Loading models and preprocessors...")
try:
    scaler = joblib.load("scaler.pkl")
    encoder = joblib.load("encoder.pkl")
    dt_model = joblib.load("dt_model.pkl")
    console.log("[green]Models loaded successfully![/green]")
except Exception as e:
    console.log(f"[red]Error loading models: {e}[/red]")

def extract_features(packet):
    """Extract relevant features from a packet - enhanced to better detect attack patterns"""
    try:
        # Initialize default feature values
        features = {
            'duration': 0,
            'protocol_type': 'tcp',  # Default protocol
            'service': 'http',  # Default service
            'flag': 'SF',  # Default flag (normal connection)
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

        # Extract basic packet info
        if IP in packet:
            # Check for IP-based anomalies
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Check for suspicious patterns
            is_broadcast = ip_dst.endswith('.255')
            is_multicast = ip_dst.startswith('224.') or ip_dst.startswith('239.')
            
            # Update connection stats based on recent traffic
            global connection_stats
            src_key = f"{ip_src}"
            dst_key = f"{ip_dst}"
            
            # Update connection count (how many connections from this source)
            if src_key in connection_stats:
                connection_stats[src_key]['count'] += 1
                connection_stats[src_key]['last_seen'] = time.time()
            else:
                connection_stats[src_key] = {'count': 1, 'last_seen': time.time(), 'error_count': 0}
            
            # Get the connection count for this source
            features['count'] = min(connection_stats[src_key]['count'], 255)  # Cap at 255 for model compatibility
            
            # Determine protocol type
            if TCP in packet:
                features['protocol_type'] = 'tcp'
                # Set service based on destination port
                dport = packet[TCP].dport
                if dport == 80 or dport == 443:
                    features['service'] = 'http'
                elif dport == 21:
                    features['service'] = 'ftp'
                elif dport == 23:
                    features['service'] = 'telnet'
                elif dport == 25:
                    features['service'] = 'smtp'
                else:
                    features['service'] = 'private'
                
                # Track service count
                srv_key = f"{features['service']}"
                if srv_key in service_stats:
                    service_stats[srv_key] += 1
                else:
                    service_stats[srv_key] = 1
                
                features['srv_count'] = min(service_stats[srv_key], 255)  # Cap at 255
                
                # Set flag based on TCP flags (enhanced detection)
                flags = packet[TCP].flags
                if flags & 0x02 and flags & 0x10:  # SYN+ACK
                    features['flag'] = 'S1'
                elif flags & 0x02:  # SYN
                    features['flag'] = 'S0'
                    # SYN packets without established connection can be suspicious
                    connection_stats[src_key]['error_count'] += 1
                    # Calculate error rates - high values indicate potential SYN scan or DoS
                    features['serror_rate'] = min(connection_stats[src_key]['error_count'] / max(connection_stats[src_key]['count'], 1), 1.0)
                    features['srv_serror_rate'] = features['serror_rate']
                    
                    # Update these fields to make SYN flood more detectable
                    if connection_stats[src_key]['count'] > 15 and features['serror_rate'] > 0.7:
                        features['dst_host_serror_rate'] = features['serror_rate']
                        features['dst_host_srv_serror_rate'] = features['serror_rate']
                elif flags & 0x01:  # FIN
                    features['flag'] = 'SF'
                elif flags & 0x04:  # RST
                    features['flag'] = 'REJ'
                    # RST packets can indicate port scanning
                    connection_stats[src_key]['error_count'] += 1
                    features['rerror_rate'] = min(connection_stats[src_key]['error_count'] / max(connection_stats[src_key]['count'], 1), 1.0)
                    features['srv_rerror_rate'] = features['rerror_rate']
                    
                    # Update these fields for RST-based scans
                    if connection_stats[src_key]['count'] > 10 and features['rerror_rate'] > 0.7:
                        features['dst_host_rerror_rate'] = features['rerror_rate']
                        features['dst_host_srv_rerror_rate'] = features['rerror_rate']
                
                # Set urgent if URG flag is set
                if flags & 0x20:  # URG flag
                    features['urgent'] = 1
                
            elif UDP in packet:
                features['protocol_type'] = 'udp'
                features['service'] = 'private'
                features['flag'] = 'SF'
                
                # UDP flood detection
                if connection_stats[src_key]['count'] > 30:
                    # Many UDP packets from same source is suspicious
                    features['serror_rate'] = 0.8
                    features['dst_host_serror_rate'] = 0.8
                
            elif ICMP in packet:
                features['protocol_type'] = 'icmp'
                features['service'] = 'eco_i'
                features['flag'] = 'SF'
                
                # ICMP flood detection
                if connection_stats[src_key]['count'] > 20:
                    # Many ICMP packets from same source is suspicious
                    features['serror_rate'] = 0.9
                    features['dst_host_serror_rate'] = 0.9
            
            # Set bytes
            features['src_bytes'] = len(packet)
            features['dst_bytes'] = len(packet.payload) if hasattr(packet, 'payload') else 0
            
            # Check for land attack (same source and destination)
            if packet[IP].src == packet[IP].dst:
                features['land'] = 1
                # Land attack detection enhancement
                features['serror_rate'] = 1.0
                features['srv_serror_rate'] = 1.0
                features['dst_host_serror_rate'] = 1.0
                features['dst_host_srv_serror_rate'] = 1.0
            
            # Check for fragmentation
            if packet[IP].flags & 0x01 or packet[IP].frag != 0:  # More fragments or fragment offset
                features['wrong_fragment'] = 1
                # Fragmentation attacks detection enhancement
                features['serror_rate'] = 0.8
                
            # Check if traffic is normal or potentially malicious based on patterns
            if (is_broadcast or is_multicast) and features['protocol_type'] == 'udp':
                # Broadcast/multicast UDP is often legitimate
                pass
            elif features['count'] > 100 or features['serror_rate'] > 0.5 or features['rerror_rate'] > 0.5:
                # High connection count or error rates are suspicious
                features['hot'] = 1
                
            # Clean up old stats to prevent memory leaks
            current_time = time.time()
            for k in list(connection_stats.keys()):
                if current_time - connection_stats[k]['last_seen'] > 300:  # 5 minutes
                    del connection_stats[k]

        return features
    except Exception as e:
        console.log(f"[red]Error extracting features: {e}[/red]")
        return None

def packet_callback(packet):
    """Process each captured packet"""
    global captured_packets, attack_count_since_last_email
    
    if IP in packet:
        try:
            # Whitelist check for dashboard traffic between client and server
            if (packet[IP].src == "10.0.0.2" and packet[IP].dst == "10.0.0.3") or \
               (packet[IP].src == "10.0.0.3" and packet[IP].dst == "10.0.0.2"):
                # Check if it's web traffic on port 5000 or standard HTTP/HTTPS ports
                if TCP in packet and (packet[TCP].dport == 5000 or packet[TCP].sport == 5000 or 
                                     packet[TCP].dport == 80 or packet[TCP].sport == 80 or
                                     packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    # This is whitelisted dashboard traffic, set prediction to normal
                    prediction = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'protocol': 'tcp',
                        'service': 'http',
                        'dt_prediction': 'Normal',
                        'consensus': 'Normal'
                    }
                    
                    # Add to predictions list (limit to last 500)
                    predictions.append(prediction)
                    if len(predictions) > 500:
                        predictions.pop(0)
                    
                    # Add to captured packets list (limit to last 200)
                    captured_packets.append({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': packet[IP].src, 
                        'dst_ip': packet[IP].dst,
                        'protocol': 'tcp',
                        'service': 'http',
                        'prediction': 'Normal'
                    })
                    if len(captured_packets) > 200:
                        captured_packets.pop(0)
                    
                    # We quietly process this as normal traffic, no need to log
                    return
            
            # For all other traffic, proceed with normal processing
            # Extract features from packet
            features = extract_features(packet)
            if features:
                # Convert to DataFrame for prediction
                df = pd.DataFrame([features])
                
                # Preprocess the data
                preprocessed_df = script.preprocess(df, is_train=False)
                
                # Make predictions using only the Decision Tree model
                dt_pred = dt_model.predict(preprocessed_df)[0]
                
                # Use the Decision Tree prediction directly without consensus
                consensus = dt_pred
                
                # Create prediction record
                prediction = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': features['protocol_type'],
                    'service': features['service'],
                    'dt_prediction': 'Normal' if dt_pred == 0 else 'Attack',
                    'consensus': 'Normal' if consensus == 0 else 'Attack'
                }
                
                # Add to predictions list (limit to last 500)
                predictions.append(prediction)
                if len(predictions) > 500:
                    predictions.pop(0)
                
                # Add to captured packets list (limit to last 200)
                captured_packets.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': packet[IP].src, 
                    'dst_ip': packet[IP].dst,
                    'protocol': features['protocol_type'],
                    'service': features['service'],
                    'prediction': 'Normal' if consensus == 0 else 'Attack'
                })
                if len(captured_packets) > 200:
                    captured_packets.pop(0)
                
                # Log the prediction
                pred_str = 'Normal' if consensus == 0 else 'Attack'
                console.log(f"[{'green' if consensus == 0 else 'red'}]Prediction: {pred_str} - {packet[IP].src} -> {packet[IP].dst} ({features['protocol_type']})[/]")
                
                # If attack is detected, increment the counter and check threshold
                if consensus == 1:  # Attack detected
                    attack_count_since_last_email += 1
                    console.log(f"[yellow]Attack count: {attack_count_since_last_email}/{ATTACK_THRESHOLD}[/yellow]")
                    check_attack_threshold()
        
        except Exception as e:
            console.log(f"[red]Error processing packet: {e}[/red]")

def start_sniffer():
    """Start packet capturing"""
    global running
    console.log("[yellow]Starting packet capture on eth1 interface...[/yellow]")
    while running:
        try:
            # Capture packets on eth1 interface specifically
            sniff(prn=packet_callback, store=False, iface="eth1")
            time.sleep(1)  # Short delay to prevent CPU overuse
        except Exception as e:
            console.log(f"[red]Sniffing error: {e}[/red]")
            time.sleep(5)  # Longer delay if there's an error

@app.route('/')
def home():
    """Home page with IDS dashboard"""
    return render_template('ids_dashboard.html')

@app.route('/api/traffic')
def get_traffic():
    """API endpoint to get captured traffic data"""
    return jsonify(captured_packets)

@app.route('/api/predictions')
def get_predictions():
    """API endpoint to get prediction data"""
    return jsonify(predictions)

@app.route('/api/stats')
def get_stats():
    """API endpoint to get summary statistics"""
    if not predictions:
        return jsonify({
            'total': 0,
            'normal': 0,
            'attack': 0,
            'attack_percentage': 0
        })
    
    total = len(predictions)
    normal = sum(1 for p in predictions if p['consensus'] == 'Normal')
    attack = total - normal
    
    return jsonify({
        'total': total,
        'normal': normal,
        'attack': attack,
        'attack_percentage': round((attack / total) * 100, 2) if total > 0 else 0
    })

@app.route('/api/retrain', methods=['POST'])
def retrain_model():
    """API endpoint to retrain the model with custom parameters"""
    global scaler, encoder, dt_model  # Removed rf_model reference
    
    try:
        # Get parameters from the request
        data = request.json
        test_size = float(data.get('test_size', 0.2))
        random_state = int(data.get('random_state', 42))
        
        # Validate test_size
        if test_size <= 0 or test_size >= 1:
            return jsonify({'status': 'error', 'message': 'Test size must be between 0 and 1'})
        
        console.log(f"[yellow]Retraining model with test_size={test_size}, random_state={random_state}[/yellow]")
        
        # Load the dataset
        console.log("[blue]Loading dataset...[/blue]")
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 
            'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'outcome', 'level'
        ]
        
        data_train = pd.read_csv("nsl-kdd/KDDTrain+.txt", names=columns)
        
        # Convert labels
        console.log("[blue]Converting outcome to binary labels...[/blue]")
        data_train.loc[data_train['outcome'] == "normal", "outcome"] = 0
        data_train.loc[data_train['outcome'] != 0, "outcome"] = 1
        
        # Preprocess the data
        console.log("[blue]Preprocessing data...[/blue]")
        cat_cols = ['protocol_type', 'service', 'flag']
        num_cols = [col for col in data_train.columns if col not in cat_cols + ['outcome', 'level']]
        
        # Handle categorical features
        encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        encoded = pd.DataFrame(encoder.fit_transform(data_train[cat_cols]))
        encoded.columns = encoder.get_feature_names_out(cat_cols)
        
        data_train = data_train.drop(cat_cols, axis=1).reset_index(drop=True)
        data_train = pd.concat([data_train, encoded], axis=1)
        
        # Scale numerical features
        scaler = RobustScaler()
        data_train[num_cols] = scaler.fit_transform(data_train[num_cols])
        
        # Save preprocessors
        console.log("[blue]Saving preprocessors...[/blue]")
        joblib.dump(encoder, "encoder.pkl")
        joblib.dump(scaler, "scaler.pkl")
        
        # Split the data
        console.log(f"[blue]Splitting data with test_size={test_size}...[/blue]")
        X = data_train.drop(['outcome', 'level'], axis=1).values
        y = data_train['outcome'].values.astype('int')
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
        
        # Train the Decision Tree model
        console.log("[blue]Training Decision Tree model...[/blue]")
        dt_model = DecisionTreeClassifier(max_depth=3)
        dt_model.fit(X_train, y_train)
        
        # Save the model
        console.log("[blue]Saving model...[/blue]")
        joblib.dump(dt_model, "dt_model.pkl")
        
        # Evaluate the model
        console.log("[blue]Evaluating model...[/blue]")
        dt_predictions = dt_model.predict(X_test)
        dt_report = classification_report(y_test, dt_predictions, output_dict=True)
        
        console.log("[green]Model retrained and loaded into the current session![/green]")
        
        return jsonify({
            'status': 'success',
            'message': 'Model retrained successfully',
            'results': {
                'decision_tree': {
                    'accuracy': dt_report['accuracy'],
                    'precision': dt_report['weighted avg']['precision'],
                    'recall': dt_report['weighted avg']['recall'],
                    'f1': dt_report['weighted avg']['f1-score']
                }
            }
        })
    
    except Exception as e:
        console.log(f"[red]Error during model retraining: {str(e)}[/red]")
        return jsonify({'status': 'error', 'message': f'Error during retraining: {str(e)}'})

def create_template_directory():
    """Create templates directory if it doesn't exist"""
    import os
    if not os.path.exists('templates'):
        os.makedirs('templates')
        console.log("[green]Created templates directory[/green]")

def create_dashboard_template():
    """Create HTML template for the dashboard without auto-refresh"""
    import os
    
    # Create templates directory if it doesn't exist
    create_template_directory()
    
    # Create dashboard HTML file
    template_path = os.path.join('templates', 'ids_dashboard.html')
    with open(template_path, 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network IDS Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            padding: 20px;
        }
        .card {
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            font-weight: bold;
            background-color: #343a40;
            color: white;
            border-radius: 10px 10px 0 0 !important;
        }
        .table th {
            background-color: #343a40;
            color: white;
        }
        .table-danger {
            background-color: rgba(255, 99, 132, 0.2);
        }
        .alert-count {
            font-size: 24px;
            font-weight: bold;
        }
        .modal-header {
            background-color: #343a40;
            color: white;
        }
        .metric-card {
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ccc;
            margin-bottom: 10px;
        }
        .metric-title {
            font-weight: bold;
            font-size: 1.1em;
        }
        .metric-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        .model-card {
            border-left: 4px solid #28a745;
            padding-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row mb-4">
            <div class="col-md-12">
                <h1 class="text-center">Network Intrusion Detection System Dashboard</h1>
                <p class="text-center text-muted">Monitoring traffic on interface eth1</p>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-header">Statistics</div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6 text-center">
                                <h5>Normal</h5>
                                <p class="alert-count text-success" id="normalCount">0</p>
                            </div>
                            <div class="col-md-6 text-center">
                                <h5>Attack</h5>
                                <p class="alert-count text-danger" id="attackCount">0</p>
                            </div>
                        </div>
                        <div class="progress mt-3" style="height: 30px;">
                            <div class="progress-bar bg-success" id="normalBar" role="progressbar" style="width: 100%">Normal</div>
                            <div class="progress-bar bg-danger" id="attackBar" role="progressbar" style="width: 0%">Attack</div>
                        </div>
                        <div class="mt-3">
                            <button class="btn btn-success btn-block" data-toggle="modal" data-target="#retrainModal">
                                Retrain Models
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-9">
                <div class="card">
                    <div class="card-header">Traffic Analysis</div>
                    <div class="card-body">
                        <canvas id="trafficChart" width="400" height="120"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span>Recent Network Traffic</span>
                        <div>
                            <button id="refreshButton" class="btn btn-primary btn-sm">Refresh Data</button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-sm">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Source IP</th>
                                        <th>Destination IP</th>
                                        <th>Protocol</th>
                                        <th>Service</th>
                                        <th>DT Model</th>
                                        <th>Consensus</th>
                                    </tr>
                                </thead>
                                <tbody id="trafficTable">
                                    <!-- Traffic data will be dynamically added here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Retrain Model Modal -->
    <div class="modal fade" id="retrainModal" tabindex="-1" role="dialog" aria-labelledby="retrainModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="retrainModalLabel">Retrain ML Models</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true" style="color: white;">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <p>Use this form to retrain the machine learning models with different train/test split parameters.</p>
                    </div>
                    
                    <form id="retrainForm">
                        <div class="form-group">
                            <label for="testSize">Test Size (0.1 - 0.9)</label>
                            <input type="range" class="custom-range" id="testSize" min="0.1" max="0.9" step="0.05" value="0.2">
                            <div class="row">
                                <div class="col-6 text-left"><small>10% Test</small></div>
                                <div class="col-6 text-right"><small>90% Test</small></div>
                            </div>
                            <p class="text-center mt-2">
                                Current Split: <span id="testSizeValue" class="font-weight-bold">20%</span> Test / 
                                <span id="trainSizeValue" class="font-weight-bold">80%</span> Train
                            </p>
                        </div>
                        
                        <div class="form-group">
                            <label for="randomState">Random State (1-100)</label>
                            <input type="number" class="form-control" id="randomState" min="1" max="100" value="42">
                            <small class="form-text text-muted">Controls the randomness of the train/test split.</small>
                        </div>
                        
                        <div class="form-group">
                            <button type="submit" class="btn btn-primary btn-block">Retrain Models</button>
                        </div>
                    </form>
                    
                    <div id="trainingStatus" class="alert alert-warning d-none">
                        <p><strong>Training in progress...</strong></p>
                        <p>This may take a few minutes. Please don't close this window.</p>
                        <div class="progress">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
                        </div>
                    </div>
                    
                    <div id="trainingResults" class="d-none">
                        <h5 class="mb-3">Training Results</h5>
                        <div class="row"> 
                            <div class="col-md-6">
                                <div class="model-card">
                                    <h6 class="mb-3">Decision Tree Model</h6>
                                    <div class="row">
                                        <div class="col-6">
                                            <div class="metric-card bg-light">
                                                <div class="metric-title">Accuracy</div>
                                                <div class="metric-value text-primary" id="dtAccuracy">0.00%</div>
                                            </div>
                                        </div>
                                        <div class="col-6">
                                            <div class="metric-card bg-light">
                                                <div class="metric-title">Precision</div>
                                                <div class="metric-value text-success" id="dtPrecision">0.00%</div>
                                            </div>
                                        </div>
                                        <div class="col-6">
                                            <div class="metric-card bg-light">
                                                <div class="metric-title">Recall</div>
                                                <div class="metric-value text-warning" id="dtRecall">0.00%</div>
                                            </div>
                                        </div>
                                        <div class="col-6">
                                            <div class="metric-card bg-light">
                                                <div class="metric-title">F1 Score</div>
                                                <div class="metric-value text-danger" id="dtF1">0.00%</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap and jQuery JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    
    <script>
        // Chart initialization
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Normal Traffic',
                        data: [],
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 2,
                        tension: 0.1
                    },
                    {
                        label: 'Attack Traffic',
                        data: [],
                        backgroundColor: 'rgba(255, 99, 132, 0.2)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 2,
                        tension: 0.1
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Packet Count'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                }
            }
        });

        // Store historical counts for the chart
        let normalCounts = Array(20).fill(0);
        let attackCounts = Array(20).fill(0);
        let timeLabels = Array(20).fill('');
        
        // Function to format time for display
        function formatTime(dateString) {
            const date = new Date(dateString);
            return date.toLocaleTimeString();
        }

        // Function to update the dashboard with new data
        function updateDashboard() {
            // Fetch traffic statistics
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('normalCount').textContent = data.normal;
                    document.getElementById('attackCount').textContent = data.attack;
                    
                    // Update progress bar
                    const normalPercentage = data.total > 0 ? (data.normal / data.total) * 100 : 100;
                    const attackPercentage = data.total > 0 ? (data.attack / data.total) * 100 : 0;
                    
                    document.getElementById('normalBar').style.width = normalPercentage + '%';
                    document.getElementById('attackBar').style.width = attackPercentage + '%';
                    
                    // Update traffic chart
                    const now = new Date().toLocaleTimeString();
                    
                    // Shift arrays to make room for new data
                    normalCounts.shift();
                    attackCounts.shift();
                    timeLabels.shift();
                    
                    // Add new data
                    normalCounts.push(data.normal);
                    attackCounts.push(data.attack);
                    timeLabels.push(now);
                    
                    // Update chart data
                    trafficChart.data.labels = timeLabels;
                    trafficChart.data.datasets[0].data = normalCounts;
                    trafficChart.data.datasets[1].data = attackCounts;
                    trafficChart.update();
                })
                .catch(error => console.error('Error fetching stats:', error));
            
            // Fetch prediction data
            fetch('/api/predictions')
                .then(response => response.json())
                .then(data => {
                    const tableBody = document.getElementById('trafficTable');
                    tableBody.innerHTML = ''; // Clear existing data
                    
                    // Add rows for each prediction, most recent first
                    data.slice().reverse().forEach(packet => {
                        const row = document.createElement('tr');
                        
                        // Add class for attack rows
                        if (packet.consensus === 'Attack') {
                            row.classList.add('table-danger');
                        }
                        
                        row.innerHTML = `
                            <td>${packet.timestamp}</td>
                            <td>${packet.src_ip}</td>
                            <td>${packet.dst_ip}</td>
                            <td>${packet.protocol}</td>
                            <td>${packet.service}</td>
                            <td>${packet.dt_prediction}</td>
                            <td><strong>${packet.consensus}</strong></td>
                        `;
                        
                        tableBody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error fetching traffic data:', error));
        }

        // Initial update
        updateDashboard();
        
        // Add manual refresh button handler
        document.getElementById('refreshButton').addEventListener('click', updateDashboard);
        
        // Retrain model slider value display
        document.getElementById('testSize').addEventListener('input', function() {
            const testSize = parseFloat(this.value);
            document.getElementById('testSizeValue').textContent = (testSize * 100).toFixed(0) + '%';
            document.getElementById('trainSizeValue').textContent = (100 - (testSize * 100)).toFixed(0) + '%';
        });
        
        // Retrain model form submission
        document.getElementById('retrainForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form values
            const testSize = parseFloat(document.getElementById('testSize').value);
            const randomState = parseInt(document.getElementById('randomState').value);
            
            // Show training status
            document.getElementById('trainingStatus').classList.remove('d-none');
            document.getElementById('trainingResults').classList.add('d-none');
            
            // Disable form
            const form = document.getElementById('retrainForm');
            Array.from(form.elements).forEach(input => input.disabled = true);
            
            // Make API request to retrain model
            fetch('/api/retrain', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    test_size: testSize,
                    random_state: randomState
                })
            })
            .then(response => response.json())
            .then(data => {
                // Hide training status
                document.getElementById('trainingStatus').classList.add('d-none');
                
                if (data.status === 'success') {
                    // Show training results
                    document.getElementById('trainingResults').classList.remove('d-none');
                    
                    // Update metrics
                    document.getElementById('dtAccuracy').textContent = (data.results.decision_tree.accuracy * 100).toFixed(2) + '%';
                    document.getElementById('dtPrecision').textContent = (data.results.decision_tree.precision * 100).toFixed(2) + '%';
                    document.getElementById('dtRecall').textContent = (data.results.decision_tree.recall * 100).toFixed(2) + '%';
                    document.getElementById('dtF1').textContent = (data.results.decision_tree.f1 * 100).toFixed(2) + '%';
                    
                    alert('Models retrained successfully!');
                } else {
                    alert('Error retraining models: ' + data.message);
                }
                
                // Re-enable form
                Array.from(form.elements).forEach(input => input.disabled = false);
            })
            .catch(error => {
                console.error('Error retraining models:', error);
                document.getElementById('trainingStatus').classList.add('d-none');
                alert('Error retraining models. See console for details.');
                
                // Re-enable form
                Array.from(form.elements).forEach(input => input.disabled = false);
            });
        });
    </script>
</body>
</html>
        ''')
    console.log(f"[green]Created dashboard template at {template_path}[/green]")

def send_email_alert(attack_details):
    """Send an email alert with attack details"""
    global last_email_time, attack_count_since_last_email
    
    if not EMAIL_ALERTS_ENABLED:
        console.log("[yellow]Email alerts are disabled. Skipping alert.[/yellow]")
        return False
    
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        console.log("[yellow]Email credentials not configured. Skipping alert.[/yellow]")
        return False
    
    # Check if we're within the cooldown period
    current_time = datetime.now()
    if last_email_time and (current_time - last_email_time < timedelta(minutes=EMAIL_COOLDOWN)):
        console.log(f"[yellow]Email cooldown period active. Skipping alert. Next alert in {EMAIL_COOLDOWN - ((current_time - last_email_time).seconds // 60)} minutes[/yellow]")
        return False
    
    try:
        # Prepare email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USERNAME
        msg['To'] = EMAIL_ADDRESS
        msg['Subject'] = f"⚠️ ALERT: {attack_count_since_last_email} Network Attacks Detected!"
        
        # Email body with HTML formatting
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h2 style="color: #d9534f; border-bottom: 1px solid #e0e0e0; padding-bottom: 10px;">🚨 Network Intrusion Alert</h2>
            
            <p>Your AI-Based Network IDS has detected <strong style="color: #d9534f;">{attack_count_since_last_email} potential attack(s)</strong> 
            in the last monitoring period.</p>
            
            <h3 style="margin-top: 20px; color: #333;">Attack Details:</h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                <tr style="background-color: #f5f5f5;">
                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Time</th>
                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Source IP</th>
                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Destination IP</th>
                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Protocol</th>
                    <th style="padding: 8px; text-align: left; border: 1px solid #ddd;">Service</th>
                </tr>
        """
        
        # Add up to 10 most recent attack details
        for attack in attack_details[:10]:
            body += f"""
                <tr>
                    <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{attack['timestamp']}</td>
                    <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{attack['src_ip']}</td>
                    <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{attack['dst_ip']}</td>
                    <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{attack['protocol']}</td>
                    <td style="padding: 8px; text-align: left; border: 1px solid #ddd;">{attack['service']}</td>
                </tr>
            """
        
        # Complete the HTML email
        body += """
            </table>
            
            <p style="margin-top: 20px;">View the <a href="http://localhost:5000" style="color: #337ab7;">IDS Dashboard</a> for more details.</p>
            
            <div style="margin-top: 30px; padding-top: 10px; border-top: 1px solid #e0e0e0; color: #777; font-size: 12px;">
                <p>This is an automated alert from your AI-Based Network Intrusion Detection System.</p>
            </div>
        </body>
        </html>
        """
        
        # Attach the HTML body
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        console.log(f"[green]Email alert sent to {EMAIL_ADDRESS}[/green]")
        
        # Update email tracking
        last_email_time = current_time
        attack_count_since_last_email = 0
        
        return True
        
    except Exception as e:
        console.log(f"[red]Error sending email alert: {e}[/red]")
        return False

def check_attack_threshold():
    """Check if enough attacks have occurred to trigger an email alert"""
    global attack_count_since_last_email
    
    if attack_count_since_last_email >= ATTACK_THRESHOLD:
        # Get recent attack details to include in the email
        attack_details = []
        for packet in reversed(captured_packets):
            if packet.get('prediction') == 'Attack':
                attack_details.append(packet)
            if len(attack_details) >= 10:  # Limit to 10 most recent attacks
                break
        
        if attack_details:
            # Send email alert
            send_email_alert(attack_details)
        else:
            console.log("[yellow]Attack threshold reached but no attack details found.[/yellow]")

if __name__ == '__main__':
    # Create the dashboard template
    create_dashboard_template()
    
    # Start packet sniffer in a separate thread
    sniffer_thread = Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Start the web server
    console.log("[bold green]Starting IDS server on port 5000...[/bold green]")
    console.log("[cyan]Access the dashboard at http://localhost:5000[/cyan]")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    
    # When Flask exits, stop the sniffer
    running = False