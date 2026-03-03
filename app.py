import os
import json
import joblib
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
from google import genai
import os
from dotenv import load_dotenv # <-- Add this

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'AeroGuard_super_secret_key')
socketio = SocketIO(app, cors_allowed_origins="*")
load_dotenv()
# Initialize Gemini Client
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if gemini_api_key:
    gemini_client = genai.Client(api_key=gemini_api_key)
else:
    print("WARNING: GEMINI_API_KEY environment variable not set.")
    gemini_client = None

# --- Load ML Artifacts (Phase 3 Addition) ---
print("Loading AeroGuard ML models...")
try:
    ids_model = joblib.load('nstream_model.pkl')
    scaler = joblib.load('nstream_scaler.pkl')
    app_encoder = joblib.load('nstream_app_encoder.pkl')
    feature_columns = joblib.load('nstream_features.pkl')
    
    with open('whitelist.json', 'r') as f:
        whitelist_ips = json.load(f)
        
    print("Models and whitelist loaded successfully.")
except FileNotFoundError as e:
    print(f"CRITICAL ERROR: Could not find ML artifact. {e}")
    print("Please ensure nstream_model.pkl, nstream_scaler.pkl, nstream_app_encoder.pkl, nstream_features.pkl, and whitelist.json are in the root directory.")

# --- REST API Routes ---

@app.route('/')
def index():
    if 'gemini_uses' not in session:
        session['gemini_uses'] = 0
    return render_template('index.html', free_uses_remaining=5 - session['gemini_uses'])

@app.route('/upload_features', methods=['POST'])
def upload_features():
    """Receives the extracted features, runs the IDS model, and emits anomalies."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    feature_file = request.files['file']
    temp_path = "temp_cloud_features.pkl"
    feature_file.save(temp_path)
    
    try:
        # 1. Load the data
        df = pd.read_pickle(temp_path)
        
        # 2. Filter out Whitelisted IPs
        initial_count = len(df)
        df = df[~df['src_ip'].isin(whitelist_ips) & ~df['dst_ip'].isin(whitelist_ips)]
        print(f"Filtered out {initial_count - len(df)} whitelisted flows.")

        if df.empty:
            socketio.emit('analysis_complete', {'anomalies': [], 'message': 'All traffic was whitelisted.'})
            return jsonify({"message": "Processed successfully"}), 200

        # 3. Preprocess categorical data (handle unseen apps gracefully)
        if 'application_name' in df.columns:
            # If the app wasn't in the training data, map it to a default integer (e.g., -1) to avoid crashing
            known_apps = set(app_encoder.classes_)
            df['app_name_encoded'] = df['application_name'].apply(
                lambda x: app_encoder.transform([x])[0] if x in known_apps else -1
            )

        # 4. Prepare features for the model
        # Ensure we only use the exact columns the model was trained on
        X = df[feature_columns].copy()
        
        # Handle any stray NaNs or infinite values just like the training script
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)

        # 5. Scale and Predict
        X_scaled = scaler.transform(X)
        predictions = ids_model.predict(X_scaled)
        
        # 6. Extract Anomalies (-1 in Isolation Forest means anomaly)
        df['prediction'] = predictions
        anomalies_df = df[df['prediction'] == -1]
        
        # Format anomalies for the frontend (taking the top 10 most severe/relevant to avoid overwhelming the UI)
        formatted_anomalies = []
        for index, row in anomalies_df.head(10).iterrows():
            formatted_anomalies.append({
                "id": str(index),
                "src_ip": row.get('src_ip', 'Unknown'),
                "dst_ip": row.get('dst_ip', 'Unknown'),
                "protocol": row.get('protocol', 'Unknown'),
                "app": row.get('application_name', 'Unknown'),
                "bytes": row.get('bidirectional_bytes', 0),
                "details": f"Port {row.get('dst_port', 'N/A')}, Duration: {row.get('bidirectional_duration_ms', 0)}ms"
            })
            
        print(f"Analysis complete: Found {len(anomalies_df)} anomalies out of {len(df)} flows.")
        
        # 7. Send results to the web dashboard
        socketio.emit('analysis_complete', {
            'anomalies': formatted_anomalies,
            'total_flows_analyzed': len(df),
            'total_anomalies_found': len(anomalies_df)
        })
        
    except Exception as e:
        print(f"Error during ML processing: {e}")
        socketio.emit('agent_progress', {'status': f'Cloud analysis error: {str(e)}'})
        return jsonify({"error": str(e)}), 500
        
    finally:
        # Clean up the cloud's temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return jsonify({"message": "Features processed successfully"}), 200

@app.route('/analyze_anomaly', methods=['POST'])
def analyze_anomaly():
    """Handles the Gemini AI explanation with a 5-use limit."""
    if 'gemini_uses' not in session:
        session['gemini_uses'] = 0
        
    if session['gemini_uses'] >= 5:
        return jsonify({"error": "Free limit reached. Please upgrade to continue using AI analysis."}), 403

    if not gemini_client:
        return jsonify({"error": "Gemini API key is not configured on the server."}), 500

    data = request.json
    anomaly_details = data.get('anomaly_details', {})
    
    # Construct a highly specific, strictly formatted prompt
    prompt = f"""
    You are AeroGuard AI, an expert cybersecurity analyst. Analyze this network anomaly. 
    Rule 1: Be extremely concise. 
    Rule 2: Do NOT mention 'your model', 'your project', 'machine learning', or 'Isolation Forest'. 
    Rule 3: Format your response exactly as two short bullet points.
    
    1. **Potential Threat**: (Briefly explain what this traffic pattern usually indicates)
    2. **Mitigation**: (One actionable step to secure the network)
    
    Anomaly Details:
    - Source IP: {anomaly_details.get('src_ip')}
    - Dest IP: {anomaly_details.get('dst_ip')}
    - Protocol ID: {anomaly_details.get('protocol')}
    - Application: {anomaly_details.get('app')}
    - Bytes Transferred: {anomaly_details.get('bytes')}
    - Extra Details: {anomaly_details.get('details')}
    """
    
    try:
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        session['gemini_uses'] += 1
        
        return jsonify({
            "explanation": response.text,
            "remaining_uses": 5 - session['gemini_uses']
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- WebSocket Events ---

@socketio.on('start_capture')
def handle_start_capture(data):
    duration = data.get('duration') 
    emit('trigger_agent_capture', {'duration': duration}, broadcast=True)

@socketio.on('agent_progress')
def handle_agent_progress(data):
    emit('update_ui_progress', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)