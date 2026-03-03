// Initialize WebSocket connection to the Flask server
const socket = io();

// DOM Elements
const startBtn = document.getElementById('start-btn');
const durationSelect = document.getElementById('capture-duration');
const progressContainer = document.getElementById('progress-container');
const statusText = document.getElementById('status-text');
const resultsPanel = document.getElementById('results-panel');
const anomalyBody = document.getElementById('anomaly-body');
const summaryText = document.getElementById('summary-text');
const usesRemainingSpan = document.getElementById('uses-remaining');

// --- WebSocket Listeners ---

// Listen for live progress updates from the local agent
socket.on('update_ui_progress', (data) => {
    statusText.innerText = data.status;
});

// Listen for the final ML analysis results from the cloud server
socket.on('analysis_complete', (data) => {
    progressContainer.classList.add('hidden');
    startBtn.disabled = false;
    
    // Show results panel
    resultsPanel.classList.remove('hidden');
    summaryText.innerText = `Analyzed ${data.total_flows_analyzed} flows. Found ${data.total_anomalies_found} anomalies.`;
    
    // Clear previous results
    anomalyBody.innerHTML = '';
    
    if (data.anomalies.length === 0) {
        anomalyBody.innerHTML = '<tr><td colspan="5">No anomalies detected. Network is secure.</td></tr>';
        return;
    }

    // Populate the table
    data.anomalies.forEach(anomaly => {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${anomaly.src_ip}</td>
            <td>${anomaly.dst_ip}</td>
            <td>${anomaly.app} (Proto: ${anomaly.protocol})</td>
            <td>${anomaly.details} <br><small>${anomaly.bytes} bytes</small></td>
            <td>
                <button class="ai-btn" onclick='analyzeWithAI(${JSON.stringify(anomaly)})'>
                    Analyze with AI
                </button>
            </td>
        `;
        anomalyBody.appendChild(row);
    });
});

// --- UI Actions ---

function startCapture() {
    const duration = durationSelect.value;
    
    // Update UI state
    startBtn.disabled = true;
    resultsPanel.classList.add('hidden');
    progressContainer.classList.remove('hidden');
    statusText.innerText = 'Sending command to local agent...';
    
    // Tell the cloud server to trigger the local agent
    socket.emit('start_capture', { duration: duration });
}

async function analyzeWithAI(anomalyData) {
    const modal = document.getElementById('ai-modal');
    const aiLoading = document.getElementById('ai-loading');
    const aiExplanation = document.getElementById('ai-explanation');
    
    modal.classList.remove('hidden');
    aiExplanation.innerText = '';
    aiLoading.classList.remove('hidden');
    
    try {
        const response = await fetch('/analyze_anomaly', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ anomaly_details: anomalyData })
        });
        
        const result = await response.json();
        aiLoading.classList.add('hidden');
        
        if (response.ok) {
            // Update the UI with Gemini's explanation and update remaining uses
            aiExplanation.innerText = result.explanation;
            usesRemainingSpan.innerText = result.remaining_uses;
        } else {
            aiExplanation.innerText = `Error: ${result.error}`;
        }
    } catch (error) {
        aiLoading.classList.add('hidden');
        aiExplanation.innerText = 'Failed to connect to the server.';
    }
}

function closeModal() {
    document.getElementById('ai-modal').classList.add('hidden');
}