#!/usr/bin/env python3
"""
Simple test version to verify everything works
"""

from flask import Flask, jsonify, request
import threading
import time
import subprocess

app = Flask(__name__)

# Simple in-memory storage
scans = {}
scan_counter = 0

def run_nmap(target):
    """Simple nmap runner"""
    try:
        cmd = f"nmap -sS -T4 --top-ports 100 --open {target}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout
    except:
        return "Scan failed"

def background_scan(scan_id, target):
    """Background scan function"""
    scans[scan_id]['status'] = 'running'
    scans[scan_id]['logs'].append(f"Starting scan on {target}")
    
    # Run nmap
    output = run_nmap(target)
    scans[scan_id]['logs'].append(f"Nmap output: {output[:200]}...")
    
    # Parse ports
    open_ports = []
    for line in output.split('\n'):
        if '/tcp' in line and 'open' in line:
            open_ports.append(line.strip())
    
    scans[scan_id]['results'] = {'ports': open_ports}
    scans[scan_id]['status'] = 'completed'
    scans[scan_id]['logs'].append(f"Scan completed. Found {len(open_ports)} ports")

@app.route('/')
def home():
    return """
    <h1>🔥 Akuma Scanner - Simple Test</h1>
    <h2>Test Commands:</h2>
    <p><code>curl -X POST -H "Content-Type: application/json" -d '{"target":"terem.ru"}' http://localhost:5000/scan</code></p>
    <p><code>curl http://localhost:5000/status/1</code></p>
    <p><code>curl http://localhost:5000/logs/1</code></p>
    """

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_counter
    scan_counter += 1
    
    data = request.get_json()
    target = data.get('target', 'example.com')
    
    # Create scan
    scans[scan_counter] = {
        'id': scan_counter,
        'target': target,
        'status': 'pending',
        'logs': [],
        'results': {}
    }
    
    # Start background thread
    thread = threading.Thread(target=background_scan, args=(scan_counter, target))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_counter,
        'target': target,
        'status': 'started'
    })

@app.route('/status/<int:scan_id>')
def get_status(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'scan_id': scan_id,
        'target': scans[scan_id]['target'],
        'status': scans[scan_id]['status'],
        'results': scans[scan_id]['results']
    })

@app.route('/logs/<int:scan_id>')
def get_logs(scan_id):
    if scan_id not in scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'scan_id': scan_id,
        'logs': scans[scan_id]['logs']
    })

@app.route('/scans')
def list_scans():
    return jsonify({'scans': list(scans.values())})

if __name__ == '__main__':
    print("🚀 Starting Simple Akuma Test Server...")
    print("🎯 Test with: curl -X POST -H 'Content-Type: application/json' -d '{\"target\":\"terem.ru\"}' http://localhost:5000/scan")
    app.run(host='0.0.0.0', port=5000, debug=True)
