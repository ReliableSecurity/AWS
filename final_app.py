#!/usr/bin/env python3
"""
Akuma Advanced Pentest Scanner - Flask Web Interface
Fixed version with working scanner integration
"""

import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
from complete_scanner import start_scan_thread

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akuma_scanner_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akuma_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Global scan progress tracking
scan_progress_data = {}
scan_logs_data = {}

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    targets = db.Column(db.Text)  # JSON string of targets
    status = db.Column(db.String(20), default='pending')
    progress = db.Column(db.Integer, default=0)
    current_phase = db.Column(db.String(50))
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Options
    subdomain_enum = db.Column(db.Boolean, default=False)
    directory_fuzz = db.Column(db.Boolean, default=False)
    fuzz_depth = db.Column(db.Integer, default=1)
    
    def get_targets(self):
        try:
            return json.loads(self.targets) if self.targets else []
        except:
            return self.targets.split(',') if self.targets else []

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    result_type = db.Column(db.String(50), nullable=False)  # port, subdomain, vulnerability, etc.
    data = db.Column(db.Text)  # JSON data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper functions
def get_scan_progress(scan_id):
    """Get current scan progress and phase information"""
    if scan_id in scan_progress_data:
        return scan_progress_data[scan_id]
    
    # Default progress info
    scan = db.session.get(Scan, scan_id)
    if scan:
        return {
            'progress': scan.progress,
            'phase': scan.current_phase or 'pending',
            'status': scan.status
        }
    
    return {
        'progress': 0,
        'phase': 'pending',
        'status': 'pending'
    }

def get_scan_logs(scan_id):
    """Get current scan logs"""
    return scan_logs_data.get(scan_id, [])

def update_scan_progress(scan_id, progress, phase, status=None):
    """Update scan progress in both memory and database"""
    global scan_progress_data
    
    scan_progress_data[scan_id] = {
        'progress': progress,
        'phase': phase,
        'status': status or 'running'
    }
    
    # Update database
    try:
        scan = db.session.get(Scan, scan_id)
        if scan:
            scan.progress = progress
            scan.current_phase = phase
            if status:
                scan.status = status
            if status == 'running' and not scan.started_at:
                scan.started_at = datetime.utcnow()
            elif status == 'completed':
                scan.completed_at = datetime.utcnow()
            
            db.session.commit()
            print(f"[DEBUG] Updated scan {scan_id}: {progress}% - {phase}")
    except Exception as e:
        print(f"[ERROR] Database update failed: {e}")
        db.session.rollback()

def add_scan_log(scan_id, message):
    """Add log message to scan logs"""
    global scan_logs_data
    
    if scan_id not in scan_logs_data:
        scan_logs_data[scan_id] = []
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    scan_logs_data[scan_id].append(log_entry)
    
    # Keep only last 1000 log entries
    if len(scan_logs_data[scan_id]) > 1000:
        scan_logs_data[scan_id] = scan_logs_data[scan_id][-1000:]
    
    print(f"[AKUMA-{scan_id}] {log_entry}")

# Routes
@app.route('/')
def dashboard():
    total_scans = Scan.query.count()
    running_scans = Scan.query.filter_by(status='running').count()
    completed_scans = Scan.query.filter_by(status='completed').count()
    failed_scans = Scan.query.filter_by(status='failed').count()
    
    stats = {
        'total_scans': total_scans,
        'running_scans': running_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/api/dashboard/stats')
def api_dashboard_stats():
    total_scans = Scan.query.count()
    running_scans = Scan.query.filter_by(status='running').count()
    completed_scans = Scan.query.filter_by(status='completed').count()
    failed_scans = Scan.query.filter_by(status='failed').count()
    
    return jsonify({
        'total_scans': total_scans,
        'running_scans': running_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans
    })

@app.route('/scans')
def scans():
    page = request.args.get('page', 1, type=int)
    scans = Scan.query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('scans.html', scans=scans)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        print(f"[DEBUG] Starting scan with data: {data}")
        
        # Create new scan record
        scan = Scan(
            name=data.get('name', 'Unnamed Scan'),
            targets=json.dumps(data.get('targets', [])),
            subdomain_enum=data.get('subdomain_enum', False),
            directory_fuzz=data.get('directory_fuzz', False),
            fuzz_depth=data.get('fuzz_depth', 1),
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        print(f"[DEBUG] Created scan with ID: {scan.id}")
        
        # Initialize scan logs
        scan_logs_data[scan.id] = []
        
        # Start scan in background thread
        thread = threading.Thread(
            target=start_scan_thread, 
            args=(app, scan.id, data.get('targets', []), {
                'subdomain_enum': data.get('subdomain_enum', False),
                'directory_fuzz': data.get('directory_fuzz', False),
                'fuzz_depth': data.get('fuzz_depth', 1)
            })
        )
        thread.daemon = True
        thread.start()
        
        print(f"[DEBUG] Started scan thread for scan ID: {scan.id}")
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.id,
            'message': f'Scan "{scan.name}" started successfully'
        })
        
    except Exception as e:
        print(f"[ERROR] Start scan failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/<int:scan_id>/status')
def api_scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    progress_info = get_scan_progress(scan_id)
    
    return jsonify({
        'id': scan.id,
        'name': scan.name,
        'status': scan.status,
        'progress': progress_info.get('progress', scan.progress),
        'current_phase': progress_info.get('phase', scan.current_phase),
        'targets': scan.get_targets(),
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template('scan_details.html', scan=scan)

@app.route('/api/scan/<int:scan_id>/logs')
def api_scan_logs(scan_id):
    logs = get_scan_logs(scan_id)
    return jsonify({'logs': logs})

@app.route('/api/scan/<int:scan_id>/results')
def api_scan_results(scan_id):
    results = ScanResult.query.filter_by(scan_id=scan_id).all()
    results_data = []
    
    for result in results:
        try:
            data = json.loads(result.data) if result.data else {}
        except:
            data = {'raw_data': result.data}
        
        results_data.append({
            'id': result.id,
            'target': result.target,
            'type': result.result_type,
            'data': data,
            'created_at': result.created_at.isoformat()
        })
    
    return jsonify({'results': results_data})

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan:
        # Delete associated results
        ScanResult.query.filter_by(scan_id=scan_id).delete()
        
        # Delete scan
        db.session.delete(scan)
        db.session.commit()
        
        # Clean up progress data
        if scan_id in scan_progress_data:
            del scan_progress_data[scan_id]
        if scan_id in scan_logs_data:
            del scan_logs_data[scan_id]
        
        flash('Scan deleted successfully', 'success')
    else:
        flash('Scan not found', 'error')
    
    return redirect(url_for('scans'))

@app.route('/notifications')
def notifications():
    return render_template('notifications.html')

# Export functions for scanner module
app.update_scan_progress = update_scan_progress
app.add_scan_log = add_scan_log
app.db = db
app.ScanResult = ScanResult

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("[+] Database created")
    
    print("[+] Starting Akuma Advanced Pentest Scanner...")
    print("[+] Ready to scan targets!")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
