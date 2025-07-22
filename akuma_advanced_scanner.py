#!/usr/bin/env python3
"""
Akuma Advanced Pentest Scanner - Improved with proper commands
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
import subprocess
import socket
import requests
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akuma_scanner_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akuma_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Global scan tracking
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
def run_command(cmd, timeout=300):
    """Run system command and return output"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, 
            text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except Exception as e:
        return f"Command failed: {str(e)}"

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

def update_scan_progress(scan_id, progress, phase, status=None):
    """Update scan progress"""
    global scan_progress_data
    
    scan_progress_data[scan_id] = {
        'progress': progress,
        'phase': phase,
        'status': status or 'running'
    }
    
    # Update database in a separate thread to avoid context issues
    def update_db():
        with app.app_context():
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
    
    threading.Thread(target=update_db, daemon=True).start()

def save_scan_result(scan_id, target, result_type, data):
    """Save scan result to database"""
    def save_db():
        with app.app_context():
            try:
                result = ScanResult(
                    scan_id=scan_id,
                    target=target,
                    result_type=result_type,
                    data=json.dumps(data) if isinstance(data, dict) else str(data)
                )
                db.session.add(result)
                db.session.commit()
                print(f"[DEBUG] Saved {result_type} result for {target}")
            except Exception as e:
                print(f"[ERROR] Failed to save result: {e}")
                db.session.rollback()
    
    threading.Thread(target=save_db, daemon=True).start()

def discover_subdomains(scan_id, target, options):
    """Discover subdomains using subfinder"""
    try:
        add_scan_log(scan_id, f"🔍 Starting subdomain discovery for {target}")
        update_scan_progress(scan_id, 10, "Subdomain Discovery", "running")
        
        # Use subfinder
        cmd = f"subfinder -d {target} -silent"
        add_scan_log(scan_id, f"Running: {cmd}")
        
        output = run_command(cmd, timeout=180)
        
        subdomains = []
        for line in output.split('\n'):
            line = line.strip()
            if line and target in line and line != target:
                subdomains.append(line)
                add_scan_log(scan_id, f"🟢 Found subdomain: {line}")
        
        # Add main domain to subdomains list if not present
        if target not in subdomains:
            subdomains.insert(0, target)
        
        if len(subdomains) > 1:  # More than just the main domain
            save_scan_result(scan_id, target, 'subdomains', {
                'subdomains': subdomains,
                'method': 'subfinder',
                'command_used': cmd
            })
            add_scan_log(scan_id, f"✅ Found {len(subdomains)-1} subdomains for {target}")
        else:
            add_scan_log(scan_id, f"❌ No additional subdomains found for {target}")
        
        return subdomains
        
    except Exception as e:
        add_scan_log(scan_id, f"❌ Subdomain discovery failed: {str(e)}")
        return [target]  # Return at least the main domain

def scan_ports_advanced(scan_id, target, target_type="main"):
    """Advanced port scanning with service detection"""
    try:
        # Resolve domain if needed
        ip_target = target
        try:
            if not target.replace('.', '').replace(':', '').isdigit():  # Not an IP
                ip_target = socket.gethostbyname(target)
                add_scan_log(scan_id, f"✅ {target} resolved to {ip_target}")
        except:
            add_scan_log(scan_id, f"⚠️ Could not resolve {target}, using as-is")
        
        add_scan_log(scan_id, f"🔍 Starting advanced port scan on {target} ({ip_target})")
        
        # Advanced nmap command with service detection
        cmd = f"nmap -sS -Pn -sV --min-rate=5000 -p- --open {ip_target}"
        add_scan_log(scan_id, f"Running: {cmd}")
        add_scan_log(scan_id, "⚠️ This may take several minutes for full port range...")
        
        output = run_command(cmd, timeout=600)  # 10 minutes timeout
        add_scan_log(scan_id, f"Advanced port scan completed for {target}")
        
        # Parse results with service versions
        open_ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                port_info = line.strip()
                # Extract port, service, and version info
                if re.search(r'(\d+/tcp)\s+open\s+(\w+)?\s*(.*)?', port_info):
                    open_ports.append(port_info)
                    add_scan_log(scan_id, f"🟢 {target}: {port_info}")
        
        if open_ports:
            save_scan_result(scan_id, target, 'ports', {
                'open_ports': open_ports,
                'scan_method': 'nmap_advanced',
                'command_used': cmd,
                'target_type': target_type
            })
            add_scan_log(scan_id, f"✅ {target}: Found {len(open_ports)} open ports with services")
        else:
            add_scan_log(scan_id, f"❌ {target}: No open ports found")
        
        return open_ports
        
    except Exception as e:
        add_scan_log(scan_id, f"❌ Port scan failed for {target}: {str(e)}")
        return []

def fuzz_directories(scan_id, target, target_type="main"):
    """Directory fuzzing with feroxbuster"""
    try:
        add_scan_log(scan_id, f"🔍 Starting directory fuzzing on {target}")
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target_url = f"http://{target}"
        else:
            target_url = target
        
        # Check if wordlist exists
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if not os.path.exists(wordlist):
            add_scan_log(scan_id, f"⚠️ Wordlist not found, using alternative")
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        cmd = f"feroxbuster --url {target_url} -w {wordlist} -t 50 -x php,html,txt,js --silent"
        add_scan_log(scan_id, f"Running: {cmd}")
        
        output = run_command(cmd, timeout=300)
        
        # Parse feroxbuster output
        found_dirs = []
        for line in output.split('\n'):
            if target_url in line and any(code in line for code in ['200', '301', '302', '403']):
                found_dirs.append(line.strip())
                add_scan_log(scan_id, f"🟢 {target}: Found directory - {line.strip()}")
        
        if found_dirs:
            save_scan_result(scan_id, target, 'directories', {
                'directories': found_dirs,
                'method': 'feroxbuster',
                'command_used': cmd,
                'target_type': target_type
            })
            add_scan_log(scan_id, f"✅ {target}: Found {len(found_dirs)} directories")
        else:
            add_scan_log(scan_id, f"❌ {target}: No interesting directories found")
        
        return found_dirs
        
    except Exception as e:
        add_scan_log(scan_id, f"❌ Directory fuzzing failed for {target}: {str(e)}")
        return []

def vulnerability_scan(scan_id, target, target_type="main"):
    """Vulnerability scanning"""
    try:
        add_scan_log(scan_id, f"🔍 Starting vulnerability scan on {target}")
        
        vulnerabilities = []
        target_url = f"http://{target}" if not target.startswith(('http://', 'https://')) else target
        
        try:
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vuln = f"Missing {header} header - {description}"
                    vulnerabilities.append(vuln)
                    add_scan_log(scan_id, f"⚠️ {target}: {vuln}")
            
            # Check server header disclosure
            if 'Server' in headers:
                server_info = headers['Server']
                vuln = f"Server information disclosure: {server_info}"
                vulnerabilities.append(vuln)
                add_scan_log(scan_id, f"⚠️ {target}: {vuln}")
            
            # Check for common vulnerabilities
            if 'Set-Cookie' in headers:
                cookies = headers['Set-Cookie']
                if 'HttpOnly' not in cookies:
                    vuln = "Cookies missing HttpOnly flag"
                    vulnerabilities.append(vuln)
                    add_scan_log(scan_id, f"⚠️ {target}: {vuln}")
                if 'Secure' not in cookies:
                    vuln = "Cookies missing Secure flag"
                    vulnerabilities.append(vuln)
                    add_scan_log(scan_id, f"⚠️ {target}: {vuln}")
            
        except Exception as e:
            add_scan_log(scan_id, f"❌ HTTP vulnerability scan failed for {target}: {str(e)}")
        
        if vulnerabilities:
            save_scan_result(scan_id, target, 'vulnerabilities', {
                'vulnerabilities': vulnerabilities,
                'scan_type': 'web_security_headers',
                'target': target_url,
                'target_type': target_type
            })
            add_scan_log(scan_id, f"⚠️ {target}: Found {len(vulnerabilities)} potential vulnerabilities")
        else:
            add_scan_log(scan_id, f"✅ {target}: No obvious vulnerabilities found")
            
        return vulnerabilities
        
    except Exception as e:
        add_scan_log(scan_id, f"❌ Vulnerability scan failed for {target}: {str(e)}")
        return []

def start_scan_thread(scan_id, targets, options):
    """Main scan thread function with improved logic"""
    try:
        add_scan_log(scan_id, "🚀 Starting Akuma Advanced Pentest Scanner")
        update_scan_progress(scan_id, 5, "Initializing", "running")
        
        all_targets = []
        
        # Step 1: Subdomain discovery (if enabled)
        if options.get('subdomain_enum', False):
            add_scan_log(scan_id, "🌐 Phase 1: Subdomain Discovery")
            update_scan_progress(scan_id, 10, "Subdomain Discovery")
            
            for target in targets:
                if not target.replace('.', '').replace(':', '').isdigit():  # Only for domains
                    subdomains = discover_subdomains(scan_id, target, options)
                    all_targets.extend(subdomains)
                else:
                    all_targets.append(target)
        else:
            all_targets = targets.copy()
        
        # Remove duplicates
        all_targets = list(set(all_targets))
        add_scan_log(scan_id, f"📋 Total targets to scan: {len(all_targets)}")
        
        # Step 2: Port scanning for all targets
        add_scan_log(scan_id, "🔌 Phase 2: Port Scanning")
        update_scan_progress(scan_id, 25, "Port Scanning")
        
        for i, target in enumerate(all_targets):
            target_type = "subdomain" if target not in targets else "main"
            current_progress = 25 + (i / len(all_targets)) * 40
            update_scan_progress(scan_id, int(current_progress), f"Scanning ports: {target}")
            
            scan_ports_advanced(scan_id, target, target_type)
            time.sleep(1)  # Small delay between targets
        
        # Step 3: Directory fuzzing (if enabled)
        if options.get('directory_fuzz', False):
            add_scan_log(scan_id, "📁 Phase 3: Directory Fuzzing")
            update_scan_progress(scan_id, 70, "Directory Fuzzing")
            
            for i, target in enumerate(all_targets):
                target_type = "subdomain" if target not in targets else "main"
                current_progress = 70 + (i / len(all_targets)) * 20
                update_scan_progress(scan_id, int(current_progress), f"Fuzzing directories: {target}")
                
                fuzz_directories(scan_id, target, target_type)
                time.sleep(1)
        
        # Step 4: Vulnerability scanning
        add_scan_log(scan_id, "⚠️ Phase 4: Vulnerability Assessment")
        update_scan_progress(scan_id, 90, "Vulnerability Scanning")
        
        for i, target in enumerate(all_targets):
            target_type = "subdomain" if target not in targets else "main"
            current_progress = 90 + (i / len(all_targets)) * 9
            update_scan_progress(scan_id, int(current_progress), f"Vulnerability scan: {target}")
            
            vulnerability_scan(scan_id, target, target_type)
            time.sleep(1)
        
        # Complete the scan
        update_scan_progress(scan_id, 100, "Completed", "completed")
        add_scan_log(scan_id, f"🎉 Scan completed successfully! Scanned {len(all_targets)} targets")
        
    except Exception as e:
        add_scan_log(scan_id, f"❌ Scan failed: {str(e)}")
        update_scan_progress(scan_id, 0, "Failed", "failed")
        print(f"[ERROR] Scan {scan_id} failed: {str(e)}")

def get_scan_progress(scan_id):
    """Get current scan progress and phase information"""
    if scan_id in scan_progress_data:
        return scan_progress_data[scan_id]
    
    # Default progress info
    with app.app_context():
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

# FIXED: Correct route for starting scans with proper parameter handling
@app.route('/start_scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        print(f"[DEBUG] Starting scan with data: {data}")
        
        # Handle different parameter names from frontend
        subdomain_enum = data.get('subdomain_enum', data.get('subdomains', False))
        directory_fuzz = data.get('directory_fuzz', data.get('fuzzing', False))
        
        # Create new scan record
        scan = Scan(
            name=data.get('name', 'Unnamed Scan'),
            targets=json.dumps(data.get('targets', [])),
            subdomain_enum=subdomain_enum,
            directory_fuzz=directory_fuzz,
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
            args=(scan.id, data.get('targets', []), {
                'subdomain_enum': subdomain_enum,
                'directory_fuzz': directory_fuzz,
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
        'status': progress_info.get('status', scan.status),
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

# FIXED: Correct route for deleting scans
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

# FIXED: Add logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("[+] Database created")
    
    print("[+] Starting Akuma Advanced Pentest Scanner...")
    print("[+] Improved commands: subfinder, feroxbuster, advanced nmap")
    print("[+] Ready for advanced pentesting!")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

# Adding vulnerability detection phase to existing logic

# Adding vulnerability scanning to scan function
def run_vulnerability_scan(targets):
    for target in targets:
        ip, port = target.split(':')
        cmd = ['nuclei', '-u', f'http://{ip}:{port}']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        print(out.decode())
        if err:
            print(err.decode())

def run_scan_with_vulnerability_detection(targets):
    # Assuming targets is a list with format 'ip:port'
    run_vulnerability_scan(targets)


# CMS Detection
def detect_cms(url):
    cms_signatures = {
        'wordpress': ['/wp-content/', '/wp-admin/', '/wp-includes/'],
        'joomla': ['/administrator/', '/components/', '/modules/'],
        'drupal': ['/sites/default/', '/modules/', '/themes/'],
        'magento': ['/app/', '/skin/', '/js/mage/']
    }
    
    for cms, signatures in cms_signatures.items():
        for sig in signatures:
            try:
                response = requests.get(url + sig, timeout=5)
                if response.status_code == 200:
                    print(f'Detected CMS: {cms.upper()}')
                    return cms
            except:
                pass
    return 'unknown'


# Advanced Fuzzing
def run_parameter_fuzzing(url, parameters):
    payloads = ['<script>alert(1)</script>', '\'"OR 1=1--', '../../../etc/passwd']
    
    for param in parameters:
        for payload in payloads:
            data = {param: payload}
            try:
                response = requests.post(url, data=data, timeout=5)
                if 'error' in response.text.lower() or 'sql' in response.text.lower():
                    print(f'Potential vulnerability found in parameter {param}')
            except:
                pass

def run_header_fuzzing(url):
    headers_to_fuzz = ['X-Forwarded-For', 'User-Agent', 'Referer', 'X-Real-IP']
    payloads = ['<script>alert(1)</script>', '\'"OR 1=1--', '../../../etc/passwd']
    
    for header in headers_to_fuzz:
        for payload in payloads:
            headers = {header: payload}
            try:
                response = requests.get(url, headers=headers, timeout=5)
                if 'error' in response.text.lower():
                    print(f'Potential vulnerability found in header {header}')
            except:
                pass


# Notification System
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

class NotificationSystem:
    def __init__(self):
        self.email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'username': '',  # To be configured
            'password': ''   # To be configured
        }
    
    def send_email_notification(self, recipient, subject, message):
        try:
            msg = MimeMultipart()
            msg['From'] = self.email_config['username']
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MimeText(message, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            text = msg.as_string()
            server.sendmail(self.email_config['username'], recipient, text)
            server.quit()
            print(f'Email notification sent to {recipient}')
        except Exception as e:
            print(f'Failed to send email: {e}')
    
    def send_telegram_notification(self, bot_token, chat_id, message):
        try:
            url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
            data = {'chat_id': chat_id, 'text': message}
            requests.post(url, data=data)
            print('Telegram notification sent')
        except Exception as e:
            print(f'Failed to send Telegram notification: {e}')

notification_system = NotificationSystem()


# Scan Scheduling
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit

scheduler = BackgroundScheduler()
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def schedule_scan(scan_id, cron_expression):
    """Schedule a scan using cron expression"""
    def scheduled_scan_job():
        scan = Scan.query.get(scan_id)
        if scan:
            targets = json.loads(scan.targets)
            run_comprehensive_scan(scan_id, targets, {
                'include_subdomains': scan.include_subdomains,
                'fuzzing_depth': scan.fuzzing_depth,
                'enable_bruteforce': scan.enable_bruteforce
            })
    
    trigger = CronTrigger.from_crontab(cron_expression)
    scheduler.add_job(scheduled_scan_job, trigger, id=f'scan_{scan_id}')
    print(f'Scheduled scan {scan_id} with expression: {cron_expression}')

def cancel_scheduled_scan(scan_id):
    """Cancel a scheduled scan"""
    try:
        scheduler.remove_job(f'scan_{scan_id}')
        print(f'Cancelled scheduled scan {scan_id}')
    except:
        print(f'No scheduled scan found for ID {scan_id}')


# JWT Authentication
from functools import wraps
import jwt
from datetime import datetime, timedelta

JWT_SECRET = 'akuma_jwt_secret_key_2024'
JWT_ALGORITHM = 'HS256'

def generate_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(user_id, *args, **kwargs)
    return decorated


# Scan Comparison System
def compare_scans(scan1_id, scan2_id):
    """Compare two scans and highlight differences"""
    scan1 = Scan.query.get(scan1_id)
    scan2 = Scan.query.get(scan2_id)
    
    if not scan1 or not scan2:
        return {'error': 'One or both scans not found'}
    
    results1 = ScanResult.query.filter_by(scan_id=scan1_id).all()
    results2 = ScanResult.query.filter_by(scan_id=scan2_id).all()
    
    # Convert to dictionaries for easier comparison
    ports1 = {r.port: r for r in results1 if r.result_type == 'port'}
    ports2 = {r.port: r for r in results2 if r.result_type == 'port'}
    
    vulns1 = {r.data: r for r in results1 if r.result_type == 'vulnerability'}
    vulns2 = {r.data: r for r in results2 if r.result_type == 'vulnerability'}
    
    comparison = {
        'new_ports': [p for p in ports2.keys() if p not in ports1.keys()],
        'closed_ports': [p for p in ports1.keys() if p not in ports2.keys()],
        'new_vulnerabilities': [v for v in vulns2.keys() if v not in vulns1.keys()],
        'fixed_vulnerabilities': [v for v in vulns1.keys() if v not in vulns2.keys()],
        'scan1_date': scan1.started_at,
        'scan2_date': scan2.started_at
    }
    
    return comparison

def generate_comparison_report(comparison):
    """Generate HTML report for scan comparison"""
    html_report = f'''
    <html>
    <head><title>Scan Comparison Report</title></head>
    <body>
        <h1>Scan Comparison Report</h1>
        <p>Scan 1: {comparison['scan1_date']}</p>
        <p>Scan 2: {comparison['scan2_date']}</p>
        
        <h2>New Ports Discovered</h2>
        <ul>{''.join([f'<li>{port}</li>' for port in comparison['new_ports']])}</ul>
        
        <h2>Closed Ports</h2>
        <ul>{''.join([f'<li>{port}</li>' for port in comparison['closed_ports']])}</ul>
        
        <h2>New Vulnerabilities</h2>
        <ul>{''.join([f'<li>{vuln}</li>' for vuln in comparison['new_vulnerabilities']])}</ul>
        
        <h2>Fixed Vulnerabilities</h2>
        <ul>{''.join([f'<li>{vuln}</li>' for vuln in comparison['fixed_vulnerabilities']])}</ul>
    </body>
    </html>
    '''
    return html_report


# New API Routes for Advanced Features

@app.route('/api/schedule_scan', methods=['POST'])
@jwt_required
def api_schedule_scan(user_id):
    data = request.get_json()
    scan_id = data.get('scan_id')
    cron_expression = data.get('cron_expression')
    
    if not scan_id or not cron_expression:
        return jsonify({'error': 'scan_id and cron_expression required'}), 400
    
    schedule_scan(scan_id, cron_expression)
    return jsonify({'status': 'scheduled', 'scan_id': scan_id})

@app.route('/api/compare_scans', methods=['POST'])
@jwt_required
def api_compare_scans(user_id):
    data = request.get_json()
    scan1_id = data.get('scan1_id')
    scan2_id = data.get('scan2_id')
    
    if not scan1_id or not scan2_id:
        return jsonify({'error': 'Both scan IDs required'}), 400
    
    comparison = compare_scans(scan1_id, scan2_id)
    return jsonify(comparison)

@app.route('/api/send_notification', methods=['POST'])
@jwt_required
def api_send_notification(user_id):
    data = request.get_json()
    notification_type = data.get('type')  # 'email' or 'telegram'
    
    if notification_type == 'email':
        recipient = data.get('recipient')
        subject = data.get('subject')
        message = data.get('message')
        notification_system.send_email_notification(recipient, subject, message)
    elif notification_type == 'telegram':
        bot_token = data.get('bot_token')
        chat_id = data.get('chat_id')
        message = data.get('message')
        notification_system.send_telegram_notification(bot_token, chat_id, message)
    
    return jsonify({'status': 'notification_sent'})

@app.route('/api/jwt_token', methods=['POST'])
def get_jwt_token():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        token = generate_jwt_token(user.id)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/cms_detection', methods=['POST'])
@jwt_required
def api_cms_detection(user_id):
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    cms = detect_cms(url)
    return jsonify({'cms': cms, 'url': url})


# Advanced Features Route
@app.route('/advanced')
def advanced_features():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scans = Scan.query.all()
    return render_template('advanced_features.html', scans=scans)

