#!/usr/bin/env python3
"""
Complete Working Scanner with proper Flask integration
"""

import subprocess
import threading
import time
import json
import socket
import requests
from datetime import datetime
import os
import random

class PentestScanner:
    def __init__(self):
        self.active_scans = {}
        
    def run_command(self, cmd, timeout=30):
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

    def scan_ports_nmap(self, scan_id, target, app_context):
        """Real nmap port scanning"""
        with app_context:
            app = app_context.app
            
            app.add_scan_log(scan_id, f"🔍 Starting port scan on {target}")
            app.update_scan_progress(scan_id, 20, "Port Scanning", "running")
            
            # TCP scan
            cmd = f"nmap -sS -T4 --top-ports 1000 --open {target}"
            app.add_scan_log(scan_id, f"Running: {cmd}")
            
            output = self.run_command(cmd, timeout=120)
            app.add_scan_log(scan_id, f"Nmap output:\n{output}")
            
            # Parse results and save to database
            open_ports = []
            for line in output.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port_info = line.strip()
                    open_ports.append(port_info)
                    app.add_scan_log(scan_id, f"🟢 Found open port: {port_info}")
            
            # Save results to database
            if open_ports:
                result_data = {
                    'open_ports': open_ports,
                    'scan_method': 'nmap',
                    'command': cmd
                }
                
                result = app.ScanResult(
                    scan_id=scan_id,
                    target=target,
                    result_type='ports',
                    data=json.dumps(result_data)
                )
                app.db.session.add(result)
                app.db.session.commit()
                
                app.add_scan_log(scan_id, f"✅ Port scan completed. Found {len(open_ports)} open ports")
            else:
                app.add_scan_log(scan_id, "❌ No open ports found")

    def scan_subdomains(self, scan_id, domain, app_context):
        """Subdomain enumeration"""
        with app_context:
            app = app_context.app
            
            app.add_scan_log(scan_id, f"🔍 Starting subdomain enumeration for {domain}")
            app.update_scan_progress(scan_id, 40, "Subdomain Enumeration")
            
            # Use subfinder if available, otherwise use basic DNS
            subdomains = []
            
            # Try subfinder first
            cmd = f"subfinder -d {domain} -silent"
            app.add_scan_log(scan_id, f"Running: {cmd}")
            output = self.run_command(cmd, timeout=60)
            
            if "command not found" not in output.lower():
                for line in output.split('\n'):
                    if line.strip() and domain in line:
                        subdomains.append(line.strip())
            else:
                app.add_scan_log(scan_id, "⚠️ subfinder not found, using basic enumeration")
                # Basic subdomain list
                common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'stage']
                for sub in common_subs:
                    subdomain = f"{sub}.{domain}"
                    try:
                        socket.gethostbyname(subdomain)
                        subdomains.append(subdomain)
                        app.add_scan_log(scan_id, f"🟢 Found subdomain: {subdomain}")
                    except:
                        pass
            
            if subdomains:
                result_data = {
                    'subdomains': subdomains,
                    'method': 'subfinder' if "command not found" not in output.lower() else 'basic'
                }
                
                result = app.ScanResult(
                    scan_id=scan_id,
                    target=domain,
                    result_type='subdomains',
                    data=json.dumps(result_data)
                )
                app.db.session.add(result)
                app.db.session.commit()
                
                app.add_scan_log(scan_id, f"✅ Found {len(subdomains)} subdomains")
            else:
                app.add_scan_log(scan_id, "❌ No subdomains found")

    def directory_bruteforce(self, scan_id, target, app_context):
        """Directory fuzzing with feroxbuster or dirb"""
        with app_context:
            app = app_context.app
            
            app.add_scan_log(scan_id, f"🔍 Starting directory bruteforce on {target}")
            app.update_scan_progress(scan_id, 60, "Directory Fuzzing")
            
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            # Try feroxbuster first, then dirb
            directories = []
            
            # Feroxbuster command
            cmd = f"feroxbuster -u {target} -t 50 -w /usr/share/wordlists/dirb/common.txt --no-recursion -s 200,204,301,302,307,401,403 --silent"
            app.add_scan_log(scan_id, f"Running: feroxbuster on {target}")
            
            output = self.run_command(cmd, timeout=180)
            
            if "command not found" not in output.lower():
                for line in output.split('\n'):
                    if target in line and any(code in line for code in ['200', '301', '302', '403']):
                        directories.append(line.strip())
                        app.add_scan_log(scan_id, f"🟢 Found: {line.strip()}")
            else:
                app.add_scan_log(scan_id, "⚠️ feroxbuster not found, trying dirb")
                
                # Fallback to dirb
                cmd = f"dirb {target} /usr/share/wordlists/dirb/common.txt -S -w"
                output = self.run_command(cmd, timeout=120)
                
                if "command not found" not in output.lower():
                    for line in output.split('\n'):
                        if '==>' in line and 'http' in line:
                            directories.append(line.strip())
                            app.add_scan_log(scan_id, f"🟢 Found: {line.strip()}")
            
            if directories:
                result_data = {
                    'directories': directories,
                    'target': target,
                    'method': 'feroxbuster' if "command not found" not in output.lower() else 'dirb'
                }
                
                result = app.ScanResult(
                    scan_id=scan_id,
                    target=target,
                    result_type='directories',
                    data=json.dumps(result_data)
                )
                app.db.session.add(result)
                app.db.session.commit()
                
                app.add_scan_log(scan_id, f"✅ Directory scan completed. Found {len(directories)} paths")
            else:
                app.add_scan_log(scan_id, "❌ No directories found")

    def vulnerability_scan(self, scan_id, target, app_context):
        """Basic vulnerability scanning"""
        with app_context:
            app = app_context.app
            
            app.add_scan_log(scan_id, f"🔍 Starting vulnerability scan on {target}")
            app.update_scan_progress(scan_id, 80, "Vulnerability Scanning")
            
            vulnerabilities = []
            
            # HTTP Headers check
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            try:
                response = requests.get(target, timeout=10)
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
                        app.add_scan_log(scan_id, f"⚠️ {vuln}")
                
                # Check server header disclosure
                if 'Server' in headers:
                    server_info = headers['Server']
                    vuln = f"Server information disclosure: {server_info}"
                    vulnerabilities.append(vuln)
                    app.add_scan_log(scan_id, f"⚠️ {vuln}")
                
            except Exception as e:
                app.add_scan_log(scan_id, f"❌ HTTP vulnerability scan failed: {str(e)}")
            
            # Save vulnerability results
            if vulnerabilities:
                result_data = {
                    'vulnerabilities': vulnerabilities,
                    'scan_type': 'basic_web',
                    'target': target
                }
                
                result = app.ScanResult(
                    scan_id=scan_id,
                    target=target,
                    result_type='vulnerabilities',
                    data=json.dumps(result_data)
                )
                app.db.session.add(result)
                app.db.session.commit()
                
                app.add_scan_log(scan_id, f"⚠️ Found {len(vulnerabilities)} potential vulnerabilities")
            else:
                app.add_scan_log(scan_id, "✅ No obvious vulnerabilities found")

def start_scan_thread(app, scan_id, targets, options):
    """Main scan thread function"""
    scanner = PentestScanner()
    
    with app.app_context():
        try:
            app.add_scan_log(scan_id, "🚀 Starting Akuma Advanced Pentest Scanner")
            app.update_scan_progress(scan_id, 10, "Initializing", "running")
            
            for i, target in enumerate(targets):
                current_target_progress = int((i / len(targets)) * 90)
                
                app.add_scan_log(scan_id, f"🎯 Scanning target: {target}")
                app.update_scan_progress(scan_id, current_target_progress, f"Scanning {target}")
                
                # Resolve domain if needed
                ip_target = target
                try:
                    if not target.replace('.', '').isdigit():  # Not an IP
                        ip_target = socket.gethostbyname(target)
                        app.add_scan_log(scan_id, f"✅ {target} resolved to {ip_target}")
                except:
                    app.add_scan_log(scan_id, f"⚠️ Could not resolve {target}, using as-is")
                
                # Port scanning
                scanner.scan_ports_nmap(scan_id, ip_target, app.app_context())
                time.sleep(2)
                
                # Subdomain enumeration (if enabled)
                if options.get('subdomain_enum', False) and not target.replace('.', '').isdigit():
                    scanner.scan_subdomains(scan_id, target, app.app_context())
                    time.sleep(2)
                
                # Directory fuzzing (if enabled)
                if options.get('directory_fuzz', False):
                    scanner.directory_bruteforce(scan_id, target, app.app_context())
                    time.sleep(2)
                
                # Vulnerability scanning
                scanner.vulnerability_scan(scan_id, target, app.app_context())
                time.sleep(1)
            
            # Complete the scan
            app.update_scan_progress(scan_id, 100, "Completed", "completed")
            app.add_scan_log(scan_id, "🎉 Scan completed successfully!")
            
        except Exception as e:
            app.add_scan_log(scan_id, f"❌ Scan failed: {str(e)}")
            app.update_scan_progress(scan_id, 0, "Failed", "failed")
            print(f"[ERROR] Scan {scan_id} failed: {str(e)}")

# For testing
if __name__ == "__main__":
    print("Akuma Complete Scanner - Testing Mode")
    # This would be called by the Flask app
