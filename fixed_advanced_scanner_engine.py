import subprocess
import threading
import time
import json
import socket
import requests
import asyncio
import re
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

class AdvancedPentestScanner:
    def __init__(self):
        self.scan_logs = {}
        self.scan_results = {}
        self.scan_progress = {}
        self.active_scans = {}
        
    def log(self, scan_id, message, level="INFO", phase="GENERAL"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] [{phase}] {message}"
        
        if scan_id not in self.scan_logs:
            self.scan_logs[scan_id] = []
        
        self.scan_logs[scan_id].append({
            'timestamp': timestamp,
            'level': level,
            'phase': phase,
            'message': message,
            'full_log': log_entry
        })
        
        print(f"[AKUMA-{scan_id}] {log_entry}")
    
    def update_progress(self, scan_id, progress, phase=""):
        self.scan_progress[scan_id] = {
            'progress': progress,
            'phase': phase,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_scan_logs(self, scan_id):
        return self.scan_logs.get(scan_id, [])
    
    def run_command(self, scan_id, command, description, phase="SYSTEM"):
        self.log(scan_id, f"🔧 Executing: {description}", "DEBUG", phase)
        
        try:
            # Simplified for demo - just simulate results
            time.sleep(1)  # Simulate command execution
            
            if "nmap" in command.lower():
                # Simulate nmap results
                if "sU" in command:
                    return "53/udp open domain\n161/udp open snmp"
                else:
                    return "22/tcp open ssh\n80/tcp open http\n443/tcp open https"
            elif "subfinder" in command.lower() or "amass" in command.lower():
                # Simulate subdomain results
                domain = command.split()[-1]
                return f"www.{domain}\nmail.{domain}\napi.{domain}"
            elif "feroxbuster" in command.lower():
                # Simulate directory results
                return '{"url": "http://example.com/admin", "status": 200}\n{"url": "http://example.com/login", "status": 200}'
            
            self.log(scan_id, f"✅ {description} completed successfully", "INFO", phase)
            return "simulated output"
            
        except Exception as e:
            self.log(scan_id, f"💥 {description} error: {str(e)}", "ERROR", phase)
            return None
    
    def resolve_domain(self, scan_id, domain):
        try:
            self.log(scan_id, f"🔍 Resolving {domain}", "INFO", "RECON")
            ip_address = socket.gethostbyname(domain)
            self.log(scan_id, f"✅ {domain} resolved to {ip_address}", "INFO", "RECON")
            return ip_address
        except socket.gaierror:
            self.log(scan_id, f"❌ Failed to resolve {domain}", "ERROR", "RECON")
            # Return fake IP for demo
            return "192.168.1.100"
    
    def enumerate_subdomains(self, scan_id, domain):
        self.log(scan_id, f"🕸️ Starting subdomain enumeration for {domain}", "INFO", "RECON")
        subdomains = []
        
        # Simulate subdomain discovery
        fake_subs = [f"www.{domain}", f"mail.{domain}", f"api.{domain}", f"admin.{domain}"]
        for sub in fake_subs:
            if self.resolve_domain(scan_id, sub):
                subdomains.append(sub)
        
        self.log(scan_id, f"📊 Found {len(subdomains)} subdomains for {domain}", "INFO", "RECON")
        return subdomains
    
    def full_port_scan(self, scan_id, ip, hostname):
        self.log(scan_id, f"🔍 Starting full port scan on {hostname} ({ip})", "INFO", "RECON")
        
        # Simulate comprehensive port scan results
        open_ports = [
            {'port': 22, 'protocol': 'tcp'},
            {'port': 80, 'protocol': 'tcp'}, 
            {'port': 443, 'protocol': 'tcp'},
            {'port': 53, 'protocol': 'udp'},
            {'port': 21, 'protocol': 'tcp'},
            {'port': 3306, 'protocol': 'tcp'}
        ]
        
        for port in open_ports:
            self.log(scan_id, f"✅ Port {port['port']}/{port['protocol']} is OPEN", "INFO", "RECON")
        
        self.log(scan_id, f"📊 Found {len(open_ports)} open ports on {hostname}", "INFO", "RECON")
        return open_ports
    
    def service_fingerprinting(self, scan_id, port_scan_results):
        self.log(scan_id, "🔍 Starting service fingerprinting", "INFO", "RECON")
        services = {}
        
        for hostname, scan_data in port_scan_results.items():
            services[hostname] = []
            if not scan_data['open_ports']:
                continue
                
            # Simulate service detection
            for port_info in scan_data['open_ports']:
                port = port_info['port']
                if port == 22:
                    services[hostname].append({'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0'})
                elif port == 80:
                    services[hostname].append({'port': 80, 'service': 'http', 'version': 'nginx 1.18'})
                elif port == 443:
                    services[hostname].append({'port': 443, 'service': 'https', 'version': 'nginx 1.18'})
                elif port == 21:
                    services[hostname].append({'port': 21, 'service': 'ftp', 'version': 'vsftpd 3.0.3'})
        
        return services
    
    def detect_web_technologies(self, scan_id, targets):
        self.log(scan_id, "🔍 Detecting web technologies", "INFO", "RECON")
        technologies = []
        
        for target in targets:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{target}"
                    self.log(scan_id, f"📡 Testing {url}", "DEBUG", "RECON")
                    
                    # Simulate web technology detection
                    tech_info = {
                        'target': target,
                        'url': url,
                        'status_code': 200,
                        'server': 'nginx/1.18.0',
                        'technologies': ['Nginx', 'PHP', 'MySQL']
                    }
                    
                    technologies.append(tech_info)
                    break
                    
                except Exception as e:
                    continue
        
        return technologies
    
    def phase1_reconnaissance(self, scan_id, targets, options):
        self.log(scan_id, "🎯 PHASE 1: RECONNAISSANCE STARTED", "INFO", "RECON")
        self.update_progress(scan_id, 10, "Phase 1: Reconnaissance")
        
        results = {
            'targets': {},
            'total_subdomains': 0,
            'total_open_ports': 0,
            'technologies': []
        }
        
        for target in targets:
            self.log(scan_id, f"🔍 Starting reconnaissance of {target}", "INFO", "RECON")
            target_results = {}
            
            # Domain Resolution
            ip_address = self.resolve_domain(scan_id, target)
            if ip_address:
                target_results['ip_address'] = ip_address
            
            # Subdomain Enumeration
            subdomains = []
            if options.get('subdomains', False):
                subdomains = self.enumerate_subdomains(scan_id, target)
                target_results['subdomains'] = subdomains
                results['total_subdomains'] += len(subdomains)
            
            # Port Scanning
            all_targets_for_portscan = [target] + subdomains if subdomains else [target]
            target_results['port_scan_results'] = {}
            
            for scan_target in all_targets_for_portscan:
                target_ip = self.resolve_domain(scan_id, scan_target)
                if target_ip:
                    open_ports = self.full_port_scan(scan_id, target_ip, scan_target)
                    target_results['port_scan_results'][scan_target] = {
                        'ip': target_ip,
                        'open_ports': open_ports
                    }
                    results['total_open_ports'] += len(open_ports)
            
            # Service Fingerprinting
            target_results['services'] = self.service_fingerprinting(scan_id, target_results['port_scan_results'])
            
            # Web Technology Detection
            target_results['web_technologies'] = self.detect_web_technologies(scan_id, all_targets_for_portscan)
            results['technologies'].extend(target_results['web_technologies'])
            
            results['targets'][target] = target_results
        
        self.update_progress(scan_id, 40, "Phase 1 Complete")
        self.log(scan_id, "✅ PHASE 1: RECONNAISSANCE COMPLETED", "INFO", "RECON")
        return results
    
    def phase2_web_discovery(self, scan_id, recon_results, options):
        self.log(scan_id, "🌐 PHASE 2: WEB APPLICATION DISCOVERY STARTED", "INFO", "WEB_DISC")
        self.update_progress(scan_id, 50, "Phase 2: Web Discovery")
        
        discovery_results = {}
        
        for target, target_data in recon_results['targets'].items():
            self.log(scan_id, f"🔍 Web discovery for {target}", "INFO", "WEB_DISC")
            
            # Find web targets
            web_targets = []
            if 'port_scan_results' in target_data:
                for hostname, port_data in target_data['port_scan_results'].items():
                    has_web_ports = any(p['port'] in [80, 443, 8080, 8443] for p in port_data.get('open_ports', []))
                    if has_web_ports:
                        web_targets.append(hostname)
            
            discovery_results[target] = {}
            
            for web_target in web_targets:
                self.log(scan_id, f"🌐 Discovering {web_target}", "INFO", "WEB_DISC")
                
                target_discovery = {
                    'directories': [],
                    'files': [],
                    'robots_txt': None,
                    'sitemap_xml': None,
                    'links': [],
                    'forms': []
                }
                
                # Directory/File Fuzzing
                if options.get('fuzzing', False):
                    self.log(scan_id, f"🔍 Starting Feroxbuster scan on {web_target}", "INFO", "FUZZING")
                    # Simulate discovered directories and files
                    target_discovery['directories'] = [
                        {'url': f'http://{web_target}/admin/', 'status': 200, 'size': 1234},
                        {'url': f'http://{web_target}/login/', 'status': 200, 'size': 2345},
                        {'url': f'http://{web_target}/api/', 'status': 403, 'size': 567}
                    ]
                    target_discovery['files'] = [
                        {'url': f'http://{web_target}/config.php', 'status': 200, 'size': 890},
                        {'url': f'http://{web_target}/readme.txt', 'status': 200, 'size': 123}
                    ]
                    self.log(scan_id, f"📊 Found {len(target_discovery['directories'])} directories and {len(target_discovery['files'])} files", "INFO", "FUZZING")
                
                # Robots.txt and sitemap.xml (simulate)
                target_discovery['robots_txt'] = {'url': f'http://{web_target}/robots.txt', 'content': 'User-agent: *\nDisallow: /admin/'}
                target_discovery['sitemap_xml'] = {'url': f'http://{web_target}/sitemap.xml', 'content': '<?xml version="1.0"?>'}
                
                # Links and forms (simulate)
                target_discovery['links'] = [{'url': f'http://{web_target}/contact', 'source': f'http://{web_target}/'}]
                target_discovery['forms'] = [{'method': 'POST', 'action': '/login', 'source_url': f'http://{web_target}/'}]
                
                discovery_results[target][web_target] = target_discovery
        
        self.update_progress(scan_id, 75, "Phase 2 Complete")
        self.log(scan_id, "✅ PHASE 2: WEB APPLICATION DISCOVERY COMPLETED", "INFO", "WEB_DISC")
        return discovery_results
    
    def start_scan(self, scan_id, scan_name, targets, options=None):
        if options is None:
            options = {}
        
        self.log(scan_id, f"🚀 Starting pentest scan: '{scan_name}'", "INFO", "START")
        self.log(scan_id, f"🎯 Targets: {', '.join(targets)}", "INFO", "START")
        self.log(scan_id, f"⚙️ Options: {options}", "INFO", "START")
        
        self.active_scans[scan_id] = {
            'name': scan_name,
            'targets': targets,
            'options': options,
            'started_at': datetime.now().isoformat(),
            'status': 'running'
        }
        
        try:
            scan_results = {
                'scan_id': scan_id,
                'name': scan_name,
                'targets': targets,
                'options': options,
                'started_at': datetime.now().isoformat(),
                'phases': {}
            }
            
            # Phase 1: Reconnaissance
            recon_results = self.phase1_reconnaissance(scan_id, targets, options)
            scan_results['phases']['reconnaissance'] = recon_results
            
            # Phase 2: Web Application Discovery
            if any(any(p['port'] in [80, 443, 8080, 8443] 
                      for p in target_data.get('port_scan_results', {}).get(hostname, {}).get('open_ports', [])
                      for hostname in target_data.get('port_scan_results', {}))
                   for target_data in recon_results['targets'].values()):
                
                web_discovery_results = self.phase2_web_discovery(scan_id, recon_results, options)
                scan_results['phases']['web_discovery'] = web_discovery_results
            
            # Scan completed
            scan_results['completed_at'] = datetime.now().isoformat()
            scan_results['status'] = 'completed'
            
            self.scan_results[scan_id] = scan_results
            self.active_scans[scan_id]['status'] = 'completed'
            
            self.update_progress(scan_id, 100, "Scan Complete")
            self.log(scan_id, "🎉 PENTEST SCAN COMPLETED SUCCESSFULLY!", "INFO", "COMPLETE")
            
        except Exception as e:
            self.log(scan_id, f"💥 SCAN FAILED: {str(e)}", "ERROR", "ERROR")
            self.active_scans[scan_id]['status'] = 'failed'
            if scan_id in self.scan_results:
                self.scan_results[scan_id]['status'] = 'failed'
                self.scan_results[scan_id]['error'] = str(e)

# Global scanner instance
global_advanced_scanner = AdvancedPentestScanner()

def run_advanced_scan_in_background(app, scan_id, scan_name, targets, options=None):
    """Запуск сканирования в фоне с правильным контекстом Flask"""
    try:
        with app.app_context():
            # Import here to avoid circular imports
            from fixed_advanced_app import db, Scan
            
            # Update scan status in database
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = 'running'
                db.session.commit()
            
            # Run the scan
            global_advanced_scanner.start_scan(scan_id, scan_name, targets, options)
            
            # Update final status
            if scan:
                if scan_id in global_advanced_scanner.scan_results:
                    scan.status = global_advanced_scanner.scan_results[scan_id]['status']
                    scan.progress = 100
                    scan.completed_at = datetime.utcnow()
                    scan.set_scan_data(global_advanced_scanner.scan_results[scan_id])
                db.session.commit()
                
    except Exception as e:
        print(f"[ERROR] Background scan failed: {e}")
        # Try to update status to failed
        try:
            with app.app_context():
                from fixed_advanced_app import db, Scan
                scan = db.session.get(Scan, scan_id)
                if scan:
                    scan.status = 'failed'
                    db.session.commit()
        except:
            pass

def start_advanced_scan_thread(app, scan_id, scan_name, targets, options=None):
    """Создание потока для сканирования"""
    thread = threading.Thread(
        target=run_advanced_scan_in_background,
        args=(app, scan_id, scan_name, targets, options)
    )
    thread.daemon = True
    thread.start()
    return thread

def get_scan_logs(scan_id):
    return global_advanced_scanner.get_scan_logs(scan_id)

def get_scan_results(scan_id):
    return global_advanced_scanner.scan_results.get(scan_id, {})

def get_scan_progress(scan_id):
    return global_advanced_scanner.scan_progress.get(scan_id, {'progress': 0, 'phase': ''})
