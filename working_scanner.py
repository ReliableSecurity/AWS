import subprocess
import threading
import time
import json
import socket
import requests
from datetime import datetime

class WorkingPentestScanner:
    def __init__(self):
        self.scan_logs = {}
        self.scan_results = {}
        self.scan_progress = {}
        
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
    
    def resolve_domain(self, scan_id, domain):
        try:
            self.log(scan_id, f"🔍 Resolving {domain}", "INFO", "RECON")
            ip_address = socket.gethostbyname(domain)
            self.log(scan_id, f"✅ {domain} resolved to {ip_address}", "INFO", "RECON")
            return ip_address
        except socket.gaierror:
            self.log(scan_id, f"❌ Failed to resolve {domain}", "ERROR", "RECON")
            return None
    
    def enumerate_subdomains(self, scan_id, domain):
        self.log(scan_id, f"🕸️ Starting subdomain enumeration for {domain}", "INFO", "RECON")
        subdomains = []
        
        # Common subdomain list
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'app', 'blog', 'shop']
        for sub in common_subs:
            test_domain = f"{sub}.{domain}"
            if self.resolve_domain(scan_id, test_domain):
                subdomains.append(test_domain)
                time.sleep(0.1)  # Small delay
        
        self.log(scan_id, f"📊 Found {len(subdomains)} subdomains for {domain}", "INFO", "RECON")
        return subdomains
    
    def port_scan_tcp(self, scan_id, ip, hostname):
        self.log(scan_id, f"🔍 Starting TCP port scan on {hostname} ({ip})", "INFO", "RECON")
        open_ports = []
        
        # Common TCP ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({'port': port, 'protocol': 'tcp'})
                    self.log(scan_id, f"✅ Port {port}/tcp is OPEN", "INFO", "RECON")
                sock.close()
            except:
                continue
        
        self.log(scan_id, f"📊 Found {len(open_ports)} open TCP ports on {hostname}", "INFO", "RECON")
        return open_ports
    
    def detect_web_technologies(self, scan_id, target):
        self.log(scan_id, f"🔍 Detecting web technologies for {target}", "INFO", "RECON")
        technologies = []
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}"
                self.log(scan_id, f"📡 Testing {url}", "DEBUG", "RECON")
                
                response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                if response.status_code == 200:
                    tech_info = {
                        'target': target,
                        'url': url,
                        'status_code': response.status_code,
                        'server': response.headers.get('Server', 'Unknown'),
                        'title': self.extract_title(response.text),
                        'headers': dict(response.headers)
                    }
                    
                    technologies.append(tech_info)
                    self.log(scan_id, f"✅ {url} responded with {response.status_code}", "INFO", "RECON")
                    break
                    
            except Exception as e:
                self.log(scan_id, f"❌ Failed to test {protocol}://{target}: {str(e)}", "DEBUG", "RECON")
                continue
        
        return technologies
    
    def extract_title(self, html):
        try:
            start = html.lower().find('<title>') + 7
            end = html.lower().find('</title>')
            if start != 6 and end != -1:
                return html[start:end].strip()
        except:
            pass
        return "No title"
    
    def directory_fuzzing(self, scan_id, target):
        self.log(scan_id, f"🔍 Starting directory fuzzing on {target}", "INFO", "FUZZING")
        discovered = {
            'directories': [],
            'files': []
        }
        
        # Common directories and files
        common_paths = [
            'admin', 'login', 'dashboard', 'api', 'upload', 'uploads', 'images',
            'js', 'css', 'config', 'backup', 'test', 'temp', 'logs',
            'robots.txt', 'sitemap.xml', 'config.php', 'readme.txt', '.htaccess'
        ]
        
        for protocol in ['http', 'https']:
            base_url = f"{protocol}://{target}"
            
            for path in common_paths:
                try:
                    url = f"{base_url}/{path}"
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403]:
                        item = {
                            'url': url,
                            'status': response.status_code,
                            'size': len(response.content)
                        }
                        
                        if path.endswith('/') or '.' not in path:
                            discovered['directories'].append(item)
                        else:
                            discovered['files'].append(item)
                            
                        self.log(scan_id, f"✅ Found: {url} [{response.status_code}]", "INFO", "FUZZING")
                        
                except:
                    continue
        
        self.log(scan_id, f"📊 Found {len(discovered['directories'])} directories and {len(discovered['files'])} files", "INFO", "FUZZING")
        return discovered
    
    def start_scan(self, app_context, scan_id, scan_name, targets, options=None):
        if options is None:
            options = {}
        
        self.log(scan_id, f"🚀 Starting pentest scan: '{scan_name}'", "INFO", "START")
        self.log(scan_id, f"🎯 Targets: {', '.join(targets)}", "INFO", "START")
        
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
            self.log(scan_id, "🎯 PHASE 1: RECONNAISSANCE STARTED", "INFO", "RECON")
            self.update_progress(scan_id, 10, "Phase 1: Reconnaissance")
            
            recon_results = {'targets': {}}
            
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
                    
                    # Port Scanning
                    all_targets_for_portscan = [target] + subdomains if subdomains else [target]
                    target_results['port_scan_results'] = {}
                    
                    for scan_target in all_targets_for_portscan:
                        target_ip = self.resolve_domain(scan_id, scan_target) or ip_address
                        if target_ip:
                            open_ports = self.port_scan_tcp(scan_id, target_ip, scan_target)
                            target_results['port_scan_results'][scan_target] = {
                                'ip': target_ip,
                                'open_ports': open_ports
                            }
                    
                    # Web Technology Detection
                    target_results['web_technologies'] = self.detect_web_technologies(scan_id, target)
                    
                recon_results['targets'][target] = target_results
            
            scan_results['phases']['reconnaissance'] = recon_results
            self.update_progress(scan_id, 60, "Phase 1 Complete")
            
            # Phase 2: Web Discovery
            if options.get('fuzzing', False):
                self.log(scan_id, "🌐 PHASE 2: WEB APPLICATION DISCOVERY STARTED", "INFO", "WEB_DISC")
                self.update_progress(scan_id, 70, "Phase 2: Web Discovery")
                
                web_discovery_results = {}
                
                for target, target_data in recon_results['targets'].items():
                    # Check for web services
                    has_web_services = False
                    if 'port_scan_results' in target_data:
                        for hostname, port_data in target_data['port_scan_results'].items():
                            for port_info in port_data.get('open_ports', []):
                                if port_info['port'] in [80, 443, 8080, 8443]:
                                    has_web_services = True
                                    break
                    
                    if has_web_services:
                        web_discovery_results[target] = self.directory_fuzzing(scan_id, target)
                
                scan_results['phases']['web_discovery'] = web_discovery_results
                self.update_progress(scan_id, 90, "Phase 2 Complete")
            
            # Completed
            scan_results['completed_at'] = datetime.now().isoformat()
            scan_results['status'] = 'completed'
            
            self.scan_results[scan_id] = scan_results
            
            # Update database
            with app_context:
                from final_app import db, Scan
                scan = db.session.get(Scan, scan_id)
                if scan:
                    scan.status = 'completed'
                    scan.progress = 100
                    scan.completed_at = datetime.utcnow()
                    scan.set_scan_data(scan_results)
                    db.session.commit()
            
            self.update_progress(scan_id, 100, "Scan Complete")
            self.log(scan_id, "🎉 PENTEST SCAN COMPLETED SUCCESSFULLY!", "INFO", "COMPLETE")
            
        except Exception as e:
            self.log(scan_id, f"💥 SCAN FAILED: {str(e)}", "ERROR", "ERROR")
            
            # Update database with error
            try:
                with app_context:
                    from final_app import db, Scan
                    scan = db.session.get(Scan, scan_id)
                    if scan:
                        scan.status = 'failed'
                        db.session.commit()
            except:
                pass

# Global scanner instance
global_working_scanner = WorkingPentestScanner()

def run_working_scan_in_background(app_context, scan_id, scan_name, targets, options=None):
    global_working_scanner.start_scan(app_context, scan_id, scan_name, targets, options)

def start_working_scan_thread(app_context, scan_id, scan_name, targets, options=None):
    thread = threading.Thread(
        target=run_working_scan_in_background,
        args=(app_context, scan_id, scan_name, targets, options)
    )
    thread.daemon = True
    thread.start()
    return thread

def get_scan_logs(scan_id):
    return global_working_scanner.get_scan_logs(scan_id)

def get_scan_results(scan_id):
    return global_working_scanner.scan_results.get(scan_id, {})

def get_scan_progress(scan_id):
    return global_working_scanner.scan_progress.get(scan_id, {'progress': 0, 'phase': ''})
