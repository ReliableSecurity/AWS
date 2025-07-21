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
        """Добавляем лог с указанием фазы пентеста"""
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
        """Обновление прогресса сканирования"""
        self.scan_progress[scan_id] = {
            'progress': progress,
            'phase': phase,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_scan_logs(self, scan_id):
        """Получить логи сканирования"""
        return self.scan_logs.get(scan_id, [])
    
    def run_command(self, scan_id, command, description, phase="SYSTEM"):
        """Выполнение системных команд с логированием"""
        self.log(scan_id, f"🔧 Executing: {description}", "DEBUG", phase)
        self.log(scan_id, f"Command: {command}", "DEBUG", phase)
        
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=300
            )
            
            if result.returncode == 0:
                self.log(scan_id, f"✅ {description} completed successfully", "INFO", phase)
                return result.stdout
            else:
                self.log(scan_id, f"❌ {description} failed: {result.stderr}", "ERROR", phase)
                return None
        except subprocess.TimeoutExpired:
            self.log(scan_id, f"⏰ {description} timed out", "WARNING", phase)
            return None
        except Exception as e:
            self.log(scan_id, f"💥 {description} error: {str(e)}", "ERROR", phase)
            return None
    
    # ========================= PHASE 1: RECONNAISSANCE =========================
    
    def phase1_reconnaissance(self, scan_id, targets, options):
        """Фаза 1: Разведка"""
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
            
            # 1.1 Domain Resolution
            ip_address = self.resolve_domain(scan_id, target)
            if ip_address:
                target_results['ip_address'] = ip_address
            
            # 1.2 Subdomain Enumeration
            subdomains = []
            if options.get('subdomains', False):
                subdomains = self.enumerate_subdomains(scan_id, target)
                target_results['subdomains'] = subdomains
                results['total_subdomains'] += len(subdomains)
            
            # 1.3 Port Scanning (Full Range)
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
            
            # 1.4 Service Fingerprinting
            target_results['services'] = self.service_fingerprinting(scan_id, target_results['port_scan_results'])
            
            # 1.5 Web Technology Detection
            target_results['web_technologies'] = self.detect_web_technologies(scan_id, all_targets_for_portscan)
            results['technologies'].extend(target_results['web_technologies'])
            
            results['targets'][target] = target_results
        
        self.update_progress(scan_id, 40, "Phase 1 Complete")
        self.log(scan_id, "✅ PHASE 1: RECONNAISSANCE COMPLETED", "INFO", "RECON")
        return results
    
    def resolve_domain(self, scan_id, domain):
        """Разрешение домена в IP"""
        try:
            self.log(scan_id, f"🔍 Resolving {domain}", "INFO", "RECON")
            ip_address = socket.gethostbyname(domain)
            self.log(scan_id, f"✅ {domain} resolved to {ip_address}", "INFO", "RECON")
            return ip_address
        except socket.gaierror:
            self.log(scan_id, f"❌ Failed to resolve {domain}", "ERROR", "RECON")
            return None
    
    def enumerate_subdomains(self, scan_id, domain):
        """Поиск поддоменов с использованием различных методов"""
        self.log(scan_id, f"🕸️ Starting subdomain enumeration for {domain}", "INFO", "RECON")
        subdomains = set()
        
        # Method 1: Subfinder
        subfinder_output = self.run_command(
            scan_id, 
            f"subfinder -d {domain} -silent",
            f"Subfinder enumeration for {domain}",
            "RECON"
        )
        if subfinder_output:
            subdomains.update(subfinder_output.strip().split('\n'))
        
        # Method 2: Amass
        amass_output = self.run_command(
            scan_id,
            f"amass enum -passive -d {domain}",
            f"Amass enumeration for {domain}",
            "RECON"
        )
        if amass_output:
            subdomains.update(amass_output.strip().split('\n'))
        
        # Method 3: Basic DNS bruteforce
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'app']
        for sub in common_subs:
            test_domain = f"{sub}.{domain}"
            if self.resolve_domain(scan_id, test_domain):
                subdomains.add(test_domain)
        
        # Убираем пустые строки и основной домен
        subdomains = [sub for sub in subdomains if sub and sub != domain and sub.strip()]
        
        self.log(scan_id, f"📊 Found {len(subdomains)} subdomains for {domain}", "INFO", "RECON")
        return subdomains
    
    def full_port_scan(self, scan_id, ip, hostname):
        """Полное сканирование всех 65535 портов TCP + основные UDP"""
        self.log(scan_id, f"🔍 Starting full port scan on {hostname} ({ip})", "INFO", "RECON")
        open_ports = []
        
        # TCP Port Scan (all ports)
        self.log(scan_id, f"🔍 TCP scan: 1-65535 ports on {hostname}", "INFO", "RECON")
        nmap_tcp = self.run_command(
            scan_id,
            f"nmap -p- --open -T4 --max-retries 1 {ip}",
            f"Full TCP port scan for {hostname}",
            "RECON"
        )
        
        if nmap_tcp:
            tcp_ports = self.parse_nmap_output(nmap_tcp)
            open_ports.extend([{'port': p, 'protocol': 'tcp'} for p in tcp_ports])
        
        # UDP Port Scan (top 1000)
        self.log(scan_id, f"🔍 UDP scan: top 1000 ports on {hostname}", "INFO", "RECON")
        nmap_udp = self.run_command(
            scan_id,
            f"nmap -sU --top-ports 1000 --open {ip}",
            f"UDP port scan for {hostname}",
            "RECON"
        )
        
        if nmap_udp:
            udp_ports = self.parse_nmap_output(nmap_udp)
            open_ports.extend([{'port': p, 'protocol': 'udp'} for p in udp_ports])
        
        self.log(scan_id, f"📊 Found {len(open_ports)} open ports on {hostname}", "INFO", "RECON")
        return open_ports
    
    def parse_nmap_output(self, nmap_output):
        """Парсинг вывода nmap для извлечения открытых портов"""
        ports = []
        for line in nmap_output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                try:
                    port = int(line.split('/')[0])
                    ports.append(port)
                except:
                    continue
        return ports
    
    def service_fingerprinting(self, scan_id, port_scan_results):
        """Определение сервисов на открытых портах"""
        self.log(scan_id, "🔍 Starting service fingerprinting", "INFO", "RECON")
        services = {}
        
        for hostname, scan_data in port_scan_results.items():
            services[hostname] = []
            if not scan_data['open_ports']:
                continue
                
            # Формируем строку портов для nmap
            tcp_ports = [str(p['port']) for p in scan_data['open_ports'] if p['protocol'] == 'tcp']
            if tcp_ports:
                ports_str = ','.join(tcp_ports)
                nmap_service = self.run_command(
                    scan_id,
                    f"nmap -sV -p {ports_str} {scan_data['ip']}",
                    f"Service fingerprinting for {hostname}",
                    "RECON"
                )
                
                if nmap_service:
                    services[hostname] = self.parse_nmap_services(nmap_service)
        
        return services
    
    def parse_nmap_services(self, nmap_output):
        """Парсинг сервисов из вывода nmap"""
        services = []
        for line in nmap_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    services.append({
                        'port': int(port),
                        'service': service,
                        'version': version
                    })
        return services
    
    def detect_web_technologies(self, scan_id, targets):
        """Определение веб-технологий"""
        self.log(scan_id, "🔍 Detecting web technologies", "INFO", "RECON")
        technologies = []
        
        for target in targets:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{target}"
                    self.log(scan_id, f"📡 Testing {url}", "DEBUG", "RECON")
                    
                    response = requests.get(url, timeout=10, verify=False)
                    if response.status_code == 200:
                        tech_info = {
                            'target': target,
                            'url': url,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'technologies': []
                        }
                        
                        # Detect from headers
                        headers = response.headers
                        content = response.text
                        
                        # Common CMS detection
                        if 'X-Powered-CMS' in headers:
                            tech_info['technologies'].append(headers['X-Powered-CMS'])
                        
                        if 'wordpress' in content.lower():
                            tech_info['technologies'].append('WordPress')
                        
                        if 'drupal' in content.lower():
                            tech_info['technologies'].append('Drupal')
                        
                        technologies.append(tech_info)
                        
                except Exception as e:
                    self.log(scan_id, f"❌ Failed to test {protocol}://{target}: {str(e)}", "DEBUG", "RECON")
        
        return technologies
    
    # ========================= PHASE 2: WEB DISCOVERY =========================
    
    def phase2_web_discovery(self, scan_id, recon_results, options):
        """Фаза 2: Обнаружение веб-приложений"""
        self.log(scan_id, "🌐 PHASE 2: WEB APPLICATION DISCOVERY STARTED", "INFO", "WEB_DISC")
        self.update_progress(scan_id, 50, "Phase 2: Web Discovery")
        
        discovery_results = {}
        
        for target, target_data in recon_results['targets'].items():
            self.log(scan_id, f"🔍 Web discovery for {target}", "INFO", "WEB_DISC")
            
            # Собираем все веб-цели (основной домен + поддомены с веб-портами)
            web_targets = []
            
            # Проверяем основной домен
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
                
                # 2.1 Directory/File Bruteforcing with Feroxbuster
                if options.get('fuzzing', False):
                    target_discovery['directories'], target_discovery['files'] = self.feroxbuster_scan(scan_id, web_target)
                
                # 2.2 Robots.txt and sitemap.xml
                target_discovery['robots_txt'] = self.check_robots_txt(scan_id, web_target)
                target_discovery['sitemap_xml'] = self.check_sitemap_xml(scan_id, web_target)
                
                # 2.3 Link extraction and crawling
                target_discovery['links'] = self.extract_links(scan_id, web_target)
                
                # 2.4 Form discovery
                target_discovery['forms'] = self.discover_forms(scan_id, web_target)
                
                discovery_results[target][web_target] = target_discovery
        
        self.update_progress(scan_id, 75, "Phase 2 Complete")
        self.log(scan_id, "✅ PHASE 2: WEB APPLICATION DISCOVERY COMPLETED", "INFO", "WEB_DISC")
        return discovery_results
    
    def feroxbuster_scan(self, scan_id, target):
        """Directory and file bruteforcing с Feroxbuster"""
        self.log(scan_id, f"🔍 Starting Feroxbuster scan on {target}", "INFO", "FUZZING")
        
        directories = []
        files = []
        
        for protocol in ['http', 'https']:
            url = f"{protocol}://{target}"
            
            # Feroxbuster command
            ferox_output = self.run_command(
                scan_id,
                f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,xml -t 50 --no-recursion --json",
                f"Feroxbuster scan for {url}",
                "FUZZING"
            )
            
            if ferox_output:
                # Parse JSON output from feroxbuster
                for line in ferox_output.split('\n'):
                    if line.strip():
                        try:
                            result = json.loads(line)
                            if result.get('status') and result['status'] in [200, 301, 302, 403]:
                                url_path = result.get('url', '')
                                if url_path.endswith('/'):
                                    directories.append({
                                        'url': url_path,
                                        'status': result['status'],
                                        'size': result.get('content_length', 0)
                                    })
                                else:
                                    files.append({
                                        'url': url_path,
                                        'status': result['status'],
                                        'size': result.get('content_length', 0)
                                    })
                        except json.JSONDecodeError:
                            continue
        
        self.log(scan_id, f"📊 Feroxbuster found {len(directories)} directories and {len(files)} files", "INFO", "FUZZING")
        return directories, files
    
    def check_robots_txt(self, scan_id, target):
        """Проверка robots.txt"""
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}/robots.txt"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    self.log(scan_id, f"✅ Found robots.txt at {url}", "INFO", "WEB_DISC")
                    return {
                        'url': url,
                        'content': response.text
                    }
            except:
                continue
        return None
    
    def check_sitemap_xml(self, scan_id, target):
        """Проверка sitemap.xml"""
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}/sitemap.xml"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    self.log(scan_id, f"✅ Found sitemap.xml at {url}", "INFO", "WEB_DISC")
                    return {
                        'url': url,
                        'content': response.text
                    }
            except:
                continue
        return None
    
    def extract_links(self, scan_id, target):
        """Извлечение ссылок с главной страницы"""
        links = []
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Simple regex to find links
                    link_pattern = r'href=[\'"]?([^\'" >]+)'
                    found_links = re.findall(link_pattern, response.text, re.IGNORECASE)
                    
                    for link in found_links:
                        if link.startswith('http') or link.startswith('/'):
                            links.append({
                                'url': urljoin(url, link),
                                'source': url
                            })
                    break
            except:
                continue
        
        self.log(scan_id, f"📊 Extracted {len(links)} links from {target}", "INFO", "WEB_DISC")
        return links
    
    def discover_forms(self, scan_id, target):
        """Обнаружение форм на странице"""
        forms = []
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Simple form detection
                    form_pattern = r'<form[^>]*>(.*?)</form>'
                    found_forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
                    
                    for form in found_forms:
                        # Extract method and action
                        method_match = re.search(r'method=[\'"]?([^\'" >]+)', form, re.IGNORECASE)
                        action_match = re.search(r'action=[\'"]?([^\'" >]+)', form, re.IGNORECASE)
                        
                        forms.append({
                            'method': method_match.group(1) if method_match else 'GET',
                            'action': action_match.group(1) if action_match else '',
                            'source_url': url
                        })
                    break
            except:
                continue
        
        self.log(scan_id, f"📊 Found {len(forms)} forms on {target}", "INFO", "WEB_DISC")
        return forms
    
    # ========================= MAIN SCAN ORCHESTRATOR =========================
    
    def start_scan(self, scan_id, scan_name, targets, options=None):
        """Основная функция сканирования"""
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
            # Initialize results structure
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
    """Запуск сканирования в фоне с контекстом Flask"""
    with app.app_context():
        from app import db, Scan
        # Update scan status in database
        scan = Scan.query.get(scan_id)
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
    """Получить логи сканирования"""
    return global_advanced_scanner.get_scan_logs(scan_id)

def get_scan_results(scan_id):
    """Получить результаты сканирования"""
    return global_advanced_scanner.scan_results.get(scan_id, {})

def get_scan_progress(scan_id):
    """Получить прогресс сканирования"""
    return global_advanced_scanner.scan_progress.get(scan_id, {'progress': 0, 'phase': ''})
