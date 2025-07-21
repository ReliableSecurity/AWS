import subprocess
import threading
import time
import json
import socket
from datetime import datetime
import requests
import os
import asyncio

class RealAkumaScanner:
    def __init__(self):
        self.scan_logs = {}
        self.scan_results = {}
        
    def log(self, scan_id, message, level="INFO"):
        """Добавляем лог в память и выводим в консоль"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        if scan_id not in self.scan_logs:
            self.scan_logs[scan_id] = []
        self.scan_logs[scan_id].append(log_entry)
        
        print(f"[AKUMA-{scan_id}] {log_entry}")
        
    def get_scan_logs(self, scan_id):
        """Получить логи сканирования"""
        return self.scan_logs.get(scan_id, [])
        
    def run_command(self, scan_id, command, description):
        """Выполнение команды с логированием"""
        self.log(scan_id, f"🔧 {description}")
        self.log(scan_id, f"💻 Executing: {command}")
        
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=30
            )
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.log(scan_id, f"📤 {line}")
                        
            if result.stderr and result.returncode != 0:
                for line in result.stderr.strip().split('\n'):
                    if line.strip():
                        self.log(scan_id, f"⚠️ {line}", "ERROR")
                        
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            self.log(scan_id, f"⏰ Command timeout: {command}", "WARNING")
            return "", "Timeout", 1
        except Exception as e:
            self.log(scan_id, f"❌ Command failed: {str(e)}", "ERROR")
            return "", str(e), 1
    
    def resolve_domain(self, scan_id, domain):
        """Резолвим домен"""
        self.log(scan_id, "🔍 Starting domain resolution...")
        
        try:
            ip = socket.gethostbyname(domain)
            self.log(scan_id, f"✅ {domain} resolved to {ip}")
            return ip
        except Exception as e:
            self.log(scan_id, f"❌ Failed to resolve {domain}: {str(e)}", "ERROR")
            return None
    
    def discover_subdomains(self, scan_id, domain):
        """Поиск поддоменов"""
        self.log(scan_id, "🕸️ Starting subdomain discovery...")
        
        subdomains = []
        
        # Простой список популярных поддоменов для проверки
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop']
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
                self.log(scan_id, f"✅ Found subdomain: {subdomain}")
            except:
                pass
                
        self.log(scan_id, f"📊 Found {len(subdomains)} subdomains")
        return subdomains
    
    def port_scan(self, scan_id, target):
        """Сканирование портов"""
        self.log(scan_id, f"🔍 Starting port scan on {target}")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    self.log(scan_id, f"✅ Port {port} is OPEN")
                sock.close()
            except:
                pass
                
        self.log(scan_id, f"📊 Found {len(open_ports)} open ports: {open_ports}")
        return open_ports
    
    def web_scan(self, scan_id, target):
        """Веб-сканирование"""
        self.log(scan_id, f"🌐 Starting web scan on {target}")
        
        results = {}
        
        # Проверяем HTTP и HTTPS
        for protocol in ['http', 'https']:
            url = f"{protocol}://{target}"
            try:
                self.log(scan_id, f"📡 Testing {url}")
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                results[protocol] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'title': self.extract_title(response.text),
                    'server': response.headers.get('Server', 'Unknown')
                }
                
                self.log(scan_id, f"✅ {url} responded with {response.status_code}")
                self.log(scan_id, f"🔧 Server: {results[protocol]['server']}")
                if results[protocol]['title']:
                    self.log(scan_id, f"📄 Title: {results[protocol]['title']}")
                    
            except Exception as e:
                self.log(scan_id, f"❌ {url} failed: {str(e)}", "WARNING")
                
        return results
    
    def extract_title(self, html):
        """Извлекаем title из HTML"""
        try:
            start = html.lower().find('<title>')
            end = html.lower().find('</title>')
            if start != -1 and end != -1:
                return html[start+7:end].strip()
        except:
            pass
        return None
    
    def vulnerability_scan(self, scan_id, target):
        """Базовое сканирование уязвимостей"""
        self.log(scan_id, "🛡️ Starting vulnerability assessment...")
        
        vulns = []
        
        # Проверяем на открытые порты с потенциальными проблемами
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    if port == 23:  # Telnet
                        vulns.append(f"Insecure Telnet service on port {port}")
                        self.log(scan_id, f"⚠️ VULNERABILITY: Telnet service detected", "WARNING")
                    elif port == 21:  # FTP
                        vulns.append(f"FTP service on port {port} (check for anonymous access)")
                        self.log(scan_id, f"⚠️ POTENTIAL ISSUE: FTP service detected", "WARNING")
                sock.close()
            except:
                pass
                
        self.log(scan_id, f"🛡️ Vulnerability scan completed. Found {len(vulns)} issues")
        return vulns
    
    def start_scan(self, scan_id, target, options=None):
        """Главная функция сканирования"""
        try:
            self.log(scan_id, f"🚀 Starting comprehensive scan of {target}")
            self.log(scan_id, f"⏰ Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            results = {
                'target': target,
                'started_at': datetime.now().isoformat(),
                'ip_address': None,
                'subdomains': [],
                'open_ports': [],
                'web_info': {},
                'vulnerabilities': [],
                'status': 'running'
            }
            
            # 1. Резолвим домен
            ip_address = self.resolve_domain(scan_id, target)
            if ip_address:
                results['ip_address'] = ip_address
            else:
                self.log(scan_id, "❌ Cannot resolve domain, scan aborted", "ERROR")
                return
            
            # 2. Поиск поддоменов
            results['subdomains'] = self.discover_subdomains(scan_id, target)
            
            # 3. Сканирование портов
            results['open_ports'] = self.port_scan(scan_id, ip_address)
            
            # 4. Веб-сканирование
            if 80 in results['open_ports'] or 443 in results['open_ports']:
                results['web_info'] = self.web_scan(scan_id, target)
            
            # 5. Поиск уязвимостей
            results['vulnerabilities'] = self.vulnerability_scan(scan_id, ip_address)
            
            results['status'] = 'completed'
            results['completed_at'] = datetime.now().isoformat()
            
            self.scan_results[scan_id] = results
            self.log(scan_id, f"🎉 Scan completed successfully!")
            self.log(scan_id, f"📊 Results: {len(results['subdomains'])} subdomains, {len(results['open_ports'])} open ports, {len(results['vulnerabilities'])} vulnerabilities")
            
        except Exception as e:
            self.log(scan_id, f"💥 Scan failed with error: {str(e)}", "ERROR")
            if scan_id in self.scan_results:
                self.scan_results[scan_id]['status'] = 'failed'
            raise

# Глобальный экземпляр сканера
global_scanner = RealAkumaScanner()

def run_scan_in_background(app, scan_id, target, options=None):
    """Запускает сканирование в отдельном потоке с контекстом приложения"""
    with app.app_context():
        global_scanner.start_scan(scan_id, target, options)

def start_scan_thread(app, scan_id, target, options=None):
    """Запуск сканирования в потоке"""
    thread = threading.Thread(target=run_scan_in_background, args=(app, scan_id, target, options), daemon=True)
    thread.start()
    return thread

def get_scan_logs(scan_id):
    """Получить логи сканирования"""
    return global_scanner.get_scan_logs(scan_id)

def get_scan_results(scan_id):
    """Получить результаты сканирования"""
    return global_scanner.scan_results.get(scan_id, {})
