import socket
import threading
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from app import app, db, Scan
from sqlalchemy.orm import sessionmaker
from datetime import datetime

class AkumaScanner:
    def __init__(self):
        self.session = None
        
    def init_db_session(self): 
        """Создаём отдельную сессию для потока""" 
        # Используем текущий контекст приложения 
        from app import db 
        self.session = db.session
        
    def log_progress(self, scan_id, message, progress=None):
        """Логирует прогресс сканирования"""
        print(f"[AKUMA {scan_id}] {message}")
        if progress is not None:
            self.update_scan_progress(scan_id, progress)
            
    def update_scan_progress(self, scan_id, progress):
        """Обновляет прогресс скана"""
        try:
            scan = None  # DB query disabled #(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.progress = progress
                pass  # DB commit disabled
        except Exception as e:
            print(f"[ERROR] Failed to update progress: {e}")
            
    def update_scan_status(self, scan_id, status, progress=None):
        """Обновляет статус скана"""
        try:
            scan = None  # DB query disabled #(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status = status
                if progress is not None:
                    scan.progress = progress
                if status == 'completed':
                    scan.completed_at = datetime.utcnow()
                pass  # DB commit disabled
        except Exception as e:
            print(f"[ERROR] Failed to update status: {e}")

    def scan_subdomains(self, scan_id, domain):
        """Сканирование поддоменов"""
        self.log_progress(scan_id, f"Starting subdomain enumeration for {domain}")
        
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'shop', 'blog', 'news', 'mobile']
        found_domains = [domain]  # Основной домен
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
            for future in futures:
                result = future.result()
                if result:
                    found_domains.append(result)
                    self.log_progress(scan_id, f"Found subdomain: {result}")
        
        return found_domains

    def scan_tcp_ports(self, scan_id, target, ports_range="1-1000"):
        """TCP сканирование портов"""
        self.log_progress(scan_id, f"Starting TCP port scan for {target}")
        
        start_port, end_port = map(int, ports_range.split('-'))
        open_ports = []
        total_ports = end_port - start_port + 1
        scanned = 0
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        # Сканируем батчами
        batch_size = 50
        for i in range(start_port, end_port + 1, batch_size):
            batch_end = min(i + batch_size - 1, end_port)
            batch_ports = range(i, batch_end + 1)
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_port, port) for port in batch_ports]
                for future in futures:
                    result = future.result()
                    if result:
                        service = self.get_service_name(result)
                        open_ports.append({'port': result, 'protocol': 'tcp', 'service': service})
                        self.log_progress(scan_id, f"Found open TCP port: {result} ({service})")
                    scanned += len(batch_ports)
            
            # Обновляем прогресс (TCP = 30-60% от общего)
            tcp_progress = int((scanned / total_ports) * 30) + 30
            self.update_scan_progress(scan_id, tcp_progress)
        
        return open_ports

    def scan_udp_ports(self, scan_id, target):
        """UDP сканирование популярных портов"""
        self.log_progress(scan_id, f"Starting UDP port scan for {target}")
        
        # Популярные UDP порты
        udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 500, 514, 520, 1434, 1900, 5353]
        open_ports = []
        
        def check_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b'test', (target, port))
                sock.recvfrom(1024)
                sock.close()
                return port
            except socket.timeout:
                return port  # UDP может не отвечать, но быть открытым
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_udp_port, port) for port in udp_ports]
            for future in futures:
                result = future.result()
                if result:
                    service = self.get_service_name(result, 'udp')
                    open_ports.append({'port': result, 'protocol': 'udp', 'service': service})
                    self.log_progress(scan_id, f"Found open UDP port: {result} ({service})")
        
        return open_ports

    def get_service_name(self, port, protocol='tcp'):
        """Определяет название сервиса по порту"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
            27017: 'MongoDB', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt',
            123: 'NTP', 161: 'SNMP', 389: 'LDAP', 500: 'IPSec'
        }
        return services.get(port, 'Unknown')

    def detect_technologies_and_vulnerabilities(self, scan_id, target, tcp_ports):
        """Определение технологий и поиск уязвимостей"""
        self.log_progress(scan_id, f"Detecting technologies and vulnerabilities for {target}")
        
        technologies = []
        vulnerabilities = []
        
        # Проверяем HTTP/HTTPS сервисы
        for port_info in tcp_ports:
            port = port_info['port']
            if port in [80, 8080, 8000, 8888]:
                try:
                    response = requests.get(f"http://{target}:{port}", timeout=5)
                    tech, vuln = self.analyze_http_response(response, port)
                    technologies.extend(tech)
                    vulnerabilities.extend(vuln)
                except:
                    pass
            elif port == 443:
                try:
                    response = requests.get(f"https://{target}:{port}", timeout=5, verify=False)
                    tech, vuln = self.analyze_http_response(response, port)
                    technologies.extend(tech)
                    vulnerabilities.extend(vuln)
                except:
                    pass
        
        return technologies, vulnerabilities

    def analyze_http_response(self, response, port):
        """Анализ HTTP ответа"""
        technologies = []
        vulnerabilities = []
        headers = response.headers
        content = response.text.lower()
        
        # Технологии из заголовков
        if 'server' in headers:
            technologies.append({
                'name': headers['server'], 
                'type': 'Web Server',
                'port': port
            })
        
        if 'x-powered-by' in headers:
            technologies.append({
                'name': headers['x-powered-by'], 
                'type': 'Backend',
                'port': port
            })
        
        # Технологии из содержимого
        cms_checks = [
            ('wordpress', 'WordPress'),
            ('joomla', 'Joomla'),
            ('drupal', 'Drupal'),
            ('magento', 'Magento')
        ]
        
        for check, name in cms_checks:
            if check in content:
                technologies.append({
                    'name': name, 
                    'type': 'CMS',
                    'port': port
                })
        
        # Проверка уязвимостей (отсутствие заголовков безопасности)
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HSTS protection',
            'Content-Security-Policy': 'CSP protection'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in headers:
                missing_headers.append(f"{header} ({description})")
        
        if missing_headers:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'description': f"Missing headers on port {port}: {', '.join(missing_headers)}",
                'port': port
            })
        
        return technologies, vulnerabilities

    def start_scan(self, scan_id):
        """Главная функция сканирования"""
        self.init_db_session()
        
        try:
            # Получаем скан
            scan = None  # DB query disabled #(Scan).filter_by(id=scan_id).first()
            if not scan:
                print(f"[ERROR] Scan {scan_id} not found!")
                return
            
            target = scan.target
            self.log_progress(scan_id, f"Starting comprehensive scan of {target}")
            self.update_scan_status(scan_id, 'running', 0)
            
            scan_results = {
                'target': target,
                'started_at': time.time(),
                'subdomains': [],
                'tcp_ports': [],
                'udp_ports': [],
                'technologies': [],
                'vulnerabilities': []
            }
            
            # Резолвим IP
            try:
                ip = socket.gethostbyname(target)
                scan_results['ip'] = ip
                self.log_progress(scan_id, f"Target resolved to IP: {ip}")
            except:
                self.log_progress(scan_id, f"Failed to resolve {target}")
                self.update_scan_status(scan_id, 'failed', 0)
                return
            
            # 1. Поддомены (0-20%)
            options = scan.get_options()
            if options.get('subdomains', True):
                subdomains = self.scan_subdomains(scan_id, target)
                scan_results['subdomains'] = subdomains
            else:
                scan_results['subdomains'] = [target]
            self.update_scan_progress(scan_id, 20)
            
            # 2. TCP порты (20-60%)
            tcp_ports = self.scan_tcp_ports(scan_id, ip, "1-1000")
            scan_results['tcp_ports'] = tcp_ports
            self.update_scan_progress(scan_id, 60)
            
            # 3. UDP порты (60-75%)
            udp_ports = self.scan_udp_ports(scan_id, ip)
            scan_results['udp_ports'] = udp_ports
            self.update_scan_progress(scan_id, 75)
            
            # 4. Технологии и уязвимости (75-90%)
            technologies, vulnerabilities = self.detect_technologies_and_vulnerabilities(scan_id, ip, tcp_ports)
            scan_results['technologies'] = technologies
            scan_results['vulnerabilities'] = vulnerabilities
            self.update_scan_progress(scan_id, 90)
            
            # 5. Финализация (90-100%)
            scan_results['completed_at'] = time.time()
            scan_results['duration'] = scan_results['completed_at'] - scan_results['started_at']
            
            # Сохраняем результаты в базе
            scan.set_scan_data(scan_results)
            pass  # DB commit disabled
            
            self.update_scan_status(scan_id, 'completed', 100)
            
            total_findings = len(tcp_ports) + len(udp_ports) + len(technologies) + len(vulnerabilities)
            self.log_progress(scan_id, f"Scan completed! Found {total_findings} total findings in {scan_results['duration']:.1f}s")
            
        except Exception as e:
            self.log_progress(scan_id, f"Scan failed with error: {e}")
            self.update_scan_status(scan_id, 'failed', 0)
        finally:
            if self.session:
                self.session.close()

def run_scan_in_background(app, scan_id): 
    """Запускает сканирование в отдельном потоке с контекстом приложения""" 
    with app.app_context(): 
        scanner = AkumaScanner() 
        scanner.start_scan(scan_id)

def start_scan_thread(app, scan_id):
    """Запуск сканирования в потоке"""
    thread = threading.Thread(target=run_scan_in_background, args=(app, scan_id,), daemon=True)
    thread.start()
    return thread
