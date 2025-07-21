#!/usr/bin/env python3
"""
AKUMA WEB SCANNER - РАБОЧИЙ ТЕСТ
Братан, это минималистичная но РАБОЧАЯ версия твоего сканера!
"""

import socket
import threading
import subprocess
import json
import time
from concurrent.futures import ThreadPoolExecutor
import requests

def scan_tcp_ports(target, ports_range="1-1000", threads=50):
    """Быстрое TCP сканирование"""
    print(f"[+] Scanning TCP ports {ports_range} on {target}")
    
    start_port, end_port = map(int, ports_range.split('-'))
    open_ports = []
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_port, port) for port in range(start_port, end_port + 1)]
        for i, future in enumerate(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[!] Found open TCP port: {result}")
            
            # Показываем прогресс
            if (i + 1) % 100 == 0:
                progress = int(((i + 1) / len(futures)) * 100)
                print(f"[*] TCP scan progress: {progress}%")
    
    return open_ports

def scan_udp_ports(target, common_only=True):
    """UDP сканирование популярных портов"""
    print(f"[+] Scanning common UDP ports on {target}")
    
    # Топ UDP порты
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
            # UDP порт открыт но не отвечает
            return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_udp_port, port) for port in udp_ports]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[!] Found open UDP port: {result}")
    
    return open_ports

def scan_subdomains(domain):
    """Простое сканирование поддоменов"""
    print(f"[+] Scanning subdomains for {domain}")
    
    subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'shop', 'blog']
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
                print(f"[!] Found subdomain: {result}")
    
    return found_domains

def run_full_scan(target):
    """Полное сканирование цели"""
    print(f"\n{'='*50}")
    print(f"AKUMA SCANNER - FULL SCAN OF {target}")
    print(f"{'='*50}")
    
    start_time = time.time()
    results = {}
    
    try:
        # Резолвим домен
        ip = socket.gethostbyname(target)
        print(f"[+] Target IP: {ip}")
        results['ip'] = ip
        
        # 1. Сканирование поддоменов
        print(f"\n[PHASE 1] Subdomain enumeration")
        subdomains = scan_subdomains(target)
        results['subdomains'] = subdomains
        
        # 2. TCP сканирование
        print(f"\n[PHASE 2] TCP port scanning")
        tcp_ports = scan_tcp_ports(ip, "1-1000")
        results['tcp_ports'] = tcp_ports
        
        # 3. UDP сканирование
        print(f"\n[PHASE 3] UDP port scanning")
        udp_ports = scan_udp_ports(ip)
        results['udp_ports'] = udp_ports
        
        # 4. Определение сервисов
        print(f"\n[PHASE 4] Service detection")
        services = {}
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis'
        }
        
        all_ports = tcp_ports + udp_ports
        for port in all_ports:
            service = service_map.get(port, 'Unknown')
            services[port] = service
            print(f"[!] Port {port}: {service}")
        
        results['services'] = services
        
        # 5. Базовые проверки безопасности
        print(f"\n[PHASE 5] Basic security checks")
        vulnerabilities = []
        
        # Проверяем HTTP/HTTPS
        for port in [80, 443, 8080]:
            if port in tcp_ports:
                protocol = 'https' if port == 443 else 'http'
                try:
                    response = requests.get(f"{protocol}://{ip}:{port}", timeout=5, verify=False)
                    headers = response.headers
                    
                    # Проверяем заголовки безопасности
                    security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
                    missing = [h for h in security_headers if h not in headers]
                    
                    if missing:
                        vuln = f"Missing security headers on port {port}: {', '.join(missing)}"
                        vulnerabilities.append(vuln)
                        print(f"[!] {vuln}")
                        
                    if 'server' in headers:
                        print(f"[!] Server banner on port {port}: {headers['server']}")
                        
                except Exception as e:
                    print(f"[!] HTTP check failed for port {port}: {e}")
        
        results['vulnerabilities'] = vulnerabilities
        
        # Итоговая статистика
        scan_time = time.time() - start_time
        print(f"\n{'='*50}")
        print(f"SCAN COMPLETED IN {scan_time:.2f} SECONDS")
        print(f"{'='*50}")
        print(f"Subdomains found: {len(subdomains)}")
        print(f"Open TCP ports: {len(tcp_ports)}")
        print(f"Open UDP ports: {len(udp_ports)}")
        print(f"Services identified: {len(services)}")
        print(f"Potential issues: {len(vulnerabilities)}")
        print(f"{'='*50}")
        
        # Сохраняем результат
        with open(f'scan_results_{target}_{int(time.time())}.json', 'w') as f:
            json.dump(results, f, indent=2)
            
        return results
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user!")
        return None
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        return None

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 simple_scanner_test.py <target>")
        print("Example: python3 simple_scanner_test.py google.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"Starting Akuma scan of {target}...")
    run_full_scan(target)
