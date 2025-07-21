#!/usr/bin/env python3
"""
Final direct test on terem.ru without web server
"""

import subprocess
import socket
import requests
import json
from datetime import datetime

def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def run_command(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except Exception as e:
        return f"Command failed: {str(e)}"

def scan_terem():
    target = "terem.ru"
    results = {}
    
    log("🚀 Starting comprehensive scan of terem.ru")
    
    # 1. Domain Resolution
    log(f"🔍 Resolving {target}")
    try:
        ip = socket.gethostbyname(target)
        log(f"✅ {target} resolved to {ip}")
        results['ip'] = ip
    except Exception as e:
        log(f"❌ DNS resolution failed: {e}")
        return
    
    # 2. Port Scanning
    log(f"🔍 Port scanning {ip}")
    cmd = f"nmap -sS -T4 --top-ports 1000 --open {ip}"
    log(f"Running: {cmd}")
    
    output = run_command(cmd, timeout=60)
    log("Nmap scan completed")
    
    open_ports = []
    for line in output.split('\n'):
        if '/tcp' in line and 'open' in line:
            port_info = line.strip()
            open_ports.append(port_info)
            log(f"🟢 Found open port: {port_info}")
    
    results['ports'] = open_ports
    log(f"✅ Found {len(open_ports)} open ports")
    
    # 3. Subdomain Discovery
    log(f"🔍 Discovering subdomains for {target}")
    subdomains = []
    common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 'shop']
    
    for sub in common_subs:
        subdomain = f"{sub}.{target}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.append(subdomain)
            log(f"🟢 Found subdomain: {subdomain}")
        except:
            pass
    
    results['subdomains'] = subdomains
    log(f"✅ Found {len(subdomains)} subdomains")
    
    # 4. HTTP Analysis
    log(f"🔍 Analyzing HTTP headers for {target}")
    try:
        response = requests.get(f"http://{target}", timeout=10, allow_redirects=True)
        headers = response.headers
        
        vulnerabilities = []
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS protection', 
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content Security Policy'
        }
        
        for header, desc in security_headers.items():
            if header not in headers:
                vuln = f"Missing {header} - {desc}"
                vulnerabilities.append(vuln)
                log(f"⚠️ {vuln}")
        
        if 'Server' in headers:
            server = headers['Server']
            vuln = f"Server disclosure: {server}"
            vulnerabilities.append(vuln)
            log(f"⚠️ {vuln}")
        
        results['vulnerabilities'] = vulnerabilities
        results['status_code'] = response.status_code
        results['server'] = headers.get('Server', 'Unknown')
        
        log(f"✅ HTTP analysis completed - Status: {response.status_code}")
        
    except Exception as e:
        log(f"❌ HTTP analysis failed: {e}")
    
    # 5. Directory Discovery
    log(f"🔍 Checking common directories on {target}")
    directories = []
    common_dirs = ['/admin', '/login', '/api', '/backup', '/wp-admin', '/phpmyadmin', '/test']
    
    for directory in common_dirs:
        try:
            url = f"http://{target}{directory}"
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                dir_info = f"{directory} [{response.status_code}]"
                directories.append(dir_info)
                log(f"🟢 Found: {dir_info}")
        except:
            pass
    
    results['directories'] = directories
    log(f"✅ Found {len(directories)} interesting directories")
    
    # Final Report
    log("🎉 SCAN COMPLETED!")
    print("\n" + "="*60)
    print(f"📊 COMPREHENSIVE SCAN REPORT FOR {target.upper()}")
    print("="*60)
    print(f"🌐 IP Address: {results.get('ip', 'Unknown')}")
    print(f"📟 Server: {results.get('server', 'Unknown')}")
    print(f"📡 HTTP Status: {results.get('status_code', 'Unknown')}")
    
    print(f"\n🔌 OPEN PORTS ({len(results.get('ports', []))}):")
    for port in results.get('ports', []):
        print(f"   🟢 {port}")
    
    print(f"\n🌐 SUBDOMAINS ({len(results.get('subdomains', []))}):")
    for sub in results.get('subdomains', []):
        print(f"   🌐 {sub}")
    
    print(f"\n📁 DIRECTORIES ({len(results.get('directories', []))}):")
    for dir_info in results.get('directories', []):
        print(f"   📁 {dir_info}")
    
    print(f"\n⚠️ VULNERABILITIES ({len(results.get('vulnerabilities', []))}):")
    for vuln in results.get('vulnerabilities', []):
        print(f"   ⚠️ {vuln}")
    
    print("\n" + "="*60)
    print("🔥 AKUMA SCANNER - MISSION COMPLETE! 🔥")
    print("="*60)

if __name__ == "__main__":
    scan_terem()
