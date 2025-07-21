#!/usr/bin/env python3
"""
Test script to verify scanner functionality
"""

import sys
import time
from complete_scanner import PentestScanner

class MockApp:
    def __init__(self):
        self.logs = []
        self.progress = {}
    
    def add_scan_log(self, scan_id, message):
        log_msg = f"[SCAN-{scan_id}] {message}"
        self.logs.append(log_msg)
        print(log_msg)
    
    def update_scan_progress(self, scan_id, progress, phase, status="running"):
        self.progress[scan_id] = {
            'progress': progress,
            'phase': phase,
            'status': status
        }
        print(f"[PROGRESS-{scan_id}] {progress}% - {phase} ({status})")

def test_scanner():
    print("🚀 Testing Akuma Scanner Components...")
    
    scanner = PentestScanner()
    app = MockApp()
    scan_id = 1
    
    # Test basic port scanning command
    print("\n[TEST 1] Testing nmap command...")
    cmd = "nmap -sS -T4 --top-ports 100 --open 8.8.8.8"
    output = scanner.run_command(cmd, timeout=30)
    print(f"Nmap output preview: {output[:200]}...")
    
    # Test domain resolution
    print("\n[TEST 2] Testing domain resolution...")
    try:
        import socket
        ip = socket.gethostbyname('google.com')
        print(f"✅ google.com resolved to {ip}")
    except Exception as e:
        print(f"❌ Resolution failed: {e}")
    
    # Test HTTP request
    print("\n[TEST 3] Testing HTTP requests...")
    try:
        import requests
        response = requests.get('http://google.com', timeout=5)
        print(f"✅ HTTP request successful: {response.status_code}")
        print(f"Server header: {response.headers.get('Server', 'Not disclosed')}")
    except Exception as e:
        print(f"❌ HTTP request failed: {e}")
    
    print("\n✅ Scanner components test completed!")
    return True

if __name__ == "__main__":
    test_scanner()
