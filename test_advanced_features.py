#!/usr/bin/env python3
"""
Advanced Features Test Script for Akuma Scanner
"""

import requests
import json
import time
import sys

# Configuration
BASE_URL = "http://localhost:5000"
USERNAME = "admin"
PASSWORD = "admin123"

def get_auth_token():
    """Get JWT authentication token"""
    response = requests.post(f"{BASE_URL}/api/jwt_token", json={
        "username": USERNAME,
        "password": PASSWORD
    })
    
    if response.status_code == 200:
        return response.json()["token"]
    else:
        print("❌ Failed to authenticate")
        return None

def test_cms_detection(token):
    """Test CMS detection functionality"""
    print("🎨 Testing CMS Detection...")
    
    headers = {"Authorization": f"Bearer {token}"}
    test_urls = [
        "http://wordpress.com",
        "http://joomla.org", 
        "http://drupal.org"
    ]
    
    for url in test_urls:
        response = requests.post(f"{BASE_URL}/api/cms_detection", 
                                json={"url": url}, headers=headers)
        if response.status_code == 200:
            result = response.json()
            print(f"  ✅ {url} -> {result['cms'].upper()}")
        else:
            print(f"  ❌ {url} -> Failed")

def test_vulnerability_scan(token):
    """Test vulnerability scanning with nuclei"""
    print("🎯 Testing Vulnerability Detection...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test basic vulnerability scan
    response = requests.post(f"{BASE_URL}/api/start_scan", 
                            json={
                                "targets": ["testphp.vulnweb.com"],
                                "scan_name": "Vuln Test Scan",
                                "options": {
                                    "include_subdomains": False,
                                    "fuzzing_depth": 2,
                                    "enable_bruteforce": False,
                                    "vulnerability_scan": True
                                }
                            }, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        print(f"  ✅ Vulnerability scan started: {result['scan_id']}")
        return result['scan_id']
    else:
        print("  ❌ Failed to start vulnerability scan")
        return None

def test_ssl_analysis():
    """Test SSL/TLS certificate analysis"""
    print("🔒 Testing SSL/TLS Analysis...")
    
    try:
        import ssl
        import socket
        
        hostname = "google.com"
        port = 443
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"  ✅ SSL Certificate for {hostname}:")
                print(f"      Issuer: {dict(x[0] for x in cert['issuer'])}")
                print(f"      Subject: {dict(x[0] for x in cert['subject'])}")
                print(f"      Version: {cert.get('version', 'Unknown')}")
        
    except Exception as e:
        print(f"  ❌ SSL analysis failed: {e}")

def test_scan_scheduling(token, scan_id):
    """Test scan scheduling functionality"""
    print("⏰ Testing Scan Scheduling...")
    
    if not scan_id:
        print("  ❌ No scan ID available for scheduling test")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Schedule a scan for every hour
    response = requests.post(f"{BASE_URL}/api/schedule_scan",
                            json={
                                "scan_id": scan_id,
                                "cron_expression": "0 * * * *"  # Every hour
                            }, headers=headers)
    
    if response.status_code == 200:
        print(f"  ✅ Scan {scan_id} scheduled successfully")
    else:
        print(f"  ❌ Failed to schedule scan: {response.text}")

def test_scan_comparison(token):
    """Test scan comparison functionality"""
    print("📊 Testing Scan Comparison...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get all scans first
    response = requests.get(f"{BASE_URL}/api/scans", headers=headers)
    
    if response.status_code == 200:
        scans = response.json()
        if len(scans) >= 2:
            scan1_id = scans[0]["id"]
            scan2_id = scans[1]["id"]
            
            compare_response = requests.post(f"{BASE_URL}/api/compare_scans",
                                           json={
                                               "scan1_id": scan1_id,
                                               "scan2_id": scan2_id
                                           }, headers=headers)
            
            if compare_response.status_code == 200:
                comparison = compare_response.json()
                print(f"  ✅ Comparison complete:")
                print(f"      New ports: {len(comparison.get('new_ports', []))}")
                print(f"      New vulnerabilities: {len(comparison.get('new_vulnerabilities', []))}")
            else:
                print(f"  ❌ Comparison failed: {compare_response.text}")
        else:
            print("  ⚠️  Need at least 2 scans for comparison")
    else:
        print("  ❌ Failed to fetch scans")

def test_notifications(token):
    """Test notification system"""
    print("📧 Testing Notification System...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test email notification (will fail without proper config, but should not crash)
    response = requests.post(f"{BASE_URL}/api/send_notification",
                            json={
                                "type": "email",
                                "recipient": "test@example.com",
                                "subject": "Akuma Scanner Test",
                                "message": "This is a test notification from Akuma Scanner"
                            }, headers=headers)
    
    if response.status_code == 200:
        print("  ✅ Email notification API responded successfully")
    else:
        print(f"  ❌ Email notification failed: {response.text}")

def main():
    print("🔥 Akuma Advanced Features Test Suite")
    print("=" * 50)
    
    # Get authentication token
    token = get_auth_token()
    if not token:
        sys.exit(1)
    
    print(f"✅ Authentication successful")
    print()
    
    # Run all tests
    test_ssl_analysis()
    print()
    
    test_cms_detection(token)
    print()
    
    scan_id = test_vulnerability_scan(token)
    print()
    
    test_scan_scheduling(token, scan_id)
    print()
    
    test_scan_comparison(token)
    print()
    
    test_notifications(token)
    print()
    
    print("🎉 Advanced features testing complete!")

if __name__ == "__main__":
    main()
