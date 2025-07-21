#!/usr/bin/env python3
"""
Test web interface with curl commands
"""

import subprocess
import time
import json

def run_curl(url, method="GET", data=None):
    """Run curl command and return response"""
    cmd = ["curl", "-s"]
    if method == "POST":
        cmd.extend(["-X", "POST"])
        if data:
            cmd.extend(["-H", "Content-Type: application/json"])
            cmd.extend(["-d", json.dumps(data)])
    
    cmd.append(f"http://localhost:5000{url}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"

def test_web_interface():
    print("🌐 Testing Akuma Web Interface...")
    
    # Test 1: Dashboard
    print("\n[TEST 1] Dashboard...")
    response = run_curl("/")
    if "Akuma" in response and "200" not in response or "error" not in response.lower():
        print("✅ Dashboard loads successfully")
    else:
        print("❌ Dashboard failed")
    
    # Test 2: API Stats
    print("\n[TEST 2] API Stats...")
    response = run_curl("/api/dashboard/stats")
    if "total_scans" in response:
        print("✅ API stats working")
        print(f"   Stats: {response}")
    else:
        print("❌ API stats failed")
    
    # Test 3: Start Scan
    print("\n[TEST 3] Starting scan on terem.ru...")
    scan_data = {
        "name": "Web Test Scan",
        "targets": ["terem.ru"],
        "subdomain_enum": True,
        "directory_fuzz": True
    }
    
    response = run_curl("/start_scan", method="POST", data=scan_data)
    if "success" in response:
        print("✅ Scan started successfully!")
        print(f"   Response: {response}")
        
        # Extract scan ID
        try:
            result = json.loads(response)
            scan_id = result.get('scan_id')
            
            if scan_id:
                # Test 4: Check scan status
                print(f"\n[TEST 4] Checking scan {scan_id} status...")
                time.sleep(5)  # Wait a bit
                
                status_response = run_curl(f"/api/scan/{scan_id}/status")
                if "status" in status_response:
                    print("✅ Scan status API working")
                    print(f"   Status: {status_response}")
                else:
                    print("❌ Scan status API failed")
                
                # Test 5: Check scan logs
                print(f"\n[TEST 5] Checking scan {scan_id} logs...")
                logs_response = run_curl(f"/api/scan/{scan_id}/logs")
                if "logs" in logs_response:
                    print("✅ Scan logs API working")
                    logs = json.loads(logs_response)
                    print(f"   Found {len(logs.get('logs', []))} log entries")
                else:
                    print("❌ Scan logs API failed")
        
        except Exception as e:
            print(f"❌ Failed to process scan response: {e}")
    
    else:
        print("❌ Scan start failed")
        print(f"   Response: {response}")
    
    print("\n🎯 Web interface test completed!")

if __name__ == "__main__":
    test_web_interface()
