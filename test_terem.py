#!/usr/bin/env python3
"""
Test Akuma scanner on terem.ru
"""

import json
import time
import threading
from fixed_working_app import app, db, Scan, start_scan_thread

def test_terem_scan():
    with app.app_context():
        # Create fresh database
        db.create_all()
        print("✅ Database created")
        
        # Create test scan for terem.ru
        scan = Scan(
            name="Terem.ru Pentest",
            targets=json.dumps(["terem.ru"]),
            subdomain_enum=True,
            directory_fuzz=True,
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        print(f"✅ Created terem.ru scan with ID: {scan.id}")
        
        # Start scan thread
        print("🚀 Starting scan on terem.ru...")
        thread = threading.Thread(
            target=start_scan_thread,
            args=(scan.id, ["terem.ru"], {
                'subdomain_enum': True,
                'directory_fuzz': True
            })
        )
        thread.daemon = True
        thread.start()
        
        print("⏳ Scanning terem.ru - this may take 30-60 seconds...")
        time.sleep(45)  # Wait for scan to complete
        
        # Check final results
        updated_scan = db.session.get(Scan, scan.id)
        print(f"\n📊 SCAN RESULTS FOR TEREM.RU:")
        print(f"   Status: {updated_scan.status}")
        print(f"   Progress: {updated_scan.progress}%")
        print(f"   Phase: {updated_scan.current_phase}")
        
        # Check detailed results
        from fixed_working_app import ScanResult
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        print(f"\n📋 DETAILED RESULTS ({len(results)} found):")
        
        for result in results:
            print(f"\n🎯 {result.result_type.upper()} for {result.target}:")
            try:
                data = json.loads(result.data)
                if result.result_type == 'ports':
                    for port in data.get('open_ports', []):
                        print(f"   🟢 {port}")
                elif result.result_type == 'subdomains':
                    for subdomain in data.get('subdomains', []):
                        print(f"   🌐 {subdomain}")
                elif result.result_type == 'directories':
                    for directory in data.get('directories', []):
                        print(f"   📁 {directory}")
                elif result.result_type == 'vulnerabilities':
                    for vuln in data.get('vulnerabilities', []):
                        print(f"   ⚠️ {vuln}")
            except:
                print(f"   {result.data}")
        
        if results:
            print("\n✅ TEREM.RU SCAN COMPLETED SUCCESSFULLY!")
            return True
        else:
            print("\n❌ No results found - check logs")
            return False

if __name__ == "__main__":
    print("🔍 Testing Akuma Scanner on terem.ru...")
    success = test_terem_scan()
    if success:
        print("\n🎉 TEREM.RU SCAN SUCCESS! Scanner is working perfectly! 🔥")
    else:
        print("\n⚠️ Check scan logs for issues")
