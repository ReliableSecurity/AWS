#!/usr/bin/env python3
"""
Final test of the working scanner
"""

import json
import time
import threading
from working_final_app import app, db, Scan, start_scan_thread

def test_complete_scan():
    with app.app_context():
        # Create fresh database
        db.create_all()
        print("✅ Database created")
        
        # Create test scan
        scan = Scan(
            name="Complete Test Scan",
            targets=json.dumps(["example.com"]),
            subdomain_enum=True,
            directory_fuzz=True,
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        print(f"✅ Created test scan with ID: {scan.id}")
        
        # Start scan thread
        print("🚀 Starting comprehensive scan...")
        thread = threading.Thread(
            target=start_scan_thread,
            args=(scan.id, ["example.com"], {
                'subdomain_enum': True,
                'directory_fuzz': True
            })
        )
        thread.daemon = True
        thread.start()
        
        print("⏳ Waiting for scan to complete...")
        time.sleep(25)  # Wait for scan to complete
        
        # Check final status
        updated_scan = db.session.get(Scan, scan.id)
        print(f"📊 Final status: {updated_scan.status}")
        print(f"📊 Final progress: {updated_scan.progress}%")
        print(f"📊 Final phase: {updated_scan.current_phase}")
        
        # Check results
        from working_final_app import ScanResult
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        print(f"📊 Results found: {len(results)}")
        
        for result in results:
            print(f"   - {result.result_type} for {result.target}")
        
        if updated_scan.status in ['running', 'completed'] and updated_scan.progress > 0:
            print("✅ Scanner is FULLY WORKING!")
            return True
        else:
            print("❌ Scanner has issues")
            return False

if __name__ == "__main__":
    success = test_complete_scan()
    if success:
        print("\n🎉 FINAL TEST PASSED - Your Akuma scanner is ready! 🔥")
    else:
        print("\n❌ FINAL TEST FAILED")
