#!/usr/bin/env python3
"""
Quick test to verify scan functionality
"""

import json
import time
import threading
from final_app import app, db, Scan, start_scan_thread

def test_scan():
    with app.app_context():
        # Create tables
        db.create_all()
        print("✅ Database created")
        
        # Create test scan
        scan = Scan(
            name="Test Google Scan",
            targets=json.dumps(["google.com"]),
            subdomain_enum=False,
            directory_fuzz=False,
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        print(f"✅ Created test scan with ID: {scan.id}")
        
        # Start scan thread
        print("🚀 Starting scan thread...")
        thread = threading.Thread(
            target=start_scan_thread,
            args=(app, scan.id, ["google.com"], {
                'subdomain_enum': False,
                'directory_fuzz': False
            })
        )
        thread.daemon = True
        thread.start()
        
        print("⏳ Waiting for scan to progress...")
        time.sleep(15)  # Wait 15 seconds
        
        # Check scan status
        updated_scan = db.session.get(Scan, scan.id)
        print(f"📊 Scan status: {updated_scan.status}")
        print(f"📊 Scan progress: {updated_scan.progress}%")
        print(f"📊 Current phase: {updated_scan.current_phase}")
        
        if updated_scan.status != 'pending':
            print("✅ Scan successfully started and running!")
            return True
        else:
            print("❌ Scan is still pending - something went wrong")
            return False

if __name__ == "__main__":
    success = test_scan()
    if success:
        print("\n🎉 Test PASSED - Scanner is working!")
    else:
        print("\n❌ Test FAILED - Scanner has issues")
