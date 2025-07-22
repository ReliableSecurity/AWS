#!/bin/bash

echo "🔥 Starting Akuma Advanced Web Scanner 🔥"
echo "==========================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Running as root - this is not recommended for production!"
fi

# Check system dependencies
echo "📋 Checking system dependencies..."

MISSING_TOOLS=()

command -v nmap >/dev/null 2>&1 || MISSING_TOOLS+=("nmap")
command -v subfinder >/dev/null 2>&1 || MISSING_TOOLS+=("subfinder")  
command -v feroxbuster >/dev/null 2>&1 || MISSING_TOOLS+=("feroxbuster")
command -v nuclei >/dev/null 2>&1 || MISSING_TOOLS+=("nuclei")
command -v python3 >/dev/null 2>&1 || MISSING_TOOLS+=("python3")

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "❌ Missing required tools: ${MISSING_TOOLS[*]}"
    echo "Install them with:"
    echo "sudo apt update && sudo apt install -y nmap python3 python3-pip"
    echo "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "go install -v github.com/epi052/feroxbuster@latest"  
    echo "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

echo "✅ All system dependencies found"

# Check Python dependencies
echo "📦 Checking Python dependencies..."
python3 -c "
import pkg_resources
import sys

required_packages = [
    'flask>=2.3.0',
    'flask-sqlalchemy>=3.0.0',
    'requests>=2.25.0',
    'apscheduler>=3.9.0',
    'pyjwt>=2.4.0'
]

missing_packages = []

for package in required_packages:
    try:
        pkg_resources.require(package)
    except:
        missing_packages.append(package.split('>=')[0])

if missing_packages:
    print(f'❌ Missing Python packages: {missing_packages}')
    print('Install with: pip3 install -r requirements.txt')
    sys.exit(1)
else:
    print('✅ All Python dependencies satisfied')
"

if [ $? -ne 0 ]; then
    exit 1
fi

# Check if database exists, create if not
echo "🗄️  Checking database..."
if [ ! -f "instance/akuma_advanced.db" ]; then
    echo "📝 Creating database..."
    mkdir -p instance
    python3 -c "
import sys
sys.path.append('.')
from akuma_advanced_scanner import db, User, app
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
    
    # Create default admin user if doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            email='admin@akuma.local', 
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(admin_user)
        db.session.commit()
        print('✅ Default admin user created (admin/admin123)')
    else:
        print('✅ Database and admin user already exist')
"
else
    echo "✅ Database exists"
fi

# Set environment variables
export FLASK_ENV=development
export FLASK_APP=akuma_advanced_scanner.py

# Start the application
echo "🚀 Starting Akuma Advanced Scanner..."
echo "📍 Web interface will be available at: http://localhost:5000"
echo "🔑 Default credentials: admin / admin123"
echo "📚 Advanced features: http://localhost:5000/advanced"
echo ""
echo "Press Ctrl+C to stop the scanner"
echo ""

# Run the advanced scanner
python3 akuma_advanced_scanner.py

echo "👋 Akuma Advanced Scanner stopped"
