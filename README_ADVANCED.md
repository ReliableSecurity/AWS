# 🔥 Akuma Advanced Web Scanner - Complete Feature Documentation

## 🎯 New Advanced Features

### 1. Vulnerability Detection with Nuclei
- **Nuclei Integration**: Automated vulnerability scanning using 3000+ templates
- **Custom Payloads**: SQLi, XSS, LFI, RFI, SSRF detection
- **Severity Classification**: Critical, High, Medium, Low, Info
- **Real-time Results**: Live vulnerability discovery with detailed reports

**Usage:**
```bash
# Via API
curl -X POST http://localhost:5000/api/start_scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"], "options": {"vulnerability_scan": true}}'

# Via Web Interface
Navigate to Advanced > Vulnerability Scan
```

### 2. SSL/TLS Certificate Analysis
- **Certificate Inspection**: Validity, issuer, expiration dates
- **Cipher Suite Analysis**: Supported protocols and encryption methods
- **Security Assessment**: Weak configurations and recommendations
- **Chain Validation**: Complete certificate chain verification

**Supported Checks:**
- Certificate expiration warnings
- Weak signature algorithms (MD5, SHA1)
- Insecure cipher suites
- Protocol version support (TLS 1.0, 1.1, 1.2, 1.3)

### 3. CMS Detection & Fingerprinting
- **WordPress**: Version detection, plugin enumeration, theme identification
- **Joomla**: Component discovery, version fingerprinting
- **Drupal**: Module detection, version identification
- **Magento**: Extension enumeration, security checks
- **Custom CMS**: Signature-based detection for proprietary systems

### 4. Advanced HTTP Fuzzing
- **Parameter Fuzzing**: Form fields, URL parameters, JSON payloads
- **Header Fuzzing**: Custom headers, injection attempts
- **Method Fuzzing**: HTTP verbs testing (PUT, DELETE, PATCH, OPTIONS)
- **Encoding Fuzzing**: URL encoding, Base64, HTML entities

### 5. Custom Wordlists Support
- **Upload Interface**: Custom wordlist management
- **Directory Lists**: SecLists integration, custom paths
- **Subdomain Lists**: Comprehensive subdomain enumeration
- **Parameter Lists**: Common parameter names for fuzzing

### 6. Scan Scheduling System
- **Cron-based Scheduling**: Flexible timing with cron expressions
- **Recurring Scans**: Daily, weekly, monthly scan automation
- **Resource Management**: Concurrent scan limits, queuing system
- **Notification Integration**: Email/Telegram alerts on completion

**Cron Examples:**
```bash
# Daily at 2 AM
0 2 * * *

# Weekly on Sundays
0 2 * * 0

# Every 6 hours
0 */6 * * *
```

### 7. Multi-Channel Notifications
- **Email Notifications**: SMTP integration with HTML reports
- **Telegram Bot**: Real-time scan status and results
- **Slack Integration**: Team notifications with rich formatting
- **Webhook Support**: Custom notification endpoints

**Configuration:**
```python
# Email setup
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your-email@gmail.com"
EMAIL_PASSWORD = "app-password"

# Telegram setup  
TELEGRAM_BOT_TOKEN = "your-bot-token"
TELEGRAM_CHAT_ID = "your-chat-id"
```

### 8. Enhanced User Management
- **Role-based Access**: Admin, Operator, Viewer roles
- **API Key Management**: Individual user API tokens
- **Audit Logging**: User action tracking and history
- **Team Collaboration**: Shared scan results and reports

**User Roles:**
- **Admin**: Full system access, user management
- **Operator**: Can create/run scans, view all results
- **Viewer**: Read-only access to scan results

### 9. JWT API Authentication
- **Token-based Auth**: Secure API access with JWT tokens
- **Expiration Handling**: Configurable token lifetimes
- **Refresh Mechanism**: Automatic token renewal
- **Scope-based Access**: Fine-grained API permissions

**API Usage:**
```bash
# Get JWT token
curl -X POST http://localhost:5000/api/jwt_token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use token in requests
curl -X GET http://localhost:5000/api/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 10. Docker Deployment
- **Multi-container Setup**: Scanner, database, reverse proxy
- **Volume Persistence**: Scan data and configuration storage
- **Environment Configuration**: Easy deployment variables
- **Scaling Support**: Horizontal scaling with load balancer

**Quick Deploy:**
```bash
# Clone and build
git clone https://github.com/sweetpotatohack/AWS
cd AWS/akuma_v2/gui

# Start with Docker Compose
docker-compose up -d

# Access at http://localhost
```

### 11. Scan Comparison Engine
- **Differential Analysis**: Compare scan results across time
- **Change Detection**: New/closed ports, new/fixed vulnerabilities  
- **Trend Analysis**: Security posture improvements or degradation
- **Visual Reports**: Interactive comparison charts and graphs

**Comparison Features:**
- Port state changes (opened/closed)
- New vulnerability discoveries
- Fixed security issues
- Service version changes
- SSL certificate updates

## 🚀 Installation & Setup

### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip nmap subfinder feroxbuster nuclei

# Install Python packages
pip3 install -r requirements.txt
```

### Database Setup
```bash
# Initialize database
python3 -c "from akuma_advanced_scanner import db; db.create_all()"

# Create admin user
python3 -c "
from akuma_advanced_scanner import db, User
from werkzeug.security import generate_password_hash
user = User(username='admin', email='admin@akuma.local', password_hash=generate_password_hash('admin123'))
db.session.add(user)
db.session.commit()
"
```

### Configuration
```bash
# Copy example config
cp config.example.py config.py

# Edit configuration
nano config.py
```

## 📊 API Endpoints

### Authentication
- `POST /api/jwt_token` - Get JWT authentication token
- `POST /api/refresh_token` - Refresh expired token

### Scanning
- `POST /api/start_scan` - Start comprehensive scan
- `GET /api/scans` - List all scans
- `GET /api/scan/{id}` - Get scan details
- `DELETE /api/scan/{id}` - Delete scan
- `POST /api/schedule_scan` - Schedule recurring scan

### Analysis
- `POST /api/cms_detection` - Detect CMS
- `POST /api/ssl_analysis` - Analyze SSL/TLS
- `POST /api/compare_scans` - Compare scan results
- `GET /api/vulnerability_report/{id}` - Get vulnerability report

### Management
- `POST /api/send_notification` - Send notifications
- `GET /api/users` - List users (Admin only)
- `POST /api/create_user` - Create new user (Admin only)

## 🛡️ Security Features

### Input Validation
- SQL injection prevention
- XSS protection in web interface
- Command injection safeguards
- File upload restrictions

### Access Control
- Role-based permissions
- JWT token validation
- API rate limiting
- Session management

### Data Protection
- Encrypted password storage
- Secure API key generation
- Database encryption at rest
- SSL/TLS for all communications

## 🔧 Advanced Configuration

### Scanner Modules
```python
# Enable/disable modules
MODULES = {
    'subdomain_enum': True,
    'port_scan': True, 
    'dir_bruteforce': True,
    'vulnerability_scan': True,
    'ssl_analysis': True,
    'cms_detection': True
}
```

### Performance Tuning
```python
# Concurrent scan limits
MAX_CONCURRENT_SCANS = 5
THREAD_POOL_SIZE = 20
REQUEST_TIMEOUT = 30

# Scanner timeouts
NMAP_TIMEOUT = 1800
NUCLEI_TIMEOUT = 3600
FEROX_TIMEOUT = 1800
```

### Notification Templates
```python
# Custom email templates
EMAIL_TEMPLATES = {
    'scan_complete': 'templates/email/scan_complete.html',
    'vulnerability_found': 'templates/email/vulnerability.html',
    'scan_failed': 'templates/email/scan_failed.html'
}
```

## 🎮 Testing Suite

Run comprehensive tests:
```bash
# Test all advanced features
python3 test_advanced_features.py

# Test specific modules
python3 -m pytest tests/test_vulnerability_scan.py
python3 -m pytest tests/test_ssl_analysis.py
python3 -m pytest tests/test_cms_detection.py
```

## 📈 Performance Metrics

### Scanning Speed
- **Port Scan**: ~1000 ports/second (optimized nmap)
- **Directory Brute**: ~100 requests/second (concurrent)
- **Vulnerability**: ~50 checks/second (nuclei templates)
- **SSL Analysis**: ~10 certificates/second

### Resource Usage
- **Memory**: ~500MB baseline, +100MB per active scan
- **CPU**: 2-4 cores recommended for optimal performance
- **Disk**: ~10GB for databases, logs, and temporary files
- **Network**: Configurable rate limiting (default: 100 req/sec)

## 🌟 Roadmap

### Version 2.1 (Next Release)
- [ ] Machine Learning vulnerability prioritization
- [ ] Automated exploit verification
- [ ] Advanced reporting with PDF export
- [ ] Integration with security tools (Burp, OWASP ZAP)

### Version 2.2 (Future)
- [ ] Mobile app for scan management
- [ ] Blockchain-based result integrity
- [ ] AI-powered false positive reduction
- [ ] Cloud deployment templates (AWS, Azure, GCP)

---

**🔥 Akuma Advanced Web Scanner - Where Security Meets Intelligence 🔥**

*"In the world of cybersecurity, knowledge is power, and power is protection."*

## Support & Community

- 📧 Email: support@akuma-scanner.com
- 💬 Discord: https://discord.gg/akuma-scanner
- 🐛 Issues: https://github.com/sweetpotatohack/AWS/issues
- 📚 Wiki: https://github.com/sweetpotatohack/AWS/wiki

---
*Built with ❤️ by the Akuma Security Team*
