from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    scans = db.relationship('Scan', backref='user', lazy=True)

    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.id)

# Enhanced Scan Model
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_domain = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')
    progress = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Scan options
    include_subdomains = db.Column(db.Boolean, default=False)
    fuzzing_depth = db.Column(db.Integer, default=0)  # 0=disabled, 1,2,5
    enable_bruteforce = db.Column(db.Boolean, default=False)
    
    # Results summary
    vulnerabilities_count = db.Column(db.Integer, default=0)
    subdomains_count = db.Column(db.Integer, default=0)
    open_ports_count = db.Column(db.Integer, default=0)
    
    # Relationships
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    subdomains = db.relationship('SubdomainResult', backref='scan', lazy=True, cascade='all, delete-orphan')

# Detailed Results Models
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    subdomain = db.Column(db.String(255), default='')  # empty for main domain
    result_type = db.Column(db.String(50), nullable=False)  # 'vulnerability', 'port', 'technology', etc.
    category = db.Column(db.String(100))  # 'SQLi', 'XSS', 'Open Port', etc.
    severity = db.Column(db.String(20), default='info')  # 'critical', 'high', 'medium', 'low', 'info'
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)  # JSON string with detailed evidence
    url = db.Column(db.String(1000))
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SubdomainResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    subdomain = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))
    status = db.Column(db.String(20), default='active')  # active, inactive
    scan_completed = db.Column(db.Boolean, default=False)
    vulnerabilities_count = db.Column(db.Integer, default=0)
    ports_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return jsonify({'success': True, 'message': 'Login successful'})
        else:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Enhanced Dashboard with statistics"""
    # Calculate statistics
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
    
    # Recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id)\
                            .order_by(Scan.created_at.desc())\
                            .limit(5)\
                            .all()
    
    # Vulnerability statistics
    total_vulnerabilities = db.session.query(db.func.sum(Scan.vulnerabilities_count))\
                                     .filter_by(user_id=current_user.id)\
                                     .scalar() or 0
    
    avg_vulns_per_scan = round(total_vulnerabilities / max(completed_scans, 1), 1)
    
    stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'average_vulns_per_scan': avg_vulns_per_scan,
        'recent_scans': recent_scans
    }
    
    return render_template('pages/dashboard.html', stats=stats)

@app.route('/scans')
@login_required
def scans():
    """Scans list page with user's scans only"""
    user_scans = Scan.query.filter_by(user_id=current_user.id)\
                          .order_by(Scan.created_at.desc())\
                          .all()
    return render_template('pages/scans.html', scans=user_scans)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    """Enhanced detailed scan results"""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    
    # Get all results grouped by type and subdomain
    results = ScanResult.query.filter_by(scan_id=scan_id).all()
    subdomains = SubdomainResult.query.filter_by(scan_id=scan_id).all()
    
    # Group results by category
    vulnerabilities = [r for r in results if r.result_type == 'vulnerability']
    ports = [r for r in results if r.result_type == 'port']
    technologies = [r for r in results if r.result_type == 'technology']
    directories = [r for r in results if r.result_type == 'directory']
    sensitive_content = [r for r in results if r.result_type == 'sensitive']
    
    # Group by subdomain for hierarchical display
    results_by_subdomain = {}
    for result in results:
        domain = result.subdomain or scan.target_domain
        if domain not in results_by_subdomain:
            results_by_subdomain[domain] = {
                'vulnerabilities': [],
                'ports': [],
                'technologies': [],
                'directories': [],
                'sensitive': []
            }
        
        if result.result_type in results_by_subdomain[domain]:
            results_by_subdomain[domain][result.result_type + 's'].append(result)
        else:
            results_by_subdomain[domain].setdefault(result.result_type + 's', []).append(result)
    
    return render_template('pages/scan_detail.html', 
                          scan=scan, 
                          results_by_subdomain=results_by_subdomain,
                          subdomains=subdomains,
                          vulnerabilities=vulnerabilities,
                          ports=ports,
                          technologies=technologies,
                          directories=directories,
                          sensitive_content=sensitive_content,
                          total_results=len(results))

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Delete a scan and its results"""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted successfully')
    return redirect(url_for('scans'))

@app.route('/notifications')
@login_required
def notifications():
    """Notifications page"""
    return render_template('pages/notifications.html')

@app.route('/api/start_scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new scan with options"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target domain is required'}), 400
    
    # Create new scan with options
    scan = Scan(
        target_domain=target,
        user_id=current_user.id,
        include_subdomains=data.get('subdomains', False),
        fuzzing_depth=data.get('fuzzing_depth', 0),
        enable_bruteforce=data.get('bruteforce', False),
        status='running',
        started_at=datetime.utcnow()
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Here you would integrate with your scanning engine
    # For now, return success
    return jsonify({
        'success': True, 
        'scan_id': scan.id,
        'message': f'Scan started for {target}'
    })

@app.route('/api/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    """Get scan status and progress"""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    
    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'progress': scan.progress,
        'target': scan.target_domain,
        'vulnerabilities_count': scan.vulnerabilities_count,
        'subdomains_count': scan.subdomains_count,
        'open_ports_count': scan.open_ports_count
    })

def create_admin_user():
    """Create default admin user"""
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin/admin123")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
