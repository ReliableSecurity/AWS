from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akuma_advanced_pentest_scanner_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akuma_advanced_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ========================= MODELS =========================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)  # Название сканирования
    targets = db.Column(db.Text, nullable=False)  # JSON список целей
    status = db.Column(db.String(50), default='pending')
    progress = db.Column(db.Integer, default=0)
    current_phase = db.Column(db.String(100), default='')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    options = db.Column(db.Text, default='{}')  # JSON настройки сканирования
    scan_data = db.Column(db.Text)  # Полные результаты сканирования
    
    def get_targets(self):
        return json.loads(self.targets) if self.targets else []
    
    def set_targets(self, targets_list):
        self.targets = json.dumps(targets_list)
    
    def get_options(self):
        return json.loads(self.options) if self.options else {}
    
    def set_options(self, options_dict):
        self.options = json.dumps(options_dict)
        
    def get_scan_data(self):
        return json.loads(self.scan_data) if self.scan_data else {}
        
    def set_scan_data(self, data):
        self.scan_data = json.dumps(data, indent=2)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========================= ROUTES =========================

@app.route('/')
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Статистика для дашборда
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
    running_scans = Scan.query.filter_by(user_id=current_user.id, status='running').count()
    
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(5).all()
    
    dashboard_stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'running_scans': running_scans,
        'success_rate': round((completed_scans / total_scans * 100) if total_scans > 0 else 0, 1)
    }
    
    return render_template('dashboard.html', stats=dashboard_stats, recent_scans=recent_scans)

@app.route('/scans')
@login_required
def scans():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).all()
    return render_template('scans.html', scans=scans)

@app.route('/notifications')
@login_required
def notifications():
    return render_template('notifications.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ========================= SCAN API ROUTES =========================

@app.route('/api/start_scan', methods=['POST'])
@login_required
def api_start_scan():
    try:
        data = request.get_json()
        scan_name = data.get('name', '')
        targets = data.get('targets', [])
        
        if not scan_name:
            return jsonify({'status': 'error', 'message': 'Scan name is required'}), 400
        
        if not targets:
            return jsonify({'status': 'error', 'message': 'At least one target is required'}), 400
        
        # Очистим targets от пустых строк
        targets = [t.strip() for t in targets if t.strip()]
        
        options = {
            'subdomains': data.get('subdomains', False),
            'fuzzing': data.get('fuzzing', False),
        }
        
        # Создаём новый скан
        scan = Scan(
            name=scan_name,
            status='pending',
            user_id=current_user.id,
            started_at=datetime.utcnow()
        )
        scan.set_targets(targets)
        scan.set_options(options)
        
        db.session.add(scan)
        db.session.commit()
        
        # Запускаем продвинутое сканирование!
        from advanced_scanner_engine import start_advanced_scan_thread
        start_advanced_scan_thread(app, scan.id, scan_name, targets, options)
        
        return jsonify({
            'status': 'success',
            'message': 'Pentest scan started successfully',
            'scan_id': scan.id
        })
        
    except Exception as e:
        print(f"[ERROR] Start scan failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/scan/<int:scan_id>/status')
@login_required
def api_scan_status(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Получаем прогресс из advanced scanner
    from advanced_scanner_engine import get_scan_progress
    progress_info = get_scan_progress(scan_id)
    
    return jsonify({
        'id': scan.id,
        'name': scan.name,
        'status': scan.status,
        'progress': progress_info.get('progress', scan.progress),
        'current_phase': progress_info.get('phase', scan.current_phase),
        'targets': scan.get_targets(),
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })

@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template('scan_details.html', scan=scan)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if scan:
        db.session.delete(scan)
        db.session.commit()
        flash('Scan deleted successfully')
    return redirect(url_for('scans'))

@app.route('/api/scan/<int:scan_id>/logs')
@login_required
def get_scan_logs_api(scan_id):
    """API для получения логов сканирования"""
    try:
        from advanced_scanner_engine import get_scan_logs
        logs = get_scan_logs(scan_id)
        print(f"[DEBUG] Getting logs for scan {scan_id}: {len(logs) if logs else 0} entries")
        return jsonify({'logs': logs or []})
    except Exception as e:
        print(f"[ERROR] Failed to get logs for scan {scan_id}: {e}")
        return jsonify({'logs': [], 'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>/results')
@login_required  
def get_scan_results_api(scan_id):
    """API для получения результатов сканирования"""
    try:
        from advanced_scanner_engine import get_scan_results
        results = get_scan_results(scan_id)
        print(f"[DEBUG] Getting results for scan {scan_id}: found {len(results) if results else 0} keys")
        return jsonify(results or {'status': 'no_results'})
    except Exception as e:
        print(f"[ERROR] Failed to get results for scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats')
@login_required
def get_dashboard_stats():
    """API для получения статистики дашборда"""
    # Базовая статистика
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
    running_scans = Scan.query.filter_by(user_id=current_user.id, status='running').count()
    failed_scans = Scan.query.filter_by(user_id=current_user.id, status='failed').count()
    
    # Статистика по фазам (из завершённых сканов)
    completed_scan_records = Scan.query.filter_by(user_id=current_user.id, status='completed').all()
    
    total_targets_scanned = 0
    total_subdomains_found = 0
    total_open_ports_found = 0
    total_directories_found = 0
    
    for scan in completed_scan_records:
        scan_data = scan.get_scan_data()
        if 'phases' in scan_data and 'reconnaissance' in scan_data['phases']:
            recon = scan_data['phases']['reconnaissance']
            total_targets_scanned += len(recon.get('targets', {}))
            total_subdomains_found += recon.get('total_subdomains', 0)
            total_open_ports_found += recon.get('total_open_ports', 0)
        
        if 'phases' in scan_data and 'web_discovery' in scan_data['phases']:
            web_disc = scan_data['phases']['web_discovery']
            for target_data in web_disc.values():
                for web_target_data in target_data.values():
                    total_directories_found += len(web_target_data.get('directories', []))
    
    return jsonify({
        'scan_stats': {
            'total': total_scans,
            'completed': completed_scans,
            'running': running_scans,
            'failed': failed_scans,
            'success_rate': round((completed_scans / total_scans * 100) if total_scans > 0 else 0, 1)
        },
        'pentest_stats': {
            'targets_scanned': total_targets_scanned,
            'subdomains_found': total_subdomains_found,
            'open_ports_found': total_open_ports_found,
            'directories_found': total_directories_found
        }
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Создаём админа если его нет
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                password_hash=generate_password_hash('akuma2024')
            )
            db.session.add(admin_user)
            db.session.commit()
            print("[+] Admin user created (admin:akuma2024)")
        else:
            print("[+] Admin user exists")
    
    print("[+] Starting Akuma Advanced Pentest Scanner...")
    app.run(host='0.0.0.0', port=5000, debug=True)
