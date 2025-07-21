from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akuma_web_scanner_secret_key_2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akuma_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')
    progress = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())
    completed_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    options = db.Column(db.Text, default='{}')
    scan_data = db.Column(db.Text)  # Для хранения JSON результатов
    
    def get_options(self):
        return json.loads(self.options) if self.options else {}
    
    def set_options(self, options_dict):
        self.options = json.dumps(options_dict)
        
    def get_scan_data(self):
        return json.loads(self.scan_data) if self.scan_data else {}
        
    def set_scan_data(self, data):
        self.scan_data = json.dumps(data)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    result_type = db.Column(db.String(50), nullable=False)
    data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow())

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Проверяем Content-Type
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Username and password required'})
            else:
                flash('Username and password required', 'error')
                return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if request.is_json:
                return jsonify({'status': 'success', 'redirect': url_for('dashboard')})
            else:
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Invalid credentials'})
            else:
                flash('Invalid credentials', 'error')
                return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/") 
@login_required 
def dashboard(): 
    total_scans = Scan.query.filter_by(user_id=current_user.id).count() 
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status="completed").count() 
    running_scans = Scan.query.filter_by(user_id=current_user.id, status="running").count() 
     
    # Получаем последние сканы 
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(5).all() 
     
    # Подсчитываем уязвимости (пока заглушка) 
    total_vulnerabilities = 0 
    if completed_scans > 0: 
        average_vulns_per_scan = total_vulnerabilities / completed_scans 
    else: 
        average_vulns_per_scan = 0 
     
    # Создаем объект stats для шаблона 
    stats = { 
        "total_scans": total_scans, 
        "completed_scans": completed_scans, 
        "running_scans": running_scans, 
        "total_vulnerabilities": total_vulnerabilities, 
        "average_vulns_per_scan": round(average_vulns_per_scan, 2), 
        "recent_scans": recent_scans 
    } 
     
    return render_template("pages/dashboard.html", stats=stats)

@app.route('/scans')
@login_required
def scans():
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).all()
    return render_template('pages/scans.html', scans=user_scans)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_details(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    
    # Получаем данные сканирования
    scan_data = scan.get_scan_data()
    
    return render_template('scan_details_live.html', scan=scan, scan_data=scan_data)

@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    
    # Удаляем связанные результаты
    ScanResult.query.filter_by(scan_id=scan_id).delete()
    
    # Удаляем сам скан
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan deleted successfully', 'success')
    return redirect(url_for('scans'))

@app.route('/notifications')
@login_required
def notifications():
    return render_template('pages/notifications.html')

# API Routes
@app.route('/api/start_scan', methods=['POST'])
@login_required
def api_start_scan():
    try:
        data = request.get_json()
        target = data.get('target')
        
        if not target:
            return jsonify({'status': 'error', 'message': 'Target is required'}), 400
        
        options = {
            'subdomains': data.get('subdomains', False),
            'fuzzing': data.get('fuzzing', False),
            'bruteforce': data.get('bruteforce', False)
        }
        
        # Создаём новый скан
        scan = Scan(
            target=target,
            status='pending',
            user_id=current_user.id,
            started_at=datetime.utcnow()
        )
        scan.set_options(options)
        
        db.session.add(scan)
        db.session.commit()
        
        # Запускаем реальное сканирование с правильными параметрами!
        from scanner_engine import start_scan_thread
        scan_options = {
            "include_subdomains": options.get('subdomains', False),
            "fuzzing_depth": 2 if options.get('fuzzing') else 0,
            "bruteforce": options.get('bruteforce', False)
        }
        start_scan_thread(app, scan.id, target, scan_options)
        
        return jsonify({
            'status': 'success',
            'message': 'Scan started successfully',
            'scan_id': scan.id
        })
        
    except Exception as e:
        print(f"[ERROR] Start scan failed: {str(e)}")  # Логируем ошибку
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
@app.route('/api/scan/<int:scan_id>/status')
@login_required
def api_scan_status(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'status': scan.status,
        'progress': scan.progress,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })

if __name__ == '__main__':
    # Создаём таблицы
    with app.app_context():
        db.create_all()
        
        # Создаём админа если его нет
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()
            print("[+] Admin user created: admin/admin123")
        else:
            print("[+] Admin user exists")
    
    print("[+] Starting Akuma Web Scanner...")
    app.run(host='0.0.0.0', port=5000, debug=True)

@app.route('/api/scan/<int:scan_id>/logs')
@login_required
def get_scan_logs_api(scan_id):
    """API для получения логов сканирования"""
    try:
        from scanner_engine import get_scan_logs
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
        from scanner_engine import get_scan_results
        results = get_scan_results(scan_id)
        print(f"[DEBUG] Getting results for scan {scan_id}: {results}")
        return jsonify(results or {'status': 'no_results'})
    except Exception as e:
        print(f"[ERROR] Failed to get results for scan {scan_id}: {e}")
        return jsonify({'error': str(e)}, 500)
