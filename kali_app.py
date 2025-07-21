#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Akuma Web Scanner v2.0
Веб-интерфейс в стиле Kali Linux терминала
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sys
import os
import json
import asyncio
import threading
from datetime import datetime
import uuid
import hashlib

# Добавляем пути
sys.path.append('/home/kali/AWS/akuma_v2/core')
sys.path.append('/home/kali/AWS/akuma_v2/database')

from master_scanner import AkumaMasterScanner
from models import db, User, ScanSession, Vulnerability, Directory, Target

app = Flask(__name__)
app.config['SECRET_KEY'] = 'akuma_kali_scanner_v2_666'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akuma_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Глобальные переменные
active_scans = {}
scan_history = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class WebMasterScanner(AkumaMasterScanner):
    """Расширенная версия сканера для веб-интерфейса"""
    
    def __init__(self, target_domain, scan_id, user_id):
        super().__init__(target_domain)
        self.web_scan_id = scan_id
        self.user_id = user_id
        
    async def log(self, level, message, scan_id=None):
        """Отправляем логи через WebSocket"""
        socketio.emit('scan_log', {
            'scan_id': self.web_scan_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'level': level,
            'message': message
        })
        
        # Также сохраняем в историю
        if self.web_scan_id not in scan_history:
            scan_history[self.web_scan_id] = []
        
        scan_history[self.web_scan_id].append({
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        })

    async def update_progress(self, phase_name):
        """Обновляем прогресс через WebSocket"""
        await super().update_progress(phase_name)
        
        progress_percent = (self.scan_results['progress'] / self.scan_results['total_phases']) * 100
        
        socketio.emit('scan_progress', {
            'scan_id': self.web_scan_id,
            'progress': progress_percent,
            'phase': phase_name,
            'current': self.scan_results['progress'],
            'total': self.scan_results['total_phases']
        })

    async def save_results_to_db(self):
        """Сохранение результатов в базу данных"""
        try:
            with app.app_context():
                # Обновляем сессию сканирования
                scan_session = ScanSession.query.filter_by(id=self.web_scan_id).first()
                if scan_session:
                    scan_session.status = 'completed'
                    scan_session.completed_at = datetime.now()
                    scan_session.progress = 100
                    
                    # Сохраняем уязвимости
                    for vuln_data in self.scan_results.get('vulnerabilities', []):
                        vuln = Vulnerability(
                            type=vuln_data['vuln_type'],
                            severity=vuln_data['severity'],
                            description=vuln_data.get('payload', ''),
                            url=vuln_data['url'],
                            target_id=1  # TODO: связать с правильной целью
                        )
                        db.session.add(vuln)
                    
                    # Сохраняем найденные директории
                    for dir_data in self.scan_results.get('directories', []):
                        directory = Directory(
                            path=dir_data['path'],
                            status_code=dir_data['status_code'],
                            size=dir_data.get('content_length', 0),
                            target_id=1  # TODO: связать с правильной целью
                        )
                        db.session.add(directory)
                    
                    db.session.commit()
                    
        except Exception as e:
            print(f"Ошибка сохранения в БД: {e}")

@app.route('/')
def index():
    """Главная страница"""
    if not current_user.is_authenticated:
        return render_template('login.html')
    return render_template('kali_scanner.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password_hash == hashlib.sha256(password.encode()).hexdigest():
            login_user(user)
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Неверные данные входа'})
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Выход"""
    logout_user()
    return render_template('login.html')

@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scan():
    """Запуск нового сканирования"""
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target domain required'}), 400
    
    # Создаём новую сессию сканирования
    scan_id = str(uuid.uuid4())
    
    scan_session = ScanSession(
        id=scan_id,
        target_domain=target,
        status='running',
        started_at=datetime.now(),
        user_id=1,
        scan_config=json.dumps(data)
    )
    
    db.session.add(scan_session)
    db.session.commit()
    
    # Создаём и запускаем сканер
    scanner = WebMasterScanner(target, scan_id, 1)
    active_scans[scan_id] = scanner
    
    # Запускаем в отдельном потоке
    def run_async_scan():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def scan_wrapper():
            try:
                results = await scanner.run_full_scan()
                await scanner.save_results_to_db()
                
                # Уведомляем о завершении
                socketio.emit('scan_complete', {
                    'scan_id': scan_id,
                    'results': results
                })
                
            except Exception as e:
                socketio.emit('scan_error', {
                    'scan_id': scan_id,
                    'error': str(e)
                })
            finally:
                # Удаляем из активных
                if scan_id in active_scans:
                    del active_scans[scan_id]
        
        loop.run_until_complete(scan_wrapper())
        loop.close()
    
    thread = threading.Thread(target=run_async_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': f'Сканирование {target} запущено'
    })

@app.route('/api/scan/fuzzing', methods=['POST'])
@login_required
def start_fuzzing():
    """Запуск фазинга"""
    data = request.json
    target_url = data.get('target_url')
    wordlist_path = data.get('wordlist_path')
    
    if not target_url:
        return jsonify({'error': 'Target URL required'}), 400
    
    scan_id = str(uuid.uuid4())
    
    def run_fuzzing():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def fuzzing_wrapper():
            scanner = WebMasterScanner(target_url, scan_id, 1)
            results = await scanner.run_fuzzing(target_url, wordlist_path)
            
            socketio.emit('fuzzing_complete', {
                'scan_id': scan_id,
                'results': results
            })
        
        loop.run_until_complete(fuzzing_wrapper())
        loop.close()
    
    thread = threading.Thread(target=run_fuzzing)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Фазинг запущен'
    })

@app.route('/api/scan/bruteforce', methods=['POST'])
@login_required
def start_bruteforce():
    """Запуск брутфорса"""
    data = request.json
    target_url = data.get('target_url')
    wordlist_path = data.get('wordlist_path')
    
    scan_id = str(uuid.uuid4())
    
    def run_bruteforce():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def bruteforce_wrapper():
            scanner = WebMasterScanner(target_url, scan_id, 1)
            results = await scanner.run_bruteforce(target_url, wordlist_path)
            
            socketio.emit('bruteforce_complete', {
                'scan_id': scan_id,
                'results': results
            })
        
        loop.run_until_complete(bruteforce_wrapper())
        loop.close()
    
    thread = threading.Thread(target=run_bruteforce)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Брутфорс запущен'
    })

@app.route('/api/scans/history')
@login_required
def get_scan_history():
    """История сканирований пользователя"""
    scans = ScanSession.query.filter_by(user_id=1).order_by(ScanSession.created_at.desc()).limit(20).all()
    
    result = []
    for scan in scans:
        result.append({
            'id': scan.id,
            'target_domain': scan.target_domain,
            'status': scan.status,
            'created_at': scan.created_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'progress': scan.progress
        })
    
    return jsonify(result)

@app.route('/api/scan/compare/<scan_id1>/<scan_id2>')
@login_required  
def compare_scans(scan_id1, scan_id2):
    """Сравнение двух сканирований"""
    # TODO: Реализовать сравнение результатов сканирований
    return jsonify({
        'message': 'Функция сравнения в разработке',
        'scan1': scan_id1,
        'scan2': scan_id2
    })

@socketio.on('connect')
def handle_connect():
    """Обработка подключения клиента"""
    emit('connected', {'message': 'Подключено к Akuma Scanner v2.0'})

@socketio.on('disconnect')  
def handle_disconnect():
    """Обработка отключения клиента"""
    print('Клиент отключился')

def init_db():
    """Инициализация базы данных"""
    with app.app_context():
        db.create_all()
        
        # Создаём пользователя по умолчанию
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@akuma.scanner',
                password_hash=hashlib.sha256('admin123'.encode()).hexdigest(),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Создан пользователь: admin / admin123")

if __name__ == '__main__':
    init_db()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                  AKUMA WEB SCANNER v2.0                   ║
    ║                 Kali Linux Style Interface                ║  
    ║              Created by Феня (2025)                       ║
    ╚═══════════════════════════════════════════════════════════╝
    
    🔥 Запуск на http://0.0.0.0:5000
    📋 Логин: admin / Пароль: admin123
    """)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
