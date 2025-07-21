#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS - Akuma Web Scanner
Профессиональный веб-сканер безопасности
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
import sys
import os
import json
import asyncio
import threading
from datetime import datetime, timedelta
import uuid

# Добавляем пути к модулям
sys.path.append('/home/kali/AWS/akuma_v2/core')
sys.path.append('/home/kali/AWS/akuma_v2/modules')

from master_scanner import AkumaMasterScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aws_kali_scanner_2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aws_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Модели базы данных
class ScanSession(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    target_domain = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='created')  # created, running, completed, error
    progress = db.Column(db.Integer, default=0)
    current_phase = db.Column(db.String(100))
    
    # Результаты
    subdomains_count = db.Column(db.Integer, default=0)
    open_ports_count = db.Column(db.Integer, default=0)
    vulnerabilities_count = db.Column(db.Integer, default=0)
    sensitive_findings_count = db.Column(db.Integer, default=0)
    
    # Временные метки
    created_at = db.Column(db.DateTime, default=datetime.now)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # JSON результаты
    scan_results = db.Column(db.Text)  # JSON строка с полными результатами

# Глобальные перемены для управления сканированием
active_scans = {}

class WebAkumaScanner(AkumaMasterScanner):
    """Веб-версия сканера с интеграцией в Flask"""
    
    def __init__(self, target_domain, scan_id):
        super().__init__(target_domain)
        self.web_scan_id = scan_id
        
    async def log(self, level, message, scan_id=None):
        """Отправляем логи через WebSocket"""
        socketio.emit('scan_log', {
            'scan_id': self.web_scan_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'level': level,
            'message': message
        })
        
    async def update_progress(self, phase_name):
        """Обновляем прогресс через WebSocket"""
        await super().update_progress(phase_name)
        
        progress_percent = (self.scan_results['progress'] / self.scan_results['total_phases']) * 100
        
        # Обновляем в базе данных
        with app.app_context():
            scan = ScanSession.query.get(self.web_scan_id)
            if scan:
                scan.progress = int(progress_percent)
                scan.current_phase = phase_name
                db.session.commit()
        
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
                scan = ScanSession.query.get(self.web_scan_id)
                if scan:
                    scan.status = 'completed'
                    scan.completed_at = datetime.now()
                    scan.progress = 100
                    
                    # Сохраняем статистику
                    scan.subdomains_count = len(self.scan_results.get('subdomains', []))
                    scan.open_ports_count = len(self.scan_results.get('open_ports', []))
                    scan.vulnerabilities_count = len(self.scan_results.get('vulnerabilities', []))
                    scan.sensitive_findings_count = len(self.scan_results.get('sensitive_content', []))
                    
                    # Сохраняем полные результаты как JSON
                    scan.scan_results = json.dumps(self.scan_results)
                    
                    db.session.commit()
                    
        except Exception as e:
            print(f"Ошибка сохранения в БД: {e}")

# Маршруты
@app.route('/')
def dashboard():
    """Главная страница - Dashboard"""
    # Получаем статистику за разные периоды
    stats = get_dashboard_stats()
    return render_template('pages/dashboard.html', stats=stats)

@app.route('/scans')
def scans():
    """Страница со списком сканирований"""
    scans = ScanSession.query.order_by(ScanSession.created_at.desc()).limit(50).all()
    return render_template('pages/scans.html', scans=scans)

@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Детальная страница сканирования"""
    scan = ScanSession.query.get_or_404(scan_id)
    
    # Парсим результаты из JSON
    results = {}
    if scan.scan_results:
        try:
            results = json.loads(scan.scan_results)
        except:
            results = {}
    
    return render_template('pages/scan_detail.html', scan=scan, results=results)

@app.route('/notifications')
def notifications():
    """Страница уведомлений"""
    return render_template('pages/notifications.html')

# API для запуска сканирования
@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Запуск нового сканирования"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target domain required'}), 400
    
    # Создаём новую сессию сканирования
    scan_id = str(uuid.uuid4())
    
    scan_session = ScanSession(
        id=scan_id,
        target_domain=target,
        status='running',
        started_at=datetime.now()
    )
    
    db.session.add(scan_session)
    db.session.commit()
    
    # Создаём и запускаем сканер
    scanner = WebAkumaScanner(target, scan_id)
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
                # Обновляем статус в БД
                with app.app_context():
                    scan = ScanSession.query.get(scan_id)
                    if scan:
                        scan.status = 'error'
                        db.session.commit()
                
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

@app.route('/api/scan/<scan_id>/services')
def get_scan_services(scan_id):
    """Получение сервисов найденных в сканировании для фазинга"""
    scan = ScanSession.query.get_or_404(scan_id)
    
    if not scan.scan_results:
        return jsonify({'services': []})
    
    try:
        results = json.loads(scan.scan_results)
        
        # Собираем веб-сервисы для фазинга
        web_services = []
        for target in results.get('live_targets', []):
            if target.get('port') in [80, 443, 8080, 8443, 8888]:
                web_services.append({
                    'url': target['url'],
                    'port': target['port'],
                    'protocol': target['protocol'],
                    'service': target.get('service', 'HTTP')
                })
        
        # Собираем сервисы для брутфорса
        bruteforce_services = []
        for port_info in results.get('open_ports', []):
            if port_info['port'] in [21, 22, 23, 25, 3389]:  # FTP, SSH, Telnet, SMTP, RDP
                bruteforce_services.append({
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'host': port_info['domain']
                })
        
        return jsonify({
            'web_services': web_services,
            'bruteforce_services': bruteforce_services
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """Удаление сканирования"""
    scan = ScanSession.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Сканирование удалено'})

def get_dashboard_stats():
    """Получение статистики для дашборда"""
    now = datetime.now()
    
    # Периоды для статистики
    periods = {
        '1_month': now - timedelta(days=30),
        '3_months': now - timedelta(days=90),
        '6_months': now - timedelta(days=180),
        '12_months': now - timedelta(days=365)
    }
    
    stats = {}
    
    for period_name, start_date in periods.items():
        scans = ScanSession.query.filter(ScanSession.created_at >= start_date).all()
        
        total_vulns = sum(scan.vulnerabilities_count or 0 for scan in scans)
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.status == 'completed'])
        
        stats[period_name] = {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'total_vulnerabilities': total_vulns,
            'average_vulns_per_scan': round(total_vulns / max(total_scans, 1), 2)
        }
    
    # Последние сканирования
    recent_scans = ScanSession.query.order_by(ScanSession.created_at.desc()).limit(5).all()
    stats['recent_scans'] = recent_scans
    
    return stats

# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Подключено к AWS Scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Клиент отключился')

def init_db():
    """Инициализация базы данных"""
    with app.app_context():
        db.create_all()
        print("База данных AWS Scanner инициализирована")

if __name__ == '__main__':
    init_db()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                     AWS - Akuma Web Scanner               ║
    ║                 Professional Security Scanner            ║  
    ║              🔥 Терминальный стиль Kali Linux 🔥          ║
    ║                                                           ║
    ║              Created by Феня (2025)                       ║
    ╚═══════════════════════════════════════════════════════════╝
    
    🌐 Веб-интерфейс: http://0.0.0.0:5000
    📊 Dashboard: /
    🔍 Scans: /scans  
    🔔 Notifications: /notifications
    """)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
