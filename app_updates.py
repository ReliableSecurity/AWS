# Добавим новые роуты для live логов в app.py

# В секцию роутов добавляем:

@app.route('/api/scan/<int:scan_id>/logs')
@login_required
def get_scan_logs(scan_id):
    """API для получения логов сканирования"""
    from real_scanner_engine import get_scan_logs
    logs = get_scan_logs(scan_id)
    return jsonify({'logs': logs})

@app.route('/api/scan/<int:scan_id>/results')
@login_required  
def get_scan_results_api(scan_id):
    """API для получения результатов сканирования"""
    from real_scanner_engine import get_scan_results
    results = get_scan_results(scan_id)
    return jsonify(results)

# Обновляем функцию запуска сканирования:
def start_scan_updated():
    data = request.get_json()
    target = data.get('target')
    include_subdomains = data.get('include_subdomains', True)
    fuzzing_depth = data.get('fuzzing_depth', 2)
    
    if not target:
        return jsonify({'status': 'error', 'message': 'Target is required'}), 400
    
    try:
        scan = Scan(
            target=target,
            user_id=current_user.id,
            status='running',
            progress=0,
            started_at=datetime.utcnow(),
            options=json.dumps({
                'include_subdomains': include_subdomains,
                'fuzzing_depth': fuzzing_depth
            })
        )
        
        db.session.add(scan)
        db.session.commit()
        
        # Запускаем настоящее сканирование
        from real_scanner_engine import start_scan_thread
        start_scan_thread(app, scan.id, target, {
            'include_subdomains': include_subdomains,
            'fuzzing_depth': fuzzing_depth
        })
        
        return jsonify({
            'status': 'success', 
            'scan_id': scan.id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to start scan: {str(e)}'}), 500

