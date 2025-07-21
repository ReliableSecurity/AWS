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
