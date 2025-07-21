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
