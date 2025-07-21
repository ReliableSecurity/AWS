// Login Form Handler
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMessage = document.getElementById('error-message');
            
            // Очищаем предыдущие ошибки
            if (errorMessage) {
                errorMessage.style.display = 'none';
            }
            
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = data.redirect;
                } else {
                    if (errorMessage) {
                        errorMessage.textContent = data.message;
                        errorMessage.style.display = 'block';
                    }
                }
            })
            .catch(error => {
                console.error('Error:', error);
                if (errorMessage) {
                    errorMessage.textContent = 'Login failed. Please try again.';
                    errorMessage.style.display = 'block';
                }
            });
        });
    }

    // Scan Form Handler
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const subdomains = document.getElementById('subdomains').checked;
            const fuzzing = document.getElementById('fuzzing').checked;
            const bruteforce = document.getElementById('bruteforce').checked;
            
            fetch('/api/start_scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: target,
                    subdomains: subdomains,
                    fuzzing: fuzzing,
                    bruteforce: bruteforce
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    showNotification('Scan started successfully!', 'success');
                    setTimeout(() => {
                        window.location.href = `/scan/${data.scan_id}`;
                    }, 1000);
                } else {
                    showNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Failed to start scan', 'error');
            });
        });
    }
});

// Notification System
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Стили для уведомлений
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        font-weight: bold;
        z-index: 10000;
        transition: all 0.3s ease;
    `;
    
    if (type === 'success') {
        notification.style.backgroundColor = '#00ff00';
        notification.style.color = 'black';
    } else if (type === 'error') {
        notification.style.backgroundColor = '#ff0000';
    }
    
    document.body.appendChild(notification);
    
    // Убираем через 3 секунды
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Auto-refresh for scan status
function startScanStatusPolling() {
    const scanId = window.location.pathname.split('/')[2];
    if (scanId && !isNaN(scanId)) {
        const pollInterval = setInterval(() => {
            fetch(`/api/scan/${scanId}/status`)
                .then(response => response.json())
                .then(data => {
                    // Обновляем прогресс бар
                    const progressBar = document.querySelector('.progress-bar');
                    if (progressBar) {
                        progressBar.style.width = `${data.progress}%`;
                        progressBar.textContent = `${data.progress}%`;
                    }
                    
                    // Обновляем статус
                    const statusElement = document.querySelector('.scan-status');
                    if (statusElement) {
                        statusElement.textContent = data.status.toUpperCase();
                        statusElement.className = `scan-status status-${data.status}`;
                    }
                    
                    // Если скан завершён - перезагружаем страницу для показа результатов
                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(pollInterval);
                        if (data.status === 'completed') {
                            setTimeout(() => {
                                window.location.reload();
                            }, 2000);
                        }
                    }
                })
                .catch(error => console.error('Error polling status:', error));
        }, 3000); // Обновляем каждые 3 секунды
    }
}

// Запускаем автообновление если мы на странице детального просмотра скана
if (window.location.pathname.includes('/scan/')) {
    startScanStatusPolling();
}
