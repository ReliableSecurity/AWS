# 🔥 Akuma Web Scanner (AWS) - Advanced Pentest Framework

![Akuma Banner](https://img.shields.io/badge/Akuma-Web%20Scanner-red?style=for-the-badge&logo=hackthebox&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green?style=for-the-badge&logo=flask)
![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=for-the-badge)

**Akuma Web Scanner** - это профессиональный пентестинговый фреймворк в стиле Kali Linux с современным web-интерфейсом и реальными инструментами разведки.

## 🚀 Особенности

### 🔍 **Разведка и Сканирование**
- **Subdomain Discovery** - Поиск поддоменов с помощью `subfinder`
- **Advanced Port Scanning** - Глубокое сканирование портов через `nmap`
- **Directory Fuzzing** - Брутфорс директорий с `feroxbuster`
- **Service Detection** - Определение сервисов и версий
- **Live Logging** - Логи в реальном времени

### 🎯 **Web-интерфейс**
- **Matrix-стиль анимация** - Хакерский терминальный интерфейс
- **Live Updates** - Обновления статуса каждые 5 секунд
- **Dashboard** - Статистика и управление сканированиями
- **Scan History** - История всех проведенных сканирований
- **Detailed Reports** - Детальные отчеты с результатами

### 🛠️ **Технические возможности**
- **Asynchronous Scanning** - Многопоточное выполнение
- **Database Storage** - SQLite база данных для хранения результатов
- **RESTful API** - API для интеграции с внешними системами
- **Responsive Design** - Адаптивный дизайн для всех устройств

## 📦 Установка

### Требования
```bash
# Kali Linux / Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-pip nmap subfinder feroxbuster

# Или через snap
sudo snap install subfinder
```

### Быстрый старт
```bash
# Клонирование репозитория
git clone https://github.com/sweetpotatohack/AWS.git
cd AWS

# Установка зависимостей
pip3 install flask sqlalchemy

# Запуск сканера
python3 improved_scanner_app.py
```

🌐 **Веб-интерфейс доступен по адресу:** `http://localhost:5000`

## 🎮 Использование

### 1. **Веб-интерфейс**
```
http://localhost:5000
```
- Логин: `admin`
- Пароль: `admin123`

### 2. **Создание сканирования**
1. Перейди в Dashboard
2. Введи цель (например: `example.com`)
3. Выбери опции:
   - ✅ **Subdomains** - Поиск поддоменов
   - ✅ **Fuzzing** - Брутфорс директорий
4. Нажми **Start Scan**

### 3. **Мониторинг**
- **Live Logs** - Логи в реальном времени
- **Progress Bar** - Прогресс выполнения
- **Results** - Детальные результаты

## 🔧 Архитектура

```
AWS/
├── improved_scanner_app.py    # Основное приложение Flask
├── static/
│   ├── css/style.css         # Kali-стили и Matrix-анимация
│   └── js/matrix.js          # JavaScript для интерфейса
├── templates/
│   ├── base.html             # Базовый шаблон
│   ├── dashboard.html        # Главная панель
│   ├── scans.html           # История сканирований
│   ├── scan_detail.html     # Детали скана
│   └── notifications.html   # Уведомления
└── instance/
    └── akuma.db             # База данных SQLite
```

## 🛡️ Компоненты сканирования

### **Phase 1: Subdomain Discovery**
```bash
subfinder -d target.com -silent
```
- Поиск поддоменов из различных источников
- Пассивная разведка DNS записей
- Проверка доступности поддоменов

### **Phase 2: Port Scanning**
```bash
nmap -sS -Pn -sV --min-rate=5000 -p- --open target
```
- Stealth SYN сканирование
- Детекция версий сервисов
- Сканирование всего диапазона портов
- Только открытые порты

### **Phase 3: Directory Fuzzing**
```bash
feroxbuster --url http://target -w wordlist -t 50 -x php,html,txt,js
```
- Высокоскоростной брутфорс директорий
- Множественные расширения файлов
- 50 потоков для быстрого сканирования

## 📊 Пример результатов

```
🌐 Phase 1: Subdomain Discovery
🟢 Found subdomain: admin.example.com
🟢 Found subdomain: api.example.com  
🟢 Found subdomain: mail.example.com
✅ Found 15 subdomains for example.com

🔌 Phase 2: Port Scanning
🟢 example.com: 22/tcp   open  ssh     OpenSSH 8.9
🟢 example.com: 80/tcp   open  http    nginx 1.18.0
🟢 example.com: 443/tcp  open  ssl/http nginx 1.18.0
✅ example.com: Found 3 open ports

📁 Phase 3: Directory Fuzzing  
🟢 Found: /admin/ (200)
🟢 Found: /api/ (200)
🟢 Found: /backup/ (403)
✅ Found 25 directories
```

## 🔐 Безопасность

⚠️ **Важно**: Используй только на своих системах или с явного разрешения!

- Этот инструмент предназначен для **легального пентестинга**
- Не используй на чужих системах без разрешения
- Соблюдай законы твоей юрисдикции

## 🤝 Вклад в проект

Приветствуются улучшения и новые модули:

1. Fork репозитория
2. Создай feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit изменения (`git commit -m 'Add some AmazingFeature'`)
4. Push в branch (`git push origin feature/AmazingFeature`)
5. Открой Pull Request

## 📜 Лицензия

Распространяется под лицензией MIT. Смотри `LICENSE` для подробностей.

## 🙏 Благодарности

- **Kali Linux** - За вдохновение в дизайне
- **subfinder** - Отличный инструмент для поиска поддоменов  
- **nmap** - Король сканеров портов
- **feroxbuster** - Быстрый directory fuzzer

## 📧 Контакты

**Author**: sweetpotatohack  
**GitHub**: [@sweetpotatohack](https://github.com/sweetpotatohack)

---

**⚡ Happy Hacking! ⚡**

```
    ___    _  ___   ____  ___  ___    
   / _ |  / |/ / | / /  |/  / / _ |   
  / __ | /    /  |/ / /|_/ / / __ |   
 /_/ |_|/_/|_/_/|_/_/  /_/ /_/ |_|   
                                     
 Advanced Web Scanner Framework      
```
