#!/usr/bin/env python3
"""
Akuma Advanced Scanner Configuration
"""

import os

# Flask Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'akuma_advanced_scanner_secret_2024'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///akuma_advanced.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security Settings
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'akuma_jwt_secret_advanced_2024'
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_HOURS = 24
    
    # Scanner Settings
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '5'))
    THREAD_POOL_SIZE = int(os.environ.get('THREAD_POOL_SIZE', '20'))
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))
    
    # Tool Timeouts (seconds)
    NMAP_TIMEOUT = int(os.environ.get('NMAP_TIMEOUT', '1800'))
    NUCLEI_TIMEOUT = int(os.environ.get('NUCLEI_TIMEOUT', '3600'))
    FEROX_TIMEOUT = int(os.environ.get('FEROX_TIMEOUT', '1800'))
    SUBFINDER_TIMEOUT = int(os.environ.get('SUBFINDER_TIMEOUT', '600'))
    
    # Email Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'
    
    # Telegram Configuration
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
    
    # Advanced Features
    ENABLE_VULNERABILITY_SCAN = os.environ.get('ENABLE_VULNERABILITY_SCAN', 'True').lower() == 'true'
    ENABLE_SSL_ANALYSIS = os.environ.get('ENABLE_SSL_ANALYSIS', 'True').lower() == 'true'
    ENABLE_CMS_DETECTION = os.environ.get('ENABLE_CMS_DETECTION', 'True').lower() == 'true'
    ENABLE_ADVANCED_FUZZING = os.environ.get('ENABLE_ADVANCED_FUZZING', 'True').lower() == 'true'
    ENABLE_SCHEDULING = os.environ.get('ENABLE_SCHEDULING', 'True').lower() == 'true'
    
    # File Upload Settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', '16777216'))  # 16MB
    
    # Rate Limiting
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True').lower() == 'true'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per minute')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'akuma_scanner.log')
    
    # Scanner Modules
    MODULES = {
        'subdomain_enum': os.environ.get('MODULE_SUBDOMAIN', 'True').lower() == 'true',
        'port_scan': os.environ.get('MODULE_PORTSCAN', 'True').lower() == 'true',
        'dir_bruteforce': os.environ.get('MODULE_DIRBRUTE', 'True').lower() == 'true',
        'vulnerability_scan': os.environ.get('MODULE_VULNSCAN', 'True').lower() == 'true',
        'ssl_analysis': os.environ.get('MODULE_SSL', 'True').lower() == 'true',
        'cms_detection': os.environ.get('MODULE_CMS', 'True').lower() == 'true',
        'advanced_fuzzing': os.environ.get('MODULE_FUZZING', 'True').lower() == 'true'
    }
    
    # Wordlists
    WORDLISTS = {
        'directories': os.environ.get('WORDLIST_DIRS', '/usr/share/seclists/Discovery/Web-Content/big.txt'),
        'subdomains': os.environ.get('WORDLIST_SUBDOMAINS', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'),
        'parameters': os.environ.get('WORDLIST_PARAMS', '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt')
    }

# Development Configuration
class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

# Production Configuration
class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    
    # Production-specific settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://akuma:password@localhost/akuma_scanner'
    
# Testing Configuration
class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
