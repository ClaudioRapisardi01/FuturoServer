import os
from datetime import timedelta
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env
load_dotenv()


class Config:
    """Configurazione dell'applicazione."""

    # Configurazione base
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'
    TESTING = os.environ.get('TESTING', '0') == '1'

    # Configurazione Database
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'serverfuturo')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))

    # Configurazione Flask-Login
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    SESSION_COOKIE_SECURE = not DEBUG
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Configurazione file upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

    # Configurazione email
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', '1') == '1'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@serverfuturo.com')

    # Configurazione JWT per API
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # Configurazione rate limiting
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = '100/hour'
    RATELIMIT_HEADERS_ENABLED = True

    # Configurazione logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = 'logs/serverfuturo.log'

    # Configurazione sicurezza
    BCRYPT_LOG_ROUNDS = 12
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'supersecuresalt'

    # Configurazione payments (Stripe, PayPal, etc.)
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY')
    PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'sandbox')
    PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID')
    PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_CLIENT_SECRET')

    # Configurazione notifiche
    PUSH_NOTIFICATION_KEY = os.environ.get('PUSH_NOTIFICATION_KEY')
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')

    # Configurazione cache
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 300

    @staticmethod
    def init_app(app):
        """Inizializza l'applicazione con le configurazioni."""
        pass


class DevelopmentConfig(Config):
    """Configurazione per ambiente di sviluppo."""
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Configurazione per ambiente di produzione."""
    DEBUG = False
    TESTING = False

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)

        # Log errors via email in production
        import logging
        from logging.handlers import SMTPHandler
        if app.config.get('MAIL_SERVER'):
            mail_handler = SMTPHandler(
                mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
                fromaddr=app.config['MAIL_DEFAULT_SENDER'],
                toaddrs=app.config.get('ADMINS', []),
                subject='ServerFuturo Application Error'
            )
            mail_handler.setLevel(logging.ERROR)
            app.logger.addHandler(mail_handler)


class TestingConfig(Config):
    """Configurazione per ambiente di test."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Ottiene la configurazione corrente."""
    config_name = os.environ.get('FLASK_ENV', 'development')
    return config.get(config_name, Config)