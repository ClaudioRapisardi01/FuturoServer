import os
import socket
import logging
from flask import Flask, send_from_directory, session, g, request, jsonify, render_template
from sqlalchemy import MetaData
from blueprints.base import base_bp
from blueprints.user import user_bp
from blueprints.abbonamenti import abbonamenti_bp
from blueprints.dispositivi import dispositivi_bp
from blueprints.api import api_bp
from config import get_config
from logging.handlers import RotatingFileHandler

# Configura l'applicazione
app = Flask(__name__)

# Carica la configurazione
config = get_config()
app.config.from_object(config)
app.secret_key = config.SECRET_KEY

# Assicurati che la cartella logs esista
if not os.path.exists('logs'):
    os.mkdir('logs')

# Configura il logging
if not app.debug and not app.testing:
    file_handler = RotatingFileHandler('logs/serverfuturo.log', maxBytes=10240 * 1024, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('ServerFuturo startup')


# Template filters personalizzati
@app.template_filter('format_datetime')
def format_datetime(value, format='%d/%m/%Y %H:%M'):
    """Formatta datetime"""
    if value is None:
        return ""
    return value.strftime(format)


@app.template_filter('truncate_string')
def truncate_string(value, length=50, end='...'):
    """Tronca stringa"""
    if value is None:
        return ""
    return value if len(value) <= length else value[:length] + end


@app.template_filter('format_currency')
def format_currency(value):
    """Formatta valuta"""
    if value is None:
        return "€0.00"
    return f"€{value:.2f}"


@app.template_filter('format_filesize')
def format_filesize(value):
    """Formatta dimensione file"""
    if value is None:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


# Context processors per variabili globali nei template
@app.context_processor
def inject_global_variables():
    """Inietta variabili globali nei template"""
    return {
        'app_name': 'Project Futuro',
        'copyright_year': '2025',
        'environment': app.config.get('ENV', 'development'),
        'debug_mode': app.debug
    }


# Registra i Blueprint
app.register_blueprint(base_bp)
app.register_blueprint(user_bp)
app.register_blueprint(abbonamenti_bp)
app.register_blueprint(dispositivi_bp)
app.register_blueprint(api_bp)


# Route per servire file statici (CSS, JS, immagini)
@app.route('/static/<path:path>')
def send_static(path):
    """Serve file statici"""
    return send_from_directory('static', path)


# Route per favicon
@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )


# Middleware per logging richieste
@app.before_request
def before_request():
    """Eseguito prima di ogni richiesta"""
    # Popola g con informazioni utili
    g.user_id = session.get('user_id')
    g.user_email = session.get('user_email')
    g.user_role = session.get('user_role')

    # Log per debug in sviluppo
    if app.debug:
        app.logger.debug(f'{request.method} {request.path} - User: {g.user_id}')


@app.after_request
def after_request(response):
    """Eseguito dopo ogni richiesta"""
    # Aggiungi headers di sicurezza in produzione
    if not app.debug:
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


# Gestori errori
@app.errorhandler(404)
def not_found_error(error):
    """Gestisci errore 404"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Gestisci errore 500"""
    app.logger.error(f'Server Error: {error}', exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    """Gestisci errore 403"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('errors/403.html'), 403


# CLI Commands
@app.cli.command("init-db")
def init_db():
    """Inizializza il database"""
    # Qui potresti eseguire script SQL di inizializzazione
    print("Database initialization completed.")


@app.cli.command("create-admin")
def create_admin():
    """Crea un utente admin"""
    from db import DB

    email = input("Email admin: ")
    password = input("Password admin: ")

    query = """
        INSERT INTO utenti (email, password, nome, cognome, ruolo, attivo)
        VALUES (%s, %s, 'Admin', 'User', 'admin', TRUE)
        ON DUPLICATE KEY UPDATE ruolo = 'admin'
    """

    if DB.execute(query, (email, password)):
        print(f"Admin user created: {email}")
    else:
        print("Error creating admin user")


@app.cli.command("check-subscriptions")
def check_subscriptions():
    """Controlla e aggiorna lo stato degli abbonamenti scaduti"""
    from db import DB

    # Aggiorna abbonamenti scaduti
    query = """
        UPDATE utenti_abbonamenti 
        SET stato = 'scaduto' 
        WHERE stato = 'attivo' AND dataFine < NOW()
    """

    if DB.execute(query):
        print("Subscription statuses updated.")

        # Log per ogni abbonamento scaduto
        expired_query = """
            SELECT ua.id, u.email, a.nome 
            FROM utenti_abbonamenti ua
            JOIN utenti u ON ua.idUtente = u.id
            JOIN abbonamenti a ON ua.idAbbonamento = a.id
            WHERE ua.stato = 'scaduto' AND ua.dataFine >= DATE_SUB(NOW(), INTERVAL 1 DAY)
        """

        expired_subs = DB.read_data(expired_query)
        for sub in expired_subs:
            app.logger.info(f"Subscription expired: User {sub['email']}, Plan {sub['nome']}")


# Configurazione per sviluppo locale
if __name__ == '__main__':
    # Crea cartelle necessarie
    for folder in ['logs', 'uploads', 'temp']:
        if not os.path.exists(folder):
            os.mkdir(folder)

    # Determina l'ambiente
    hostname = socket.gethostname()
    is_development = hostname == 'PC-RAPISARDI3' or os.environ.get('FLASK_ENV') == 'development'

    # Configurazione per sviluppo o produzione
    if is_development:
        app.run(
            host='0.0.0.0',
            port=80,
            debug=True,
            use_reloader=True,
            use_debugger=True
        )
    else:
        # In produzione, usa un server WSGI come Gunicorn
        import waitress

        waitress.serve(
            app,
            host='0.0.0.0',
            port=80,
            url_scheme='https',
            threads=4,
            cleanup_interval=10
        )