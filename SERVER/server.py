# SERVER Application
# Questo server gestisce:
# 1. Un'API per fornire la lista di IP da bloccare al BOX
# 2. Un'API per ricevere dati dal BOX
# 3. Una dashboard web per visualizzare lo stato di sicurezza

from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
import pymysql
import os
import json
from datetime import datetime, timedelta
import time

# Configurazione
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'security_dashboard_secret_key'  # Necessario per flash e session

# Configurazione MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'claudio',
    'password': 'Superrapa22',
    'db': 'security_system',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Directory per archiviare i dati ricevuti
DATA_DIR = "data_received"
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Crea le cartelle per i template e gli static se non esistono
if not os.path.exists('templates'):
    os.makedirs('templates')
if not os.path.exists('static'):
    os.makedirs('static')


def get_db_connection():
    """Ottiene una connessione al database."""
    try:
        connection = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            db=DB_CONFIG['db'],
            charset=DB_CONFIG['charset'],
            cursorclass=DB_CONFIG['cursorclass']
        )
        return connection
    except Exception as e:
        print(f"Errore nella connessione al database: {e}")
        return None


def create_database_if_not_exists():
    """Verifica che il database esista e lo crea se necessario."""
    try:
        # Connessione a MySQL senza specificare il database
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()

        # Crea il database se non esiste
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['db']}")

        conn.commit()
        cursor.close()
        conn.close()

        print(f"Database {DB_CONFIG['db']} verificato o creato")
        return True
    except Exception as e:
        print(f"Errore nella creazione del database: {e}")
        return False


# API per la lista di IP da bloccare
@app.route('/api/blocklist', methods=['GET'])
def get_block_list():
    """
    API che fornisce la lista di IP da bloccare.
    Il BOX chiama questa API ogni 24 ore.
    """
    try:
        # Ottiene una connessione al database
        conn = get_db_connection()
        if not conn:
            return jsonify({
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "message": "Impossibile connettersi al database"
            }), 500

        # Esegue query al database MySQL per ottenere gli IP da bloccare
        with conn.cursor() as cursor:
            cursor.execute("SELECT ip_address FROM blocked_ips WHERE active = 1")
            results = cursor.fetchall()
            blocked_ips = [row['ip_address'] for row in results]

        conn.close()

        # Risponde con la lista degli IP
        return jsonify({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "data": blocked_ips
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "message": str(e)
        }), 500


# API per ricevere i report dal BOX
@app.route('/api/report', methods=['POST'])
def receive_report():
    """
    API che riceve dati dal BOX.
    Il BOX invia dati di rete e informazioni sui dispositivi connessi.
    """
    try:
        data = request.json

        if not data or 'box_code' not in data:
            return jsonify({
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "message": "Missing required data"
            }), 400

        # Salva i dati ricevuti in un file JSON con timestamp
        timestamp = datetime.now().isoformat().replace(':', '-')
        box_code = data.get('box_code')
        filename = f"{DATA_DIR}/box_{box_code}_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "data": data
            }, f, indent=4)

        # Ottiene una connessione al database
        conn = get_db_connection()
        if not conn:
            return jsonify({
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "message": "Data received and stored in file only (database connection failed)"
            })

        # Salva i dati nel database
        with conn.cursor() as cursor:
            # Salva informazioni sul BOX
            box_data = data.get('box_data', {})
            cursor.execute(
                "INSERT INTO box_reports (box_code, device_name, ip_private, ip_public, mac_address, latency, timestamp) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    box_code,
                    box_data.get('device_name', ''),
                    box_data.get('ip_private', ''),
                    box_data.get('ip_public', ''),
                    box_data.get('mac_address', ''),
                    box_data.get('latency', 0),
                    datetime.now()
                )
            )

            # Salva informazioni sui dispositivi rilevati
            devices = data.get('devices', [])
            for device in devices:
                cursor.execute(
                    "INSERT INTO detected_devices (box_code, device_name, ip_address, mac_address, timestamp) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        box_code,
                        device.get('name', ''),
                        device.get('ip', ''),
                        device.get('mac', ''),
                        datetime.now()
                    )
                )

            # Salva informazioni dai client
            client_reports = data.get('client_reports', [])
            for report in client_reports:
                cursor.execute(
                    "INSERT INTO client_reports (box_code, client_name, ip_private, mac_address, threats_detected, ips_blocked, timestamp) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        box_code,
                        report.get('name', ''),
                        report.get('ip_priv', ''),
                        report.get('MAC', ''),
                        report.get('minacce', 0),
                        report.get('ip_bloccati', 0),
                        datetime.now()
                    )
                )

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "message": "Data received and stored"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "message": str(e)
        }), 500


# Funzioni per la dashboard

# Pagina principale che richiede il codice del BOX
@app.route('/')
def home():
    """Pagina principale che richiede il codice del BOX."""
    return render_template('index.html')


# Dashboard principale che mostra i dati del sistema
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Dashboard principale che mostra i dati del sistema."""
    if request.method == 'POST':
        box_code = request.form.get('box_code')
        if not box_code:
            flash('Inserisci un codice BOX valido')
            return redirect(url_for('home'))

        # Salva il codice nella sessione
        session['box_code'] = box_code
        print(box_code)
        # Verifica se il BOX esiste nel database
        conn = get_db_connection()
        if not conn:
            flash('Errore di connessione al database')
            return redirect(url_for('home'))

        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM box_reports WHERE box_code = %s", (box_code,))
            result = cursor.fetchone()

            if result['count'] == 0:
                flash('Codice BOX non trovato nel sistema')
                return redirect(url_for('home'))

        conn.close()
    elif 'box_code' in session:
        box_code = session['box_code']
    else:
        flash('Inserisci un codice BOX valido')
        return redirect(url_for('home'))

    # Recupera i dati per la dashboard
    dashboard_data = get_dashboard_data(box_code)

    return render_template('dashboard.html', data=dashboard_data, box_code=box_code)


# API per ottenere i dati della dashboard in formato JSON
@app.route('/api/dashboard/<box_code>')
def dashboard_api(box_code):
    """API per ottenere i dati della dashboard in formato JSON."""
    dashboard_data = get_dashboard_data(box_code)
    return jsonify(dashboard_data)


# Rimuove il codice BOX dalla sessione
@app.route('/logout')
def logout():
    """Rimuove il codice BOX dalla sessione."""
    session.pop('box_code', None)
    flash('Sessione terminata')
    return redirect(url_for('home'))


# Raccoglie tutti i dati necessari per la dashboard
def get_dashboard_data(box_code):
    """Raccoglie tutti i dati necessari per la dashboard."""
    conn = get_db_connection()
    if not conn:
        return {
            'error': 'Errore di connessione al database',
            'timestamp': datetime.now().isoformat()
        }

    data = {
        'box_info': {},
        'security_status': {},
        'connected_devices': [],
        'client_stats': [],
        'threats_history': [],
        'recent_activity': [],
        'timestamp': datetime.now().isoformat()
    }

    try:
        with conn.cursor() as cursor:
            # Informazioni sul BOX
            cursor.execute("""
                SELECT device_name, ip_private, ip_public, mac_address, latency, timestamp
                FROM box_reports 
                WHERE box_code = %s 
                ORDER BY timestamp DESC 
                LIMIT 1
            """, (box_code,))
            box_info = cursor.fetchone()
            if box_info:
                data['box_info'] = box_info
                # Converti la data in formato stringa ISO
                if 'timestamp' in box_info and box_info['timestamp']:
                    data['box_info']['timestamp'] = box_info['timestamp'].isoformat()

            # Stato di sicurezza (totali)
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT id) as total_reports,
                    SUM(threats_detected) as total_threats,
                    SUM(ips_blocked) as total_blocked
                FROM client_reports 
                WHERE box_code = %s
            """, (box_code,))
            security_stats = cursor.fetchone()
            if security_stats:
                data['security_status'] = security_stats

            # Ultimo aggiornamento
            cursor.execute("""
                SELECT MAX(timestamp) as last_update
                FROM (
                    SELECT MAX(timestamp) as timestamp FROM box_reports WHERE box_code = %s
                    UNION
                    SELECT MAX(timestamp) as timestamp FROM client_reports WHERE box_code = %s
                    UNION
                    SELECT MAX(timestamp) as timestamp FROM detected_devices WHERE box_code = %s
                ) as updates
            """, (box_code, box_code, box_code))
            last_update = cursor.fetchone()
            if last_update and last_update['last_update']:
                data['last_update'] = last_update['last_update'].isoformat()

            # Dispositivi connessi
            cursor.execute("""
                SELECT device_name, ip_address, mac_address, timestamp
                FROM detected_devices 
                WHERE box_code = %s 
                ORDER BY timestamp DESC
                LIMIT 50
            """, (box_code,))
            devices = cursor.fetchall()
            for device in devices:
                if 'timestamp' in device and device['timestamp']:
                    device['timestamp'] = device['timestamp'].isoformat()
                data['connected_devices'].append(device)

            # Statistiche dei client
            cursor.execute("""
                SELECT 
                    client_name,
                    ip_private,
                    mac_address,
                    SUM(threats_detected) as threats_detected,
                    SUM(ips_blocked) as ips_blocked,
                    MAX(timestamp) as last_report
                FROM client_reports 
                WHERE box_code = %s 
                GROUP BY client_name, ip_private, mac_address
                ORDER BY MAX(timestamp) DESC
            """, (box_code,))
            client_stats = cursor.fetchall()
            for client in client_stats:
                if 'last_report' in client and client['last_report']:
                    client['last_report'] = client['last_report'].isoformat()
                data['client_stats'].append(client)

            # Storico delle minacce (ultimi 7 giorni)
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    SUM(threats_detected) as threats_detected,
                    SUM(ips_blocked) as ips_blocked
                FROM client_reports 
                WHERE box_code = %s AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            """, (box_code,))
            threats_history = cursor.fetchall()
            for day in threats_history:
                if 'date' in day and day['date']:
                    day['date'] = day['date'].isoformat()
                data['threats_history'].append(day)

            # Attività recente (ultimi 20 report)
            cursor.execute("""
                SELECT 
                    'client_report' as type,
                    client_name as name,
                    ip_private as ip,
                    threats_detected,
                    ips_blocked,
                    timestamp
                FROM client_reports 
                WHERE box_code = %s
                UNION
                SELECT 
                    'device_detected' as type,
                    device_name as name,
                    ip_address as ip,
                    0 as threats_detected,
                    0 as ips_blocked,
                    timestamp
                FROM detected_devices 
                WHERE box_code = %s
                ORDER BY timestamp DESC
                LIMIT 20
            """, (box_code, box_code))
            recent_activity = cursor.fetchall()
            for activity in recent_activity:
                if 'timestamp' in activity and activity['timestamp']:
                    activity['timestamp'] = activity['timestamp'].isoformat()
                data['recent_activity'].append(activity)
    except Exception as e:
        data['error'] = str(e)
    finally:
        conn.close()

    return data


# Funzioni di inizializzazione

def init_db():
    """Crea le tabelle necessarie se non esistono."""
    # Prima assicuriamoci che il database esista
    if not create_database_if_not_exists():
        print("Impossibile creare o connettersi al database. Verificare le credenziali MySQL.")
        return False

    # Ottiene una connessione al database
    conn = get_db_connection()
    if not conn:
        print("Impossibile ottenere una connessione al database.")
        return False

    try:
        with conn.cursor() as cursor:
            # Tabella per gli IP da bloccare
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                reason VARCHAR(255),
                active BOOLEAN DEFAULT TRUE,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # Tabella per i report dai BOX
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS box_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                box_code VARCHAR(50) NOT NULL,
                device_name VARCHAR(100),
                ip_private VARCHAR(45),
                ip_public VARCHAR(45),
                mac_address VARCHAR(17),
                latency FLOAT,
                timestamp DATETIME
            )
            ''')

            # Tabella per i dispositivi rilevati
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detected_devices (
                id INT AUTO_INCREMENT PRIMARY KEY,
                box_code VARCHAR(50) NOT NULL,
                device_name VARCHAR(100),
                ip_address VARCHAR(45),
                mac_address VARCHAR(17),
                timestamp DATETIME
            )
            ''')

            # Tabella per i report dai CLIENT
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS client_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                box_code VARCHAR(50) NOT NULL,
                client_name VARCHAR(100),
                ip_private VARCHAR(45),
                mac_address VARCHAR(17),
                threats_detected INT,
                ips_blocked INT,
                timestamp DATETIME
            )
            ''')

        conn.commit()
        conn.close()
        print("Database inizializzato con successo.")
        return True
    except Exception as e:
        print(f"Errore nell'inizializzazione del database: {e}")
        return False


def insert_example_ips():
    """Inserisce alcuni IP di esempio nella tabella blocked_ips."""
    try:
        conn = get_db_connection()
        if not conn:
            print("Impossibile inserire IP di esempio: connessione al database fallita.")
            return False

        with conn.cursor() as cursor:
            # Verifica se ci sono già IP nella tabella
            cursor.execute("SELECT COUNT(*) as count FROM blocked_ips")
            result = cursor.fetchone()
            count = result['count']

            if count == 0:
                print("Aggiunta di alcuni IP da bloccare di esempio...")
                example_ips = [
                    "192.168.1.100",
                    "10.0.0.25",
                    "8.8.8.8"  # Esempio: Google DNS
                ]
                for ip in example_ips:
                    cursor.execute(
                        "INSERT INTO blocked_ips (ip_address, reason, active) VALUES (%s, %s, %s)",
                        (ip, "IP di esempio", True)
                    )
                conn.commit()
                print(f"Aggiunti {len(example_ips)} IP di esempio.")

        conn.close()
        return True
    except Exception as e:
        print(f"Errore nell'inserimento degli IP di esempio: {e}")
        return False


# Crea i template HTML necessari
def create_templates():
    # Template per la pagina di login
    index_html = '''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema di Sicurezza | Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        :root {
            --dark-bg: #0d1117;
            --dark-card: #161b22;
            --dark-border: #30363d;
            --dark-text: #c9d1d9;
            --dark-text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
        }

        body {
            background-color: var(--dark-bg);
            color: var(--dark-text);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            background-image: 
                radial-gradient(circle at 25% 25%, rgba(3, 102, 214, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, rgba(63, 185, 80, 0.1) 0%, transparent 50%);
        }

        .login-container {
            max-width: 450px;
            width: 100%;
        }

        .card {
            background-color: var(--dark-card);
            border: 1px solid var(--dark-border);
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }

        .card-header {
            background-color: rgba(255, 255, 255, 0.05);
            border-bottom: 1px solid var(--dark-border);
            padding: 1.5rem;
            text-align: center;
        }

        .security-logo {
            font-size: 3.5rem;
            margin-bottom: 1rem;
            color: var(--accent-blue);
        }

        .system-title {
            color: var(--dark-text);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .system-subtitle {
            color: var(--dark-text-secondary);
            font-size: 0.95rem;
        }

        .card-body {
            padding: 2rem;
        }

        .form-control {
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--dark-border);
            color: var(--dark-text);
            padding: 0.8rem 1rem;
        }

        .form-control:focus {
            background-color: rgba(255, 255, 255, 0.1);
            color: var(--dark-text);
            box-shadow: 0 0 0 0.25rem rgba(88, 166, 255, 0.25);
            border-color: var(--accent-blue);
        }

        .form-text {
            color: var(--dark-text-secondary);
        }

        .btn-primary {
            background-color: var(--accent-blue);
            border-color: var(--accent-blue);
            padding: 0.8rem 1rem;
            font-weight: 500;
        }

        .btn-primary:hover {
            background-color: rgba(88, 166, 255, 0.8);
            border-color: rgba(88, 166, 255, 0.8);
        }

        .alert {
            background-color: rgba(248, 81, 73, 0.1);
            color: var(--accent-red);
            border-color: var(--accent-red);
        }

        .card-footer {
            background-color: rgba(255, 255, 255, 0.03);
            border-top: 1px solid var(--dark-border);
            padding: 1rem 2rem;
            text-align: center;
            color: var(--dark-text-secondary);
        }

        .security-badge {
            display: inline-block;
            margin-top: 1.5rem;
            padding: 0.5rem 1rem;
            background-color: rgba(63, 185, 80, 0.1);
            color: var(--accent-green);
            border-radius: 2rem;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .security-badge i {
            margin-right: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="card">
            <div class="card-header">
                <div class="security-logo">
                    <i class="bi bi-shield-lock"></i>
                </div>
                <h1 class="system-title">Sistema di Sicurezza di Rete</h1>
                <p class="system-subtitle">Centro di Controllo Avanzato</p>
            </div>

            <div class="card-body">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {% for message in messages %}
                            <div class="alert alert-danger alert-dismissible fade show mb-4" role="alert">
                                <i class="bi bi-exclamation-triangle-fill me-2"></i> {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}

                <form action="{{ url_for('dashboard') }}" method="post">
                    <div class="mb-4">
                        <label for="box_code" class="form-label">Codice di Accesso BOX</label>
                        <div class="input-group">
                            <span class="input-group-text" style="background-color: rgba(255, 255, 255, 0.05); border-color: var(--dark-border);">
                                <i class="bi bi-key"></i>
                            </span>
                            <input type="text" class="form-control" id="box_code" name="box_code" required
                                placeholder="Inserisci il codice identificativo del BOX">
                        </div>
                        <div class="form-text mt-2">
                            <i class="bi bi-info-circle me-1"></i> Il codice viene generato automaticamente dal BOX al primo avvio.
                        </div>
                    </div>

                    <div class="d-grid gap-2 mt-4">
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-shield-fill-check me-2"></i> Accedi al Centro di Controllo
                        </button>
                    </div>
                </form>

                <div class="text-center mt-4">
                    <div class="security-badge">
                        <i class="bi bi-shield-check"></i> Sicurezza Avanzata
                    </div>
                </div>
            </div>

            <div class="card-footer">
                <small>Sistema di Monitoraggio e Sicurezza di Rete v1.0</small>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>'''

    # Template per la dashboard
    dashboard_html = '''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Centro Sicurezza | {{ box_code }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #00ff66;
            --primary-dark: #00cc33;
            --primary-light: #33ff99;
            --secondary: #1affba;
            --accent: #ffcc00;
            --dark: #000000;
            --darker: #050505;
            --card-bg: #101010;
            --card-border: #222222;
            --text: #e6e6e6;
            --text-dim: #999999;
            --success: #00cc66;
            --danger: #ff3366;
            --warning: #ffcc00;
            --info: #33ccff;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background-color: var(--dark);
            color: var(--text);
            line-height: 1.5;
            padding-top: 70px;
        }

        /* Futuristic pattern background */
        .bg-pattern {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                linear-gradient(to right, rgba(0, 255, 102, 0.03) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(0, 255, 102, 0.03) 1px, transparent 1px);
            background-size: 25px 25px;
            z-index: -1;
        }

        .bg-pattern::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at 50% 0%, rgba(0, 255, 102, 0.1) 0%, transparent 70%);
            z-index: -1;
        }

        /* Loading overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: var(--dark);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            flex-direction: column;
            transition: opacity 0.5s ease;
        }

        .loading-spinner {
            position: relative;
            width: 80px;
            height: 80px;
            margin-bottom: 2rem;
        }

        .loading-spinner::before,
        .loading-spinner::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 4px solid transparent;
            animation: spin 1.5s ease-in-out infinite;
        }

        .loading-spinner::before {
            border-top-color: var(--primary);
            border-right-color: var(--primary-light);
            animation-delay: 0.2s;
        }

        .loading-spinner::after {
            border-bottom-color: var(--secondary);
            border-left-color: var(--secondary);
            animation-delay: 0.4s;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading-text {
            color: var(--primary);
            font-size: 1.2rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.2em;
            animation: pulse 1.5s infinite alternate;
        }

        @keyframes pulse {
            0% { opacity: 0.5; text-shadow: 0 0 5px rgba(0, 255, 102, 0); }
            100% { opacity: 1; text-shadow: 0 0 15px rgba(0, 255, 102, 0.5); }
        }

        /* Navbar */
        .navbar {
            background-color: rgba(0, 0, 0, 0.9) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(0, 255, 102, 0.2);
            padding: 0.75rem 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
        }

        .navbar-brand {
            font-weight: 700;
            color: var(--primary) !important;
            letter-spacing: 0.05em;
            font-size: 1.2rem;
        }

        .navbar-brand i {
            margin-right: 0.7rem;
            font-size: 1.4rem;
            vertical-align: middle;
        }

        .nav-link {
            color: var(--text) !important;
            font-weight: 500;
            font-size: 0.9rem;
            padding: 0.5rem 1rem;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .nav-link:hover, .nav-link:focus {
            color: var(--primary) !important;
            text-shadow: 0 0 8px rgba(0, 255, 102, 0.5);
        }

        .nav-link i {
            margin-right: 0.5rem;
        }

        /* Main content */
        .main-content {
            padding: 1.5rem;
            max-width: 1800px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid rgba(0, 255, 102, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .header-titles {
            flex-grow: 1;
        }

        .header-title {
            font-size: 1.75rem;
            font-weight: 700;
            line-height: 1.1;
            margin-bottom: 0.5rem;
            color: var(--primary);
            text-shadow: 0 0 10px rgba(0, 255, 102, 0.3);
        }

        .header-title::before {
            content: '⌁';
            margin-right: 0.5rem;
            color: var(--primary);
        }

        .header-subtitle {
            font-size: 1rem;
            color: var(--text-dim);
        }

        .box-code {
            background-color: rgba(0, 255, 102, 0.1);
            color: var(--primary);
            font-family: 'Consolas', monospace;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            border-left: 3px solid var(--primary);
        }

        .refresh-controls {
            display: flex;
            align-items: center;
            background-color: rgba(0, 0, 0, 0.4);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 102, 0.1);
        }

        .auto-refresh {
            display: flex;
            align-items: center;
            font-size: 0.85rem;
            color: var(--text-dim);
        }

        .form-check-input {
            background-color: var(--dark);
            border-color: var(--primary);
            width: 2.5em;
            height: 1.25em;
        }

        .form-check-input:checked {
            background-color: var(--primary);
            border-color: var(--primary);
        }

        .form-check-label {
            margin-right: 0.5rem;
        }

        .countdown {
            font-family: 'Consolas', monospace;
            color: var(--primary);
            background-color: rgba(0, 0, 0, 0.6);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
            min-width: 2.5rem;
            text-align: center;
            margin-left: 0.5rem;
            border: 1px solid rgba(0, 255, 102, 0.2);
        }

        .last-update {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-left: 1rem;
            white-space: nowrap;
        }

        .last-update-time {
            color: var(--primary-light);
            font-family: 'Consolas', monospace;
        }

        /* Stat cards */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background-color: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(0, 255, 102, 0.1);
            border-radius: 10px;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.3);
            border-color: rgba(0, 255, 102, 0.3);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 60%;
            height: 100%;
            background: radial-gradient(circle at top right, rgba(0, 255, 102, 0.1), transparent 80%);
            opacity: 0;
            transition: opacity 0.3s;
        }

        .stat-card:hover::before {
            opacity: 1;
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            margin-right: 1.5rem;
            border-radius: 12px;
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(0, 0, 0, 0.4));
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            flex-shrink: 0;
        }

        .stat-card-content {
            flex-grow: 1;
        }

        .stat-card-value {
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1.1;
            margin-bottom: 0.5rem;
            font-family: 'Consolas', monospace;
            background: linear-gradient(to right, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .stat-card-label {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            margin-bottom: 0;
        }

        /* Cards */
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            margin-bottom: 1.5rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            transition: transform 0.3s, box-shadow 0.3s;
            overflow: hidden;
            position: relative;
        }

        .card:hover {
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
            transform: translateY(-3px);
        }

        .card::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(to right, var(--primary), var(--secondary));
        }

        .card-header {
            background-color: rgba(0, 0, 0, 0.4);
            border-bottom: 1px solid var(--card-border);
            padding: 1rem 1.25rem;
            font-weight: 600;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--primary);
            display: flex;
            align-items: center;
        }

        .card-header i {
            margin-right: 0.7rem;
            font-size: 1.2rem;
        }

        .card-body {
            padding: 1.5rem;
        }

        /* Info grid */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1.25rem;
        }

        .info-item {
            background-color: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 1rem;
            border: 1px solid rgba(0, 255, 102, 0.1);
            transition: all 0.3s;
        }

        .info-item:hover {
            background-color: rgba(0, 0, 0, 0.5);
            border-color: rgba(0, 255, 102, 0.3);
            transform: translateY(-2px);
            box-shadow: 0 5px 10px rgba(0, 0, 0, 0.1);
        }

        .info-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
        }

        .info-label::before {
            content: '⬢';
            margin-right: 0.5rem;
            color: var(--primary);
            font-size: 0.7rem;
        }

        .info-value {
            font-size: 1rem;
            font-family: 'Consolas', monospace;
            color: var(--primary);
            word-break: break-all;
        }

        /* Tables */
        .table {
            color: var(--text);
            border-color: var(--card-border);
            margin-bottom: 0;
        }

        .table th {
            background-color: rgba(0, 0, 0, 0.3);
            color: var(--primary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
            padding: 1rem 1.25rem;
            border-color: var(--card-border);
        }

        .table td {
            padding: 1rem 1.25rem;
            border-color: var(--card-border);
            font-size: 0.9rem;
            vertical-align: middle;
        }

        .table-hover tbody tr:hover {
            background-color: rgba(0, 255, 102, 0.05);
        }

        .table-responsive {
            border-radius: 8px;
            overflow: hidden;
        }

        /* Badge */
        .badge {
            padding: 0.4rem 0.8rem;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-radius: 4px;
        }

        .badge-primary {
            background-color: rgba(0, 255, 102, 0.1);
            color: var(--primary);
            border: 1px solid rgba(0, 255, 102, 0.3);
        }

        .badge-success {
            background-color: rgba(0, 204, 102, 0.1);
            color: var(--success);
            border: 1px solid rgba(0, 204, 102, 0.3);
        }

        .badge-warning {
            background-color: rgba(255, 204, 0, 0.1);
            color: var(--warning);
            border: 1px solid rgba(255, 204, 0, 0.3);
        }

        .badge-danger {
            background-color: rgba(255, 51, 102, 0.1);
            color: var(--danger);
            border: 1px solid rgba(255, 51, 102, 0.3);
        }

        /* Chart container */
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
            padding: 1rem;
            background-color: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 102, 0.1);
        }

        /* Animations */
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .updating {
            animation: pulse 1.5s infinite;
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(0, 255, 102, 0.3);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(0, 255, 102, 0.5);
        }

        /* Utility classes */
        .text-primary {
            color: var(--primary) !important;
        }

        .text-success {
            color: var(--success) !important;
        }

        .text-warning {
            color: var(--warning) !important;
        }

        .text-danger {
            color: var(--danger) !important;
        }

        .text-muted {
            color: var(--text-dim) !important;
        }

        /* Responsive */
        @media (max-width: 767px) {
            .header {
                flex-direction: column;
                align-items: flex-start;
            }

            .refresh-controls {
                width: 100%;
                flex-wrap: wrap;
                justify-content: space-between;
            }

            .last-update {
                width: 100%;
                margin-left: 0;
                margin-top: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- Background pattern -->
    <div class="bg-pattern"></div>

    <!-- Loading overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-spinner"></div>
        <div class="loading-text">INIZIALIZZAZIONE SISTEMA</div>
    </div>

    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-lock"></i> Centro Sicurezza
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#" id="refresh-data">
                            <i class="bi bi-arrow-repeat"></i> Aggiorna
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('logout') }}">
                            <i class="bi bi-box-arrow-right"></i> Esci
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main content -->
    <div class="main-content">
        <!-- Header -->
        <div class="header">
            <div class="header-titles">
                <h1 class="header-title">Centro di Controllo Sicurezza</h1>
                <p class="header-subtitle">Box ID: <span class="box-code">{{ box_code }}</span></p>
            </div>
            <div class="refresh-controls">
                <div class="auto-refresh">
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="autoRefreshSwitch" checked>
                        <label class="form-check-label" for="autoRefreshSwitch">Aggiornamento auto</label>
                    </div>
                    <span class="countdown" id="countdown">30s</span>
                </div>
                <div class="last-update">
                    Ultimo aggiornamento: <span class="last-update-time" id="last-update-time">
                        {% if data.last_update %}
                            {{ data.last_update }}
                        {% else %}
                            N/D
                        {% endif %}
                    </span>
                </div>
            </div>
        </div>

        {% if data.error %}
            <div class="alert alert-danger" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2"></i> {{ data.error }}
            </div>
        {% else %}
            <!-- Statistiche Principali -->
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        🛡️
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-value" id="status-box">
                            {{ data.box_info.device_name if data.box_info else 'N/D' }}
                        </div>
                        <p class="stat-card-label">Stato BOX</p>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon">
                        💻
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-value" id="clients-count">
                            {{ data.client_stats|length }}
                        </div>
                        <p class="stat-card-label">Client Attivi</p>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon">
                        ⚠️
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-value" id="threats-count">
                            {{ data.security_status.total_threats if data.security_status and data.security_status.total_threats else 0 }}
                        </div>
                        <p class="stat-card-label">Minacce Rilevate</p>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon">
                        🚫
                    </div>
                    <div class="stat-card-content">
                        <div class="stat-card-value" id="blocked-count">
                            {{ data.security_status.total_blocked if data.security_status and data.security_status.total_blocked else 0 }}
                        </div>
                        <p class="stat-card-label">Connessioni Bloccate</p>
                    </div>
                </div>
            </div>

            <div class="row">
                <!-- Dettagli Box e Grafico -->
                <div class="col-lg-4">
                    <!-- Informazioni BOX -->
                    <div class="card">
                        <div class="card-header">
                            <i class="bi bi-info-circle"></i> Dettagli Dispositivo
                        </div>
                        <div class="card-body" id="box-info">
                            {% if data.box_info %}
                                <div class="info-grid">
                                    <div class="info-item">
                                        <div class="info-label">Nome Dispositivo</div>
                                        <div class="info-value">{{ data.box_info.device_name }}</div>
                                    </div>
                                    <div class="info-item">
                                        <div class="info-label">IP Privato</div>
                                        <div class="info-value">{{ data.box_info.ip_private }}</div>
                                    </div>
                                    <div class="info-item">
                                        <div class="info-label">IP Pubblico</div>
                                        <div class="info-value">{{ data.box_info.ip_public }}</div>
                                    </div>
                                    <div class="info-item">
                                        <div class="info-label">MAC Address</div>
                                        <div class="info-value">{{ data.box_info.mac_address }}</div>
                                    </div>
                                    <div class="info-item">
                                        <div class="info-label">Latenza</div>
                                        <div class="info-value">{{ '%.2f'|format(data.box_info.latency|float) if data.box_info.latency else 'N/D' }} ms</div>
                                    </div>
                                </div>
                            {% else %}
                                <p class="text-muted">Nessuna informazione disponibile</p>
                            {% endif %}
                        </div>
                    </div>

                    <!-- Grafico Minacce -->
                    <div class="card">
                        <div class="card-header">
                            <i class="bi bi-graph-up"></i> Andamento Minacce
                        </div>
                        <div class="card-body">
                            <div class="chart-container">
                                <canvas id="threatsChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tabelle principali -->
                <div class="col-lg-8">
                    <!-- Client Monitorati -->
                    <div class="card">
                        <div class="card-header">
                            <i class="bi bi-laptop"></i> Client Monitorati
                        </div>
                        <div class="card-body p-0">
                            {% if data.client_stats %}
                                <div class="table-responsive">
                                    <table class="table table-hover" id="clients-table">
                                        <thead>
                                            <tr>
                                                <th>Nome Client</th>
                                                <th>IP</th>
                                                <th>MAC</th>
                                                <th>Minacce</th>
                                                <th>Bloccati</th>
                                                <th>Ultimo Report</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for client in data.client_stats %}
                                                <tr>
                                                    <td>{{ client.client_name }}</td>
                                                    <td>{{ client.ip_private }}</td>
                                                    <td>{{ client.mac_address }}</td>
                                                    <td>{{ client.threats_detected }}</td>
                                                    <td>{{ client.ips_blocked }}</td>
                                                    <td>{{ client.last_report }}</td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            {% else %}
                                <div class="p-3">
                                    <p class="text-muted mb-0">Nessun client ha inviato report</p>
                                </div>
                            {% endif %}
                        </div>
                    </div>

                    <!-- Dispositivi di Rete -->
                    <div class="card">
                        <div class="card-header">
                            <i class="bi bi-hdd-network"></i> Dispositivi di Rete
                        </div>
                        <div class="card-body p-0">
                            {% if data.connected_devices %}
                                <div class="table-responsive">
                                    <table class="table table-hover" id="devices-table">
                                        <thead>
                                            <tr>
                                                <th>Nome Dispositivo</th>
                                                <th>IP</th>
                                                <th>MAC</th>
                                                <th>Rilevato</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for device in data.connected_devices %}
                                                <tr>
                                                    <td>{{ device.device_name }}</td>
                                                    <td>{{ device.ip_address }}</td>
                                                    <td>{{ device.mac_address }}</td>
                                                    <td>{{ device.timestamp }}</td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            {% else %}
                                <div class="p-3">
                                    <p class="text-muted mb-0">Nessun dispositivo rilevato</p>
                                </div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attività Recenti -->
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-activity"></i> Attività Recenti
                </div>
                <div class="card-body p-0">
                    {% if data.recent_activity %}
                        <div class="table-responsive">
                            <table class="table table-hover" id="activity-table">
                                <thead>
                                    <tr>
                                        <th>Tipo</th>
                                        <th>Nome</th>
                                        <th>IP</th>
                                        <th>Dettagli</th>
                                        <th>Orario</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for activity in data.recent_activity %}
                                        <tr>
                                            <td>
                                                {% if activity.type == 'client_report' %}
                                                    <span class="badge badge-primary">Report Client</span>
                                                {% else %}
                                                    <span class="badge badge-success">Dispositivo</span>
                                                {% endif %}
                                            </td>
                                            <td>{{ activity.name }}</td>
                                            <td>{{ activity.ip }}</td>
                                            <td>
                                                {% if activity.type == 'client_report' %}
                                                    Minacce: {{ activity.threats_detected }}, Bloccati: {{ activity.ips_blocked }}
                                                {% else %}
                                                    Nuovo dispositivo rilevato
                                                {% endif %}
                                            </td>
                                            <td>{{ activity.timestamp }}</td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% else %}
                        <div class="p-3">
                            <p class="text-muted mb-0">Nessuna attività recente</p>
                        </div>
                    {% endif %}
                </div>
            </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Gestione della schermata di caricamento
        setTimeout(function() {
            document.getElementById('loadingOverlay').style.opacity = '0';
            setTimeout(function() {
                document.getElementById('loadingOverlay').style.display = 'none';
            }, 500);
        }, 1500);

        // Inizializzazione grafico minacce con tema scuro
        const initThreatsChart = (data) => {
            const chartTheme = {
                gridColor: 'rgba(0, 255, 102, 0.1)',
                textColor: '#999999',
                primaryColor: '#00ff66',
                warningColor: '#ffcc00',
                dangerColor: '#ff3366',
                backgroundColor: 'rgba(0, 0, 0, 0.2)'
            };

            Chart.defaults.color = chartTheme.textColor;
            Chart.defaults.borderColor = chartTheme.gridColor;

            const labels = [];
            const threatsData = [];
            const blockedData = [];

            // Se ci sono dati nella cronologia minacce
            if (data.threats_history && data.threats_history.length > 0) {
                // Invertiamo l'array per avere date in ordine cronologico
                const sortedHistory = [...data.threats_history].reverse();

                sortedHistory.forEach(day => {
                    // Formatta la data in formato più leggibile
                    const date = new Date(day.date);
                    const formattedDate = `${date.getDate()}/${date.getMonth() + 1}`;

                    labels.push(formattedDate);
                    threatsData.push(day.threats_detected || 0);
                    blockedData.push(day.ips_blocked || 0);
                });
            } else {
                // Dati segnaposto se non ci sono dati reali
                for (let i = 6; i >= 0; i--) {
                    const date = new Date();
                    date.setDate(date.getDate() - i);
                    labels.push(`${date.getDate()}/${date.getMonth() + 1}`);
                    threatsData.push(0);
                    blockedData.push(0);
                }
            }

            const ctx = document.getElementById('threatsChart').getContext('2d');

            // Crea un gradiente per le aree
            const threatGradient = ctx.createLinearGradient(0, 0, 0, 300);
            threatGradient.addColorStop(0, 'rgba(255, 204, 0, 0.3)');
            threatGradient.addColorStop(1, 'rgba(255, 204, 0, 0)');

            const blockedGradient = ctx.createLinearGradient(0, 0, 0, 300);
            blockedGradient.addColorStop(0, 'rgba(255, 51, 102, 0.3)');
            blockedGradient.addColorStop(1, 'rgba(255, 51, 102, 0)');

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Minacce',
                            data: threatsData,
                            borderColor: chartTheme.warningColor,
                            backgroundColor: threatGradient,
                            borderWidth: 2,
                            tension: 0.4,
                            fill: true,
                            pointBackgroundColor: chartTheme.warningColor,
                            pointBorderColor: 'rgba(0, 0, 0, 0.5)',
                            pointBorderWidth: 1,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        },
                        {
                            label: 'Bloccati',
                            data: blockedData,
                            borderColor: chartTheme.dangerColor,
                            backgroundColor: blockedGradient,
                            borderWidth: 2,
                            tension: 0.4,
                            fill: true,
                            pointBackgroundColor: chartTheme.dangerColor,
                            pointBorderColor: 'rgba(0, 0, 0, 0.5)',
                            pointBorderWidth: 1,
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                boxWidth: 12,
                                padding: 15,
                                font: {
                                    family: "'Segoe UI', system-ui, sans-serif",
                                    size: 11
                                }
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#ffffff',
                            bodyColor: '#eeeeee',
                            borderColor: 'rgba(0, 255, 102, 0.3)',
                            borderWidth: 1,
                            padding: 12,
                            boxPadding: 6,
                            titleFont: {
                                family: "'Segoe UI', system-ui, sans-serif",
                                size: 13,
                                weight: 'bold'
                            },
                            bodyFont: {
                                family: "'Segoe UI', system-ui, sans-serif",
                                size: 12
                            },
                            displayColors: true,
                            boxWidth: 8,
                            boxHeight: 8,
                            usePointStyle: true,
                            callbacks: {
                                label: function(context) {
                                    let label = context.dataset.label || '';
                                    if (label) {
                                        label += ': ';
                                    }
                                    label += context.parsed.y;
                                    return label;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                color: chartTheme.gridColor,
                                drawBorder: false,
                                display: true
                            },
                            ticks: {
                                color: chartTheme.textColor,
                                font: {
                                    family: "'Consolas', monospace",
                                    size: 10
                                }
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: chartTheme.gridColor,
                                drawBorder: false,
                                display: true
                            },
                            ticks: {
                                color: chartTheme.textColor,
                                precision: 0,
                                font: {
                                    family: "'Consolas', monospace",
                                    size: 10
                                }
                            }
                        }
                    },
                    elements: {
                        line: {
                            borderWidth: 2
                        },
                        point: {
                            borderWidth: 1,
                            radius: 4,
                            hoverRadius: 6
                        }
                    }
                }
            });
        };

        // Formatta date in formato leggibile
        const formatDateTime = (isoString) => {
            if (!isoString) return 'N/D';
            const date = new Date(isoString);
            return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
        };

        // Aggiorna i dati della dashboard
        const updateDashboard = () => {
            // Mostra indicatore di aggiornamento
            document.body.classList.add('updating');

            fetch(`/api/dashboard/{{ box_code }}`)
                .then(response => response.json())
                .then(data => {
                    // Rimuovi indicatore di aggiornamento
                    document.body.classList.remove('updating');

                    if (data.error) {
                        console.error('Errore:', data.error);
                        return;
                    }

                    // Aggiorna statistiche principali
                    document.getElementById('status-box').textContent = data.box_info.device_name || 'N/D';
                    document.getElementById('clients-count').textContent = data.client_stats ? data.client_stats.length : 0;
                    document.getElementById('threats-count').textContent = data.security_status && data.security_status.total_threats ? data.security_status.total_threats : 0;
                    document.getElementById('blocked-count').textContent = data.security_status && data.security_status.total_blocked ? data.security_status.total_blocked : 0;

                    // Aggiorna ultimo aggiornamento
                    document.getElementById('last-update-time').textContent = formatDateTime(data.last_update || data.timestamp);

                    // Aggiorna info BOX
                    const boxInfoElem = document.getElementById('box-info');
                    if (data.box_info) {
                        boxInfoElem.innerHTML = `
                            <div class="info-grid">
                                <div class="info-item">
                                    <div class="info-label">Nome Dispositivo</div>
                                    <div class="info-value">${data.box_info.device_name || 'N/D'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">IP Privato</div>
                                    <div class="info-value">${data.box_info.ip_private || 'N/D'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">IP Pubblico</div>
                                    <div class="info-value">${data.box_info.ip_public || 'N/D'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">MAC Address</div>
                                    <div class="info-value">${data.box_info.mac_address || 'N/D'}</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Latenza</div>
                                    <div class="info-value">${data.box_info.latency ? data.box_info.latency.toFixed(2) : 'N/D'} ms</div>
                                </div>
                            </div>
                        `;
                    }

                    // Aggiorna tabella client
                    const clientsTable = document.getElementById('clients-table');
                    if (clientsTable && data.client_stats && data.client_stats.length > 0) {
                        let clientsHtml = `
                            <thead>
                                <tr>
                                    <th>Nome Client</th>
                                    <th>IP</th>
                                    <th>MAC</th>
                                    <th>Minacce</th>
                                    <th>Bloccati</th>
                                    <th>Ultimo Report</th>
                                </tr>
                            </thead>
                            <tbody>
                        `;

                        data.client_stats.forEach(client => {
                            clientsHtml += `
                                <tr>
                                    <td>${client.client_name || 'N/D'}</td>
                                    <td>${client.ip_private || 'N/D'}</td>
                                    <td>${client.mac_address || 'N/D'}</td>
                                    <td>${client.threats_detected || 0}</td>
                                    <td>${client.ips_blocked || 0}</td>
                                    <td>${formatDateTime(client.last_report)}</td>
                                </tr>
                            `;
                        });

                        clientsHtml += '</tbody>';
                        clientsTable.innerHTML = clientsHtml;
                    }

                    // Aggiorna tabella dispositivi
                    const devicesTable = document.getElementById('devices-table');
                    if (devicesTable && data.connected_devices && data.connected_devices.length > 0) {
                        let devicesHtml = `
                            <thead>
                                <tr>
                                    <th>Nome Dispositivo</th>
                                    <th>IP</th>
                                    <th>MAC</th>
                                    <th>Rilevato</th>
                                </tr>
                            </thead>
                            <tbody>
                        `;

                        data.connected_devices.forEach(device => {
                            devicesHtml += `
                                <tr>
                                    <td>${device.device_name || 'N/D'}</td>
                                    <td>${device.ip_address || 'N/D'}</td>
                                    <td>${device.mac_address || 'N/D'}</td>
                                    <td>${formatDateTime(device.timestamp)}</td>
                                </tr>
                            `;
                        });

                        devicesHtml += '</tbody>';
                        devicesTable.innerHTML = devicesHtml;
                    }

                    // Aggiorna tabella attività
                    const activityTable = document.getElementById('activity-table');
                    if (activityTable && data.recent_activity && data.recent_activity.length > 0) {
                        let activityHtml = `
                            <thead>
                                <tr>
                                    <th>Tipo</th>
                                    <th>Nome</th>
                                    <th>IP</th>
                                    <th>Dettagli</th>
                                    <th>Orario</th>
                                </tr>
                            </thead>
                            <tbody>
                        `;

                        data.recent_activity.forEach(activity => {
                            activityHtml += `
                                <tr>
                                    <td>
                                        ${activity.type === 'client_report' 
                                            ? '<span class="badge badge-primary">Report Client</span>'
                                            : '<span class="badge badge-success">Dispositivo</span>'}
                                    </td>
                                    <td>${activity.name || 'N/D'}</td>
                                    <td>${activity.ip || 'N/D'}</td>
                                    <td>
                                        ${activity.type === 'client_report'
                                            ? `Minacce: ${activity.threats_detected || 0}, Bloccati: ${activity.ips_blocked || 0}`
                                            : 'Nuovo dispositivo rilevato'}
                                    </td>
                                    <td>${formatDateTime(activity.timestamp)}</td>
                                </tr>
                            `;
                        });

                        activityHtml += '</tbody>';
                        activityTable.innerHTML = activityHtml;
                    }
                })
                .catch(error => {
                    document.body.classList.remove('updating');
                    console.error('Errore nell\'aggiornamento dei dati:', error);
                });
        };

        // Gestione del timer per aggiornamento automatico
        let countdownValue = 30;
        let countdownInterval;

        const startCountdown = () => {
            clearInterval(countdownInterval);
            countdownValue = 30;
            document.getElementById('countdown').textContent = `${countdownValue}s`;

            countdownInterval = setInterval(() => {
                countdownValue--;
                document.getElementById('countdown').textContent = `${countdownValue}s`;

                if (countdownValue <= 0) {
                    updateDashboard();
                    countdownValue = 30;
                }
            }, 1000);
        };

        // Inizializzazione al caricamento della pagina
        document.addEventListener('DOMContentLoaded', () => {
            // Inizializza il grafico
            initThreatsChart({{ data|tojson }});

            // Gestione aggiornamento manuale
            document.getElementById('refresh-data').addEventListener('click', (e) => {
                e.preventDefault();
                updateDashboard();
                startCountdown();
            });

            // Gestione switch aggiornamento automatico
            const autoRefreshSwitch = document.getElementById('autoRefreshSwitch');

            autoRefreshSwitch.addEventListener('change', () => {
                if (autoRefreshSwitch.checked) {
                    startCountdown();
                } else {
                    clearInterval(countdownInterval);
                    document.getElementById('countdown').textContent = 'Off';
                }
            });

            // Avvia il timer se l'interruttore è attivo
            if (autoRefreshSwitch.checked) {
                startCountdown();
            }
        });

        // Assicurarsi che la schermata di caricamento venga nascosta
        window.addEventListener('load', function() {
            setTimeout(function() {
                document.getElementById('loadingOverlay').style.opacity = '0';
                setTimeout(function() {
                    document.getElementById('loadingOverlay').style.display = 'none';
                }, 500);
            }, 1000);
        });

        // Timer di sicurezza - nasconde il loading dopo un massimo di 3 secondi anche se ci sono errori
        setTimeout(function() {
            document.getElementById('loadingOverlay').style.opacity = '0';
            setTimeout(function() {
                document.getElementById('loadingOverlay').style.display = 'none';
            }, 500);
        }, 3000);
    </script>
</body>
</html>'''

    # Crea i file
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(index_html)

    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
        f.write(dashboard_html)

    print("Template HTML creati con successo")
    return True


if __name__ == '__main__':
    # Gestione dell'avvio con controllo errori
    try:
        # Inizializza il database
        if init_db():
            # Inserisci alcuni IP da bloccare di esempio se la tabella è vuota
            insert_example_ips()

            # Crea i file template per la dashboard

            print("Avvio del server...")
            # Avvia il server Flask
            app.run(host='0.0.0.0', port=80, debug=True)
        else:
            print("Il server non può essere avviato a causa di problemi con il database.")
    except Exception as e:
        print(f"Errore critico durante l'avvio del server: {e}")
        print("Verifica che il servizio MySQL sia in esecuzione e che le credenziali siano corrette.")