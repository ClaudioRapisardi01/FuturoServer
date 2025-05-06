# SERVER Application
# Questo server gestisce:
# 1. Un'API per fornire la lista di IP da bloccare al BOX
# 2. Un'API per ricevere dati dal BOX

from flask import Flask, jsonify, request
import pymysql
import os
import json
from datetime import datetime
import time

app = Flask(__name__)

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


if __name__ == '__main__':
    # Gestione dell'avvio con controllo errori
    try:
        # Inizializza il database
        if init_db():
            # Inserisci alcuni IP da bloccare di esempio se la tabella è vuota
            insert_example_ips()

            print("Avvio del server...")
            # Avvia il server Flask
            app.run(host='0.0.0.0', port=5000, debug=True)
        else:
            print("Il server non può essere avviato a causa di problemi con il database.")
    except Exception as e:
        print(f"Errore critico durante l'avvio del server: {e}")
        print("Verifica che il servizio MySQL sia in esecuzione e che le credenziali siano corrette.")