# BOX Application
# Questo BOX gestisce:
# 1. Generazione di un codice univoco all'avvio
# 2. Scansione della rete ogni 10 minuti
# 3. Invio dei dati al SERVER
# 4. Aggiornamento della lista IP da bloccare ogni 24 ore
# 5. Tre API per il CLIENT

from flask import Flask, jsonify, request
import requests
import socket
import uuid
import json
import os
import time
import threading
import nmap
import datetime
import ipaddress
import subprocess
import struct
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

# Configurazione
SERVER_URL = "http://app.capecchispa.net:80"  # Indirizzo del SERVER, da modificare in produzione
BOX_CODE_FILE = "box_code.txt"
IP_BLOCKLIST_FILE = "ip_blocklist.json"
DEVICE_DATA_FILE = "network_devices.json"
SCAN_INTERVAL = 600  # 10 minuti in secondi
BLOCKLIST_UPDATE_INTERVAL = 86400  # 24 ore in secondi

# Variabili globali
box_code = None
network_devices = []
ip_blocklist = []


def get_public_ip():
    """Ottiene l'IP pubblico della rete."""
    try:
        response = requests.get('https://api.ipify.org')
        return response.text
    except:
        return None


def get_network_info():
    """Ottiene informazioni sulla rete locale con un approccio semplificato."""
    try:
        network_info = {}

        # Determina l'IP privato usando socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connessione a Google DNS per determinare l'interfaccia
        network_info['ip_private'] = s.getsockname()[0]
        s.close()

        # Semplificazione: assume che la rete sia una /24 (classe C)
        # Prende i primi 3 ottetti dell'IP e aggiunge .0/24
        ip_parts = network_info['ip_private'].split('.')
        network_info['network_cidr'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        # Imposta netmask standard per rete /24
        network_info['netmask'] = "255.255.255.0"

        # Per il gateway, usa l'indirizzo .1 come comune default
        network_info['gateway'] = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"

        # Per il MAC, usa un valore generico o lascia vuoto
        network_info['mac_address'] = "00:00:00:00:00:00"  # Placeholder

        # Nome dell'interfaccia (non è critico per le funzionalità base)
        network_info['interface'] = "default"

        return network_info
    except Exception as e:
        print(f"Errore nel determinare le informazioni di rete: {e}")
        # Fallback con valori predefiniti
        return {
            'interface': "default",
            'gateway': "192.168.1.1",
            'ip_private': "192.168.1.100",
            'netmask': "255.255.255.0",
            'network_cidr': "192.168.1.0/24",
            'mac_address': "00:00:00:00:00:00"
        }


def measure_latency():
    """Misura la latenza verso il gateway."""
    try:
        network_info = get_network_info()
        if not network_info:
            return None

        gateway = network_info['gateway']

        # Misura il tempo di ping
        start_time = time.time()
        socket.create_connection((gateway, 80), timeout=2)
        end_time = time.time()

        return (end_time - start_time) * 1000  # Converti in millisecondi
    except:
        return None


def generate_box_code():
    """Genera un codice univoco per il BOX e lo salva in un file."""
    global box_code

    # Controlla se esiste già un codice salvato
    if os.path.exists(BOX_CODE_FILE):
        with open(BOX_CODE_FILE, 'r') as f:
            box_code = f.read().strip()
    else:
        # Genera un nuovo codice
        box_code = str(uuid.uuid4())
        with open(BOX_CODE_FILE, 'w') as f:
            f.write(box_code)

    return box_code


def scan_network():
    """Esegue una scansione di rete usando nmap per rilevare i dispositivi."""
    global network_devices

    try:
        network_info = get_network_info()
        if not network_info:
            return []

        network_cidr = network_info['network_cidr']

        print(f"Scansione della rete {network_cidr}...")

        # Metodo 1: Scansione ARP per rilevare i dispositivi nella rete locale
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({
                'name': f"Device-{received.psrc}",
                'ip': received.psrc,
                'mac': received.hwsrc
            })

        # Metodo 2: Utilizza nmap per una scansione più approfondita
        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments='-sn')

        for host in nm.all_hosts():
            # Se il dispositivo non è già stato rilevato con ARP
            if not any(d['ip'] == host for d in devices):
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except:
                    hostname = f"Unknown-{host}"

                mac_address = nm[host]['addresses'].get('mac', '') if 'mac' in nm[host]['addresses'] else ''

                devices.append({
                    'name': hostname,
                    'ip': host,
                    'mac': mac_address
                })

        # Aggiorna la lista dei dispositivi
        network_devices = devices

        # Salva i dati dei dispositivi
        with open(DEVICE_DATA_FILE, 'w') as f:
            json.dump({
                'timestamp': datetime.datetime.now().isoformat(),
                'devices': devices
            }, f, indent=4)

        return devices
    except Exception as e:
        print(f"Errore durante la scansione della rete: {e}")
        return []


def send_data_to_server():
    """Invia i dati raccolti al SERVER."""
    try:
        if not box_code or not network_devices:
            return False

        # Raccoglie tutte le informazioni
        network_info = get_network_info()
        latency = measure_latency()
        public_ip = get_public_ip()

        # Costruisce il payload JSON
        payload = {
            'box_code': box_code,
            'timestamp': datetime.datetime.now().isoformat(),
            'box_data': {
                'device_name': socket.gethostname(),
                'ip_private': network_info['ip_private'] if network_info else None,
                'ip_public': public_ip,
                'mac_address': network_info['mac_address'] if network_info else None,
                'latency': latency
            },
            'devices': network_devices,
            'client_reports': []  # Sarà popolato dai report dei CLIENT
        }

        # Carica eventuali report client salvati
        if os.path.exists('client_reports.json'):
            try:
                with open('client_reports.json', 'r') as f:
                    client_data = json.load(f)
                    payload['client_reports'] = client_data.get('reports', [])

                # Reset dei report client dopo l'invio
                with open('client_reports.json', 'w') as f:
                    json.dump({'reports': []}, f)
            except:
                pass

        # Invia i dati al SERVER
        response = requests.post(
            f"{SERVER_URL}/api/report",
            json=payload,
            headers={'Content-Type': 'application/json'}
        )

        return response.status_code == 200
    except Exception as e:
        print(f"Errore nell'invio dei dati al SERVER: {e}")
        return False


def update_blocklist():
    """Aggiorna la lista degli IP da bloccare dal SERVER."""
    global ip_blocklist

    try:
        # Richiede la lista degli IP da bloccare
        response = requests.get(f"{SERVER_URL}/api/blocklist")

        if response.status_code == 200:
            data = response.json()
            ip_blocklist = data.get('data', [])

            # Salva la lista degli IP
            with open(IP_BLOCKLIST_FILE, 'w') as f:
                json.dump({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'ips': ip_blocklist
                }, f, indent=4)

            return True
        else:
            return False
    except Exception as e:
        print(f"Errore nell'aggiornamento della lista IP: {e}")
        return False


def periodic_scan():
    """Funzione eseguita periodicamente per scansionare la rete e inviare i dati."""
    while True:
        scan_network()
        send_data_to_server()
        time.sleep(SCAN_INTERVAL)


def periodic_blocklist_update():
    """Funzione eseguita periodicamente per aggiornare la lista degli IP da bloccare."""
    while True:
        update_blocklist()
        time.sleep(BLOCKLIST_UPDATE_INTERVAL)


# API per il CLIENT

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """API che fornisce la lista di IP da bloccare al CLIENT."""
    global ip_blocklist

    return jsonify({
        'status': 'success',
        'timestamp': datetime.datetime.now().isoformat(),
        'data': ip_blocklist
    })


@app.route('/api/report', methods=['POST'])
def receive_client_report():
    """API che riceve dati dal CLIENT."""
    try:
        data = request.json
        if not data:
            return jsonify({
                'status': 'error',
                'timestamp': datetime.datetime.now().isoformat(),
                'message': 'Dati mancanti'
            }), 400

        # Aggiungi il timestamp
        data['timestamp'] = datetime.datetime.now().isoformat()

        # Salva il report del client
        client_reports = []
        if os.path.exists('client_reports.json'):
            try:
                with open('client_reports.json', 'r') as f:
                    file_data = json.load(f)
                    client_reports = file_data.get('reports', [])
            except:
                pass

        client_reports.append(data)

        with open('client_reports.json', 'w') as f:
            json.dump({
                'timestamp': datetime.datetime.now().isoformat(),
                'reports': client_reports
            }, f, indent=4)

        return jsonify({
            'status': 'success',
            'timestamp': datetime.datetime.now().isoformat(),
            'message': 'Report ricevuto'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.datetime.now().isoformat(),
            'message': str(e)
        }), 500


@app.route('/api/discover', methods=['GET'])
def discover():
    """API utilizzata dal CLIENT per individuare il BOX nella rete."""
    return jsonify({
        'status': 'success',
        'timestamp': datetime.datetime.now().isoformat(),
        'box_name': socket.gethostname(),
        'box_code': box_code
    })


if __name__ == '__main__':
    # Genera o recupera il codice del BOX
    generate_box_code()

    # Inizializza le strutture dati
    if os.path.exists(IP_BLOCKLIST_FILE):
        try:
            with open(IP_BLOCKLIST_FILE, 'r') as f:
                data = json.load(f)
                ip_blocklist = data.get('ips', [])
        except:
            ip_blocklist = []

    if os.path.exists(DEVICE_DATA_FILE):
        try:
            with open(DEVICE_DATA_FILE, 'r') as f:
                data = json.load(f)
                network_devices = data.get('devices', [])
        except:
            network_devices = []

    # Inizializza il file dei report client se non esiste
    if not os.path.exists('client_reports.json'):
        with open('client_reports.json', 'w') as f:
            json.dump({'reports': []}, f, indent=4)

    # Avvia i thread per le attività periodiche
    scan_thread = threading.Thread(target=periodic_scan, daemon=True)
    blocklist_thread = threading.Thread(target=periodic_blocklist_update, daemon=True)

    scan_thread.start()
    blocklist_thread.start()

    # Aggiorna la lista degli IP da bloccare all'avvio
    update_blocklist()

    # Avvia il server Flask
    app.run(host='0.0.0.0', port=5001, debug=True)