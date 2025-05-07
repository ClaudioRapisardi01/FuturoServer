# CLIENT Application
# Questo CLIENT gestisce:
# 1. Individuazione del BOX nella rete locale
# 2. Download della lista di IP da bloccare dal BOX
# 3. Monitoraggio delle connessioni in entrata e uscita
# 4. Terminazione dei processi che comunicano con IP bloccati
# 5. Invio periodico di report al BOX

import requests
import socket
import json
import time
import threading
import os
import datetime
import ipaddress
import psutil
from scapy.all import IP, sniff
import subprocess

# Configurazione
BOX_DISCOVERY_PORT = 5001  # Porta del servizio API del BOX
BOX_IP_FILE = "box_ip.txt"  # File dove salvare l'IP del BOX
CLIENT_NAME = socket.gethostname()
REPORT_INTERVAL = 600  # 10 minuti in secondi

# Variabili globali
box_ip = None
blocked_ips = []
threats_detected = 0
ips_blocked = 0
active_connections = {}  # Dizionario per tenere traccia delle connessioni attive


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

        # Per il MAC, ottiene informazioni dall'interfaccia di rete attiva
        try:
            if os.name == 'nt':  # Windows
                output = subprocess.check_output("ipconfig /all", shell=True, text=True)
                for line in output.split('\n'):
                    if "Physical Address" in line and ":" in line:
                        mac = line.split(":")[-1].strip()
                        if mac and mac != "":
                            network_info['mac_address'] = mac
                            break
            else:  # Linux/Unix
                output = subprocess.check_output("ifconfig || ip link", shell=True, text=True)
                for line in output.split('\n'):
                    if ("ether" in line or "HWaddr" in line) and network_info['ip_private'] in output:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.lower() in ["ether", "hwaddr"] and i + 1 < len(parts):
                                network_info['mac_address'] = parts[i + 1]
                                break
        except:
            # Fallback se non riesce a ottenere il MAC
            network_info['mac_address'] = "00:00:00:00:00:00"

        print(f"Informazioni di rete determinate: Rete {network_info['network_cidr']}, IP {network_info['ip_private']}")
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


def discover_box():
    """Cerca il BOX nella rete locale provando a contattare ogni IP nel range di rete."""
    global box_ip

    # Controlla se l'IP del BOX è già salvato
    if os.path.exists(BOX_IP_FILE):
        with open(BOX_IP_FILE, 'r') as f:
            saved_ip = f.read().strip()

            # Verifica se l'IP salvato è ancora valido
            try:
                response = requests.get(f"http://{saved_ip}:{BOX_DISCOVERY_PORT}/api/discover", timeout=2)
                if response.status_code == 200:
                    box_ip = saved_ip
                    print(f"BOX trovato all'IP salvato: {box_ip}")
                    return box_ip
            except:
                pass

    # Se non trova l'IP salvato, scansiona la rete
    network_info = get_network_info()
    if not network_info:
        print("Impossibile ottenere informazioni di rete. Utilizzo rete predefinita 192.168.1.0/24")
        network_cidr = "192.168.1.0/24"
        our_ip = "192.168.1.100"  # IP di fallback
    else:
        network_cidr = network_info['network_cidr']
        our_ip = network_info['ip_private']

    print(f"Ricerca del BOX nella rete {network_cidr}...")

    # Scansiona tutti gli IP nella rete (escluso il broadcast e il proprio IP)
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)

            # Salta il proprio IP
            if ip_str == our_ip:
                continue

            try:
                print(ip_str)
                # Prova a contattare l'API di discovery
                response = requests.get(f"http://{ip_str}:{BOX_DISCOVERY_PORT}/api/discover", timeout=1)

                if response.status_code == 200:
                    box_ip = ip_str

                    # Salva l'IP del BOX
                    with open(BOX_IP_FILE, 'w') as f:
                        f.write(box_ip)

                    print(f"BOX trovato all'IP: {box_ip}")
                    return box_ip
            except:
                pass
    except Exception as e:
        print(f"Errore durante la scansione della rete: {e}")

    print("BOX non trovato nella rete locale.")
    return None


def get_blocked_ips():
    """Scarica la lista di IP da bloccare dal BOX."""
    global blocked_ips

    if not box_ip:
        print("Impossibile ottenere la lista di IP: BOX non trovato.")
        return False

    try:
        response = requests.get(f"http://{box_ip}:{BOX_DISCOVERY_PORT}/api/blocklist")

        if response.status_code == 200:
            data = response.json()
            blocked_ips = data.get('data', [])

            # Salva la lista degli IP bloccati
            with open("blocked_ips.json", 'w') as f:
                json.dump({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'ips': blocked_ips
                }, f, indent=4)

            print(f"Lista di {len(blocked_ips)} IP da bloccare aggiornata.")
            return True
        else:
            print(f"Errore nel download della lista IP: {response.status_code}")
            return False
    except Exception as e:
        print(f"Errore nel download della lista IP: {e}")
        return False


def get_process_by_pid(pid):
    """Ottiene le informazioni sul processo dato il PID."""
    try:
        return psutil.Process(pid)
    except:
        return None


def get_process_by_connection(conn):
    """Trova il processo associato a una connessione."""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                connections = proc.connections()
                for c in connections:
                    if (c.laddr.port == conn.laddr.port and c.laddr.ip == conn.laddr.ip and
                            c.raddr.port == conn.raddr.port and c.raddr.ip == conn.raddr.ip):
                        return proc
            except:
                continue
        return None
    except Exception as e:
        print(f"Errore nel trovare il processo per la connessione: {e}")
        return None


def kill_process(process):
    """Termina un processo."""
    global ips_blocked

    try:
        process_name = process.name()
        process_pid = process.pid

        process.terminate()

        # Attendi fino a 3 secondi per la terminazione
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            # Se il processo non termina, usare kill
            process.kill()

        ips_blocked += 1
        print(f"Processo {process_name} (PID: {process_pid}) terminato per connessione a IP bloccato.")
        return True
    except Exception as e:
        print(f"Errore nella terminazione del processo: {e}")
        return False


def is_ip_blocked(ip):
    """Verifica se un IP è nella lista di quelli da bloccare."""
    return ip in blocked_ips


def monitor_connections_with_psutil():
    """Monitora le connessioni di rete utilizzando psutil."""
    global threats_detected

    while True:
        if not blocked_ips:
            time.sleep(5)
            continue

        try:
            # Ottieni tutte le connessioni
            connections = psutil.net_connections(kind='inet')

            for conn in connections:
                # Salta le connessioni senza indirizzo remoto
                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip

                # Verifica se l'IP è bloccato
                if is_ip_blocked(remote_ip):
                    threats_detected += 1
                    print(f"Rilevata connessione a IP bloccato: {remote_ip}")

                    # Trova e termina il processo
                    process = get_process_by_pid(conn.pid)
                    if process:
                        kill_process(process)

            time.sleep(1)  # Controlla ogni secondo
        except Exception as e:
            print(f"Errore nel monitoraggio delle connessioni: {e}")
            time.sleep(5)  # Pausa più lunga in caso di errore


def packet_callback(packet):
    """Callback per l'analisi dei pacchetti con Scapy."""
    global threats_detected

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ottieni l'IP locale
        network_info = get_network_info()
        if not network_info:
            return

        local_ip = network_info['ip_private']

        # Determina l'IP remoto (diverso dall'IP locale)
        remote_ip = src_ip if src_ip != local_ip else dst_ip

        # Salta gli IP locali o di loopback
        if (remote_ip.startswith('127.') or
                remote_ip.startswith('10.') or
                remote_ip.startswith('172.16.') or
                remote_ip.startswith('192.168.')):
            return

        # Verifica se l'IP è bloccato
        if is_ip_blocked(remote_ip):
            threats_detected += 1
            print(f"Rilevato pacchetto da/verso IP bloccato: {remote_ip}")

            # Usa ss o netstat per trovare il processo che usa questa connessione
            if os.name == 'posix':  # Linux
                # Usa ss per trovare il processo
                try:
                    cmd = f"ss -p | grep {remote_ip}"
                    output = subprocess.check_output(cmd, shell=True, text=True)

                    for line in output.splitlines():
                        if "pid=" in line:
                            pid_part = line.split("pid=")[1].split(",")[0]
                            try:
                                pid = int(pid_part)
                                process = get_process_by_pid(pid)
                                if process:
                                    kill_process(process)
                            except:
                                continue
                except:
                    pass
            else:  # Windows
                # Usa netstat per trovare il processo
                try:
                    cmd = f"netstat -ano | findstr {remote_ip}"
                    output = subprocess.check_output(cmd, shell=True, text=True)

                    for line in output.splitlines():
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                pid = int(parts[4])
                                process = get_process_by_pid(pid)
                                if process:
                                    kill_process(process)
                            except:
                                continue
                except:
                    pass


def monitor_connections_with_scapy():
    """Monitora le connessioni di rete utilizzando Scapy."""
    # Avvia lo sniffer di pacchetti in un thread separato
    sniff_thread = threading.Thread(
        target=lambda: sniff(prn=packet_callback, store=0),
        daemon=True
    )
    sniff_thread.start()


def send_report_to_box():
    """Invia periodicamente un report al BOX."""
    global threats_detected, ips_blocked

    while True:
        if not box_ip:
            time.sleep(60)  # Attendi e riprova se il BOX non è stato trovato
            discover_box()
            continue

        try:
            network_info = get_network_info()
            if not network_info:
                time.sleep(60)
                continue

            # Prepara il report
            report = {
                'name': CLIENT_NAME,
                'ip_priv': network_info['ip_private'],
                'MAC': network_info['mac_address'],
                'minacce': threats_detected,
                'ip_bloccati': ips_blocked,
                'timestamp': datetime.datetime.now().isoformat()
            }

            # Invia il report al BOX
            response = requests.post(
                f"http://{box_ip}:{BOX_DISCOVERY_PORT}/api/report",
                json=report,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                print(f"Report inviato al BOX. Minacce rilevate: {threats_detected}, IP bloccati: {ips_blocked}")

                # Reset dei contatori dopo l'invio del report
                threats_detected = 0
                ips_blocked = 0
            else:
                print(f"Errore nell'invio del report: {response.status_code}")
        except Exception as e:
            print(f"Errore nell'invio del report: {e}")

        # Attendi l'intervallo di report
        time.sleep(REPORT_INTERVAL)


if __name__ == '__main__':
    # Cerca il BOX nella rete
    if not discover_box():
        print("Impossibile trovare il BOX. Riproveremo più tardi.")

    # Carica la lista di IP bloccati
    if os.path.exists("blocked_ips.json"):
        try:
            with open("blocked_ips.json", 'r') as f:
                data = json.load(f)
                blocked_ips = data.get('ips', [])
        except:
            blocked_ips = []

    # Aggiorna la lista di IP bloccati
    get_blocked_ips()

    # Avvia il thread per il monitoraggio delle connessioni
    monitoring_thread = threading.Thread(target=monitor_connections_with_psutil, daemon=True)
    monitoring_thread.start()

    # Avvia il monitoraggio con Scapy (opzionale, per una copertura più completa)
    monitor_connections_with_scapy()

    # Avvia il thread per l'invio periodico dei report
    report_thread = threading.Thread(target=send_report_to_box, daemon=True)
    report_thread.start()


    # Thread per aggiornare periodicamente la lista degli IP bloccati
    def update_blocklist_periodically():
        while True:
            time.sleep(3600)  # Aggiorna ogni ora
            get_blocked_ips()


    blocklist_thread = threading.Thread(target=update_blocklist_periodically, daemon=True)
    blocklist_thread.start()

    # Mantieni il programma in esecuzione
    try:
        while True:
            time.sleep(10)

            # Se il BOX non è stato trovato, riprova periodicamente
            if not box_ip:
                discover_box()
                if box_ip:
                    get_blocked_ips()
    except KeyboardInterrupt:
        print("CLIENT terminato dall'utente.")