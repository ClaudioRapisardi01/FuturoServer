# test_db.py
from db import DB
from datetime import datetime, timedelta
import json

# Configura il database
DB.config(
    host="localhost",
    user="claudio",
    password="Superrapa22",
    database="serverfuturo"
)


def test_user_operations():
    """Test operazioni utenti"""
    print("=== Test Operazioni Utenti ===")

    # Inserimento utente
    insert_query = """
    INSERT INTO utenti (nome, cognome, email, password, indirizzo, cap, 
                       regione, nazione, telefono, ruolo)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = ('Mario', 'Rossi', 'mario.rossi@test.it', 'password_hash',
              'Via Roma 1', '00100', 'Lazio', 'Italia', '333111111', 'utente')

    if DB.execute(insert_query, params):
        print("✓ Utente inserito con successo")

        # Lettura utente
        select_query = "SELECT * FROM utenti WHERE email = %s"
        user = DB.read_data(select_query, ('mario.rossi@test.it',))

        if user:
            print("✓ Utente letto con successo")
            print(f"  ID: {user[0]['id']}")
            print(f"  Nome: {user[0]['nome']} {user[0]['cognome']}")
            return user[0]['id']
        else:
            print("✗ Errore nella lettura utente")
    else:
        print("✗ Errore nell'inserimento utente")

    return None


def test_device_operations(user_id):
    """Test operazioni dispositivi"""
    print("\n=== Test Operazioni Dispositivi ===")

    if not user_id:
        print("✗ Impossibile testare senza un ID utente valido")
        return

    # Inserimento dispositivo
    insert_query = """
    INSERT INTO dispositivi (idUtente, seriale, ipPub, ipPriv, MAC, latenza, vulnerabilita)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    params = (user_id, 'SER123456', '192.168.1.100', '10.0.0.1',
              '00:11:22:33:44:55', 50, 'Nessuna vulnerabilità rilevata')

    if DB.execute(insert_query, params):
        print("✓ Dispositivo inserito con successo")

        # Lettura dispositivi dell'utente
        select_query = "SELECT * FROM dispositivi WHERE idUtente = %s"
        devices = DB.read_data(select_query, (user_id,))

        if devices:
            print("✓ Dispositivi letti con successo")
            for device in devices:
                print(f"  Seriale: {device['seriale']}")
                print(f"  IP Pubblico: {device['ipPub']}")
                return device['seriale']
        else:
            print("✗ Errore nella lettura dispositivi")
    else:
        print("✗ Errore nell'inserimento dispositivo")

    return None


def test_detection_operations(serial):
    """Test operazioni rilevazioni"""
    print("\n=== Test Operazioni Rilevazioni ===")

    if not serial:
        print("✗ Impossibile testare senza un seriale dispositivo valido")
        return

    # Inserimento rilevazione
    insert_query = """
    INSERT INTO rilevazioni (seriale, download, upload, latenza, 
                            dispositiviConnessi, vulnerabilita, ipPub, ipPriv)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = (serial, 1024000, 512000, 45, 5, 'Nessuna', '192.168.1.100', '10.0.0.1')

    if DB.execute(insert_query, params):
        print("✓ Rilevazione inserita con successo")

        # Lettura rilevazioni per dispositivo
        select_query = "SELECT * FROM rilevazioni WHERE seriale = %s ORDER BY dataUpdate DESC LIMIT 1"
        detection = DB.read_data(select_query, (serial,))

        if detection:
            print("✓ Rilevazione letta con successo")
            print(f"  Download: {detection[0]['download']} bytes")
            print(f"  Upload: {detection[0]['upload']} bytes")
            print(f"  Latenza: {detection[0]['latenza']} ms")
        else:
            print("✗ Errore nella lettura rilevazione")
    else:
        print("✗ Errore nell'inserimento rilevazione")


def test_subscription_operations(user_id):
    """Test operazioni abbonamenti"""
    print("\n=== Test Operazioni Abbonamenti ===")

    if not user_id:
        print("✗ Impossibile testare senza un ID utente valido")
        return

    # Ottiene l'abbonamento Basic
    select_subscription = "SELECT id FROM abbonamenti WHERE nome = 'Basic'"
    subscription = DB.read_data(select_subscription)

    if subscription:
        subscription_id = subscription[0]['id']

        # Inserimento abbonamento utente
        insert_query = """
        INSERT INTO utenti_abbonamenti 
        (idUtente, idAbbonamento, dataInizio, dataFine, stato, autoRinnovo)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        data_inizio = datetime.now()
        data_fine = data_inizio + timedelta(days=30)
        params = (user_id, subscription_id, data_inizio, data_fine, 'attivo', True)

        if DB.execute(insert_query, params):
            print("✓ Abbonamento utente inserito con successo")

            # Lettura abbonamenti attivi dell'utente
            select_query = """
            SELECT ua.*, a.nome as piano, a.maxDispositivi 
            FROM utenti_abbonamenti ua
            JOIN abbonamenti a ON ua.idAbbonamento = a.id
            WHERE ua.idUtente = %s AND ua.stato = 'attivo'
            """
            active_subs = DB.read_data(select_query, (user_id,))

            if active_subs:
                print("✓ Abbonamenti attivi letti con successo")
                for sub in active_subs:
                    print(f"  Piano: {sub['piano']}")
                    print(f"  Max dispositivi: {sub['maxDispositivi']}")
                    print(f"  Scadenza: {sub['dataFine']}")
            else:
                print("✗ Errore nella lettura abbonamenti attivi")
        else:
            print("✗ Errore nell'inserimento abbonamento utente")
    else:
        print("✗ Abbonamento Basic non trovato")


def test_notification_operations(user_id):
    """Test operazioni notifiche"""
    print("\n=== Test Operazioni Notifiche ===")

    if not user_id:
        print("✗ Impossibile testare senza un ID utente valido")
        return

    # Inserimento notifica
    insert_query = """
    INSERT INTO notifiche (idUtente, titolo, messaggio, tipo, priorita)
    VALUES (%s, %s, %s, %s, %s)
    """
    params = (user_id, 'Benvenuto!', 'Grazie per la registrazione', 'info', 1)

    if DB.execute(insert_query, params):
        print("✓ Notifica inserita con successo")

        # Lettura notifiche non lette
        select_query = """
        SELECT * FROM notifiche 
        WHERE idUtente = %s AND stato = 'non_letta'
        ORDER BY priorita DESC, dataCreazione DESC
        """
        notifications = DB.read_data(select_query, (user_id,))

        if notifications:
            print("✓ Notifiche non lette caricate con successo")
            for notif in notifications:
                print(f"  {notif['titolo']}: {notif['messaggio']}")
        else:
            print("✗ Errore nella lettura notifiche")
    else:
        print("✗ Errore nell'inserimento notifica")


def cleanup_test_data():
    """Pulisce i dati di test"""
    print("\n=== Pulizia dati di test ===")

    cleanup_query = "DELETE FROM utenti WHERE email LIKE '%@test.it'"
    if DB.execute(cleanup_query):
        print("✓ Dati di test rimossi con successo")
    else:
        print("✗ Errore nella pulizia dati di test")


def main():
    print("=== Test Database Operations ===\n")

    try:
        # Test operazioni
        user_id = test_user_operations()
        device_serial = test_device_operations(user_id)
        test_detection_operations(device_serial)
        test_subscription_operations(user_id)
        test_notification_operations(user_id)

        # Pulizia
        cleanup_response = input("\nVuoi rimuovere i dati di test? [y/N]: ")
        if cleanup_response.lower() == 'y':
            cleanup_test_data()

    except Exception as e:
        print(f"\n✗ Errore durante i test: {e}")

    print("\n=== Test completati ===")


if __name__ == "__main__":
    main()