from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from functools import wraps
from db import DB
from datetime import datetime

user_bp = Blueprint('user', __name__, url_prefix='/user')


# Decoratore per verificare il login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('base.login'))

        # Verifica che la sessione sia ancora attiva nel database
        check_session_query = """
            SELECT s.*, u.attivo 
            FROM sessioni s 
            JOIN utenti u ON s.idUtente = u.id 
            WHERE s.token = %s AND s.attiva = TRUE 
            AND u.attivo = TRUE
        """
        session_data = DB.read_data(check_session_query, (session.get('token'),))

        if not session_data:
            session.clear()
            flash('Your session has expired. Please login again.', 'error')
            return redirect(url_for('base.login'))

        return f(*args, **kwargs)

    return decorated_function


# Decoratore per verificare che l'utente abbia un abbonamento attivo
def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')

        # Controlla se l'utente ha un abbonamento attivo
        check_subscription_query = """
            SELECT COUNT(*) as count, MAX(dataFine) as latest_expiry
            FROM utenti_abbonamenti 
            WHERE idUtente = %s AND stato = 'attivo' AND dataFine > NOW()
        """
        subscription_check = DB.read_data(check_subscription_query, (user_id,))

        # Se non ha un abbonamento attivo, reindirizza alla pagina di selezione
        if not subscription_check or subscription_check[0]['count'] == 0:
            flash('Per favore seleziona un piano di abbonamento per proseguire.', 'info')
            return redirect(url_for('abbonamenti.select_plan'))

        return f(*args, **kwargs)

    return decorated_function


@user_bp.route('/dashboard')
@login_required
@subscription_required
def dashboard():
    user_id = session.get('user_id')

    # Recupera informazioni utente complete
    user_query = """
        SELECT u.*, 
               (SELECT COUNT(*) FROM dispositivi WHERE idUtente = u.id AND attivo = TRUE) as active_devices,
               (SELECT a.nome FROM abbonamenti a 
                JOIN utenti_abbonamenti ua ON a.id = ua.idAbbonamento 
                WHERE ua.idUtente = u.id AND ua.stato = 'attivo' 
                ORDER BY ua.dataInizio DESC LIMIT 1) as current_plan,
               (SELECT ua.dataFine FROM utenti_abbonamenti ua
                WHERE ua.idUtente = u.id AND ua.stato = 'attivo' 
                ORDER BY ua.dataInizio DESC LIMIT 1) as plan_expiry
        FROM utenti u 
        WHERE u.id = %s
    """
    user_data = DB.read_data(user_query, (user_id,))

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('base.login'))

    user = user_data[0]

    # Recupera statistiche dell'utente
    stats_query = """
        SELECT 
            (SELECT COUNT(*) FROM log WHERE tipoEvento = 'security_event' AND idUtente = %s) as threats_blocked,
            (SELECT COUNT(*) FROM notifiche WHERE idUtente = %s AND stato = 'non_letta') as unread_notifications,
            (SELECT COUNT(*) FROM dispositivi WHERE idUtente = %s) as total_devices,
            (SELECT COUNT(*) FROM sessioni WHERE idUtente = %s AND attiva = TRUE) as active_sessions
    """
    stats_data = DB.read_data(stats_query, (user_id, user_id, user_id, user_id))
    stats = stats_data[0] if stats_data else {
        'threats_blocked': 0,
        'unread_notifications': 0,
        'total_devices': 0,
        'active_sessions': 0
    }

    # Recupera notifiche recenti
    notifications_query = """
        SELECT * FROM notifiche 
        WHERE idUtente = %s 
        ORDER BY dataCreazione DESC 
        LIMIT 5
    """
    notifications = DB.read_data(notifications_query, (user_id,))

    # Recupera dispositivi recenti
    devices_query = """
        SELECT d.*, 
               (SELECT COUNT(*) FROM rilevazioni WHERE seriale = d.seriale) as detections_count,
               (SELECT MAX(dataUpdate) FROM rilevazioni WHERE seriale = d.seriale) as last_detection
        FROM dispositivi d
        WHERE d.idUtente = %s 
        ORDER BY d.ultimoAccesso DESC 
        LIMIT 10
    """
    devices = DB.read_data(devices_query, (user_id,))

    # Aggiorna ultimo accesso
    update_access_query = "UPDATE utenti SET dataUltimoAccesso = NOW() WHERE id = %s"
    DB.execute(update_access_query, (user_id,))

    return render_template('dashboard/home.html',
                           user=user,
                           stats=stats,
                           notifications=notifications or [],
                           devices=devices or [])


@user_bp.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')

    # Recupera informazioni utente complete
    user_query = """
        SELECT u.*, 
               (SELECT COUNT(*) FROM dispositivi WHERE idUtente = u.id) as device_count,
               (SELECT COUNT(*) FROM notifiche WHERE idUtente = u.id) as notification_count,
               (SELECT COUNT(*) FROM pagamenti WHERE idUtente = u.id AND stato = 'completato') as completed_payments
        FROM utenti u 
        WHERE u.id = %s
    """
    user_data = DB.read_data(user_query, (user_id,))

    if not user_data:
        flash('User not found.', 'error')
        return redirect(url_for('user.dashboard'))

    user = user_data[0]

    # Recupera abbonamento attuale
    subscription_query = """
        SELECT ua.*, a.nome as piano, a.prezzo, a.maxDispositivi
        FROM utenti_abbonamenti ua
        JOIN abbonamenti a ON ua.idAbbonamento = a.id
        WHERE ua.idUtente = %s AND ua.stato = 'attivo'
        ORDER BY ua.dataInizio DESC
        LIMIT 1
    """
    subscription_data = DB.read_data(subscription_query, (user_id,))
    subscription = subscription_data[0] if subscription_data else None

    return render_template('user/profile.html', user=user, subscription=subscription)


@user_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session.get('user_id')

    if request.method == 'POST':
        nome = request.form.get('nome')
        cognome = request.form.get('cognome')
        telefono = request.form.get('telefono')
        indirizzo = request.form.get('indirizzo')
        cap = request.form.get('cap')
        regione = request.form.get('regione')
        nazione = request.form.get('nazione')

        # Validazione base
        if not all([nome, cognome]):
            flash('Nome e cognome sono obbligatori', 'error')
            return redirect(url_for('user.edit_profile'))

        update_query = """
            UPDATE utenti 
            SET nome = %s, cognome = %s, telefono = %s, 
                indirizzo = %s, cap = %s, regione = %s, nazione = %s
            WHERE id = %s
        """

        if DB.execute(update_query, (nome, cognome, telefono, indirizzo, cap, regione, nazione, user_id)):
            # Log dell'aggiornamento del profilo
            log_query = """
                INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, dataEvento)
                VALUES (%s, 'profile_update', 'User profile updated', %s, NOW())
            """
            DB.execute(log_query, (user_id, request.remote_addr))

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user.profile'))
        else:
            flash('Error updating profile.', 'error')

    # GET request - mostra form
    user_query = "SELECT * FROM utenti WHERE id = %s"
    user_data = DB.read_data(user_query, (user_id,))

    if not user_data:
        flash('User not found.', 'error')
        return redirect(url_for('user.dashboard'))

    user = user_data[0]
    return render_template('user/edit_profile.html', user=user)


@user_bp.route('/settings')
@login_required
def settings():
    user_id = session.get('user_id')

    # Recupera notifiche dell'utente
    notifications_query = """
        SELECT * FROM notifiche 
        WHERE idUtente = %s 
        ORDER BY dataCreazione DESC
        LIMIT 50
    """
    notifications = DB.read_data(notifications_query, (user_id,))

    # Recupera sessioni attive
    sessions_query = """
        SELECT s.*, 
               CASE 
                   WHEN s.token = %s THEN TRUE 
                   ELSE FALSE 
               END as current_session
        FROM sessioni s
        WHERE s.idUtente = %s AND s.attiva = TRUE
        ORDER BY s.dataCreazione DESC
    """
    sessions = DB.read_data(sessions_query, (session.get('token'), user_id))

    # Recupera impostazioni utente
    user_settings_query = """
        SELECT * FROM impostazioni_utente 
        WHERE idUtente = %s
    """
    user_settings = DB.read_data(user_settings_query, (user_id,))

    return render_template('user/settings.html',
                           notifications=notifications or [],
                           sessions=sessions or [],
                           user_settings=user_settings or [])


@user_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    user_id = session.get('user_id')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    # Verifica password attuale
    check_password_query = "SELECT password FROM utenti WHERE id = %s"
    user_data = DB.read_data(check_password_query, (user_id,))

    if not user_data or user_data[0]['password'] != current_password:
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('user.settings'))

    # Aggiorna password
    update_password_query = "UPDATE utenti SET password = %s WHERE id = %s"
    if DB.execute(update_password_query, (new_password, user_id)):
        # Log del cambio password
        log_query = """
            INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, dataEvento)
            VALUES (%s, 'password_change', 'Password changed successfully', %s, NOW())
        """
        DB.execute(log_query, (user_id, request.remote_addr))
        flash('Password changed successfully!', 'success')
    else:
        flash('Error changing password.', 'error')

    return redirect(url_for('user.settings'))


@user_bp.route('/notification/<int:notification_id>/mark-read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    user_id = session.get('user_id')

    # Verifica che la notifica appartenga all'utente
    check_notification_query = "SELECT id FROM notifiche WHERE id = %s AND idUtente = %s"
    notification_data = DB.read_data(check_notification_query, (notification_id, user_id))

    if not notification_data:
        flash('Notification not found.', 'error')
        return redirect(url_for('user.settings'))

    # Marca come letta
    update_notification_query = """
        UPDATE notifiche 
        SET stato = 'letta', dataLettura = NOW()
        WHERE id = %s
    """
    if DB.execute(update_notification_query, (notification_id,)):
        flash('Notification marked as read.', 'success')
    else:
        flash('Error marking notification as read.', 'error')

    return redirect(url_for('user.settings'))


@user_bp.route('/devices')
@login_required
@subscription_required
def devices():
    user_id = session.get('user_id')

    # Recupera tutti i dispositivi dell'utente
    devices_query = """
        SELECT d.*, 
               (SELECT COUNT(*) FROM rilevazioni WHERE seriale = d.seriale) as detections_count,
               (SELECT MAX(dataUpdate) FROM rilevazioni WHERE seriale = d.seriale) as last_detection,
               (SELECT vulnerabilita FROM rilevazioni WHERE seriale = d.seriale ORDER BY dataUpdate DESC LIMIT 1) as current_vulnerabilities
        FROM dispositivi d
        WHERE d.idUtente = %s 
        ORDER BY d.ultimoAccesso DESC
    """
    devices = DB.read_data(devices_query, (user_id,))

    # Controlla limiti dispositivi
    device_limit_query = """
        SELECT a.maxDispositivi,
               (SELECT COUNT(*) FROM dispositivi WHERE idUtente = %s AND attivo = TRUE) as current_devices
        FROM utenti_abbonamenti ua
        JOIN abbonamenti a ON ua.idAbbonamento = a.id
        WHERE ua.idUtente = %s AND ua.stato = 'attivo'
        ORDER BY ua.dataInizio DESC
        LIMIT 1
    """
    limit_data = DB.read_data(device_limit_query, (user_id, user_id))
    device_limit = limit_data[0] if limit_data else {'maxDispositivi': 0, 'current_devices': 0}

    return render_template('user/devices.html', devices=devices or [], device_limit=device_limit)


@user_bp.route('/devices/register', methods=['POST'])
@login_required
@subscription_required
def register_device():
    user_id = session.get('user_id')
    serial = request.form.get('serial')
    mac = request.form.get('mac')

    # Verifica se l'utente ha ancora slot disponibili
    device_limit_check = DB.check_device_limit(user_id)

    if device_limit_check and device_limit_check['current_devices'] >= device_limit_check['device_limit']:
        flash(
            f'Hai raggiunto il limite di {device_limit_check["device_limit"]} dispositivi per il tuo piano {device_limit_check["plan_name"]}',
            'error')
        return redirect(url_for('user.devices'))

    # Registra il nuovo dispositivo
    register_device_query = """
        INSERT INTO dispositivi (idUtente, seriale, MAC, dataRegistrazione, attivo) 
        VALUES (%s, %s, %s, NOW(), TRUE)
    """

    if DB.execute(register_device_query, (user_id, serial, mac)):
        # Crea notifica
        create_notification_query = """
            INSERT INTO notifiche (idUtente, titolo, messaggio, tipo)
            VALUES (%s, 'Nuovo Dispositivo', %s, 'info')
        """
        message = f'Dispositivo {serial} registrato con successo'
        DB.execute(create_notification_query, (user_id, message))

        flash('Device registered successfully!', 'success')
    else:
        flash('Error registering device.', 'error')

    return redirect(url_for('user.devices'))


@user_bp.route('/session/<int:session_id>/revoke', methods=['POST'])
@login_required
def revoke_session(session_id):
    user_id = session.get('user_id')

    # Verifica che la sessione appartenga all'utente
    check_session_query = "SELECT id FROM sessioni WHERE id = %s AND idUtente = %s"
    session_data = DB.read_data(check_session_query, (session_id, user_id))

    if not session_data:
        flash('Session not found.', 'error')
        return redirect(url_for('user.settings'))

    # Revoca la sessione
    revoke_query = "UPDATE sessioni SET attiva = FALSE WHERE id = %s"
    if DB.execute(revoke_query, (session_id,)):
        flash('Session revoked successfully.', 'success')
    else:
        flash('Error revoking session.', 'error')

    return redirect(url_for('user.settings'))


@user_bp.route('/export-data')
@login_required
def export_data():
    user_id = session.get('user_id')

    # Recupera tutti i dati dell'utente
    user_data_query = "SELECT * FROM utenti WHERE id = %s"
    devices_query = "SELECT * FROM dispositivi WHERE idUtente = %s"
    notifications_query = "SELECT * FROM notifiche WHERE idUtente = %s"
    payments_query = "SELECT * FROM pagamenti WHERE idUtente = %s"
    logs_query = "SELECT * FROM log WHERE idUtente = %s"

    user_data = DB.read_data(user_data_query, (user_id,))
    devices = DB.read_data(devices_query, (user_id,))
    notifications = DB.read_data(notifications_query, (user_id,))
    payments = DB.read_data(payments_query, (user_id,))
    logs = DB.read_data(logs_query, (user_id,))

    # Prepara i dati per l'export
    export_data = {
        'user': user_data[0] if user_data else None,
        'devices': devices or [],
        'notifications': notifications or [],
        'payments': payments or [],
        'logs': logs or []
    }

    # In un'implementazione reale, potresti generare un file JSON o CSV
    # Per ora, ritorniamo i dati in formato JSON
    return jsonify(export_data)