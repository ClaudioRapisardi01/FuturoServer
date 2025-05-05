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


@user_bp.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')

    # Recupera informazioni utente
    user_query = """
        SELECT u.*, 
               (SELECT COUNT(*) FROM dispositivi WHERE idUtente = u.id AND attivo = TRUE) as active_devices,
               (SELECT a.nome FROM abbonamenti a 
                JOIN utenti_abbonamenti ua ON a.id = ua.idAbbonamento 
                WHERE ua.idUtente = u.id AND ua.stato = 'attivo' 
                ORDER BY ua.dataInizio DESC LIMIT 1) as current_plan
        FROM utenti u 
        WHERE u.id = %s
    """
    user_data = DB.read_data(user_query, (user_id,))

    if not user_data:
        flash('User data not found.', 'error')
        return redirect(url_for('base.login'))

    user = user_data[0]

    # Recupera statistiche
    stats_query = """
        SELECT 
            (SELECT COUNT(*) FROM log WHERE tipoEvento = 'security_event' AND idUtente = %s) as threats_blocked,
            (SELECT COUNT(*) FROM notifiche WHERE idUtente = %s AND stato = 'non_letta') as unread_notifications
    """
    stats_data = DB.read_data(stats_query, (user_id, user_id))
    stats = stats_data[0] if stats_data else {'threats_blocked': 0, 'unread_notifications': 0}

    # Recupera notifiche recenti
    notifications_query = """
        SELECT * FROM notifiche 
        WHERE idUtente = %s 
        ORDER BY dataCreazione DESC 
        LIMIT 5
    """
    notifications = DB.read_data(notifications_query, (user_id,))

    # Recupera dispositivi
    devices_query = """
        SELECT * FROM dispositivi 
        WHERE idUtente = %s 
        ORDER BY ultimoAccesso DESC 
        LIMIT 10
    """
    devices = DB.read_data(devices_query, (user_id,))

    return render_template('dashboard/home.html',
                           user=user,
                           stats=stats,
                           notifications=notifications or [],
                           devices=devices or [])


@user_bp.route('/profile')
@login_required
def profile():
    user_id = session.get('user_id')

    # Recupera informazioni utente
    user_query = "SELECT * FROM utenti WHERE id = %s"
    user_data = DB.read_data(user_query, (user_id,))

    if not user_data:
        flash('User not found.', 'error')
        return redirect(url_for('user.dashboard'))

    user = user_data[0]
    return render_template('user/profile.html', user=user)


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

        update_query = """
            UPDATE utenti 
            SET nome = %s, cognome = %s, telefono = %s, 
                indirizzo = %s, cap = %s, regione = %s, nazione = %s
            WHERE id = %s
        """

        if DB.execute(update_query, (nome, cognome, telefono, indirizzo, cap, regione, nazione, user_id)):
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
    """
    notifications = DB.read_data(notifications_query, (user_id,))

    return render_template('user/settings.html', notifications=notifications or [])


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
        SET stato = 'letta', dataLettura = %s 
        WHERE id = %s
    """
    if DB.execute(update_notification_query, (datetime.now(), notification_id)):
        flash('Notification marked as read.', 'success')
    else:
        flash('Error marking notification as read.', 'error')

    return redirect(url_for('user.settings'))