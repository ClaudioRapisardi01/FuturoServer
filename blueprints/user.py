from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from functools import wraps
from db import DB

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
            SELECT s.*, u.stato_account 
            FROM sessioni s 
            JOIN utenti u ON s.utente_id = u.id 
            WHERE s.token = %s AND s.attiva = TRUE 
            AND u.stato_account = 'attivo'
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
               (SELECT COUNT(*) FROM dispositivi WHERE utente_id = u.id AND stato = 'attivo') as active_devices,
               (SELECT nome FROM abbonamenti WHERE id = 
                   (SELECT abbonamento_id FROM utenti_abbonamenti 
                    WHERE utente_id = u.id AND stato = 'attivo' 
                    ORDER BY data_attivazione DESC LIMIT 1)
               ) as current_plan
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
            (SELECT COUNT(*) FROM logs WHERE tipo_evento = 'security_event' AND utente_id = %s) as threats_blocked,
            (SELECT COUNT(*) FROM notifiche WHERE utente_id = %s AND stato = 'non_letta') as unread_notifications
    """
    stats_data = DB.read_data(stats_query, (user_id, user_id))
    stats = stats_data[0] if stats_data else {'threats_blocked': 0, 'unread_notifications': 0}

    # Recupera notifiche recenti
    notifications_query = """
        SELECT * FROM notifiche 
        WHERE utente_id = %s 
        ORDER BY data_creazione DESC 
        LIMIT 5
    """
    notifications = DB.read_data(notifications_query, (user_id,))

    # Recupera dispositivi
    devices_query = """
        SELECT * FROM dispositivi 
        WHERE utente_id = %s 
        ORDER BY ultimo_utilizzo DESC 
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
    # Implementa la pagina del profilo
    pass


@user_bp.route('/settings')
@login_required
def settings():
    # Implementa la pagina delle impostazioni
    pass