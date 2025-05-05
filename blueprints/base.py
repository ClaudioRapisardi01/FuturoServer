from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import DB
import secrets
from datetime import datetime, timedelta

base_bp = Blueprint('base', __name__, url_prefix='/')


@base_bp.route('/')
def index():
    return render_template('index.html')


@base_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') is not None

        # Query per trovare l'utente
        user_query = "SELECT * FROM utenti WHERE email = %s AND attivo = TRUE"
        user_data = DB.read_data(user_query, (email,))

        if user_data and len(user_data) > 0:
            user = user_data[0]
            # Verifica password
            if user['password'] == password:  # In produzione dovresti usare hash
                # Crea sessione
                session_token = secrets.token_hex(32)
                session_expiry = datetime.now() + timedelta(days=14 if remember else 1)

                create_session_query = """
                    INSERT INTO sessioni (idUtente, token, ipAddress, userAgent, dataScadenza) 
                    VALUES (%s, %s, %s, %s, %s)
                """
                DB.execute(create_session_query, (
                    user['id'],
                    session_token,
                    request.remote_addr,
                    request.user_agent.string,
                    session_expiry
                ))

                # Imposta variabili di sessione
                session['user_id'] = user['id']
                session['token'] = session_token
                session['user_email'] = user['email']
                session['user_role'] = user['ruolo']

                # Aggiorna ultimo accesso
                update_access_query = "UPDATE utenti SET dataUltimoAccesso = %s WHERE id = %s"
                DB.execute(update_access_query, (datetime.now(), user['id']))

                # Log dell'accesso
                log_query = """
                    INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
                    VALUES (%s, 'login', 'User logged in', %s, %s, %s)
                """
                DB.execute(log_query, (user['id'], request.remote_addr, request.user_agent.string, datetime.now()))

                flash('Login successful! Welcome back.', 'success')
                return redirect(url_for('user.dashboard'))
            else:
                flash('Invalid email or password. Please try again.', 'error')
        else:
            flash('User not found or account not active.', 'error')

    return render_template('login.html')


@base_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form.get('nome')
        cognome = request.form.get('cognome')
        email = request.form.get('email')
        password = request.form.get('password')
        terms = request.form.get('terms') is not None

        if not all([nome, cognome, email, password, terms]):
            flash('All fields are required!', 'error')
            return render_template('register.html')

        # Verifica se email esiste già
        check_email_query = "SELECT COUNT(*) as count FROM utenti WHERE email = %s"
        result = DB.read_data(check_email_query, (email,))

        if result and result[0]['count'] > 0:
            flash('Email already exists!', 'error')
            return render_template('register.html')

        # Inserisci nuovo utente
        insert_user_query = """
            INSERT INTO utenti (email, password, nome, cognome, dataIscrizione, attivo) 
            VALUES (%s, %s, %s, %s, %s, TRUE)
        """

        if DB.execute(insert_user_query, (email, password, nome, cognome, datetime.now())):
            # Prendi l'id del nuovo utente
            user_id_query = "SELECT id FROM utenti WHERE email = %s"
            user_result = DB.read_data(user_id_query, (email,))

            if user_result:
                user_id = user_result[0]['id']

                # Log registrazione
                log_query = """
                    INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
                    VALUES (%s, 'registrazione', 'New user registered', %s, %s, %s)
                """
                DB.execute(log_query, (user_id, request.remote_addr, request.user_agent.string, datetime.now()))

                # Crea notifica di benvenuto
                welcome_notification_query = """
                    INSERT INTO notifiche (idUtente, titolo, messaggio, tipo) 
                    VALUES (%s, 'Benvenuto!', 'Grazie per esserti registrato su ServerFuturo', 'info')
                """
                DB.execute(welcome_notification_query, (user_id,))

                flash('Registration successful! Please login to continue.', 'success')
                return redirect(url_for('base.login'))
            else:
                flash('Error occurred during registration.', 'error')
        else:
            flash('Error occurred during registration.', 'error')

    return render_template('register.html')


@base_bp.route('/logout')
def logout():
    if 'user_id' in session and 'token' in session:
        # Disattiva sessione nel database
        deactivate_session_query = "UPDATE sessioni SET attiva = FALSE WHERE token = %s"
        DB.execute(deactivate_session_query, (session['token'],))

        # Log logout
        log_query = """
            INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
            VALUES (%s, 'logout', 'User logged out', %s, %s, %s)
        """
        DB.execute(log_query, (session['user_id'], request.remote_addr, request.user_agent.string, datetime.now()))

    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('base.index'))


# API endpoint per stats dashboard (chiamato via JavaScript)
@base_bp.route('/stats')
def stats():
    # Conta dispositivi attivi
    active_devices_query = """
        SELECT COUNT(*) as count FROM dispositivi 
        WHERE attivo = TRUE AND 
        ultimoAccesso > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    """
    active_devices_result = DB.read_data(active_devices_query)
    active_devices = active_devices_result[0]['count'] if active_devices_result else 0

    return jsonify({
        'active_devices': active_devices
    })