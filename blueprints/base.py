from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import DB
import secrets
from datetime import datetime, timedelta
import re

base_bp = Blueprint('base', __name__, url_prefix='/')


def generate_secure_token(length=32):
    """Genera un token sicuro"""
    return secrets.token_hex(length)


def validate_email(email):
    """Valida formato email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Valida forza password"""
    # Debug della password (primi 3 caratteri per sicurezza)
    print(f"DEBUG: Validating password (first 3 chars): {password[:3]}...")

    if len(password) < 8:
        print(f"DEBUG: Password length: {len(password)}")
        return False, "Password must be at least 8 characters long"

    # Uppercase check
    has_upper = bool(re.search(r'[A-Z]', password))
    print(f"DEBUG: Has uppercase: {has_upper}")
    if not has_upper:
        return False, "Password must contain at least one uppercase letter"

    # Lowercase check
    has_lower = bool(re.search(r'[a-z]', password))
    print(f"DEBUG: Has lowercase: {has_lower}")
    if not has_lower:
        return False, "Password must contain at least one lowercase letter"

    # Number check
    has_number = bool(re.search(r'[0-9]', password))
    print(f"DEBUG: Has number: {has_number}")
    if not has_number:
        return False, "Password must contain at least one number"

    # Special character check (expanded list)
    special_chars = r'[!@#$%^&*(),.?":{}|<>-_+=\[\]\\;\'`~]'
    has_special = bool(re.search(special_chars, password))
    print(f"DEBUG: Has special character: {has_special}")

    # Se la password non contiene caratteri speciali, mostra quali sono accettati
    if not has_special:
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>-_+=[]\\;'`~)"

    print(f"DEBUG: Password validation passed!")
    return True, ""


@base_bp.route('/')
def index():
    """Home page"""
    # Se l'utente è già loggato, reindirizza alla dashboard
    if 'user_id' in session:
        return redirect(url_for('user.dashboard'))

    # Recupera statistiche pubbliche per la homepage
    stats_query = """
        SELECT 
            (SELECT COUNT(*) FROM utenti WHERE attivo = TRUE) as total_users,
            (SELECT COUNT(*) FROM dispositivi WHERE attivo = TRUE) as total_devices,
            (SELECT COUNT(*) FROM utenti_abbonamenti WHERE stato = 'attivo') as active_subscriptions
    """
    stats = DB.read_data(stats_query)

    return render_template('index.html', stats=stats[0] if stats else None)


@base_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login dell'utente"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') is not None

        # DEBUG
        print(f"DEBUG: Login attempt for email: {email}")

        # Validazione di base
        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('login.html')

        if not validate_email(email):
            flash('Invalid email format.', 'error')
            return render_template('login.html')

        # Query per trovare l'utente
        user_query = "SELECT * FROM utenti WHERE email = %s AND attivo = TRUE"
        user_data = DB.read_data(user_query, (email,))

        if user_data and len(user_data) > 0:
            user = user_data[0]

            # DEBUG
            print(f"DEBUG: User found: {user['id']}")

            # Verifica password hash
            if check_password_hash(user['password'], password):
                # Crea sessione
                session_token = generate_secure_token()
                session_expiry = datetime.now() + timedelta(days=14 if remember else 1)

                create_session_query = """
                    INSERT INTO sessioni (idUtente, token, ipAddress, userAgent, dataScadenza) 
                    VALUES (%s, %s, %s, %s, %s)
                """
                if not DB.execute(create_session_query, (
                        user['id'],
                        session_token,
                        request.remote_addr,
                        request.user_agent.string,
                        session_expiry
                )):
                    flash('Error creating session', 'error')
                    return render_template('login.html')

                # Imposta variabili di sessione
                session['user_id'] = user['id']
                session['token'] = session_token
                session['user_email'] = user['email']
                session['user_role'] = user['ruolo']

                # DEBUG
                print(f"DEBUG: Session created for user: {user['id']}")
                print(f"DEBUG: Token: {session_token}")

                # Aggiorna ultimo accesso
                update_access_query = "UPDATE utenti SET dataUltimoAccesso = NOW() WHERE id = %s"
                DB.execute(update_access_query, (user['id'],))

                # Log dell'accesso
                log_query = """
                    INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
                    VALUES (%s, 'login', 'User logged in', %s, %s, NOW())
                """
                DB.execute(log_query, (user['id'], request.remote_addr, request.user_agent.string))

                flash('Login successful! Welcome back.', 'success')

                # Controlla se deve essere reindirizzato alla selezione dell'abbonamento
                subscription_check_query = """
                    SELECT COUNT(*) as count 
                    FROM utenti_abbonamenti 
                    WHERE idUtente = %s AND stato = 'attivo'
                """
                subscription_check = DB.read_data(subscription_check_query, (user['id'],))

                # DEBUG
                print(f"DEBUG: Subscription check result: {subscription_check}")

                if not subscription_check or subscription_check[0]['count'] == 0:
                    # DEBUG
                    print(f"DEBUG: No active subscription, redirecting to select_plan")
                    return redirect(url_for('abbonamenti.select_plan'))
                else:
                    # DEBUG
                    print(f"DEBUG: User has active subscription, redirecting to dashboard")
                    return redirect(url_for('user.dashboard'))
            else:
                flash('Invalid email or password. Please try again.', 'error')
        else:
            flash('User not found or account not active.', 'error')

    return render_template('login.html')


@base_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Registrazione nuovo utente"""
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        cognome = request.form.get('cognome', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        terms = request.form.get('terms') is not None

        # DEBUG
        print(f"DEBUG: Registration attempt for email: {email}")

        # Validazione completa
        if not all([nome, cognome, email, password, terms]):
            flash('All fields are required!', 'error')
            return render_template('register.html')

        if not validate_email(email):
            flash('Invalid email format!', 'error')
            return render_template('register.html')

        # Validazione password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('register.html')

        # Verifica se email esiste già
        check_email_query = "SELECT COUNT(*) as count FROM utenti WHERE email = %s"
        result = DB.read_data(check_email_query, (email,))

        if result and result[0]['count'] > 0:
            flash('Email already exists!', 'error')
            return render_template('register.html')

        # Genera hash della password
        password_hash = generate_password_hash(password)

        # Inserisci nuovo utente
        insert_user_query = """
            INSERT INTO utenti (email, password, nome, cognome, dataIscrizione, attivo, ruolo) 
            VALUES (%s, %s, %s, %s, NOW(), TRUE, 'utente')
        """

        if DB.execute(insert_user_query, (email, password_hash, nome, cognome)):
            # Prendi l'id del nuovo utente
            user_id_query = "SELECT id FROM utenti WHERE email = %s"
            user_result = DB.read_data(user_id_query, (email,))

            if user_result:
                user_id = user_result[0]['id']

                # DEBUG
                print(f"DEBUG: New user created with ID: {user_id}")

                # Log registrazione
                log_query = """
                    INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
                    VALUES (%s, 'registrazione', 'New user registered', %s, %s, NOW())
                """
                DB.execute(log_query, (user_id, request.remote_addr, request.user_agent.string))

                # Crea notifica di benvenuto
                welcome_notification_query = """
                    INSERT INTO notifiche (idUtente, titolo, messaggio, tipo, priorita) 
                    VALUES (%s, 'Benvenuto!', 'Grazie per esserti registrato su ServerFuturo', 'info', 1)
                """
                DB.execute(welcome_notification_query, (user_id,))

                flash('Registration successful! Please select a subscription plan.', 'success')

                # Crea una sessione automaticamente per il nuovo utente
                session_token = generate_secure_token()
                session_expiry = datetime.now() + timedelta(days=14)

                create_session_query = """
                    INSERT INTO sessioni (idUtente, token, ipAddress, userAgent, dataScadenza) 
                    VALUES (%s, %s, %s, %s, %s)
                """
                if not DB.execute(create_session_query, (
                        user_id,
                        session_token,
                        request.remote_addr,
                        request.user_agent.string,
                        session_expiry
                )):
                    flash('Error creating session', 'error')
                    return redirect(url_for('base.login'))

                # Imposta variabili di sessione
                session['user_id'] = user_id
                session['token'] = session_token
                session['user_email'] = email
                session['user_role'] = 'utente'

                # DEBUG
                print(f"DEBUG: Session created for new user: {user_id}")
                print(f"DEBUG: Token: {session_token}")

                return redirect(url_for('abbonamenti.select_plan'))
            else:
                flash('Error occurred during registration.', 'error')
        else:
            flash('Error occurred during registration.', 'error')

    return render_template('register.html')


@base_bp.route('/logout')
def logout():
    """Logout dell'utente"""
    if 'user_id' in session and 'token' in session:
        # Disattiva sessione nel database
        deactivate_session_query = "UPDATE sessioni SET attiva = FALSE WHERE token = %s"
        DB.execute(deactivate_session_query, (session['token'],))

        # Log logout
        log_query = """
            INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento) 
            VALUES (%s, 'logout', 'User logged out', %s, %s, NOW())
        """
        DB.execute(log_query, (session['user_id'], request.remote_addr, request.user_agent.string))

    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('base.index'))


@base_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Reset password request"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not validate_email(email):
            flash('Invalid email format.', 'error')
            return render_template('forgot_password.html')

        # Verifica se l'utente esiste
        user_query = "SELECT id FROM utenti WHERE email = %s AND attivo = TRUE"
        user_data = DB.read_data(user_query, (email,))

        if user_data:
            # In produzione, genereresti un token e invieresti un'email
            # Per ora, simuliamo il processo
            reset_token = generate_secure_token()

            # Salva il token nel database (dovresti avere una tabella per questo)
            # Qui per semplicità lo loggiamo
            log_query = """
                INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, dataEvento)
                VALUES (%s, 'password_reset_request', %s, %s, NOW())
            """
            DB.execute(log_query, (user_data[0]['id'], f'Reset token: {reset_token}', request.remote_addr))

            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            # Per sicurezza, mostriamo lo stesso messaggio anche se l'utente non esiste
            flash('Password reset instructions have been sent to your email.', 'success')

        return redirect(url_for('base.login'))

    return render_template('forgot_password.html')


@base_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    # In produzione, verificheresti che il token sia valido
    if request.method == 'POST':
        new_password = request.form.get('password', '')

        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('reset_password.html', token=token)

        # Genera hash della nuova password
        password_hash = generate_password_hash(new_password)

        # Aggiorna la password (trova l'utente dal token)
        # Questo è un esempio semplificato
        update_query = "UPDATE utenti SET password = %s WHERE email = 'test@example.com'"
        if DB.execute(update_query, (password_hash,)):
            flash('Password updated successfully! Please login.', 'success')
            return redirect(url_for('base.login'))
        else:
            flash('Error updating password.', 'error')

    return render_template('reset_password.html', token=token)


@base_bp.route('/terms')
def terms():
    """Termini e condizioni"""
    return render_template('legal/terms.html')


@base_bp.route('/privacy')
def privacy():
    """Privacy policy"""
    return render_template('legal/privacy.html')


@base_bp.route('/contact')
def contact():
    """Pagina di contatto"""
    return render_template('contact.html')


# API endpoint per stats dashboard (chiamato via JavaScript)
@base_bp.route('/stats')
def stats():
    """API per statistiche in tempo reale"""
    # Conta dispositivi attivi
    active_devices_query = """
        SELECT COUNT(*) as count FROM dispositivi 
        WHERE attivo = TRUE AND 
        ultimoAccesso > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    """
    active_devices_result = DB.read_data(active_devices_query)
    active_devices = active_devices_result[0]['count'] if active_devices_result else 0

    # Conta minacce bloccate (esempio)
    threats_query = """
        SELECT COUNT(*) as count FROM log 
        WHERE tipoEvento = 'security_event' AND
        dataEvento > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    """
    threats_result = DB.read_data(threats_query)
    threats_blocked = threats_result[0]['count'] if threats_result else 0

    return jsonify({
        'active_devices': active_devices,
        'threats_blocked': threats_blocked
    })


@base_bp.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test connessione database
        test_query = "SELECT 1"
        DB.read_data(test_query)

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@base_bp.errorhandler(404)
def page_not_found(e):
    """Gestione errore 404"""
    return render_template('errors/404.html'), 404


@base_bp.errorhandler(500)
def internal_server_error(e):
    """Gestione errore 500"""
    return render_template('errors/500.html'), 500


@base_bp.route('/robots.txt')
def robots_txt():
    """Robots.txt dinamico"""
    lines = [
        'User-agent: *',
        'Disallow: /user/',
        'Disallow: /subscription/',
        'Disallow: /admin/',
        'Allow: /',
        'Sitemap: https://projectfuturo.com/sitemap.xml'
    ]
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain; charset=utf-8'}