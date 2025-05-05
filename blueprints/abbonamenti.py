from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from db import DB
from datetime import datetime, timedelta
import stripe
import os
from config import Config

abbonamenti_bp = Blueprint('abbonamenti', __name__, url_prefix='/subscription')

# Configura Stripe
stripe.api_key = Config.STRIPE_SECRET_KEY


# Decoratore per verificare il login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('base.login'))

        # Se l'utente è loggato, controlla la sessione nel database
        if session.get('token'):
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


@abbonamenti_bp.route('/select')
@login_required
def select_plan():
    """Mostra la pagina di selezione del piano"""
    return render_template('subscription-plans.html', stripe_public_key=Config.STRIPE_PUBLIC_KEY)


@abbonamenti_bp.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Crea una sessione Stripe Checkout"""
    try:
        data = request.get_json()
        plan_name = data.get('plan')
        plan_id = data.get('plan_id')

        # Recupera i dettagli del piano dal database
        plan_query = "SELECT * FROM abbonamenti WHERE id = %s"
        plan_data = DB.read_data(plan_query, (plan_id,))

        if not plan_data:
            return jsonify({'error': 'Piano non trovato'}), 404

        plan = plan_data[0]

        # Crea la sessione Stripe Checkout
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': f'Piano {plan["nome"]}',
                        'description': plan['descrizione'],
                    },
                    'unit_amount': int(plan['prezzo'] * 100),  # Stripe vuole l'importo in centesimi
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('abbonamenti.payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('abbonamenti.payment_cancel', _external=True),
            metadata={
                'user_id': session.get('user_id'),
                'plan_id': plan_id,
                'plan_name': plan_name
            }
        )

        return jsonify({'sessionId': checkout_session.id})

    except Exception as e:
        print(f"Error creating checkout session: {e}")
        return jsonify({'error': str(e)}), 500


@abbonamenti_bp.route('/success')
@login_required
def payment_success():
    """Gestisce il successo del pagamento"""
    session_id = request.args.get('session_id')

    if not session_id:
        flash('Errore: Session ID mancante', 'error')
        return redirect(url_for('user.dashboard'))

    try:
        # Recupera i dettagli della sessione Stripe
        checkout_session = stripe.checkout.Session.retrieve(session_id)

        if checkout_session.payment_status == 'paid':
            user_id = checkout_session.metadata.get('user_id')
            plan_id = checkout_session.metadata.get('plan_id')

            # Crea l'abbonamento nel database
            data_inizio = datetime.now()
            data_fine = data_inizio + timedelta(days=30)  # Abbonamento mensile

            create_subscription_query = """
                INSERT INTO utenti_abbonamenti 
                (idUtente, idAbbonamento, dataInizio, dataFine, stato, autoRinnovo)
                VALUES (%s, %s, %s, %s, 'attivo', TRUE)
            """

            if DB.execute(create_subscription_query, (user_id, plan_id, data_inizio, data_fine)):
                # Registra il pagamento
                create_payment_query = """
                    INSERT INTO pagamenti 
                    (idUtente, idAbbonamento, importo, metodoPagamento, stato, transazioneId, dataTransazione, dataCompletamento)
                    VALUES (%s, %s, %s, 'carta_credito', 'completato', %s, %s, %s)
                """

                DB.execute(create_payment_query, (
                    user_id,
                    plan_id,
                    checkout_session.amount_total / 100,  # Convertire da centesimi a euro
                    session_id,
                    datetime.now(),
                    datetime.now()
                ))

                # Crea una notifica per l'utente
                create_notification_query = """
                    INSERT INTO notifiche 
                    (idUtente, titolo, messaggio, tipo, priorita)
                    VALUES (%s, 'Abbonamento Attivato', %s, 'successo', 1)
                """

                plan_query = "SELECT nome FROM abbonamenti WHERE id = %s"
                plan_data = DB.read_data(plan_query, (plan_id,))
                plan_name = plan_data[0]['nome'] if plan_data else 'Unknown'
                message = f'Il tuo abbonamento {plan_name} è stato attivato con successo!'

                DB.execute(create_notification_query, (user_id, message))

                flash('Abbonamento attivato con successo! Benvenuto.', 'success')
                return redirect(url_for('user.dashboard'))
            else:
                flash('Errore durante l\'attivazione dell\'abbonamento', 'error')
                return redirect(url_for('abbonamenti.select_plan'))
        else:
            flash('Il pagamento non è stato completato', 'error')
            return redirect(url_for('abbonamenti.select_plan'))

    except Exception as e:
        print(f"Error processing payment success: {e}")
        flash('Errore durante la verifica del pagamento', 'error')
        return redirect(url_for('abbonamenti.select_plan'))


@abbonamenti_bp.route('/cancel')
@login_required
def payment_cancel():
    """Gestisce l'annullamento del pagamento"""
    flash('Pagamento annullato. Puoi scegliere un piano in qualsiasi momento.', 'info')
    return redirect(url_for('abbonamenti.select_plan'))


@abbonamenti_bp.route('/manage')
@login_required
def manage_subscription():
    """Pagina di gestione dell'abbonamento attivo"""
    user_id = session.get('user_id')

    # Recupera l'abbonamento attivo dell'utente
    subscription_query = """
        SELECT ua.*, a.nome as piano, a.prezzo, a.caratteristiche, a.maxDispositivi
        FROM utenti_abbonamenti ua
        JOIN abbonamenti a ON ua.idAbbonamento = a.id
        WHERE ua.idUtente = %s AND ua.stato = 'attivo'
        ORDER BY ua.dataInizio DESC
        LIMIT 1
    """

    subscription_data = DB.read_data(subscription_query, (user_id,))

    if not subscription_data:
        flash('Non hai un abbonamento attivo', 'info')
        return redirect(url_for('abbonamenti.select_plan'))

    subscription = subscription_data[0]

    # Recupera i dispositivi dell'utente
    devices_query = """
        SELECT COUNT(*) as count FROM dispositivi 
        WHERE idUtente = %s AND attivo = TRUE
    """
    devices_data = DB.read_data(devices_query, (user_id,))
    device_count = devices_data[0]['count'] if devices_data else 0

    return render_template('subscription/manage.html',
                           subscription=subscription,
                           device_count=device_count)


@abbonamenti_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    """Webhook per gestire gli eventi Stripe"""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.environ.get('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return 'Invalid signature', 400

    # Gestisci gli eventi Stripe
    if event['type'] == 'invoice.payment_succeeded':
        # Rinnova l'abbonamento
        invoice = event['data']['object']
        customer_id = invoice['customer']

        # Trova l'utente basato sul customer ID di Stripe
        user_query = """
            SELECT u.id, ua.id as subscription_id 
            FROM utenti u
            JOIN pagamenti p ON u.id = p.idUtente
            WHERE p.transazioneId = %s
            LIMIT 1
        """
        # In un'implementazione reale, dovresti memorizzare il customer_id di Stripe
        # Qui è solo un esempio semplificato

    elif event['type'] == 'customer.subscription.deleted':
        # Gestisci la cancellazione dell'abbonamento
        subscription = event['data']['object']
        # Aggiorna lo stato dell'abbonamento nel database

    return '', 200


@abbonamenti_bp.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    """Cancella l'abbonamento corrente"""
    user_id = session.get('user_id')

    # Trova l'abbonamento attivo
    subscription_query = """
        SELECT id FROM utenti_abbonamenti 
        WHERE idUtente = %s AND stato = 'attivo'
        ORDER BY dataInizio DESC
        LIMIT 1
    """

    subscription_data = DB.read_data(subscription_query, (user_id,))

    if not subscription_data:
        flash('Non hai un abbonamento attivo da cancellare', 'error')
        return redirect(url_for('user.dashboard'))

    subscription_id = subscription_data[0]['id']

    # Cancella l'abbonamento
    cancel_query = """
        UPDATE utenti_abbonamenti 
        SET stato = 'cancellato', autoRinnovo = FALSE 
        WHERE id = %s
    """

    if DB.execute(cancel_query, (subscription_id,)):
        flash('Abbonamento cancellato con successo', 'success')
    else:
        flash('Errore durante la cancellazione dell\'abbonamento', 'error')

    return redirect(url_for('abbonamenti.manage_subscription'))


@abbonamenti_bp.route('/upgrade', methods=['POST'])
@login_required
def upgrade_subscription():
    """Aggiorna l'abbonamento a un piano superiore"""
    user_id = session.get('user_id')
    new_plan_id = request.form.get('new_plan_id')

    if not new_plan_id:
        flash('Piano non valido', 'error')
        return redirect(url_for('abbonamenti.manage_subscription'))

    try:
        # Cancella l'abbonamento attuale
        cancel_query = """
            UPDATE utenti_abbonamenti 
            SET stato = 'cancellato', autoRinnovo = FALSE 
            WHERE idUtente = %s AND stato = 'attivo'
        """
        DB.execute(cancel_query, (user_id,))

        # Crea un nuovo abbonamento
        data_inizio = datetime.now()
        data_fine = data_inizio + timedelta(days=30)

        create_subscription_query = """
            INSERT INTO utenti_abbonamenti 
            (idUtente, idAbbonamento, dataInizio, dataFine, stato, autoRinnovo)
            VALUES (%s, %s, %s, %s, 'attivo', TRUE)
        """

        if DB.execute(create_subscription_query, (user_id, new_plan_id, data_inizio, data_fine)):
            flash('Abbonamento aggiornato con successo!', 'success')
        else:
            flash('Errore durante l\'aggiornamento dell\'abbonamento', 'error')

    except Exception as e:
        print(f"Error upgrading subscription: {e}")
        flash('Errore durante l\'aggiornamento dell\'abbonamento', 'error')

    return redirect(url_for('abbonamenti.manage_subscription'))