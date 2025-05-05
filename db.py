import mysql.connector
from mysql.connector import Error
from typing import Optional, Dict, Any, List
from functools import wraps
from datetime import datetime


class DB:
    # Database configuration - you can modify these default values
    HOST = "localhost"
    USER = "claudio"
    PASSWORD = "Superrapa22"
    DATABASE = "serverfuturo"
    PORT = 3306

    @staticmethod
    def config(host: str = None, user: str = None, password: str = None, database: str = None, port: int = None):
        """
        Configure database connection parameters
        """
        if host:
            DB.HOST = host
        if user:
            DB.USER = user
        if password:
            DB.PASSWORD = password
        if database:
            DB.DATABASE = database
        if port:
            DB.PORT = port

    @staticmethod
    def _execute_with_connection(func):
        """
        Decorator to handle connection and disconnection automatically
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            connection = None
            cursor = None
            try:
                # Connect
                connection = mysql.connector.connect(
                    host=DB.HOST,
                    user=DB.USER,
                    password=DB.PASSWORD,
                    database=DB.DATABASE,
                    port=DB.PORT
                )

                if not connection.is_connected():
                    raise Error("Failed to connect to database")

                cursor = connection.cursor()

                # Execute the method
                result = func(connection, cursor, *args, **kwargs)

                return result

            except Error as e:
                print(f"Database error: {e}")
                return None if func.__name__ == 'read_data' else False

            finally:
                # Always close connection
                if cursor:
                    cursor.close()
                if connection and connection.is_connected():
                    connection.close()

        return wrapper

    @staticmethod
    @_execute_with_connection
    def execute(connection, cursor, query: str, params: Optional[tuple] = None, commit: bool = True) -> bool:
        """
        Execute a query (INSERT, UPDATE, DELETE)
        Connection is handled automatically

        Args:
            query: SQL query string
            params: Query parameters for prepared statements
            commit: Whether to commit the transaction (default True)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if commit:
                connection.commit()

            print(f"Query executed successfully: {cursor.rowcount} rows affected")
            return True

        except Error as e:
            print(f"Error executing query: {e}")
            connection.rollback()
            return False

    @staticmethod
    @_execute_with_connection
    def read_data(connection, cursor, query: str, params: Optional[tuple] = None) -> Optional[List[Dict[str, Any]]]:
        """
        Execute a SELECT query and return results
        Connection is handled automatically

        Args:
            query: SQL query string
            params: Query parameters for prepared statements

        Returns:
            List of dictionaries containing query results, or None if error
        """
        try:
            cursor.close()  # Close standard cursor
            dict_cursor = connection.cursor(dictionary=True)

            if params:
                dict_cursor.execute(query, params)
            else:
                dict_cursor.execute(query)

            results = dict_cursor.fetchall()
            dict_cursor.close()

            return results

        except Error as e:
            print(f"Error reading data: {e}")
            return None

    # Helper methods for common operations

    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict]:
        """Get user by email"""
        query = "SELECT * FROM utenti WHERE email = %s"
        result = DB.read_data(query, (email,))
        return result[0] if result else None

    @staticmethod
    def get_user_devices(user_id: int) -> Optional[List[Dict]]:
        """Get all devices for a user"""
        query = """
        SELECT d.*, 
               (SELECT COUNT(*) FROM rilevazioni WHERE seriale = d.seriale) as total_rilevazioni
        FROM dispositivi d
        WHERE d.idUtente = %s
        ORDER BY d.ultimoAccesso DESC
        """
        return DB.read_data(query, (user_id,))

    @staticmethod
    def get_active_subscription(user_id: int) -> Optional[Dict]:
        """Get user's active subscription"""
        query = """
        SELECT ua.*, a.nome, a.maxDispositivi, a.caratteristiche
        FROM utenti_abbonamenti ua
        JOIN abbonamenti a ON ua.idAbbonamento = a.id
        WHERE ua.idUtente = %s AND ua.stato = 'attivo'
        ORDER BY ua.dataFine DESC
        LIMIT 1
        """
        result = DB.read_data(query, (user_id,))
        return result[0] if result else None

    @staticmethod
    def log_event(user_id: int, event_type: str, description: str, ip_address: str = None, user_agent: str = None):
        """Log an event"""
        query = """
        INSERT INTO log (idUtente, tipoEvento, descrizione, ipAddress, userAgent, dataEvento)
        VALUES (%s, %s, %s, %s, %s, NOW())
        """
        return DB.execute(query, (user_id, event_type, description, ip_address, user_agent))

    @staticmethod
    def create_notification(user_id: int, title: str, message: str, tipo: str = 'info', priority: int = 0):
        """Create a notification for a user"""
        query = """
        INSERT INTO notifiche (idUtente, titolo, messaggio, tipo, priorita)
        VALUES (%s, %s, %s, %s, %s)
        """
        return DB.execute(query, (user_id, title, message, tipo, priority))

    @staticmethod
    def update_device_status(serial: str, access_time: datetime = None):
        """Update device last access time"""
        if access_time is None:
            access_time = datetime.now()

        query = "UPDATE dispositivi SET ultimoAccesso = %s WHERE seriale = %s"
        return DB.execute(query, (access_time, serial))

    @staticmethod
    def get_device_stats(serial: str, days: int = 7) -> Optional[Dict]:
        """Get device statistics for the last N days"""
        query = """
        SELECT 
            COUNT(*) as total_rilevazioni,
            AVG(download) as avg_download,
            AVG(upload) as avg_upload,
            AVG(latenza) as avg_latenza,
            MAX(dataUpdate) as ultima_rilevazione
        FROM rilevazioni
        WHERE seriale = %s AND dataUpdate >= DATE_SUB(NOW(), INTERVAL %s DAY)
        """
        result = DB.read_data(query, (serial, days))
        return result[0] if result else None

    @staticmethod
    def update_user_last_access(user_id: int):
        """Update user's last access time"""
        query = "UPDATE utenti SET dataUltimoAccesso = NOW() WHERE id = %s"
        return DB.execute(query, (user_id,))

    @staticmethod
    def get_user_notification_count(user_id: int) -> int:
        """Get count of unread notifications for a user"""
        query = "SELECT COUNT(*) as count FROM notifiche WHERE idUtente = %s AND stato = 'non_letta'"
        result = DB.read_data(query, (user_id,))
        return result[0]['count'] if result else 0

    @staticmethod
    def check_device_limit(user_id: int) -> Dict:
        """Check if user has reached device limit"""
        query = """
        SELECT 
            COUNT(d.id) as current_devices,
            a.maxDispositivi as device_limit,
            a.nome as plan_name
        FROM utenti u
        LEFT JOIN dispositivi d ON u.id = d.idUtente
        LEFT JOIN utenti_abbonamenti ua ON u.id = ua.idUtente AND ua.stato = 'attivo'
        LEFT JOIN abbonamenti a ON ua.idAbbonamento = a.id
        WHERE u.id = %s
        GROUP BY u.id
        """
        result = DB.read_data(query, (user_id,))
        return result[0] if result else None

    @staticmethod
    def add_device_detection(serial: str, data: Dict) -> bool:
        """Add a new device detection record"""
        query = """
        INSERT INTO rilevazioni 
        (seriale, download, upload, latenza, dispositiviConnessi, vulnerabilita, ipPub, ipPriv)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        params = (
            serial,
            data.get('download', 0),
            data.get('upload', 0),
            data.get('latenza', 0),
            data.get('dispositiviConnessi', 0),
            data.get('vulnerabilita', 'Nessuna'),
            data.get('ipPub', ''),
            data.get('ipPriv', '')
        )

        return DB.execute(query, params)