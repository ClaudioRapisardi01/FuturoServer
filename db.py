import mysql.connector
from mysql.connector import Error
from typing import Optional, Dict, Any, List
from functools import wraps


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


