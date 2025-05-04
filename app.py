import socket
from flask import Flask, session, send_from_directory
from sqlalchemy import MetaData
from blueprints.base import base_bp
from config import Config
app = Flask(__name__)
app.secret_key = 'chiave_super_segreta'
app.config.from_object(Config)

# Registriamo i Blueprint
app.register_blueprint(base_bp)
if __name__ == '__main__':
    if socket.gethostname()=='PC-SPEZIALE':

        app.run(host='0.0.0.0', port=80, debug=True)
    else:
        app.run(host='0.0.0.0', port=80)