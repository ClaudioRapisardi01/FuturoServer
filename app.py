import socket
from flask import Flask, session, send_from_directory
from sqlalchemy import MetaData
from blueprints.base import base_bp
from blueprints.user import user_bp
from config import Config

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config.from_object(Config)

# Registriamo i Blueprint
app.register_blueprint(base_bp)
app.register_blueprint(user_bp)

# Route per servire file statici (CSS, JS, immagini)
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    if socket.gethostname() == 'PC-SPEZIALE':
        app.run(host='0.0.0.0', port=80, debug=True)
    else:
        app.run(host='0.0.0.0', port=80)