# app/main.py
from flask import Flask
from app.auth.routes import auth_bp,register_bp
from app.api.routes.files import files_bp
from app.api.routes.users import users_bp 
from app.api.routes.audit import audit_bp
from flask_cors import CORS

# Importa otros blueprints (por ejemplo, de users, files, etc.) según tu estructura

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Registrar el blueprint de autenticación con el prefijo '/auth'
app.register_blueprint(auth_bp)
app.register_blueprint(register_bp)
app.register_blueprint(files_bp)
app.register_blueprint(audit_bp, url_prefix='/audit')
app.register_blueprint(users_bp, url_prefix='/users')
if __name__ == "__main__":
    app.run(debug=True)
