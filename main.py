# app/main.py
from flask import Flask
from app.auth.routes import auth_bp,register_bp
from app.api.routes.files import files_bp
# Importa otros blueprints (por ejemplo, de users, files, etc.) según tu estructura

app = Flask(__name__)

# Registrar el blueprint de autenticación con el prefijo '/auth'
app.register_blueprint(auth_bp)
app.register_blueprint(register_bp)
app.register_blueprint(files_bp)
if __name__ == "__main__":
    app.run(debug=True)
