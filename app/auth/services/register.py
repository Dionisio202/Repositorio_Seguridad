import datetime
import os
import re
import html
import logging

from flask import Blueprint, request, jsonify
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

from app.db.config import SessionLocal
from app.db.models import User

# Configurar logging
logging.basicConfig(level=logging.INFO, filename='app.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Crear Blueprint para registro
register_bp = Blueprint('register', __name__)

@register_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json() or {}

    required_fields = ['email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"El campo {field} es obligatorio."}), 400

    email = html.escape(data.get('email', '').strip())
    password = data.get('password', '').strip()
    first_name = html.escape(data.get('first_name', '').strip())
    last_name = html.escape(data.get('last_name', '').strip())

    if len(email) > 100 or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Formato de email inválido o demasiado largo."}), 400

    if len(first_name) > 50 or len(last_name) > 50:
        return jsonify({"error": "Nombre o apellido demasiado largo (máx 50 caracteres)."}), 400

    if (len(password) < 8 or not re.search(r"[A-Za-z]", password) 
            or not re.search(r"\d", password) 
            or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres, incluir una letra, un número y un símbolo especial."}), 400

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return jsonify({"error": "Ya existe un usuario con este email."}), 400

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        secret = os.getenv("SIGNATURE_SECRET_KEY")
        fernet_secret = os.getenv("FERNET_KEY")  # 👈 para nombre y apellido
        if not secret or not fernet_secret:
            logging.error("Faltan claves de entorno SIGNATURE_SECRET_KEY o FERNET_KEY")
            return jsonify({"error": "Error interno de configuración."}), 500

        fernet = Fernet(secret.encode())
        encrypted_private_key = fernet.encrypt(private_key_bytes)

        name_fernet = Fernet(fernet_secret.encode())
        encrypted_first_name = name_fernet.encrypt(first_name.encode())
        encrypted_last_name = name_fernet.encrypt(last_name.encode())

        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password_hash=hashed_password,
            first_name=encrypted_first_name,
            last_name=encrypted_last_name,
            role="user",
            is_active=False,
            can_upload=False,
            public_key=public_key_bytes,
            encrypted_private_key=encrypted_private_key,
            created_at=datetime.datetime.utcnow()
        )

        db.add(new_user)
        db.commit()

        return jsonify({
            "message": "Usuario registrado exitosamente",
            "user_id": new_user.id
        }), 201

    except Exception as e:
        db.rollback()
        logging.exception("Error en el registro de usuario: %s", e)
        return jsonify({"error": "Error interno. Contacte al administrador."}), 500
    finally:
        db.close()

