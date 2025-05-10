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

    # Validar campos requeridos
    required_fields = ['email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if field not in data:
            return jsonify({"detail": f"El campo {field} es obligatorio."}), 400

    # Extraer y sanitizar datos
    email = html.escape(data.get('email', '').strip())
    password = data.get('password', '').strip()
    first_name = html.escape(data.get('first_name', '').strip())
    last_name = html.escape(data.get('last_name', '').strip())

    # Validar formatos
    if len(email) > 100 or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"detail": "Formato de email inválido o demasiado largo."}), 400

    if len(first_name) > 50 or len(last_name) > 50:
        return jsonify({"detail": "Nombre o apellido demasiado largo (máx 50 caracteres)."}), 400

    # Validar contraseña (mínimo 8 caracteres, al menos una letra, un número y un símbolo)
    if (len(password) < 8 or not re.search(r"[A-Za-z]", password) 
            or not re.search(r"\d", password) 
            or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return jsonify({"detail": "La contraseña debe tener al menos 8 caracteres, incluir una letra, un número y un símbolo especial."}), 400

    db = SessionLocal()
    try:
        # Verificar si ya existe un usuario con el mismo email
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return jsonify({"detail": "Ya existe un usuario con este email."}), 400

        # Generar claves pública y privada
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

        # Cifrar la clave privada usando Fernet
        secret = os.getenv("SIGNATURE_SECRET_KEY")
        if not secret:
            logging.error("SIGNATURE_SECRET_KEY no configurada en .env")
            return jsonify({"detail": "Error interno de configuración."}), 500

        fernet = Fernet(secret.encode())
        encrypted_private_key = fernet.encrypt(private_key_bytes)

        # Crear el nuevo usuario
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password_hash=hashed_password,
            first_name=first_name,
            last_name=last_name,
            role="user",  # por defecto
            is_active=False,
            can_upload=False,  # el admin lo habilita después
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
        return jsonify({"detail": "Error interno. Contacte al administrador."}), 500
    finally:
        db.close()
