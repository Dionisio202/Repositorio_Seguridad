from flask import Blueprint, request, jsonify
from sqlalchemy.orm import Session
import random
import string
import datetime
from werkzeug.security import check_password_hash

from app.db.config import SessionLocal
from app.db.models import User

from app.auth.utils.email_utils import send_otp_email

oauth_bp = Blueprint('oauth', __name__)

# Función para generar un OTP de 6 dígitos
def generate_otp(n=6):
    return ''.join(random.choices(string.digits, k=n))

# Usa 'oauth_bp' en los decoradores de rutas
@oauth_bp.route('/request-2fa', methods=['POST'])
def request_2fa():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")  
    
    # Validar que se proporcionen email y contraseña
    if not email:
        return jsonify({"detail": "El email es obligatorio."}), 400
    if not password:
        return jsonify({"detail": "La contraseña es obligatoria."}), 400
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return jsonify({"detail": "Usuario no encontrado"}), 404
        
        # Verificar la contraseña
        if not check_password_hash(user.password_hash, password):
            return jsonify({"detail": "Contraseña incorrecta"}), 401
        
        # Generar OTP y definir expiración
        code = generate_otp()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        
        user.otp_code = code
        user.otp_expires = expires_at
        db.commit()
        
        send_otp_email(to_email=user.email, code=code)
        return jsonify({"message": "Se envió el código de verificación a tu correo."}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()

@oauth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json() or {}
    email = data.get("email")
    code_in = data.get("code")
    if not email or not code_in:
        return jsonify({"detail": "El email y el código son obligatorios."}), 400
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return jsonify({"detail": "Usuario no encontrado"}), 404
        
        if not user.otp_code:
            return jsonify({"detail": "No hay un código pendiente de verificación"}), 400
        
        now = datetime.datetime.utcnow()
        if user.otp_expires < now:
            user.otp_code = None
            user.otp_expires = None
            db.commit()
            return jsonify({"detail": "El código ha expirado. Solicita uno nuevo."}), 400
        
        if user.otp_code == code_in:
            user.otp_code = None
            user.otp_expires = None
            db.commit()
            return jsonify({
    "message": "Código verificado correctamente. Autenticación completa.",
    "user": {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "is_active": user.is_active,
        "can_upload": user.can_upload,
    }
}), 200

        else:
            return jsonify({"detail": "Código inválido"}), 400
    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()