from flask import Blueprint, redirect, request, jsonify
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta

from app.db.config import SessionLocal
from app.db.models import User, LoginAttempt
from app.auth.utils.email_utils import send_otp_email
from app.auth.utils.jwt_utils import generate_jwt, verify_jwt

oauth_bp = Blueprint('oauth', __name__)

MAX_ATTEMPTS = 5
BLOCK_TIME_MINUTES = 15

def is_user_blocked(db: Session, email: str):
    now = datetime.now()
    time_limit = now - timedelta(minutes=BLOCK_TIME_MINUTES)
    recent_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.email == email,
        LoginAttempt.attempt_time >= time_limit
    ).count()
    return recent_attempts >= MAX_ATTEMPTS

@oauth_bp.route('/request-2fa', methods=['POST'])
def request_2fa():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")  

    if not email or not password:
        return jsonify({"detail": "El email y la contraseña son obligatorios."}), 400

    db = SessionLocal()
    try:
        if is_user_blocked(db, email):
            return jsonify({"detail": "Demasiados intentos fallidos. Intenta de nuevo en 15 minutos."}), 429

        user = db.query(User).filter(User.email == email).first()
        if not user:
            db.add(LoginAttempt(email=email))
            db.commit()
            return jsonify({"detail": "Usuario no encontrado."}), 404

        if not user.is_active:
            return jsonify({"detail": "Tu cuenta está inactiva. Contacta al administrador."}), 403

        if not check_password_hash(user.password_hash, password):
            db.add(LoginAttempt(email=email))
            db.commit()
            return jsonify({"detail": "Contraseña incorrecta."}), 401

        # ✅ Limpiar intentos fallidos exitosos
        db.query(LoginAttempt).filter(LoginAttempt.email == email).delete()
        db.commit()

        token_payload = {
            "user_id": user.id,
            "email": user.email,
            "purpose": "2fa_verification"
        }
        verification_token = generate_jwt(token_payload, expires_in_minutes=3)
        verification_link = f"http://localhost:5000/auth/two-factor/verify-link?token={verification_token}"

        send_otp_email(to_email=user.email, link=verification_link)

        return jsonify({"message": "Se envió el enlace de verificación a tu correo."}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()

@oauth_bp.route('/verify-link', methods=['GET'])
def verify_link():
    token = request.args.get('token')
    if not token:
        return jsonify({"detail": "Token de verificación faltante."}), 400

    payload = verify_jwt(token)
    if not payload or payload.get("purpose") != "2fa_verification":
        return jsonify({"detail": "Token inválido o expirado."}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        if not user:
            return jsonify({"detail": "Usuario no encontrado."}), 404

        # ✅ Seguridad adicional: Verificar que siga activo
        if not user.is_active:
            return jsonify({"detail": "Cuenta inactiva. Contacta al administrador."}), 403

        user.otp_code = None
        user.otp_expires = None
        db.commit()

        # ✅ Generar token de sesión definitivo
        session_token = generate_jwt({
            "user_id": user.id,
            "email": user.email,
            "role": user.role
        })

        # ✅ Mejor práctica: Redirigir al frontend sin exponer token en URL (se maneja en frontend)
        return redirect(f"http://tu-frontend.com/verify-success?session_token={session_token}")

    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()
