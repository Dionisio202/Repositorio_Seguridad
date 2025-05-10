from flask import request, jsonify
from functools import wraps
from app.auth.utils.jwt_utils import verify_jwt
from app.db.config import SessionLocal
from app.db.models import User

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Token de autorización requerido."}), 401

        token = auth_header.split(" ")[1] if " " in auth_header else auth_header
        payload = verify_jwt(token)
        if not payload:
            return jsonify({"error": "Token inválido o expirado."}), 401

        request.user = payload  # Solo valida autenticación, no estado del usuario
        return f(*args, **kwargs)
    return decorated

def require_active_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = getattr(request, 'user', None)
        if not payload:
            return jsonify({"error": "Autenticación requerida."}), 401

        user_id = payload.get("user_id")
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.is_active:
                return jsonify({"error": "Cuenta inactiva. Contacta al administrador."}), 403
        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = getattr(request, 'user', None)
        if not payload:
            return jsonify({"error": "Autenticación requerida."}), 401

        if payload.get("role") != "admin":
            return jsonify({"error": "Permisos de administrador requeridos."}), 403

        return f(*args, **kwargs)
    return decorated

def require_can_upload(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = getattr(request, 'user', None)
        if not payload:
            return jsonify({"error": "Autenticación requerida."}), 401

        user_id = payload.get("user_id")
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
            if not user:
                return jsonify({"error": "Usuario no encontrado o inactivo."}), 404
            if not user.can_upload:
                return jsonify({"error": "No tienes permisos para subir archivos."}), 403
        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated
