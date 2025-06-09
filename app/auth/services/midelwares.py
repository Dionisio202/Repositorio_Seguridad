from flask import request, jsonify
from functools import wraps
from app.auth.utils.jwt_utils import hash_token, verify_jwt
from app.db.config import SessionLocal
from app.db.models import ActiveSession, File, FilePermission, User

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

        # ✅ Verificar que la sesión esté activa en la base de datos
        token_hashed = hash_token(token)
        db = SessionLocal()
        try:
            session_record = db.query(ActiveSession).filter(
                ActiveSession.token_hash == token_hashed,
                ActiveSession.is_active == True
            ).first()
            if not session_record:
                return jsonify({"error": "Sesión no activa. Por favor inicia sesión nuevamente."}), 401
        finally:
            db.close()

        request.user = payload  # Agregar el payload a la solicitud si todo está OK
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
                return jsonify({"error": "No tienes permisos para subir archivos."}), 501
        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated


def require_file_permission(permission_required):
    def decorator(f):
        @wraps(f)
        def decorated(db, file_id, *args, **kwargs):
            payload = getattr(request, 'user', None)
            if not payload:
                return jsonify({"error": "Autenticación requerida."}), 401

            user_id = payload.get("user_id")
            user_role = payload.get("role")

            file = db.query(File).filter(File.id == file_id).first()
            if not file:
                return jsonify({"error": "Archivo no encontrado."}), 404

            # ✅ Si es admin, permitir acceso total
            if user_role == "admin":
                return f(db, file_id, *args, **kwargs)

            # ✅ Si el usuario es propietario, permitir acceso total
            if file.user_id == user_id:
                return f(db, file_id, *args, **kwargs)

            # ✅ Verificar permisos concedidos
            permission = db.query(FilePermission).filter(
                FilePermission.file_id == file_id,
                FilePermission.granted_user_id == user_id
            ).first()

            if not permission:
                return jsonify({"error": "No tienes permisos para acceder a este archivo."}), 403

            # ✅ Validar tipo de permiso
            if permission_required == "view" and permission.permission_type not in ["view", "both"]:
                return jsonify({"error": "Permiso de visualización requerido."}), 403

            if permission_required == "download" and permission.permission_type not in ["download", "both"]:
                return jsonify({"error": "Permiso de descarga requerido."}), 403

            # ✅ Si todo OK, llamar a la función original
            return f(db, file_id, *args, **kwargs)

        return decorated
    return decorator


from functools import wraps
from app.db.config import SessionLocal

def with_db_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        db = SessionLocal()
        try:
            # Inyectamos db como argumento a la función decorada
            return f(db, *args, **kwargs)
        finally:
            db.close()
    return decorated
