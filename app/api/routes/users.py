from flask import Blueprint, request, jsonify
from app.db.config import SessionLocal
from app.db.models import User
from app.auth.services.midelwares import require_active_user, require_auth
from cryptography.fernet import Fernet
import os

users_bp = Blueprint('users', __name__, url_prefix='/users')

# Instanciar Fernet una vez
FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY.encode()) if FERNET_KEY else None

@users_bp.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    db = SessionLocal()
    user_id = request.user.get('user_id')
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado."}), 404

        # Descifrar nombres
        decrypted_first_name = fernet.decrypt(user.first_name).decode() if user.first_name else ""
        decrypted_last_name = fernet.decrypt(user.last_name).decode() if user.last_name else ""

        return jsonify({
            "email": user.email,
            "first_name": decrypted_first_name,
            "last_name": decrypted_last_name,
            "role": user.role,
            "is_active": user.is_active,
            "can_upload": user.can_upload
        }), 200
    finally:
        db.close()

@users_bp.route('/profile', methods=['PUT'])
@require_auth
@require_active_user
def update_profile():
    db = SessionLocal()
    user_id = request.user.get('user_id')
    data = request.get_json() or {}

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")

    if not first_name and not last_name and not email:
        return jsonify({"error": "Debe proporcionar al menos un dato para actualizar."}), 400

    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado."}), 404

        if email:
            existing_user = db.query(User).filter(User.email == email, User.id != user_id).first()
            if existing_user:
                return jsonify({"error": "El email ya está en uso por otro usuario."}), 400
            user.email = email

        if first_name:
            user.first_name = fernet.encrypt(first_name.encode())
        if last_name:
            user.last_name = fernet.encrypt(last_name.encode())

        db.commit()
        return jsonify({"message": "Perfil actualizado correctamente."}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()
