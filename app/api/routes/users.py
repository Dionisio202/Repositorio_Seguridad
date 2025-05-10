from flask import Blueprint, request, jsonify
from app.db.config import SessionLocal
from app.db.models import User
from app.auth.services.midelwares import require_active_user, require_auth

users_bp = Blueprint('users', __name__, url_prefix='/users')

@users_bp.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    db = SessionLocal()
    user_id = request.user.get('user_id')
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "Usuario no encontrado."}), 404

        return jsonify({
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
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
            # Verificar que no exista otro usuario con ese email
            existing_user = db.query(User).filter(User.email == email, User.id != user_id).first()
            if existing_user:
                return jsonify({"error": "El email ya está en uso por otro usuario."}), 400
            user.email = email

        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name

        db.commit()
        return jsonify({"message": "Perfil actualizado correctamente."}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()
