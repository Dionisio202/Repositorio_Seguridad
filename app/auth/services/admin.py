from flask import Blueprint, request, jsonify
from app.db.config import SessionLocal
from app.db.models import User

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/update-user', methods=['PUT'])
def update_user_role_or_status():
    data = request.get_json() or {}
    email = data.get("email")
    new_role = data.get("role")
    active_status = data.get("is_active")
    can_upload = data.get("can_upload")  # 👈 nuevo campo

    if not email:
        return jsonify({"detail": "El email es obligatorio."}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return jsonify({"detail": "Usuario no encontrado."}), 404

        if new_role:
            user.role = new_role
        if active_status is not None:
            user.is_active = active_status
        if can_upload is not None:
            user.can_upload = can_upload  # 👈 actualizar permiso

        db.commit()
        return jsonify({"message": "Usuario actualizado correctamente."}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()
