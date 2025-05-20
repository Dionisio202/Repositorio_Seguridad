from flask import Blueprint, request, jsonify
from app.auth.services.midelwares import require_admin, require_auth
from app.db.config import SessionLocal
from app.db.models import User


admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/update-user', methods=['PUT'])
@require_auth
@require_admin
def update_user_role_or_status():
    data = request.get_json() or {}
    user_id = data.get("id")  
    new_role = data.get("role")
    active_status = data.get("is_active")
    can_upload = data.get("can_upload")

    if not user_id:
        return jsonify({"detail": "El id del usuario es obligatorio."}), 400

    # Validar roles permitidos
    valid_roles = ["user", "admin"]
    if new_role and new_role not in valid_roles:
        return jsonify({"error": f"Rol inválido. Los roles permitidos son: {valid_roles}"}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"detail": "Usuario no encontrado."}), 404

        # Prevenir que el admin actual se elimine o degrade a sí mismo
        current_user_id = request.user.get("user_id")
        if current_user_id == user.id and (new_role == "user" or active_status is False):
            return jsonify({"error": "No puedes cambiar tu propio rol a 'user' o desactivarte."}), 400

        if new_role:
            user.role = new_role
        if active_status is not None:
            user.is_active = active_status
        if can_upload is not None:
            user.can_upload = can_upload

        db.commit()
        return jsonify({"message": "Usuario actualizado correctamente."}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()



@admin_bp.route('/users', methods=['GET'])
@require_auth
@require_admin
def list_users():
    db = SessionLocal()
    current_user_id = request.user.get('user_id')

    try:
        users = db.query(User).filter(User.id != current_user_id).all()

        users_list = [
            {
                "id": u.id,
                "email": u.email,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "role": u.role,
                "is_active": u.is_active,
                "can_upload": u.can_upload,
                "created_at": u.created_at,
                "updated_at": u.updated_at
            } for u in users
        ]

        return jsonify({"users": users_list}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"detail": str(e)}), 500
    finally:
        db.close()
