from flask import Blueprint, request, jsonify, send_file
from app.auth.services.midelwares import require_active_user, require_auth, require_can_upload
from app.db.config import get_db
from app.db.models import DownloadHistory, File, FilePermission, User
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
import mimetypes
import io

files_bp = Blueprint('files', __name__, url_prefix='/files')

# 📤 Subir archivo
@files_bp.route('/', methods=['POST'])
@require_auth
@require_can_upload  
def upload_file():
    db = next(get_db())
    user_id = request.user.get('user_id')  # Obtenido desde JWT

    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No se ha enviado ningún archivo."}), 400

    # ✅ Registrar el archivo (la validación de permisos ya fue realizada por el decorador)
    new_file = File(
        user_id=user_id,
        file_name=file.filename,
        file_data=file.read(),
        created_at=datetime.now(),
        updated_at=datetime.now()
    )

    db.add(new_file)
    db.commit()

    return jsonify({"message": "Archivo subido correctamente.", "file_id": new_file.id}), 201



# 📥 Descargar archivo real con MIME correcto
@files_bp.route('/<int:file_id>', methods=['GET'])
@require_auth
@require_active_user  
def download_file(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')
    file_record = db.query(File).filter(File.id == file_id).first()

    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    has_permission = (file_record.user_id == user_id) or db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.granted_user_id == user_id
    ).count() > 0

    if not has_permission:
        return jsonify({"error": "No tienes permisos para acceder a este archivo."}), 403

    # ✅ Registrar historial de descarga
    download_log = DownloadHistory(
        user_id=user_id,
        file_id=file_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.add(download_log)
    db.commit()

    mime_type, _ = mimetypes.guess_type(file_record.file_name)
    if not mime_type:
        mime_type = "application/octet-stream"

    return send_file(
        io.BytesIO(file_record.file_data),
        download_name=file_record.file_name,
        mimetype=mime_type,
        as_attachment=True
    )





@files_bp.route('/', methods=['GET'])
@require_auth
@require_active_user
def list_files():
    db = next(get_db())
    user_id = request.user.get('user_id')

    # Paginación
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page

    # Archivos propios
    own_files_query = db.query(File).filter(File.user_id == user_id)
    # Archivos compartidos
    shared_files_query = db.query(File).join(FilePermission).filter(
        FilePermission.granted_user_id == user_id
    )

    # Unir ambos conjuntos
    combined_query = own_files_query.union(shared_files_query).order_by(File.id)

    # Obtener total de archivos antes de paginar
    total_files = combined_query.count()

    # Aplicar paginación
    files_query = combined_query.offset(offset).limit(per_page).all()

    files_list = [
        {
            "file_id": f.id,
            "file_name": f.file_name,
            "user_id": f.user_id,
            "created_at": f.created_at,
            "access_type": "own" if f.user_id == user_id else "shared"
        } for f in files_query
    ]


    return jsonify({
        "total": total_files,
        "page": page,
        "per_page": per_page,
        "files": files_list
    })


# DELETE /files/<id> — Eliminar archivo por ID (solo del propio usuario)
@files_bp.route('/<int:file_id>', methods=['DELETE'])
@require_auth
@require_active_user
def delete_file(file_id):
    db: Session = next(get_db())
    user_id = request.user.get('user_id')  # ✅ Obtenido desde el JWT

    # Solo permitir eliminar archivos propios
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o sin permisos para eliminarlo."}), 404

    db.delete(file)
    db.commit()

    return jsonify({"message": "Archivo eliminado correctamente."}), 200




@files_bp.route('/<int:file_id>/share', methods=['POST'])
@require_auth
@require_active_user
def share_file(file_id):
    db = next(get_db())
    data = request.get_json() or {}
    user_id = request.user.get('user_id')
    target_user_id = data.get('target_user_id')

    # ✅ Validar que target_user_id esté presente y sea entero
    if not target_user_id:
        return jsonify({"error": "target_user_id es requerido."}), 400

    try:
        target_user_id = int(target_user_id)
    except (ValueError, TypeError):
        return jsonify({"error": "target_user_id debe ser un número entero válido."}), 400

    # ✅ Prevenir que el usuario comparta el archivo consigo mismo
    if target_user_id == user_id:
        return jsonify({"error": "No puedes compartir un archivo contigo mismo."}), 400

    # ✅ Verificar que el usuario de destino exista y esté activo
    target_user = db.query(User).filter(User.id == target_user_id, User.is_active == True).first()
    if not target_user:
        return jsonify({"error": "El usuario de destino no existe o está inactivo."}), 404

    # ✅ Verificar que el archivo pertenezca al usuario actual
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o no tienes permisos para compartirlo."}), 404

    # ✅ Evitar permisos duplicados
    existing_permission = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.granted_user_id == target_user_id
    ).first()

    if existing_permission:
        return jsonify({"error": "El permiso ya fue concedido a este usuario."}), 400

    # ✅ Registrar nuevo permiso
    permission = FilePermission(file_id=file_id, granted_user_id=target_user_id)
    db.add(permission)
    db.commit()

    return jsonify({"message": "Permiso concedido correctamente."}), 200


@files_bp.route('/<int:file_id>', methods=['PUT'])
@require_auth
@require_can_upload  
def update_file(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()

    if not file:
        return jsonify({"error": "Archivo no encontrado o sin permisos para actualizarlo."}), 404

    # ✅ Obtener datos del request
    new_file = request.files.get('file')
    new_file_name = request.form.get('file_name')

    if not new_file and not new_file_name:
        return jsonify({"error": "Debes enviar al menos un archivo o un nuevo nombre."}), 400

    # ✅ Actualizar archivo si se envió uno nuevo
    if new_file:
        file.file_data = new_file.read()

    # ✅ Actualizar nombre si se envió uno nuevo
    if new_file_name:
        file.file_name = new_file_name

    file.updated_at = datetime.now()
    db.commit()

    return jsonify({"message": "Archivo actualizado correctamente.", "file_id": file.id}), 200


@files_bp.route('/<int:file_id>/revoke', methods=['POST'])
@require_auth
@require_active_user
def revoke_file_permission(file_id):
    db = next(get_db())
    data = request.get_json() or {}
    user_id = request.user.get('user_id')
    target_user_id = data.get('target_user_id')

    # Validar target_user_id
    if not target_user_id:
        return jsonify({"error": "target_user_id es requerido."}), 400

    try:
        target_user_id = int(target_user_id)
    except (ValueError, TypeError):
        return jsonify({"error": "target_user_id debe ser un número entero válido."}), 400

    # Verificar que el archivo pertenece al usuario actual
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o no tienes permisos para revocar permisos."}), 404

    # Buscar el permiso existente
    permission = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.granted_user_id == target_user_id
    ).first()

    if not permission:
        return jsonify({"error": "No existe un permiso concedido a este usuario para este archivo."}), 404

    # Eliminar el permiso
    db.delete(permission)
    db.commit()

    return jsonify({"message": "Permiso revocado correctamente."}), 200


@files_bp.route('/<int:file_id>/download-history', methods=['GET'])
@require_auth
@require_active_user
def get_download_history(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')

    # Verificar que el archivo le pertenece al usuario actual
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o no tienes permisos para ver el historial."}), 404

    # Consultar historial de descargas agrupado por usuario
    results = db.query(
        DownloadHistory.user_id,
        func.count(DownloadHistory.id).label('download_count'),
        func.max(DownloadHistory.download_time).label('last_download')
    ).filter(DownloadHistory.file_id == file_id).group_by(DownloadHistory.user_id).all()

    history = []
    for r in results:
        user = db.query(User).filter(User.id == r.user_id).first()
        history.append({
            "user_id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "download_count": r.download_count,
            "last_download": r.last_download
        })

    return jsonify({
        "file_id": file_id,
        "history": history
    }), 200
