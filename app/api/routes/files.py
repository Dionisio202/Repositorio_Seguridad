import os
from flask import Blueprint, request, jsonify, send_file
from app.auth.services.midelwares import require_active_user, require_auth, require_can_upload, require_file_permission
from app.db.config import get_db
from app.db.models import DownloadHistory, File, FilePermission, User
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
import mimetypes
import io
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
files_bp = Blueprint('files', __name__, url_prefix='/files')
from app.auth.utils.file_utils import generate_secure_password, protect_pdf
from app.auth.utils.email_utils import send_password_email  
from app.db.models import FileAuditLog

import hashlib

# 📤 Subir archivo
@files_bp.route('/', methods=['POST'])
@require_auth
@require_can_upload
def upload_file():
    db = next(get_db())
    user_id = request.user.get('user_id')
    user = db.query(User).filter(User.id == user_id).first()

    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No se ha enviado ningún archivo."}), 400

    file_data = file.read()

    try:
        # 1️⃣ Calcular hash del archivo
        file_hash = hashlib.sha256(file_data).hexdigest()

        # 2️⃣ Verificar si ya existe un archivo con el mismo hash (evitar duplicados)
        existing_file = db.query(File).filter(File.file_hash == file_hash).first()
        if existing_file:
            return jsonify({
                "message": "El archivo ya existe en el sistema.",
                "file_id": existing_file.id
            }), 400

        # 3️⃣ Desencriptar la clave privada del usuario
        secret_key = os.getenv("SIGNATURE_SECRET_KEY")
        if not secret_key:
            return jsonify({"error": "Configuración de clave secreta no encontrada."}), 500

        fernet = Fernet(secret_key.encode())
        private_key_bytes = fernet.decrypt(user.encrypted_private_key)

        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )

        # 4️⃣ Firmar el archivo
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 5️⃣ Guardar archivo, firma y hash
        new_file = File(
            user_id=user_id,
            file_name=secure_filename(file.filename),
            file_data=file_data,
            signature=signature,
            file_hash=file_hash,  # ✅ Guarda el hash calculado
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.add(new_file)
        db.commit()

        return jsonify({
            "message": "Archivo subido y firmado correctamente.",
            "file_id": new_file.id
        }), 201

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error al procesar la firma: {str(e)}"}), 500



@files_bp.route('/<int:file_id>', methods=['GET'])
@require_auth
@require_active_user
@require_file_permission('download')  # 👈 Valida si puede descargar
def download_file(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')

    # ✅ Buscar el archivo
    file_record = db.query(File).filter(File.id == file_id).first()
    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    # ✅ Recuperar la clave pública del usuario que subió el archivo
    uploader = db.query(User).filter(User.id == file_record.user_id).first()
    if not uploader or not uploader.public_key:
        return jsonify({"error": "No se puede verificar la firma del archivo. Clave pública no disponible."}), 400

    # ✅ Verificar la firma antes de permitir la descarga
    try:
        public_key = serialization.load_pem_public_key(uploader.public_key)
        public_key.verify(
            file_record.signature,
            file_record.file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        return jsonify({"error": "La firma del archivo no es válida. Posible alteración de datos."}), 400

    # ✅ Generar contraseña y proteger el PDF
    password = generate_secure_password()
    protected_pdf_data = protect_pdf(file_record.file_data, password)

    # ✅ Obtener el correo del usuario que descarga
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.email:
        return jsonify({"error": "No se pudo obtener el correo del usuario."}), 500

    # ✅ Enviar contraseña por correo
    try:
        send_password_email(user.email, password, file_record.file_name)
    except Exception as e:
        return jsonify({"error": f"No se pudo enviar la contraseña por correo: {str(e)}"}), 500

    # ✅ Registrar historial de descarga
    download_log = DownloadHistory(
        user_id=user_id,
        file_id=file_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.add(download_log)
    db.commit()

    # ✅ Enviar archivo protegido
    mime_type, _ = mimetypes.guess_type(file_record.file_name)
    if not mime_type:
        mime_type = "application/pdf"

    return send_file(
        io.BytesIO(protected_pdf_data),
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

    # ✅ Consulta de archivos propios
    own_files = db.query(
        File.id, File.file_name, File.user_id, File.created_at
    ).filter(File.user_id == user_id).all()

    # ✅ Consulta de archivos compartidos, incluyendo el tipo de permiso
    shared_files = db.query(
        File.id, File.file_name, File.user_id, File.created_at, FilePermission.permission_type
    ).join(FilePermission).filter(
        FilePermission.granted_user_id == user_id
    ).all()

    # ✅ Unificar resultados
    files_list = []

    # Archivos propios
    for f in own_files:
        files_list.append({
            "file_id": f.id,
            "file_name": f.file_name,
            "user_id": f.user_id,
            "created_at": f.created_at,
            "access_type": "own",
            "permission_type": "full"  # Tiene control total
        })

    # Archivos compartidos
    for f in shared_files:
        files_list.append({
            "file_id": f.id,
            "file_name": f.file_name,
            "user_id": f.user_id,
            "created_at": f.created_at,
            "access_type": "shared",
            "permission_type": f.permission_type  # view, download, both
        })

    # ✅ Ordenar y aplicar paginación manual
    files_list.sort(key=lambda x: x["file_id"])
    total_files = len(files_list)
    paginated_files = files_list[offset:offset + per_page]

    return jsonify({
        "total": total_files,
        "page": page,
        "per_page": per_page,
        "files": paginated_files
    })


@files_bp.route('/<int:file_id>', methods=['DELETE'])
@require_auth
@require_active_user
def delete_file(file_id):
    db: Session = next(get_db())
    payload = request.user
    user_id = payload.get('user_id')
    user_role = payload.get('role')

    # ✅ Permitir que el dueño o un admin elimine el archivo
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado."}), 404

    if file.user_id != user_id and user_role != "admin":
        return jsonify({"error": "No tienes permisos para eliminar este archivo."}), 403

    # ✅ Registrar auditoría de eliminación antes de borrar
    from app.db.models import FileAuditLog  # Asegúrate de importar si no lo tienes
    audit = FileAuditLog(
        user_id=user_id,
        file_id=file.id,
        action='delete',
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow(),
        details=f"Archivo eliminado. Nombre: {file.file_name}"
    )
    db.add(audit)

    # ✅ Eliminar permisos asociados
    db.query(FilePermission).filter(FilePermission.file_id == file_id).delete()

    # ✅ Eliminar historial de descargas asociado
    db.query(DownloadHistory).filter(DownloadHistory.file_id == file_id).delete()

    # ✅ Eliminar el archivo
    db.delete(file)
    db.commit()

    return jsonify({"message": "Archivo y registros relacionados eliminados correctamente."}), 200


@files_bp.route('/<int:file_id>/share', methods=['POST'])
@require_auth
@require_active_user
def share_file(file_id):
    db = next(get_db())
    data = request.get_json() or {}
    user_id = request.user.get('user_id')
    target_user_id = data.get('target_user_id')
    permission_type = data.get('permission_type', 'view')  # Valor por defecto: 'view'

    # ✅ Validar que target_user_id esté presente y sea entero
    if not target_user_id:
        return jsonify({"error": "target_user_id es requerido."}), 400

    try:
        target_user_id = int(target_user_id)
    except (ValueError, TypeError):
        return jsonify({"error": "target_user_id debe ser un número entero válido."}), 400

    # ✅ Validar permission_type
    valid_permissions = ['view', 'download', 'both']
    if permission_type not in valid_permissions:
        return jsonify({
            "error": f"Tipo de permiso inválido. Debe ser uno de: {', '.join(valid_permissions)}."
        }), 400

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

    # ✅ Registrar nuevo permiso con tipo definido
    permission = FilePermission(
        file_id=file_id,
        granted_user_id=target_user_id,
        permission_type=permission_type
    )
    db.add(permission)
    db.commit()

    return jsonify({"message": f"Permiso '{permission_type}' concedido correctamente."}), 200


@files_bp.route('/<int:file_id>', methods=['PUT'])
@require_auth
@require_can_upload  
def update_file(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')
    user = db.query(User).filter(User.id == user_id).first()
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()

    if not file:
        return jsonify({"error": "Archivo no encontrado o sin permisos para actualizarlo."}), 404

    new_file = request.files.get('file')
    new_file_name = request.form.get('file_name')

    if not new_file and not new_file_name:
        return jsonify({"error": "Debes enviar al menos un archivo o un nuevo nombre."}), 400

    try:
        # ✅ Actualizar archivo si se envió uno nuevo
        if new_file:
            file_data = new_file.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            file.file_hash = file_hash
            file.file_data = file_data

            secret_key = os.getenv("SIGNATURE_SECRET_KEY")
            if not secret_key:
                return jsonify({"error": "Configuración de clave secreta no encontrada."}), 500

            fernet = Fernet(secret_key.encode())
            private_key_bytes = fernet.decrypt(user.encrypted_private_key)
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

            signature = private_key.sign(
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            file.signature = signature

        if new_file_name:
            file.file_name = new_file_name

        file.updated_at = datetime.now()
        db.commit()

        # 🔐 Registrar auditoría de actualización
        from app.db.models import FileAuditLog  # Asegúrate de importar
        audit = FileAuditLog(
            user_id=user_id,
            file_id=file.id,
            action='update',
            ip_address=request.remote_addr,
            timestamp=datetime.utcnow(),
            details=f"Archivo actualizado. Nombre: {file.file_name}"
        )
        db.add(audit)
        db.commit()

        return jsonify({"message": "Archivo actualizado correctamente.", "file_id": file.id}), 200

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error al actualizar la firma: {str(e)}"}), 500

    
@files_bp.route('/<int:file_id>/permissions', methods=['PUT'])
@require_auth
@require_active_user
def update_file_permission(file_id):
    db = next(get_db())
    data = request.get_json() or {}
    user_id = request.user.get('user_id')
    target_user_id = data.get('target_user_id')
    new_permission_type = data.get('permission_type')  # 'view', 'download', 'both', 'none'

    # ✅ Validar target_user_id
    if not target_user_id:
        return jsonify({"error": "target_user_id es requerido."}), 400
    try:
        target_user_id = int(target_user_id)
    except (ValueError, TypeError):
        return jsonify({"error": "target_user_id debe ser un número entero válido."}), 400

    # ✅ Verificar que el archivo pertenece al usuario actual
    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o no tienes permisos para modificar permisos."}), 404

    # ✅ Verificar que existe un permiso previo
    permission = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.granted_user_id == target_user_id
    ).first()

    if not permission:
        return jsonify({"error": "No existe un permiso concedido a este usuario para este archivo."}), 404

    valid_permissions = ['view', 'download', 'both', 'none']
    if new_permission_type not in valid_permissions:
        return jsonify({"error": f"Tipo de permiso inválido. Usa: {', '.join(valid_permissions)}."}), 400

    if new_permission_type == 'none':
        # ✅ Eliminar completamente el permiso
        db.delete(permission)
        db.commit()
        return jsonify({"message": "Permisos eliminados correctamente."}), 200
    else:
        # ✅ Actualizar el tipo de permiso
        permission.permission_type = new_permission_type
        db.commit()
        return jsonify({"message": f"Permiso actualizado a '{new_permission_type}' correctamente."}), 200



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


@files_bp.route('/<int:file_id>/view', methods=['GET'])
@require_auth
@require_active_user
@require_file_permission('view')  # 👈 Valida que tenga permiso 'view' o 'both'
def view_file(file_id):
    db = next(get_db())
    user_id = request.user.get('user_id')

    # ✅ Buscar el archivo (la existencia ya se validó en el middleware, pero incluimos por seguridad)
    file_record = db.query(File).filter(File.id == file_id).first()
    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    mime_type, _ = mimetypes.guess_type(file_record.file_name)
    if not mime_type:
        mime_type = "application/octet-stream"

    return send_file(
        io.BytesIO(file_record.file_data),
        download_name=file_record.file_name,
        mimetype=mime_type,
        as_attachment=False  # 👈 Importante: Esto permite mostrar en navegador
    )

@files_bp.route('/<int:file_id>/permissions/users', methods=['GET'])
@require_auth
@require_active_user
def get_users_permissions_for_file(file_id):
    db = next(get_db())
    current_user_id = request.user.get('user_id')

    # Verificar que el archivo le pertenezca al usuario actual
    file = db.query(File).filter(File.id == file_id, File.user_id == current_user_id).first()
    if not file:
        return jsonify({"error": "No tienes acceso a este archivo o no existe."}), 403

    # Obtener todos los usuarios del sistema (excepto el dueño del archivo)
    all_users = db.query(User).filter(User.id != current_user_id).all()

    # Obtener permisos existentes sobre este archivo
    permissions = db.query(FilePermission).filter(FilePermission.file_id == file_id).all()
    permissions_map = {perm.granted_user_id: perm.permission_type for perm in permissions}

    # Armar respuesta
    users_permissions = []
    for user in all_users:
        users_permissions.append({
            "user_id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "permission_type": permissions_map.get(user.id, "none")
        })

    return jsonify({
        "file_id": file_id,
        "users": users_permissions
    }), 200
