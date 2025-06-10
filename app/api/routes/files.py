import base64
import os
from flask import Blueprint, request, jsonify, send_file
from app.auth.services.midelwares import require_active_user, require_auth, require_can_upload, require_file_permission, with_db_session
from app.crypto.aes import AES128
from app.db.config import get_db
from app.db.models import DownloadHistory, File, FilePermission, User
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
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
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

import hashlib

from flask_cors import CORS

CORS(files_bp, origins="https://localhost:5173", supports_credentials=True)

fernet = Fernet(os.getenv("FERNET_KEY").encode())


MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
# 📤 Subir archivo
@files_bp.route('/', methods=['POST'])
@require_auth
@require_can_upload
@with_db_session
def upload_file(db):
    user_id = request.user.get('user_id')

    # 📥 Obtener archivo y campos del formulario
    file = request.files.get('file')
    file_hash = request.form.get('file_hash')
    signature_hex = request.form.get('signature')  # Firma enviada como string HEX
    pdf_password = request.form.get('pdf_password')

    if not file or not file_hash or not signature_hex or not pdf_password:
        return jsonify({"error": "Archivo, hash, firma y contraseña son requeridos."}), 400

    encrypted_data_from_frontend = file.read()

    # 🚫 Validar tamaño máximo
    if len(encrypted_data_from_frontend) > MAX_FILE_SIZE:
        return jsonify({
            "error": f"El archivo es demasiado grande. Tamaño máximo permitido: {MAX_FILE_SIZE // (1024 * 1024)} MB"
        }), 400

    try:
        # 🧾 Convertir firma de hex a bytes
        signature_bytes = bytes.fromhex(signature_hex)

        # 🔁 Verificar si ya existe un archivo con el mismo hash
        existing_file = db.query(File).filter(File.file_hash == file_hash).first()
        if existing_file:
            return jsonify({
                "message": "El archivo ya existe en el sistema.",
                "file_id": existing_file.id
            }), 400

        # 🔐 Aplicar segunda capa de cifrado (doble cifrado)
        double_encrypted_data = AES128.encrypt(encrypted_data_from_frontend)

        # 🔐 Cifrar la contraseña antes de guardarla
        fernet = Fernet(os.getenv("FERNET_KEY").encode())
        encrypted_pdf_password = fernet.encrypt(pdf_password.encode())

        # 💾 Guardar archivo cifrado, firma, hash y contraseña cifrada
        new_file = File(
            user_id=user_id,
            file_name=secure_filename(file.filename),
            file_data=double_encrypted_data,
            signature=signature_bytes,
            file_hash=file_hash,
            pdf_password=encrypted_pdf_password,  # ✅ Aquí cifrada
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.add(new_file)
        db.commit()

        return jsonify({
            "message": "Archivo doblemente cifrado y almacenado correctamente.",
            "file_id": new_file.id
        }), 201

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Error al procesar el archivo: {str(e)}"}), 500





@files_bp.route('/<int:file_id>', methods=['GET'])
@with_db_session
@require_auth
@require_active_user
@require_file_permission('download')
def download_file(db, file_id):
    user_id = request.user.get('user_id')

    # ✅ Buscar el archivo
    file_record = db.query(File).filter(File.id == file_id).first()
    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    try:
        # ✅ Descifrar el archivo (usando la clave del .env)
        decrypted_file_data = AES128.decrypt(file_record.file_data)
    except Exception as e:
        return jsonify({"error": f"Error al descifrar el archivo: {str(e)}"}), 500

    # ✅ Registrar historial de descarga
    download_log = DownloadHistory(
        user_id=user_id,
        file_id=file_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.add(download_log)
    db.commit()

    # ✅ Obtener correo del usuario que descarga
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.email:
        return jsonify({"error": "No se pudo obtener el correo del usuario."}), 500

    # ✅ Descifrar la contraseña almacenada
    try:
        fernet = Fernet(os.getenv("FERNET_KEY").encode())
        decrypted_pdf_password = fernet.decrypt(file_record.pdf_password).decode()
    except Exception as e:
        return jsonify({"error": f"Error al descifrar la contraseña del archivo: {str(e)}"}), 500

    # ✅ Enviar la contraseña descifrada por correo
    try:
        send_password_email(user.email, decrypted_pdf_password, file_record.file_name)
    except Exception as e:
        return jsonify({"error": f"No se pudo enviar la contraseña por correo: {str(e)}"}), 500

    # ✅ Enviar archivo descifrado
    mime_type, _ = mimetypes.guess_type(file_record.file_name)
    if not mime_type:
        mime_type = "application/octet-stream"

    return send_file(
        io.BytesIO(decrypted_file_data),
        download_name=file_record.file_name,
        mimetype=mime_type,
        as_attachment=True
    )



@files_bp.route('/protect-dw-pdf', methods=['POST'])
@require_auth
@require_active_user
def protect_dowland_pdf():
    uploaded_file = request.files.get('file')
    if not uploaded_file or uploaded_file.filename == '':
        return jsonify({"error": "No se ha enviado ningún archivo."}), 400

    pdf_data = uploaded_file.read()

    password = generate_secure_password()
    protected_pdf_data = protect_pdf(pdf_data, password)

    # ✅ Devolver JSON con el PDF protegido y la contraseña
    return jsonify({
        "protected_pdf": base64.b64encode(protected_pdf_data).decode(),  # El archivo como base64 (para que el frontend lo descargue o lo guarde)
        "pdf_password": password,  # La contraseña que luego te enviarán en /files/
        "file_name": uploaded_file.filename
    }), 200



@files_bp.route('/', methods=['GET'])
@require_auth
@require_active_user
@with_db_session
def list_files(db):
    payload = request.user
    user_id = payload.get('user_id')
    user_role = payload.get('role')

    # Paginación
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page

    files_list = []

    if user_role == "admin":
        # ✅ Si es administrador, obtener todos los archivos del sistema
        all_files = db.query(File).all()
        for f in all_files:
            files_list.append({
                "file_id": f.id,
                "file_name": f.file_name,
                "user_id": f.user_id,
                "created_at": f.created_at,
                "access_type": "admin",
                "permission_type": "full",
                "can_view": True,
                "can_download": True
            })
    else:
        # ✅ Archivos propios
        own_files = db.query(
            File.id, File.file_name, File.user_id, File.created_at
        ).filter(File.user_id == user_id).all()

        for f in own_files:
            files_list.append({
                "file_id": f.id,
                "file_name": f.file_name,
                "user_id": f.user_id,
                "created_at": f.created_at,
                "access_type": "own",
                "permission_type": "full",
                "can_view": True,
                "can_download": True
            })

        # ✅ Archivos compartidos
        shared_files = db.query(
            File.id, File.file_name, File.user_id, File.created_at, FilePermission.permission_type
        ).join(FilePermission).filter(
            FilePermission.granted_user_id == user_id
        ).all()

        for f in shared_files:
            files_list.append({
                "file_id": f.id,
                "file_name": f.file_name,
                "user_id": f.user_id,
                "created_at": f.created_at,
                "access_type": "shared",
                "permission_type": f.permission_type,
                "can_view": f.permission_type in ["view", "both"],
                "can_download": f.permission_type in ["download", "both"]
            })

    # ✅ Ordenar y paginar
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
@with_db_session
def delete_file(db,file_id):
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
@with_db_session
def share_file(db,file_id):
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




    
@files_bp.route('/<int:file_id>/permissions', methods=['PUT'])
@require_auth
@require_active_user
@with_db_session
def update_file_permission(db, file_id):
    data = request.get_json() or {}
    user_id = request.user.get('user_id')
    user_role = request.user.get('role')  # ✅ Añadido aquí
    target_user_id = data.get('target_user_id')
    new_permission_type = data.get('permission_type')  # 'view', 'download', 'both', 'none'

    # ✅ Validar target_user_id
    if not target_user_id:
        return jsonify({"error": "target_user_id es requerido."}), 400
    try:
        target_user_id = int(target_user_id)
    except (ValueError, TypeError):
        return jsonify({"error": "target_user_id debe ser un número entero válido."}), 400

    # ✅ Verificar que el archivo pertenece al usuario actual o es admin
    if user_role == "admin":
        file = db.query(File).filter(File.id == file_id).first()
    else:
        # Si es usuario normal, solo si es propietario
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
@with_db_session
def get_download_history(db,file_id):
    payload = request.user
    user_id = payload.get('user_id')
    user_role = payload.get('role')

    # Si es admin, permitir ver cualquier archivo
    if user_role == "admin":
        file = db.query(File).filter(File.id == file_id).first()
    else:
        # Si es usuario normal, solo si es propietario
        file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()

    if not file:
        return jsonify({"error": "Archivo no encontrado o no tienes permisos para ver el historial."}), 404

    # Obtener la clave Fernet
    fernet_key = os.getenv("FERNET_KEY")
    if not fernet_key:
        return jsonify({"error": "Clave de cifrado no configurada."}), 500
    name_fernet = Fernet(fernet_key.encode())

    # Consultar historial de descargas agrupado por usuario
    results = db.query(
        DownloadHistory.user_id,
        func.count(DownloadHistory.id).label('download_count'),
        func.max(DownloadHistory.download_time).label('last_download')
    ).filter(DownloadHistory.file_id == file_id).group_by(DownloadHistory.user_id).all()

    history = []
    for r in results:
        user = db.query(User).filter(User.id == r.user_id).first()

        try:
            decrypted_first_name = name_fernet.decrypt(user.first_name).decode()
            decrypted_last_name = name_fernet.decrypt(user.last_name).decode()
        except Exception:
            decrypted_first_name = "[Error]"
            decrypted_last_name = "[Error]"

        history.append({
            "user_id": user.id,
            "email": user.email,
            "first_name": decrypted_first_name,
            "last_name": decrypted_last_name,
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
@with_db_session
@require_file_permission('view')  # 👈 Valida que tenga permiso 'view' o 'both'
def view_file(db,file_id):
    # ✅ Buscar el archivo
    file_record = db.query(File).filter(File.id == file_id).first()
    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    try:
        # ✅ Descifrar el archivo
        decrypted_data = AES128.decrypt(file_record.file_data)

        # ✅ Obtener MIME type
        mime_type, _ = mimetypes.guess_type(file_record.file_name)
        if not mime_type:
            mime_type = "application/octet-stream"

        # ✅ Enviar archivo descifrado
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file_record.file_name,
            mimetype=mime_type,
            as_attachment=False  # Para mostrar en navegador
        )

    except Exception as e:
        return jsonify({"error": f"Error al visualizar el archivo: {str(e)}"}), 500


@files_bp.route('/<int:file_id>/permissions/users', methods=['GET'])
@require_auth
@require_active_user
@with_db_session
def get_users_permissions_for_file(db,file_id):
    current_user_id = request.user.get('user_id')
    user_role = request.user.get('role')

    if user_role == "admin":
        file = db.query(File).filter(File.id == file_id).first()
    else:
        file = db.query(File).filter(File.id == file_id, File.user_id == current_user_id).first()
    if not file:
        return jsonify({"error": "No tienes acceso a este archivo o no existe."}), 403

    fernet_key = os.getenv("FERNET_KEY")
    if not fernet_key:
        return jsonify({"error": "Clave de cifrado no configurada."}), 500
    name_fernet = Fernet(fernet_key.encode())

    all_users = db.query(User).filter(
    User.id != current_user_id,
    User.id != file.user_id,  # ✅ excluir al dueño también

    User.role != 'admin'  # ← esta línea lo filtra
).all()
    permissions = db.query(FilePermission).filter(FilePermission.file_id == file_id).all()
    permissions_map = {perm.granted_user_id: perm.permission_type for perm in permissions}

    download_stats = db.query(
        DownloadHistory.user_id,
        func.count(DownloadHistory.id).label('total_downloads'),
        func.max(DownloadHistory.download_time).label('last_download_time')
    ).filter(DownloadHistory.file_id == file_id).group_by(DownloadHistory.user_id).all()
    download_map = {d.user_id: d for d in download_stats}

    last_downloads = db.query(
        DownloadHistory.user_id,
        File.file_name,
        DownloadHistory.download_time
    ).join(File, File.id == DownloadHistory.file_id).filter(
        DownloadHistory.file_id == file_id
    ).order_by(DownloadHistory.user_id, desc(DownloadHistory.download_time)).all()
    last_file_name_map = {}
    for entry in last_downloads:
        if entry.user_id not in last_file_name_map:
            last_file_name_map[entry.user_id] = entry.file_name

    users_permissions = []
    for user in all_users:
        try:
            decrypted_first_name = name_fernet.decrypt(user.first_name).decode()
            decrypted_last_name = name_fernet.decrypt(user.last_name).decode()
        except Exception:
            decrypted_first_name = "[Error]"
            decrypted_last_name = "[Error]"

        stats = download_map.get(user.id)
        users_permissions.append({
            "user_id": user.id,
            "email": user.email,
            "first_name": decrypted_first_name,
            "last_name": decrypted_last_name,
            "permission_type": permissions_map.get(user.id, "none"),
            "total_downloads": stats.total_downloads if stats else 0,
            "last_download_time": stats.last_download_time.isoformat() if stats else None,
            "last_downloaded_file_name": last_file_name_map.get(user.id)
        })

    return jsonify({
        "file_id": file_id,
        "users": users_permissions
    }), 200



@files_bp.route('/verify-signature', methods=['POST'])
@require_auth
@with_db_session
def verify_signature(db):

    # 📥 Obtener datos del frontend
    file_hash = request.json.get('file_hash')
    signature_hex = request.json.get('signature')

    if not file_hash or not signature_hex:
        return jsonify({"error": "Se requiere el hash del archivo y la firma."}), 400

    # 🧾 Convertir firma a bytes
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except Exception:
        return jsonify({"error": "Formato de firma inválido."}), 400

    # 🔎 Buscar el archivo por su hash
    file_record = db.query(File).filter(File.file_hash == file_hash).first()
    if not file_record:
        return jsonify({"error": "No se encontró un archivo con ese hash."}), 404

    # 🔐 Obtener clave pública del autor del archivo
    uploader = db.query(User).filter(User.id == file_record.user_id).first()
    if not uploader or not uploader.public_key:
        return jsonify({"error": "Clave pública no disponible para este usuario."}), 400

    # 🧠 Verificar la firma sobre el hash original
    try:
        public_key = serialization.load_pem_public_key(uploader.public_key)
        public_key.verify(
            signature_bytes,
            bytes.fromhex(file_hash),
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256())
        )
    except Exception as e:
        return jsonify({"valid": False, "error": f"Firma inválida: {str(e)}"}), 400

    return jsonify({"valid": True, "message": "Firma válida. El archivo no ha sido alterado."}), 200


@files_bp.route('/by-hash/<string:file_hash>', methods=['GET'])
@require_auth
@with_db_session
def get_file_signature_by_hash(db, file_hash):
    file_record = db.query(File).filter(File.file_hash == file_hash).first()
    if not file_record:
        return jsonify({"error": "Archivo no encontrado."}), 404

    signature_hex = file_record.signature.hex()

    return jsonify({
        "file_hash": file_record.file_hash,
        "signature": signature_hex
    }), 200
