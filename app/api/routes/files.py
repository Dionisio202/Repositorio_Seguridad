from flask import Blueprint, request, jsonify, send_file
from app.db.config import get_db
from app.db.models import File
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
import mimetypes
import io

files_bp = Blueprint('files', __name__, url_prefix='/files')

# 📤 Subir archivo
@files_bp.route('/', methods=['POST'])
def upload_file():
    db = next(get_db())
    
    user_id = request.form.get('user_id')
    file = request.files.get('file')
    
    if not file:
        return jsonify({"error": "No se ha enviado ningún archivo"}), 400
    if not user_id:
        return jsonify({"error": "No se ha enviado user_id"}), 400

    new_file = File(
        user_id=int(user_id),
        file_name=file.filename,
        file_data=file.read(),
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    db.add(new_file)
    db.commit()

    return jsonify({"message": "Archivo subido correctamente", "file_id": new_file.id}), 201

# 📥 Descargar archivo real con MIME correcto
@files_bp.route('/<int:file_id>', methods=['GET'])
def download_file(file_id):
    db = next(get_db())
    file_record = db.query(File).filter(File.id == file_id).first()

    if not file_record:
        return jsonify({"error": "Archivo no encontrado"}), 404

    # Detectar MIME type usando mimetypes
    mime_type, _ = mimetypes.guess_type(file_record.file_name)
    if not mime_type:
        mime_type = "application/octet-stream"  # tipo genérico binario

    return send_file(
        io.BytesIO(file_record.file_data),
        download_name=file_record.file_name,
        mimetype=mime_type,
        as_attachment=True
    )

# 📄 Listar archivos con paginación
@files_bp.route('/', methods=['GET'])
def list_files():
    db = next(get_db())
    
    # Parámetros de paginación (por defecto: página 1, 10 archivos por página)
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page

    # Contar total de archivos
    total_files = db.query(func.count(File.id)).scalar()

    # Obtener archivos paginados
    files_query = db.query(File).order_by(File.id).offset(offset).limit(per_page).all()

    files_list = [
        {
            "file_id": f.id,
            "file_name": f.file_name,
            "user_id": f.user_id,
            "created_at": f.created_at
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
def delete_file(file_id):
    db: Session = next(get_db())
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({"error": "Falta user_id en query params"}), 400

    file = db.query(File).filter(File.id == file_id, File.user_id == user_id).first()
    if not file:
        return jsonify({"error": "Archivo no encontrado o sin permisos"}), 404

    # Eliminar registro en base de datos
    db.delete(file)
    db.commit()

    return jsonify({"message": "Archivo eliminado"}), 200