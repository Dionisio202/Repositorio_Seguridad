from flask import Blueprint, request, jsonify
from sqlalchemy.orm import Session
from app.auth.services.midelwares import require_admin, require_auth
from app.db.config import get_db
from app.db.models import FileAuditLog, LoginAttempt, DownloadHistory, ActiveSession, FilePermission, File, User
from sqlalchemy import desc
from datetime import datetime

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")

def parse_date(param):
    try:
        return datetime.fromisoformat(param) if param else None
    except Exception:
        return None

def get_user_map(db, user_ids):
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    return {u.id: u.email for u in users}

# 🕵️ Intentos de inicio de sesión (ya tiene email, no necesita cambio)
@audit_bp.route("/logins", methods=["GET"])
@require_auth
@require_admin
def get_logins():
    db: Session = next(get_db())
    email = request.args.get("email")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(LoginAttempt)
    if email:
        query = query.filter(LoginAttempt.email == email)
    if start_date:
        query = query.filter(LoginAttempt.attempt_time >= start_date)
    if end_date:
        query = query.filter(LoginAttempt.attempt_time <= end_date)

    results = query.order_by(desc(LoginAttempt.attempt_time)).all()
    return jsonify({
        "logs": [f"[{l.attempt_time.isoformat()}] Intento de login con email {l.email}" for l in results],
        "data": [{"id": l.id, "email": l.email, "attempt_time": l.attempt_time.isoformat()} for l in results]
    })

# 📥 Descargas
@audit_bp.route("/downloads", methods=["GET"])
@require_auth
@require_admin
def get_downloads():
    db: Session = next(get_db())
    user_id = request.args.get("user_id")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(DownloadHistory)
    if user_id:
        query = query.filter(DownloadHistory.user_id == int(user_id))
    if start_date:
        query = query.filter(DownloadHistory.download_time >= start_date)
    if end_date:
        query = query.filter(DownloadHistory.download_time <= end_date)

    results = query.order_by(desc(DownloadHistory.download_time)).all()
    user_map = get_user_map(db, {d.user_id for d in results})

    return jsonify({
        "logs": [
            f"[{d.download_time.isoformat()}] Usuario {user_map.get(d.user_id, d.user_id)} descargó archivo {d.file_id} desde IP {d.ip_address or 'desconocida'}"
            for d in results
        ],
        "data": [
            {
                "id": d.id,
                "user_id": d.user_id,
                "email": user_map.get(d.user_id),
                "file_id": d.file_id,
                "download_time": d.download_time.isoformat(),
                "ip_address": d.ip_address,
                "user_agent": d.user_agent
            } for d in results
        ]
    })

# 👤 Sesiones activas
@audit_bp.route("/sessions", methods=["GET"])
@require_auth
@require_admin
def get_sessions():
    db: Session = next(get_db())
    user_id = request.args.get("user_id")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(ActiveSession).filter(ActiveSession.is_active == True)
    if user_id:
        query = query.filter(ActiveSession.user_id == int(user_id))
    if start_date:
        query = query.filter(ActiveSession.last_activity_at >= start_date)
    if end_date:
        query = query.filter(ActiveSession.last_activity_at <= end_date)

    results = query.order_by(desc(ActiveSession.last_activity_at)).all()
    user_map = get_user_map(db, {s.user_id for s in results})

    return jsonify({
        "logs": [
            f"[{s.last_activity_at.isoformat()}] Usuario {user_map.get(s.user_id, s.user_id)} activo desde IP {s.ip_address or 'desconocida'} con agente {s.user_agent}"
            for s in results
        ],
        "data": [
            {
                "id": s.id,
                "user_id": s.user_id,
                "email": user_map.get(s.user_id),
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat(),
                "last_activity_at": s.last_activity_at.isoformat()
            } for s in results
        ]
    })

# 🛂 Permisos
@audit_bp.route("/permissions", methods=["GET"])
@require_auth
@require_admin
def get_permissions():
    db: Session = next(get_db())
    user_id = request.args.get("user_id")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(FilePermission)
    if user_id:
        query = query.filter(FilePermission.granted_user_id == int(user_id))
    if start_date:
        query = query.filter(FilePermission.granted_at >= start_date)
    if end_date:
        query = query.filter(FilePermission.granted_at <= end_date)

    results = query.order_by(desc(FilePermission.granted_at)).all()
    user_map = get_user_map(db, {p.granted_user_id for p in results})

    return jsonify({
        "logs": [
            f"[{p.granted_at.isoformat()}] Usuario {user_map.get(p.granted_user_id, p.granted_user_id)} recibió permiso '{p.permission_type}' sobre archivo {p.file_id}"
            for p in results
        ],
        "data": [
            {
                "id": p.id,
                "file_id": p.file_id,
                "granted_user_id": p.granted_user_id,
                "email": user_map.get(p.granted_user_id),
                "permission_type": p.permission_type,
                "granted_at": p.granted_at.isoformat()
            } for p in results
        ]
    })

# 🗂️ Archivos subidos
@audit_bp.route("/files", methods=["GET"])
@require_auth
@require_admin
def get_files():
    db: Session = next(get_db())
    user_id = request.args.get("user_id")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(File)
    if user_id:
        query = query.filter(File.user_id == int(user_id))
    if start_date:
        query = query.filter(File.created_at >= start_date)
    if end_date:
        query = query.filter(File.created_at <= end_date)

    results = query.order_by(desc(File.created_at)).all()
    user_map = get_user_map(db, {f.user_id for f in results})

    return jsonify({
        "logs": [
            f"[{f.created_at.isoformat() if f.created_at else '¿?'}] Usuario {user_map.get(f.user_id, f.user_id)} subió archivo '{f.file_name}'"
            for f in results
        ],
        "data": [
            {
                "id": f.id,
                "user_id": f.user_id,
                "email": user_map.get(f.user_id),
                "file_name": f.file_name,
                "created_at": f.created_at.isoformat() if f.created_at else None
            } for f in results
        ]
    })

# 🧾 Auditoría de acciones en archivos
@audit_bp.route("/file-actions", methods=["GET"])
@require_auth
@require_admin
def get_file_audit_logs():
    db: Session = next(get_db())
    user_id = request.args.get("user_id")
    file_id = request.args.get("file_id")
    start_date = parse_date(request.args.get("start_date"))
    end_date = parse_date(request.args.get("end_date"))

    query = db.query(FileAuditLog)
    if user_id:
        query = query.filter(FileAuditLog.user_id == int(user_id))
    if file_id:
        query = query.filter(FileAuditLog.file_id == int(file_id))
    if start_date:
        query = query.filter(FileAuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(FileAuditLog.timestamp <= end_date)

    results = query.order_by(desc(FileAuditLog.timestamp)).all()
    user_map = get_user_map(db, {a.user_id for a in results})

    return jsonify({
        "logs": [
            f"[{a.timestamp.isoformat()}] Usuario {user_map.get(a.user_id, a.user_id)} ejecutó '{a.action}' sobre archivo {a.file_id} desde IP {a.ip_address or 'desconocida'} ({a.details})"
            for a in results
        ],
        "data": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "email": user_map.get(a.user_id),
                "file_id": a.file_id,
                "action": a.action,
                "timestamp": a.timestamp.isoformat(),
                "ip_address": a.ip_address,
                "details": a.details
            } for a in results
        ]
    })
