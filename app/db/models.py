from datetime import datetime
import uuid
from sqlalchemy import Column, ForeignKey, Integer, LargeBinary, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False)
    attempt_time = Column(DateTime, default=datetime.utcnow) 

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    # Rol y estado
    role = Column(String(50), default="user")  # 'admin' o 'user'
    is_active = Column(Boolean, default=True)
    can_upload = Column(Boolean, default=False)
    # Tiempos
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    public_key = Column(LargeBinary, nullable=True)
    encrypted_private_key = Column(LargeBinary, nullable=True)  # ← firma cifrada

    
class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_data = Column(LargeBinary(length=4294967295), nullable=False)
    signature = Column(LargeBinary, nullable=True) 
    file_hash = Column(String(64), nullable=True)  
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)




class ActiveSession(Base):
    __tablename__ = 'active_sessions'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey('users.id'))
    token_hash = Column(String(255), nullable=False)  # Guarda solo hash del token
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # ✅ Se actualiza automáticamente
    is_active = Column(Boolean, default=True)

class DownloadHistory(Base):
    __tablename__ = "download_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    file_id = Column(Integer, ForeignKey('files.id'), nullable=False)
    download_time = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

class FilePermission(Base):
    __tablename__ = "file_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey('files.id'), nullable=False)
    granted_user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow)
    permission_type = Column(String(20), nullable=False, default="view")  # "view", "download", "both"

class FileAuditLog(Base):
    __tablename__ = "file_audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    file_id = Column(Integer, nullable=False)
    action = Column(String(20), nullable=False)  # 'update', 'delete'
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    details = Column(String(500))  # Texto libre para cambios específicos
