from datetime import datetime
from sqlalchemy import Column, Integer, LargeBinary, String, DateTime, Boolean
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
    user_id = Column(Integer, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_data = Column(LargeBinary(length=4294967295), nullable=False)
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class FilePermission(Base):
    __tablename__ = "file_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, nullable=False)   # Archivo compartido
    granted_user_id = Column(Integer, nullable=False)  # Usuario con permiso
    granted_at = Column(DateTime, default=datetime.utcnow)
