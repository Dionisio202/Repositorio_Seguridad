from sqlalchemy import Column, Integer, LargeBinary, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)

    # Campos de 2FA
    otp_code = Column(String(6), nullable=True)
    otp_expires = Column(DateTime, nullable=True)

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
    file_data = Column(LargeBinary, nullable=False) # Almacena el archivo binario
    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
