
from werkzeug.security import generate_password_hash
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import datetime

from repositorio_seguro.app.db.config import SessionLocal
from repositorio_seguro.app.db.models import User

# 1. Configuración de la base de datos
db = SessionLocal()

# 2. Generar claves pública y privada
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_key_bytes = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_bytes = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 3. Cifrar la clave privada con la SECRET_KEY de tu .env
secret = os.getenv("SIGNATURE_SECRET_KEY")
fernet = Fernet(secret.encode())
encrypted_private_key = fernet.encrypt(private_key_bytes)

# 4. Crear el usuario administrador
admin_user = User(
    email="m5954852@gmail.com",
    password_hash=generate_password_hash("Admin123!"),
    first_name="Admin",
    last_name="User",
    role="admin",
    is_active=True,
    can_upload=True,
    public_key=public_key_bytes,
    encrypted_private_key=encrypted_private_key,
    created_at=datetime.datetime.utcnow()
)

db.add(admin_user)
db.commit()
db.close()

print("✅ Usuario administrador creado exitosamente.")