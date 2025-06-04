from app.db.config import SessionLocal
from app.db.models import User
from werkzeug.security import generate_password_hash
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import datetime

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

# 3. Cargar claves para cifrado
signature_secret = os.getenv("SIGNATURE_SECRET_KEY")
fernet_secret = os.getenv("FERNET_KEY")

if not signature_secret or not fernet_secret:
    raise Exception("Las claves SIGNATURE_SECRET_KEY y FERNET_KEY no están definidas en el .env.")

fernet_private_key = Fernet(signature_secret.encode())
fernet_name = Fernet(fernet_secret.encode())

# 4. Cifrar la clave privada y los nombres
encrypted_private_key = fernet_private_key.encrypt(private_key_bytes)
encrypted_first_name = fernet_name.encrypt("Admin".encode())
encrypted_last_name = fernet_name.encrypt("User".encode())

# 5. Crear el usuario administrador
admin_user = User(
    email="m5954852@gmail.com",
    password_hash=generate_password_hash("Admin123!"),
    first_name=encrypted_first_name,
    last_name=encrypted_last_name,
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