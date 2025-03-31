import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import urllib.parse
from dotenv import load_dotenv

# Cargar variables del entorno
load_dotenv()

# Configuración de la base de datos desde .env
connection_string = (
    "mssql+pyodbc://{username}:{password}@{server},{port}/{database}"
    "?driver={driver}"
).format(
    username=os.getenv("DB_USERNAME"),
    password=urllib.parse.quote_plus(os.getenv("DB_PASSWORD")),
    server=os.getenv("DB_SERVER"),
    port=os.getenv("DB_PORT"),
    database=os.getenv("DB_NAME"),
    driver=urllib.parse.quote_plus(os.getenv("DB_DRIVER"))
)

# Crear engine y sesión
engine = create_engine(connection_string, fast_executemany=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
from app.db.models import Base  # <--- Importación correcta
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()