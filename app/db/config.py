import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import urllib.parse
from dotenv import load_dotenv

# Cargar variables del entorno
load_dotenv()

connection_string = (
    "mssql+pyodbc://@{server},{port}/{database}"
    "?driver={driver}&trusted_connection=yes"
).format(
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