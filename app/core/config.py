import os
from dotenv import load_dotenv

load_dotenv()  # Carga las variables del archivo .env

class Settings:
    OUTLOOK_USER: str = os.getenv("OUTLOOK_USER")
    OUTLOOK_PASS: str = os.getenv("OUTLOOK_PASS")
    OUTLOOK_HOST: str = os.getenv("OUTLOOK_HOST", "smtp-mail.outlook.com")
    OUTLOOK_PORT: int = int(os.getenv("OUTLOOK_PORT", 587))

settings = Settings()
