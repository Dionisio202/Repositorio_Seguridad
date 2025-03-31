import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import ssl
from app.core.config import settings
def send_otp_email(to_email: str, code: str):
    """
    Envía un correo con un código OTP de verificación.
    """
    # Obtén las credenciales desde la configuración
    sender_email = settings.OUTLOOK_USER
    sender_password = settings.OUTLOOK_PASS
    smtp_server = settings.OUTLOOK_HOST
    smtp_port = settings.OUTLOOK_PORT

    subject = "Tu código de verificación (2FA)"
    body = f"Hola,\n\nTu código de verificación es: {code}\n\nSi no lo solicitaste tú, ignora este correo."
    print(f"Enviando código de verificación a {to_email}")
    print(f"Código: {code}")
    print(f"Correo: {sender_email}")
    print(f"Servidor SMTP: {smtp_server}")
    print(f"Puerto SMTP: {smtp_port}")
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = Header(subject, "utf-8")
    
    message.attach(MIMEText(body, "plain", "utf-8"))

    try:
        # Configurar el contexto SSL personalizado similar a tu código JS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Similar a rejectUnauthorized: false
        
        # Conexión y envío
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()  # Puede ayudar en algunos casos
        server.starttls(context=context)
        server.ehlo()  # Recomendado después de STARTTLS
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, message.as_string())
        server.quit()
        
        print(f"✅ Correo enviado a {to_email}")
        return True
    except Exception as e:
        print(f"❌ Error al enviar correo a {to_email}: {str(e)}")
        raise e