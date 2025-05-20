import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import ssl
from app.core.config import settings

def send_otp_email(to_email, link=None):
    """
    Envía un correo con un código OTP de verificación.
    """
    # Obtén las credenciales desde la configuración
    sender_email = settings.OUTLOOK_USER
    sender_password = settings.OUTLOOK_PASS
    smtp_server = settings.OUTLOOK_HOST
    smtp_port = settings.OUTLOOK_PORT

    subject = "FortiDocs"
    
    # Crear mensaje HTML atractivo
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }}
            .container {{
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                padding: 25px;
                background-color: #f9f9f9;
            }}
            .header {{
                text-align: center;
                margin-bottom: 20px;
                border-bottom: 2px solid #4a90e2;
                padding-bottom: 10px;
            }}
            .title {{
                color: #2c3e50;
                font-size: 24px;
                margin: 0;
            }}
            .btn {{
                display: inline-block;
                background-color: #4a90e2;
                color: white;
                text-decoration: none;
                padding: 12px 24px;
                border-radius: 5px;
                font-weight: bold;
                margin: 20px 0;
                text-align: center;
            }}
            .btn:hover {{
                background-color: #3a7bc8;
            }}
            .warning {{
                background-color: #fff8e1;
                border-left: 4px solid #ffc107;
                padding: 12px;
                margin: 20px 0;
            }}
            .footer {{
                margin-top: 30px;
                text-align: center;
                font-size: 12px;
                color: #777;
                border-top: 1px solid #e0e0e0;
                padding-top: 15px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="title">🔐 Verificacion de cuenta </h1>
            </div>
            
            <p>¡Hola!</p>
            
            <p>Has solicitado verificar tu acceso a tu cuenta. Para completar este proceso de seguridad, por favor:</p>
            
            <div style="text-align: center;">
                <a href="{link}" class="btn">VERIFICAR MI ACCESO ➡️</a>
            </div>
            
            <div class="warning">
                <strong>¿No reconoces esta actividad?</strong>
                <p>Si no solicitaste este código de verificación, ignora este correo y considera cambiar tu contraseña por seguridad.</p>
            </div>
            
            <div class="footer">
                <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Versión en texto plano como respaldo
    text_body = f"Hola,\n\nHaz clic en el siguiente enlace para verificar tu acceso: {link}\n\nSi no lo solicitaste tú, ignora este correo."
    
    print(f"Correo: {sender_email}")
    print(f"Servidor SMTP: {smtp_server}")
    print(f"Puerto SMTP: {smtp_port}")
    
    message = MIMEMultipart("alternative")
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = Header(subject, "utf-8")
    
    # Adjuntar ambas versiones - primero texto plano y luego HTML
    # El cliente de correo usará la última versión que pueda mostrar
    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

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
    

def send_password_email(to_email, password, filename):
    """
    Envía un correo al usuario con la contraseña para abrir un archivo PDF.
    """
    sender_email = settings.OUTLOOK_USER
    sender_password = settings.OUTLOOK_PASS
    smtp_server = settings.OUTLOOK_HOST
    smtp_port = settings.OUTLOOK_PORT

    subject = f"🔐 Contraseña para abrir el archivo '{filename}'"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family: Arial, sans-serif;">
        <h2>🔐 Tu archivo ha sido protegido</h2>
        <p>Has descargado el archivo: <strong>{filename}</strong></p>
        <p>Para abrirlo, necesitas la siguiente contraseña:</p>
        <p style="font-size: 20px; font-weight: bold; color: #2c3e50;">{password}</p>
        <p>⚠️ Guarda esta contraseña en un lugar seguro.</p>
        <hr>
        <p style="font-size: 12px; color: #888;">Este es un mensaje automático. No respondas a este correo.</p>
    </body>
    </html>
    """

    text_body = f"""
    Has descargado el archivo: {filename}
    Contraseña para abrir el PDF: {password}
    Guarda esta contraseña en un lugar seguro.
    """

    message = MIMEMultipart("alternative")
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = Header(subject, "utf-8")

    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, message.as_string())
        server.quit()

        print(f"✅ Contraseña enviada a {to_email}")
        return True
    except Exception as e:
        print(f"❌ Error al enviar contraseña a {to_email}: {str(e)}")
        raise e
