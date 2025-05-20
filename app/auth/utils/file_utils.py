import secrets
import string
import io
from PyPDF2 import PdfReader, PdfWriter

def generate_secure_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def protect_pdf(file_data, password):
    reader = PdfReader(io.BytesIO(file_data))
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(password)
    output_stream = io.BytesIO()
    writer.write(output_stream)
    return output_stream.getvalue()
