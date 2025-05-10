from flask import Blueprint
from app.auth.services.oauth import oauth_bp
from app.auth.services.register import register_bp 
from app.auth.services.admin import admin_bp  # 👈 nuevo import

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Registrar servicios
auth_bp.register_blueprint(oauth_bp, url_prefix='/two-factor')
auth_bp.register_blueprint(register_bp, url_prefix='/register')
auth_bp.register_blueprint(admin_bp, url_prefix='/admin')  # 👈 nuevo registro
