from flask import Blueprint
#from app.auth.services.facial import facial_bp
from app.auth.services.oauth import oauth_bp
from app.auth.services.register import register_bp 
# Crea el Blueprint 'auth_bp' aquí
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
register_bpm = Blueprint('register', __name__, url_prefix='/register')

# Registra los demás blueprints bajo 'auth_bp'
#auth_bp.register_blueprint(facial_bp, url_prefix='/facial')
auth_bp.register_blueprint(oauth_bp, url_prefix='/two-factor')
register_bp.register_blueprint(register_bpm)