"""
JWT Authentication Module
Maneja la autenticación JWT para la API bancaria
"""

import jwt
import datetime
import os
from functools import wraps
from flask import request, g, current_app
from flask_restx import abort
from dotenv import load_dotenv
from .db import get_connection

# Cargar variables de entorno
load_dotenv()


class JWTManager:
    """Gestor de tokens JWT para autenticación"""
    
    def __init__(self, secret_key, algorithm='HS256', token_expiry_hours=0.10):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry_hours = token_expiry_hours
    
    def generate_token(self, user_data):
        """
        Genera un token JWT para el usuario
        
        Args:
            user_data (dict): Datos del usuario (id, username, role, etc.)
            
        Returns:
            str: Token JWT
        """
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'full_name': user_data['full_name'],
            'email': user_data['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=self.token_expiry_hours),
            'iat': datetime.datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token):
        """
        Verifica y decodifica un token JWT
        
        Args:
            token (str): Token JWT a verificar
            
        Returns:
            dict: Datos del usuario si el token es válido
            None: Si el token es inválido o expirado
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def get_user_from_db(self, user_id):
        """
        Obtiene datos actualizados del usuario desde la base de datos
        
        Args:
            user_id (int): ID del usuario
            
        Returns:
            dict: Datos del usuario o None si no existe
        """
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT id, username, role, full_name, email 
            FROM bank.users 
            WHERE id = %s
        """, (user_id,))
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user:
            return {
                "id": user[0],
                "username": user[1],
                "role": user[2],
                "full_name": user[3],
                "email": user[4]
            }
        return None


def create_jwt_manager(app):
    """
    Crea y configura el gestor JWT para la aplicación
    
    Args:
        app: Instancia de Flask
        
    Returns:
        JWTManager: Instancia configurada del gestor JWT
    """
    # Usar la clave secreta del .env o una por defecto (menos segura)
    secret_key = os.getenv('JWT_SECRET_KEY', 'fallback-key-change-in-production')
    
    # Usar tiempo de expiración del .env o valor por defecto (15 minutos)
    expiry_hours = float(os.getenv('JWT_EXPIRATION_HOURS', 0.25))
    
    return JWTManager(secret_key, token_expiry_hours=expiry_hours)


def jwt_required(f):
    """
    Decorador que requiere autenticación JWT válida
    Reemplaza el decorador token_required existente
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Obtener el header de autorización
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            abort(401, "Authorization header missing or invalid")
        
        # Extraer el token
        token = auth_header.split(" ")[1]
        
        # Obtener el gestor JWT desde el contexto de la aplicación
        jwt_manager = current_app.jwt_manager
        
        # Verificar el token
        payload = jwt_manager.verify_token(token)
        if not payload:
            abort(401, "Invalid or expired token")
        
        # Verificar que el usuario aún existe en la base de datos
        user_data = jwt_manager.get_user_from_db(payload['user_id'])
        if not user_data:
            abort(401, "User no longer exists")
        
        # Almacenar los datos del usuario en el contexto global
        g.user = user_data
        
        return f(*args, **kwargs)
    
    return decorated