import secrets
import os
import logging
import bcrypt

from flask import Flask, request, g
from flask_restx import Api, Resource, fields  # type: ignore
from functools import wraps
from dotenv import load_dotenv

from .db import get_connection, init_db
from .jwt_auth import create_jwt_manager, jwt_required
from .validators import (
    validate_cedula, validate_phone, validate_username,
    validate_password, validar_tarjeta_luhn
)
from .logging import registrar_evento, registrar_warning, registrar_error, registrar_info, registrar_debug
from app.utils.otp_manager import verificar_otp
from app.secure_storage import cifrar_dato, descifrar_dato

# Define a simple in-memory token store
tokens = {}

# Funciones auxiliares para registro
def get_client_ip(request):
    """Obtiene la IP real del cliente."""
    ip_remota = request.headers.get('X-Forwarded-For')
    if ip_remota:
        ip_remota = ip_remota.split(',')[0].strip()
    else:
        ip_remota = request.headers.get('X-Real-IP') or request.remote_addr or 'unknown'
    
    if ip_remota.startswith('172.'):
        host_header = request.headers.get('Host', '')
        if 'localhost' in host_header or '127.0.0.1' in host_header:
            ip_remota = '127.0.0.1'
    
    return ip_remota

def hash_password(password):
    """Hashea la contraseña usando bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(plain_password, stored_password):
    """Verifica contraseña hasheada o texto plano."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), stored_password.encode('utf-8'))
    except:
        return plain_password == stored_password

def check_username_exists(username):
    """Verifica si el username ya existe."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM bank.users WHERE username = %s", (username,))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists

def check_cedula_exists(cedula):
    """Verifica si la cédula ya está registrada."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM bank.clients WHERE cedula = %s", (cedula,))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists

# Cargar variables de entorno desde .env
load_dotenv()

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)

# COMENTADO: Esta línea causa error porque LoggingMiddleware no está definido
# logging_middleware = LoggingMiddleware(app)

# Configurar JWT usando variables de entorno
jwt_secret = os.getenv('JWT_SECRET_KEY', 'default-secret-key-change-this')
app.config['JWT_SECRET_KEY'] = jwt_secret
app.jwt_manager = create_jwt_manager(app)

api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

register_model = auth_ns.model('Register', {
    'nombres': fields.String(required=True, description='Nombres del cliente', example='Juan Carlos'),
    'apellidos': fields.String(required=True, description='Apellidos del cliente', example='Pérez González'),
    'direccion': fields.String(required=True, description='Dirección completa', example='Av. 10 de Agosto N24-253 y Cordero'),
    'cedula': fields.String(required=True, description='Número de cédula', example='1234567890'),
    'celular': fields.String(required=True, description='Número celular', example='0987654321'),
    'username': fields.String(required=True, description='Nombre de usuario único', example='juanperez123'),
    'password': fields.String(required=True, description='Contraseña segura', example='MiPass123!'),
    'email': fields.String(required=False, description='Correo electrónico (opcional)', example='juan@email.com')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        """Inicia sesión y devuelve un token JWT de autenticación."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        
        # Obtener IP para logging manual (mejorada para Docker)
        ip_remota = get_client_ip(request)
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and check_password(password, user[2]):  # ← ÚNICO CAMBIO AQUÍ
            user_data = {
                'id': user[0],
                'username': user[1],
                'full_name': user[4],
                'email': user[5]
            }
            
            # Generar token JWT
            token = app.jwt_manager.generate_token(user_data)
            
            cur.close()
            conn.close()
            
            # Log exitoso de login
            registrar_evento('INFO', ip_remota, username, f"Login exitoso - usuario autenticado", 200)
            
            return {"message": "Login successful", "token": token}, 200
        else:
            cur.close()
            conn.close()
            
            # Log de intento fallido de login
            registrar_warning(ip_remota, username or 'unknown', f"Intento de login fallido - credenciales inválidas", 401)
            
            api.abort(401, "Invalid credentials")

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model, validate=True)
    @auth_ns.doc('register')
    def post(self):
        """Registra un nuevo cliente con validaciones completas según TCE-07."""
        data = api.payload
        ip_address = get_client_ip(request)
        
        # Extraer y limpiar datos del cliente
        client_data = {
            'nombres': data.get('nombres', '').strip(),
            'apellidos': data.get('apellidos', '').strip(),
            'direccion': data.get('direccion', '').strip(),
            'cedula': data.get('cedula', '').strip(),
            'celular': data.get('celular', '').strip()
        }
        
        # Extraer y limpiar datos del usuario
        user_data = {
            'username': data.get('username', '').strip(),
            'password': data.get('password', ''),
            'email': data.get('email', '').strip()
        }
        
        # 1. Validar campos requeridos
        if not all([client_data['nombres'], client_data['apellidos'], client_data['direccion'], 
                   client_data['cedula'], client_data['celular'], user_data['username'], user_data['password']]):
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Campos requeridos faltantes", 400)
            api.abort(400, "All required fields must be provided")
        
        # 2. Validar cédula ecuatoriana (debe ser válida)
        if not validate_cedula(client_data['cedula']):
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Cédula inválida: {client_data['cedula']}", 400)
            api.abort(400, "Invalid cedula format or verification digit")
        
        # 3. Validar número celular ecuatoriano (debe ser válido)
        if not validate_phone(client_data['celular']):
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Teléfono inválido", 400)
            api.abort(400, "Invalid phone number format")
        
        # 4. Validar username (solo números y letras, sin información personal)
        username_valid, username_msg = validate_username(user_data['username'], client_data)
        if not username_valid:
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Username inválido: {username_msg}", 400)
            api.abort(400, username_msg)
        
        # 5. Validar contraseña (8+ caracteres, números, letras, símbolos, sin info personal)
        password_valid, password_msg = validate_password(user_data['password'], client_data)
        if not password_valid:
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Contraseña inválida", 400)
            api.abort(400, password_msg)
        
        # 6. Verificar que no existan duplicados
        if check_username_exists(user_data['username']):
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Username ya existe", 409)
            api.abort(409, "Username already exists")
        
        if check_cedula_exists(client_data['cedula']):
            registrar_warning(ip_address, user_data.get('username', 'unknown'), f"POST /auth/register | Intento de registro fallido - Cédula ya registrada", 409)
            api.abort(409, "Cedula already registered")
        
        # 7. Crear registros en base de datos (información separada)
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Insertar cliente (información personal independiente)
            cur.execute("""
                INSERT INTO bank.clients (nombres, apellidos, direccion, cedula, celular, ip_registro)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                client_data['nombres'],
                client_data['apellidos'], 
                client_data['direccion'],
                client_data['cedula'],
                client_data['celular'],
                ip_address  # Guardar IP del usuario
            ))
            
            client_id = cur.fetchone()[0]
            
            # Insertar usuario (información de acceso independiente)
            full_name = f"{client_data['nombres']} {client_data['apellidos']}"
            hashed_password = hash_password(user_data['password'])
            
            cur.execute("""
                INSERT INTO bank.users (username, password, role, full_name, email, client_id)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                user_data['username'],
                hashed_password,
                'cliente',
                full_name,
                user_data.get('email', ''),
                client_id
            ))
            
            user_id = cur.fetchone()[0]
            
            # Crear cuenta bancaria inicial
            cur.execute("""
                INSERT INTO bank.accounts (balance, user_id)
                VALUES (%s, %s)
            """, (0, user_id))
            
            # Crear tarjeta de crédito inicial
            cur.execute("""
                INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                VALUES (%s, %s, %s)
            """, (1000, 0, user_id))
            
            conn.commit()
            
            # Log del registro exitoso
            registrar_info(ip_address, user_data['username'], f"Registro exitoso - cliente_id: {client_id}", 201)
            
            return {
                "message": "Registration successful",
                "user_id": user_id,
                "client_id": client_id
            }, 201
            
        except Exception as db_error:
            conn.rollback()
            registrar_error(ip_address, user_data.get('username', 'unknown'), f"Error en base de datos durante registro: {str(db_error)}", 500)
            api.abort(500, f"Database error during registration: {str(db_error)}")
            
        finally:
            cur.close()
            conn.close()

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    @jwt_required
    def post(self):
        """Invalida el token de autenticación (JWT no requiere invalidación en servidor)."""
        return {"message": "Logout successful"}, 200

# ---------------- Token-Required Decorator ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        
        # Obtener IP para logging manual 
        ip_remota = get_client_ip(request)
        
        if not auth_header.startswith("Bearer "):
            registrar_warning(ip_remota, 'anon', "Acceso denegado - header de autorización faltante o inválido", 401)
            api.abort(401, "Authorization header missing or invalid")
            
        token = auth_header.split(" ")[1]
        
        try:
            conn = get_connection()
            cur = conn.cursor()
            # Query the token in the database and join with users table to retrieve user info
            cur.execute("""
                SELECT u.id, u.username, u.role, u.full_name, u.email 
                FROM bank.tokens t
                JOIN bank.users u ON t.user_id = u.id
                WHERE t.token = %s
            """, (token,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            
            if not user:
                registrar_warning(ip_remota, 'token_invalido', "Acceso denegado - token inválido o expirado", 401)
                api.abort(401, "Invalid or expired token")
                
            g.user = {
                "id": user[0],
                "username": user[1],
                "role": user[2],
                "full_name": user[3],
                "email": user[4]
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            registrar_error(ip_remota, 'system', f"Error en validación de token: {str(e)}", 500)
            api.abort(500, "Internal server error during authentication")
            
    return decorated

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @jwt_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        
        # Obtener información del usuario y IP
        ip_remota = get_client_ip(request)
        current_user = g.user.get('username', 'unknown') if hasattr(g, 'user') and g.user else 'unknown'
        
        if amount <= 0:
            registrar_warning(ip_remota, current_user, f"POST /bank/deposit | datos: {{account_number:{account_number}, amount:{amount}}} | respuesta: 400 Bad Request - Amount must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
        
        try:
            conn = get_connection()
            cur = conn.cursor()
            # Update the specified account using its account number (primary key)
            cur.execute(
                "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
                (amount, account_number)
            )
            result = cur.fetchone()
            if not result:
                conn.rollback()
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/deposit | datos: {{account_number:***, amount}} | respuesta: 404 Not Found - Account not found", 404)
                api.abort(404, "Account not found")
            
            new_balance = float(result[0])
            conn.commit()
            cur.close()
            conn.close()
            
            # Log de operación exitosa
            registrar_info(ip_remota, current_user, f"POST /bank/deposit | datos: {{account_number:***, amount}} | respuesta: 200 OK", 200)
            
            return {"message": "Deposit successful", "new_balance": new_balance}, 200
            
        except Exception as e:
            registrar_error(ip_remota, current_user, f"POST /bank/deposit | Error en depósito: {str(e)}", 500)
            api.abort(500, f"Error processing deposit: {str(e)}")

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @jwt_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        
        # Obtener información del usuario y IP
        ip_remota = get_client_ip(request)
        current_user = g.user.get('username', 'unknown') if hasattr(g, 'user') and g.user else 'unknown'
        
        if amount <= 0:
            registrar_warning(ip_remota, current_user, f"POST /bank/withdraw | datos: {{amount:{amount}}} | respuesta: 400 Bad Request - Amount must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
            
        user_id = g.user['id']
        
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/withdraw | datos: {{amount}} | respuesta: 404 Not Found - Account not found", 404)
                api.abort(404, "Account not found")
                
            current_balance = float(row[0])
            if current_balance < amount:
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/withdraw | datos: {{amount}} | respuesta: 400 Bad Request - Insufficient funds", 400)
                api.abort(400, "Insufficient funds")
                
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            cur.close()
            conn.close()
            
            # Log de operación exitosa
            registrar_info(ip_remota, current_user, f"POST /bank/withdraw | datos: {{amount}} | respuesta: 200 OK", 200)
            
            return {"message": "Withdrawal successful", "new_balance": new_balance}, 200
            
        except Exception as e:
            registrar_error(ip_remota, current_user, f"POST /bank/withdraw | Error en retiro: {str(e)}", 500)
            api.abort(500, f"Error processing withdrawal: {str(e)}")

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @jwt_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        
        # Obtener información del usuario y IP
        ip_remota = get_client_ip(request)
        current_user = g.user.get('username', 'unknown') if hasattr(g, 'user') and g.user else 'unknown'
        
        if not target_username or amount <= 0:
            registrar_warning(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username:{target_username}, amount:{amount}}} | respuesta: 400 Bad Request - Invalid data", 400)
            api.abort(400, "Invalid data")
            
        if target_username == g.user['username']:
            registrar_warning(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username:{target_username}, amount}} | respuesta: 400 Bad Request - Cannot transfer to the same account", 400)
            api.abort(400, "Cannot transfer to the same account")
            
        try:
            conn = get_connection()
            cur = conn.cursor()
            # Check sender's balance
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            row = cur.fetchone()
            if not row:
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username, amount}} | respuesta: 404 Not Found - Sender account not found", 404)
                api.abort(404, "Sender account not found")
                
            sender_balance = float(row[0])
            if sender_balance < amount:
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username, amount}} | respuesta: 400 Bad Request - Insufficient funds", 400)
                api.abort(400, "Insufficient funds")
                
            # Find target user
            cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
            target_user = cur.fetchone()
            if not target_user:
                cur.close()
                conn.close()
                registrar_warning(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username, amount}} | respuesta: 404 Not Found - Target user not found", 404)
                api.abort(404, "Target user not found")
                
            target_user_id = target_user[0]
            
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            cur.close()
            conn.close()
            
            # Log de operación exitosa
            registrar_info(ip_remota, current_user, f"POST /bank/transfer | datos: {{target_username, amount}} | respuesta: 200 OK", 200)
            
            return {"message": "Transfer successful", "new_balance": new_balance}, 200
            
        except Exception as e:
            registrar_error(ip_remota, current_user, f"POST /bank/transfer | Error en transferencia: {str(e)}", 500)
            api.abort(500, f"Error processing transfer: {str(e)}")

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.doc('credit_payment_secure')
    @jwt_required
    def post(self):
        """
        Realiza una compra segura con tarjeta de crédito:
        - Valida tarjeta (Luhn)
        - Verifica OTP
        - Cifra y guarda datos si no existen
        - Verifica comercio registrado
        - Registra compra
        - Loggea eventos relevantes
        """
        data = request.get_json()
        user_id = g.user['id']
        current_user = g.user.get('username', 'unknown')
        ip_remota = get_client_ip(request)

        campos = ['amount', 'card_number', 'cvv', 'expiry', 'otp', 'store_id']
        if not all(k in data for k in campos):
            registrar_warning(ip_remota, current_user, "Faltan campos requeridos", 400)
            return {"message": "Faltan campos requeridos"}, 400

        amount = float(data['amount'])
        if amount <= 0:
            registrar_warning(ip_remota, current_user, "Monto inválido", 400)
            return {"message": "Monto inválido"}, 400

        card_number = data['card_number'].replace(" ", "")
        cvv = data['cvv']
        expiry = data['expiry']
        otp = data['otp']
        store_id = data['store_id']

        if not validar_tarjeta_luhn(card_number):
            registrar_warning(ip_remota, current_user, "Número de tarjeta inválido", 400)
            return {"message": "Número de tarjeta inválido"}, 400

        if not verificar_otp(user_id, otp):
            registrar_warning(ip_remota, current_user, "OTP inválido o expirado", 401)
            return {"message": "OTP inválido o expirado"}, 401

        conn = get_connection()
        cur = conn.cursor()

        try:
            # Validar establecimiento
            cur.execute("SELECT id FROM bank.establishments WHERE id = %s AND estado = TRUE", (store_id,))
            comercio = cur.fetchone()
            if not comercio:
                registrar_warning(ip_remota, current_user, f"Establecimiento no registrado: {store_id}", 400)
                return {"message": "Establecimiento no registrado"}, 400

            # Validar fondos
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            cuenta = cur.fetchone()
            if not cuenta or float(cuenta[0]) < amount:
                registrar_warning(ip_remota, current_user, "Fondos insuficientes", 400)
                return {"message": "Fondos insuficientes"}, 400

            # Verificar si ya existe la tarjeta cifrada
            tarjeta_cifrada = cifrar_dato(card_number)
            cur.execute("""
                SELECT id FROM bank.secure_cards 
                WHERE user_id = %s AND card_number = %s
            """, (user_id, tarjeta_cifrada))
            tarjeta_existente = cur.fetchone()

            if not tarjeta_existente:
                cur.execute("""
                    INSERT INTO bank.secure_cards (user_id, card_number, cvv, expiry)
                    VALUES (%s, %s, %s, %s)
                """, (
                    user_id,
                    tarjeta_cifrada,
                    cifrar_dato(cvv),
                    cifrar_dato(expiry)
                ))

            # Realizar transacción
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))

            # Obtener nuevos balances
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])

            conn.commit()

            registrar_info(ip_remota, current_user, f"Compra exitosa por ${amount} en establecimiento {store_id}", 200)

            return {
                "message": "Compra a crédito exitosa",
                "store_id": store_id,
                "amount": amount,
                "account_balance": new_account_balance,
                "credit_card_debt": new_credit_balance
            }, 200

        except Exception as e:
            conn.rollback()
            registrar_error(ip_remota, current_user, f"Error en compra a crédito: {str(e)}", 500)
            return {"message": f"Error en la operación: {str(e)}"}, 500

        finally:
            cur.close()
            conn.close()

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(bank_ns.model('SecurePayCreditBalance', {
        'amount': fields.Float(required=True, description='Monto a pagar'),
        'first6': fields.String(required=True, description='Primeros 6 dígitos de la tarjeta'),
        'otp': fields.String(required=True, description='Código OTP'),
        'card_number': fields.String(required=True, description='Número completo de tarjeta'),
        'cvv': fields.String(required=True, description='CVV'),
        'expiry': fields.String(required=True, description='Fecha de expiración MM/YY'),
    }), validate=True)
    @bank_ns.doc('secure_pay_credit_balance')
    @jwt_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta (cumple TCE-05):
        - Valida primeros 6 dígitos vs tarjeta.
        - Valida tarjeta (Luhn) y OTP.
        - Permite tarjetas internas y externas.
        - Cifra y guarda datos si es nueva tarjeta.
        - Registra logs detallados.
        """
        data = api.payload
        user_id = g.user['id']
        current_user = g.user.get('username', 'unknown')
        ip_remota = get_client_ip(request)

        amount = float(data.get("amount", 0))
        otp = data.get("otp")
        first6 = data.get("first6")
        full_card = data.get("card_number").replace(" ", "")
        cvv = data.get("cvv")
        expiry = data.get("expiry")

        if amount <= 0:
            registrar_warning(ip_remota, current_user, f"/pay-credit-balance | Monto inválido", 400)
            api.abort(400, "Amount must be greater than zero")

        if not validar_tarjeta_luhn(full_card):
            registrar_warning(ip_remota, current_user, f"/pay-credit-balance | Tarjeta inválida", 400)
            api.abort(400, "Número de tarjeta inválido")

        if not full_card.startswith(first6):
            registrar_warning(ip_remota, current_user, f"/pay-credit-balance | 6 dígitos no coinciden", 400)
            api.abort(400, "Los primeros 6 dígitos no coinciden con la tarjeta")

        if not verificar_otp(user_id, otp):
            registrar_warning(ip_remota, current_user, f"/pay-credit-balance | OTP inválido", 401)
            api.abort(401, "OTP inválido o expirado")

        conn = get_connection()
        cur = conn.cursor()

        try:
            tarjeta_cifrada = cifrar_dato(full_card)

            # Verificar si es tarjeta interna
            cur.execute("""
                SELECT id FROM bank.secure_cards 
                WHERE user_id = %s AND card_number = %s
            """, (user_id, tarjeta_cifrada))
            es_tarjeta_interna = cur.fetchone() is not None

            # Obtener fondos del usuario
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            cuenta = cur.fetchone()
            if not cuenta or float(cuenta[0]) < amount:
                registrar_warning(ip_remota, current_user, f"/pay-credit-balance | Fondos insuficientes", 400)
                return {"message": "Fondos insuficientes"}, 400

            account_balance = float(cuenta[0])

            # Obtener deuda de la tarjeta
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            deuda = cur.fetchone()
            if not deuda:
                registrar_warning(ip_remota, current_user, f"/pay-credit-balance | No hay tarjeta de crédito", 404)
                return {"message": "No se encontró tarjeta de crédito"}, 404

            credit_debt = float(deuda[0])
            payment = min(amount, credit_debt)

            # Descontar saldos
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))

            # Guardar tarjeta si es externa
            if not es_tarjeta_interna:
                masked_card = f"{full_card[:6]}******{full_card[-4:]}"
                cur.execute("""
                    SELECT id FROM bank.stored_cards 
                    WHERE user_id = %s AND encrypted_card_number = %s
                """, (user_id, tarjeta_cifrada))
                existente = cur.fetchone()

                if not existente:
                    cur.execute("""
                        INSERT INTO bank.stored_cards (
                            user_id, masked_card, encrypted_card_number,
                            encrypted_expiry, encrypted_cvv
                        )
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        user_id,
                        masked_card,
                        tarjeta_cifrada,
                        cifrar_dato(expiry),
                        cifrar_dato(cvv)
                    ))

            # Confirmar nuevos saldos
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            nuevo_saldo = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            nueva_deuda = float(cur.fetchone()[0])

            conn.commit()

            registrar_info(ip_remota, current_user, f"/pay-credit-balance | Pago exitoso ${payment}", 200)

            return {
                "message": "Pago exitoso de deuda con tarjeta",
                "account_balance": nuevo_saldo,
                "credit_card_debt": nueva_deuda
            }, 200

        except Exception as e:
            conn.rollback()
            registrar_error(ip_remota, current_user, f"/pay-credit-balance | Error en operación: {str(e)}", 500)
            return {"message": f"Error durante la operación: {str(e)}"}, 500

        finally:
            cur.close()
            conn.close()

@bank_ns.route('/my-cards')
class MyCards(Resource):
    @bank_ns.doc('get_user_cards')
    @jwt_required
    def get(self):
        """
        Devuelve todas las tarjetas registradas por el usuario:
        - Internas (`secure_cards`) con deuda
        - Externas (`stored_cards`)
        Todos los números están enmascarados.
        """
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()

        tarjetas = []

        try:
            # Tarjetas internas (secure_cards)
            cur.execute("""
                SELECT card_number, expiry, balance 
                FROM bank.secure_cards sc
                JOIN bank.credit_cards cc ON sc.user_id = cc.user_id
                WHERE sc.user_id = %s
            """, (user_id,))
            for row in cur.fetchall():
                card = descifrar_dato(row[0])
                masked = f"{card[:6]}******{card[-4:]}"
                tarjetas.append({
                    "type": "secure",
                    "card": masked,
                    "expiry": descifrar_dato(row[1]),
                    "debt": float(row[2])
                })

            # Tarjetas externas (stored_cards)
            cur.execute("""
                SELECT masked_card, encrypted_expiry 
                FROM bank.stored_cards 
                WHERE user_id = %s
            """, (user_id,))
            for row in cur.fetchall():
                tarjetas.append({
                    "type": "stored",
                    "card": row[0],
                    "expiry": descifrar_dato(row[1]),
                    "debt": None
                })

            return {"cards": tarjetas}, 200

        except Exception as e:
            conn.rollback()
            return {"message": f"Error obteniendo tarjetas: {str(e)}"}, 500

        finally:
            cur.close()
            conn.close()

# CORREGIDO: Usar el nuevo decorador para Flask 2.0+
@app.before_request
def initialize_db():
    """Inicializar la base de datos antes de la primera request."""
    if not hasattr(g, 'db_initialized'):
        init_db()
        g.db_initialized = True

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)