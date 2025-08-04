# app/db.py
import os
import psycopg2

# Se obtienen las variables de entorno definidas en docker-compose o se usan valores por defecto.
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def get_connection():
    """
    Establece y devuelve una conexión con la base de datos PostgreSQL.
    Usa las credenciales configuradas mediante variables de entorno.
    """
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn

def init_db():
    """
    Inicializa la base de datos creando el esquema 'bank' y todas las tablas necesarias.
    También inserta datos de ejemplo (usuarios, cuentas y tarjetas de crédito) si no existen.
    """
    conn = get_connection()
    cur = conn.cursor()
    
    # 
    # CREACIÓN DEL SCHEMA
    #
    # Crear schema
    cur.execute("CREATE SCHEMA IF NOT EXISTS bank AUTHORIZATION postgres;")
    
    # Crear la tabla de clientes PRIMERO (información personal separada) y almacena datos personales de los clientes de manera independiente de las credenciales de acceso.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.clients (
        id SERIAL PRIMARY KEY,
        nombres VARCHAR(100) NOT NULL,
        apellidos VARCHAR(100) NOT NULL,
        direccion TEXT NOT NULL,
        cedula VARCHAR(10) UNIQUE NOT NULL,
        celular VARCHAR(15) NOT NULL,
        ip_registro INET,
        fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # 
    # TABLA: USUARIOS
    # 
    # Crear la tabla de usuarios CON client_id como foreign key y almacena credenciales de acceso y relación con el cliente (separación de datos sensibles).
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        client_id INTEGER REFERENCES bank.clients(id)
    );
    """)
    # 
    # TABLA: CUENTAS BANCARIAS
    # 
    # Crear la tabla de cuentas y esta relacionada a los usuarios. Maneja el saldo de cada cuenta.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.accounts (
        id SERIAL PRIMARY KEY,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    );
    """)
    #
    # TABLA: TARJETAS DE CRÉDITO
    # 
    # Crear la tabla de tarjetas de crédito y se tiene un control de las tarjetas de crédito de los usuarios.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.credit_cards (
        id SERIAL PRIMARY KEY,
        limit_credit NUMERIC NOT NULL DEFAULT 1000,
        balance NUMERIC NOT NULL DEFAULT 0,
        user_id INTEGER REFERENCES bank.users(id)
    );
    """)
    # 
    # TABLA: TOKENS DE AUTENTICACIÓN
    # 
    # Crear tabla de tokens para autenticación y asi almacena tokens temporales para mantener sesiones seguras.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 
    # TABLA: TARJETAS SEGURAS
    # 
    # para garantizar la confidencialidad de la información sensible y asi se almacenan datos de tarjetas de manera cifrada para proteger información sensible.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.secure_cards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        card_number TEXT NOT NULL,
        cvv TEXT NOT NULL,
        expiry TEXT NOT NULL,
        encrypted BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # 
    # TABLA: ESTABLECIMIENTOS
    # 
    # Crear tabla de establecimientos registrados asi como los comercios en los que los usuarios pueden realizar pagos.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.establishments (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        codigo TEXT UNIQUE NOT NULL,
        estado BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # 
    # TABLA: TARJETAS EXTERNAS
    # 
    # Crear tabla para registrar tarjetas externas seguras.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bank.stored_cards (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES bank.users(id),
        masked_card TEXT NOT NULL,
        encrypted_card_number TEXT NOT NULL,
        encrypted_expiry TEXT NOT NULL,
        encrypted_cvv TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Insertar datos de ejemplo si no existen usuarios es decir se crean usuarios de prueba solo si la tabla 'users' está vacía.
    cur.execute("SELECT COUNT(*) FROM bank.users;")
    count = cur.fetchone()[0]
    if count == 0:
        sample_users = [
            ('user1', 'pass1', 'cliente', 'Usuario Uno', 'user1@example.com'),
            ('user2', 'pass2', 'cliente', 'Usuario Dos', 'user2@example.com'),
            ('user3', 'pass3', 'cajero',  'Usuario Tres', 'user3@example.com')
        ]
        for username, password, role, full_name, email in sample_users:
            cur.execute("""
                INSERT INTO bank.users (username, password, role, full_name, email)
                VALUES (%s, %s, %s, %s, %s) RETURNING id;
            """, (username, password, role, full_name, email))
            user_id = cur.fetchone()[0]
            # Crear una cuenta con saldo inicial 1000
            cur.execute("""
                INSERT INTO bank.accounts (balance, user_id)
                VALUES (%s, %s);
            """, (1000, user_id))
            # Crear una tarjeta de crédito con límite 5000 y deuda 0
            cur.execute("""
                INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                VALUES (%s, %s, %s);
            """, (5000, 0, user_id))
    
    conn.commit()
    cur.close()
    conn.close()
