# app/logging/logger.py
"""
Sistema de logging personalizado para el Core Bancario.
Implementación propia sin uso de librerías externas de logging.

Características:
- Registra eventos en base de datos PostgreSQL
- Formato de fecha y hora: YYYY-MM-DD HH:MM:SS.ssss (hora local)
- Tipos de log: INFO, DEBUG, WARNING, ERROR
- Información de trazabilidad: IP, usuario, acción, código HTTP
"""

import os
import psycopg2
from datetime import datetime, timedelta
from typing import Optional

# Variables de entorno para conexión a PostgreSQL (reutilizando configuración de db.py)
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def obtener_hora_local() -> str:
    """
    Obtiene la hora local sin usar librerías externas.
    Implementa varios métodos de respaldo para diferentes entornos.
    
    Returns:
        str: Fecha y hora en formato YYYY-MM-DD HH:MM:SS.ssss
    """
    try:
        # Método 1: datetime.now() - debería dar hora local del sistema
        hora_local = datetime.now()
        
        # Verificar si estamos en Docker y la hora parece UTC
        # (heurística: si la diferencia con UTC es 0, probablemente estamos en UTC)
        hora_utc = datetime.utcnow()
        diferencia = abs((hora_local - hora_utc).total_seconds())
        
        # Si la diferencia es menor a 60 segundos, probablemente estamos en UTC
        if diferencia < 60:
            # Método 2: Ajustar manualmente para Ecuador (UTC-5)
            # Puedes cambiar las horas según tu zona horaria
            hora_local = hora_utc - timedelta(hours=5)
            
        return hora_local.strftime('%Y-%m-%d %H:%M:%S.%f')[:-2]
        
    except Exception:
        # Método de respaldo: usar UTC si todo falla
        return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-2]

def obtener_conexion_logs():
    """
    Obtiene una conexión a PostgreSQL para el sistema de logs.
    Reutiliza la configuración de variables de entorno del sistema principal.
    
    Returns:
        psycopg2.connection: Conexión a la base de datos
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return conn
    except psycopg2.Error as e:
        print(f"Error conectando a la base de datos para logs: {e}")
        return None

def inicializar_tabla_logs():
    """
    Crea la tabla logs_sistema si no existe.
    Se ejecuta automáticamente al importar el módulo.
    """
    conn = obtener_conexion_logs()
    if not conn:
        return
    
    try:
        cur = conn.cursor()
        
        # Crear la tabla de logs del sistema
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs_sistema (
                id_log SERIAL PRIMARY KEY,
                fecha_hora TIMESTAMP NOT NULL,
                tipo_log VARCHAR(10) NOT NULL,
                ip_remota VARCHAR(45) NOT NULL,
                usuario VARCHAR(100) NOT NULL,
                accion TEXT NOT NULL,
                codigo_http INT NOT NULL,
                CONSTRAINT check_tipo_log CHECK (tipo_log IN ('INFO', 'DEBUG', 'WARNING', 'ERROR'))
            );
        """)
        
        # Crear índices para mejorar rendimiento
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_fecha_hora ON logs_sistema(fecha_hora);
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_tipo ON logs_sistema(tipo_log);
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_usuario ON logs_sistema(usuario);
        """)
        
        conn.commit()
        cur.close()
        
    except psycopg2.Error as e:
        print(f"Error inicializando tabla de logs: {e}")
        conn.rollback()
    finally:
        conn.close()

def registrar_evento(tipo_log: str, ip_remota: str, usuario: str, accion: str, codigo_http: int) -> bool:
    """
    Registra un evento en el sistema de logs.
    
    Args:
        tipo_log (str): Tipo de log (INFO, DEBUG, WARNING, ERROR)
        ip_remota (str): Dirección IP del cliente
        usuario (str): Nombre de usuario o 'anon' si no está autenticado
        accion (str): Descripción de la acción realizada
        codigo_http (int): Código de respuesta HTTP
    
    Returns:
        bool: True si el registro fue exitoso, False en caso contrario
    """
    
    # Validación de parámetros de entrada
    if not isinstance(tipo_log, str) or tipo_log not in ['INFO', 'DEBUG', 'WARNING', 'ERROR']:
        print(f"Tipo de log inválido: {tipo_log}")
        return False
    
    if not isinstance(ip_remota, str) or len(ip_remota.strip()) == 0:
        ip_remota = "unknown"
    
    if not isinstance(usuario, str) or len(usuario.strip()) == 0:
        usuario = "anon"
    
    if not isinstance(accion, str) or len(accion.strip()) == 0:
        accion = "accion_no_especificada"
    
    if not isinstance(codigo_http, int) or codigo_http < 100 or codigo_http > 599:
        print(f"Código HTTP inválido: {codigo_http}")
        return False
    
    # Obtener fecha y hora local sin usar librerías externas
    fecha_hora = obtener_hora_local()
    
    # Enmascarar información sensible en la acción
    accion_enmascarada = enmascarar_informacion_sensible(accion)
    
    # Truncar campos que podrían ser muy largos
    ip_remota = ip_remota[:45]
    usuario = usuario[:100]
    accion_enmascarada = accion_enmascarada[:1000]  # Limitar a 1000 caracteres
    
    conn = obtener_conexion_logs()
    if not conn:
        print("No se pudo conectar a la base de datos para registrar el log")
        return False
    
    try:
        cur = conn.cursor()
        
        # Insertar el registro de log
        cur.execute("""
            INSERT INTO logs_sistema (fecha_hora, tipo_log, ip_remota, usuario, accion, codigo_http)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (fecha_hora, tipo_log, ip_remota, usuario, accion_enmascarada, codigo_http))
        
        conn.commit()
        cur.close()
        
        return True
        
    except psycopg2.Error as e:
        print(f"Error registrando evento en logs: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def enmascarar_informacion_sensible(texto: str) -> str:
    """
    Enmascara información sensible en los logs.
    
    Args:
        texto (str): Texto que puede contener información sensible
    
    Returns:
        str: Texto con información sensible enmascarada
    """
    import re
    
    # Palabras clave que indican información sensible
    palabras_sensibles = ['password', 'token', 'secret', 'key', 'credit', 'card', 'pin']
    
    # Enmascarar campos que contengan información sensible
    for palabra in palabras_sensibles:
        # Buscar patrones como "password": "valor" o password=valor
        patron_json = rf'("{palabra}"\s*:\s*)"[^"]*"'
        patron_form = rf'({palabra}\s*=\s*)[^\s&]*'
        
        texto = re.sub(patron_json, r'\1"***"', texto, flags=re.IGNORECASE)
        texto = re.sub(patron_form, r'\1***', texto, flags=re.IGNORECASE)
    
    # Enmascarar números que parezcan tarjetas de crédito (16 dígitos)
    texto = re.sub(r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', '****-****-****-****', texto)
    
    # Enmascarar números que parezcan cuentas bancarias (más de 8 dígitos consecutivos)
    texto = re.sub(r'\b\d{8,}\b', lambda m: '*' * len(m.group()), texto)
    
    return texto

def registrar_info(ip_remota: str, usuario: str, accion: str, codigo_http: int = 200) -> bool:
    """Método auxiliar para registrar eventos de tipo INFO"""
    return registrar_evento('INFO', ip_remota, usuario, accion, codigo_http)

def registrar_debug(ip_remota: str, usuario: str, accion: str, codigo_http: int = 200) -> bool:
    """Método auxiliar para registrar eventos de tipo DEBUG"""
    return registrar_evento('DEBUG', ip_remota, usuario, accion, codigo_http)

def registrar_warning(ip_remota: str, usuario: str, accion: str, codigo_http: int = 200) -> bool:
    """Método auxiliar para registrar eventos de tipo WARNING"""
    return registrar_evento('WARNING', ip_remota, usuario, accion, codigo_http)

def registrar_error(ip_remota: str, usuario: str, accion: str, codigo_http: int = 500) -> bool:
    """Método auxiliar para registrar eventos de tipo ERROR"""
    return registrar_evento('ERROR', ip_remota, usuario, accion, codigo_http)

# Inicializar la tabla de logs al importar el módulo
inicializar_tabla_logs()
