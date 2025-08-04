# app/utils/otp_manager.py

# ALMACENAMIENTO DE OTPs (en memoria)
import secrets
import time

# Este almacenamiento es temporal y solo válido mientras el backend esté en ejecución.
otp_storage = {}

def generar_otp(user_id, minutos_validez=5):
    """
    Genera un OTP de 6 dígitos para el usuario especificado.
    CORREGIDO: Previene sobrescritura de OTPs válidos.
    
    Args:
        user_id (int/str): este es el identificador único del usuario.
        minutos_validez (int): Tiempo de validez del OTP en minutos (por defecto 5 min).

    Returns:
        str: OTP generado (se forma una cadena de 6 dígitos).

    Seguridad:
    - Se utiliza la librería secrets para generar números criptográficamente seguros.
    - Cada OTP almacenado tiene su tiempo de expiración para evitar reutilización.
    - NUEVO: Verifica si existe un OTP válido antes de generar uno nuevo.
    """
    
    # CORREGIDO: Verificar si ya existe un OTP válido
    if user_id in otp_storage:
        otp_actual, expira_en = otp_storage[user_id]
        tiempo_actual = time.time()
        
        # Si el OTP actual aún es válido, NO generar uno nuevo
        if tiempo_actual <= expira_en:
            print(f"DEBUG: OTP existente válido para user {user_id}: {otp_actual}")
            return otp_actual
        else:
            # OTP expirado, eliminar del storage
            del otp_storage[user_id]
            print(f"DEBUG: OTP expirado eliminado para user {user_id}")
    
    # Generar nuevo OTP solo si no existe uno válido
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    expira_en = time.time() + minutos_validez * 60
    otp_storage[user_id] = (otp, expira_en)
    
    print(f"DEBUG: Nuevo OTP generado para user {user_id}: {otp}")
    return otp

def verificar_otp(user_id, otp_ingresado):
    """
    Verifica si un OTP que ha sido ingresado es válido para un usuario específico.
    CORREGIDO: Mejor manejo de debugging y validación.

    Args:
        user_id (int/str): es el identificador del usuario.
        otp_ingresado (str): OTP proporcionado por el usuario.

    Returns:
        bool: True si el OTP es válido y no ha expirado, False en caso contrario.
    """
    # Verificar si existe OTP para el usuario
    if user_id not in otp_storage:
        print(f"DEBUG: No existe OTP para user {user_id}")
        return False
    
    otp_guardado, expira_en = otp_storage[user_id]
    tiempo_actual = time.time()
    
    print(f"DEBUG: Verificando OTP para user {user_id}")
    print(f"DEBUG: OTP almacenado: {otp_guardado}")
    print(f"DEBUG: OTP ingresado: {otp_ingresado}")
    print(f"DEBUG: Tiempo actual: {tiempo_actual}, Expira en: {expira_en}")
    
    # Verificar si ha expirado
    if tiempo_actual > expira_en:
        del otp_storage[user_id]
        print(f"DEBUG: OTP expirado para user {user_id}")
        return False
    
    # Verificar si coincide
    if otp_ingresado == otp_guardado:
        del otp_storage[user_id]  # OTP de un solo uso
        print(f"DEBUG: OTP válido usado para user {user_id}")
        return True
    
    print(f"DEBUG: OTP incorrecto para user {user_id}")
    return False

def limpiar_otps_expirados():

    tiempo_actual = time.time()
    users_to_remove = []
    
    for user_id, (otp, expira_en) in otp_storage.items():
        if tiempo_actual > expira_en:
            users_to_remove.append(user_id)
    
    for user_id in users_to_remove:
        del otp_storage[user_id]
        print(f"DEBUG: OTP expirado eliminado para user {user_id}")

def get_active_otps():
    """Función de debugging para ver OTPs activos."""
    return {
        user_id: {
            "otp": otp,
            "expires_in_seconds": max(0, int(expira_en - time.time()))
        }
        for user_id, (otp, expira_en) in otp_storage.items()
    }