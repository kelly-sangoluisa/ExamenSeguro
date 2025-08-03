# app/utils/otp_manager.py

# ALMACENAMIENTO DE OTPs (en memoria)
import secrets
import time

# Este almacenamiento es temporal y solo válido mientras el backend esté en ejecución.
otp_storage = {}

def generar_otp(user_id, minutos_validez=5):
    """
    Genera un OTP de 6 dígitos para el usuario especificado.
    Args:
        user_id (int/str): este es el identificador único del usuario.
        minutos_validez (int): Tiempo de validez del OTP en minutos (por defecto 5 min).

    Returns:
        str: OTP generado (se forma una cadena de 6 dígitos).

    Seguridad:
    - Se utiliza la librería secrets para generar números criptográficamente seguros.
    - Cada OTP almacenado tiene su tiempo de expiración para evitar reutilización.
    - Este mecanismo puede mejorarse implementando un almacenamiento en base de datos.
    """
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    expira_en = time.time() + minutos_validez * 60
    otp_storage[user_id] = (otp, expira_en)
    return otp

def verificar_otp(user_id, otp_ingresado):
    """
    Verifica si un OTP que ha sido ingresado es válido para un usuario específico.

    Args:
        user_id (int/str): es el identificador del usuario.
        otp_ingresado (str): OTP proporcionado por el usuario.

    Returns:
        bool: True si el OTP es válido y no ha expirado, False en caso contrario.

    Seguridad:
    - El OTP es de un solo uso: si es correcto, se elimina inmediatamente del almacenamiento.
    - Si el OTP ha expirado, se elimina automáticamente.
    - Si no existe un OTP asociado al usuario, la verificación falla.
    """
    otp_guardado, expira_en = otp_storage.get(user_id, (None, 0))
    if otp_guardado is None:
        return False
    if time.time() > expira_en:
        del otp_storage[user_id]
        return False
    if otp_ingresado == otp_guardado:
        del otp_storage[user_id]  # OTP de un solo uso
        return True
    return False
