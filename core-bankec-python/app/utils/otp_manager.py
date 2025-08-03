# app/utils/otp_manager.py

import secrets
import time

# Estructura: { user_id: (otp, timestamp_de_expiración) }
otp_storage = {}

def generar_otp(user_id, minutos_validez=5):
    """Genera un OTP de 6 dígitos y lo almacena con expiración."""
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    expira_en = time.time() + minutos_validez * 60
    otp_storage[user_id] = (otp, expira_en)
    return otp

def verificar_otp(user_id, otp_ingresado):
    """Verifica si el OTP es válido y no ha expirado."""
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
