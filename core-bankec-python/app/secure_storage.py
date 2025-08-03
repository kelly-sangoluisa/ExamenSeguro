# app/secure_storage.py

import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
# Cargar variables de entorno desde el archivo .env
load_dotenv()
# Clave de cifrado simétrica usada por Fernet
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    # Si no existe la clave, la aplicación no puede funcionar de forma segura
    raise ValueError("FERNET_KEY no definida en el archivo .env")
# Inicializar el objeto Fernet para cifrado/descifrado
fernet = Fernet(FERNET_KEY.encode())

def cifrar_dato(dato: str) -> str:
     """Cifra un dato sensible usando Fernet (AES-128 en CBC con HMAC)."""
    return fernet.encrypt(dato.encode()).decode()

def descifrar_dato(dato_cifrado: str) -> str:
     """Descifra un dato previamente cifrado con Fernet."""
    return fernet.decrypt(dato_cifrado.encode()).decode()
