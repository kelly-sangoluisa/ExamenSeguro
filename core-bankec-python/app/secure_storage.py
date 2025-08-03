# app/secure_storage.py

import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY no definida en el archivo .env")

fernet = Fernet(FERNET_KEY.encode())

def cifrar_dato(dato: str) -> str:
    return fernet.encrypt(dato.encode()).decode()

def descifrar_dato(dato_cifrado: str) -> str:
    return fernet.decrypt(dato_cifrado.encode()).decode()
