# validators.py
import re

def validate_cedula(cedula):
    """Valida cédula ecuatoriana usando algoritmo oficial."""
    if not cedula or len(cedula) != 10 or not cedula.isdigit():
        return False
    
    # Verificar que los dos primeros dígitos sean válidos (01-24)
    provincia = int(cedula[:2])
    if provincia < 1 or provincia > 24:
        return False
    
    # Algoritmo de validación
    coeficientes = [2, 1, 2, 1, 2, 1, 2, 1, 2]
    suma = 0
    
    for i in range(9):
        valor = int(cedula[i]) * coeficientes[i]
        if valor >= 10:
            valor = valor - 9
        suma += valor
    
    digito_verificador = (10 - (suma % 10)) % 10
    return digito_verificador == int(cedula[9])

def validate_phone(phone):
    """Valida número celular ecuatoriano."""
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Formato: 09XXXXXXXX (10 dígitos)
    if re.match(r'^09\d{8}$', clean_phone):
        return True
    
    # Formato internacional: +593 9XXXXXXXX
    if re.match(r'^\+5939\d{8}$', clean_phone):
        return True
    
    return False

def validate_username(username, personal_info):
    """Valida que el username cumpla los requisitos de TCE-07."""
    if not username or len(username) < 4 or len(username) > 20:
        return False, "Username must be between 4 and 20 characters"
    
    # Solo letras y números (sin símbolos)
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return False, "Username can only contain letters and numbers"
    
    # No puede contener información personal
    username_lower = username.lower()
    personal_data = [
        personal_info.get('nombres', '').lower(),
        personal_info.get('apellidos', '').lower(),
        personal_info.get('cedula', ''),
    ]
    
    for data in personal_data:
        if data and len(data) >= 3 and data in username_lower:
            return False, "Username cannot contain personal information"
    
    return True, "Valid username"

def validate_password(password, personal_info):
    """
    Valida que la contraseña cumpla los requisitos de seguridad (TCE-07):
    - Longitud mínima de 8 caracteres.
    - Debe incluir letras, números y símbolos.
    - No debe contener información personal del usuario.
    """
    # Verificar longitud mínima
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    # Verificar que contenga letras, números y símbolos
    has_letter = bool(re.search(r'[a-zA-Z]', password)) # Debe contener al menos una letra
    has_number = bool(re.search(r'\d', password))       # Debe contener al menos un número
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))   # Debe contener al menos un símbolo
    
    if not (has_letter and has_number and has_symbol):
        return False, "Password must contain letters, numbers, and symbols"
    
    #  Convertir contraseña a minúsculas para comparación
    password_lower = password.lower()
    # Datos personales a evitar dentro de esta contraseña
    personal_data = [
        personal_info.get('nombres', '').lower(),
        personal_info.get('apellidos', '').lower(),
        personal_info.get('cedula', ''),
        personal_info.get('celular', ''),
    ]
    # Verificar que la contraseña no incluya datos personales relevantes
    for data in personal_data:
        if data and len(data) >= 3 and data in password_lower:
            return False, "Password cannot contain personal information"
    # Si pasa todas las validaciones, la contraseña es válida
    return True, "Valid password"

def validar_tarjeta_luhn(numero_tarjeta):
    """Valida un número de tarjeta con el algoritmo de Luhn."""
    numero_tarjeta = numero_tarjeta.replace(" ", "")
    if not numero_tarjeta.isdigit():
        return False

    suma = 0
    invertir = numero_tarjeta[::-1]
    for i, digito in enumerate(invertir):
        n = int(digito)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        suma += n
    return suma % 10 == 0
