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
    """Valida que la contraseña cumpla los requisitos de TCE-07."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    # Verificar que contenga letras, números y símbolos
    has_letter = bool(re.search(r'[a-zA-Z]', password))
    has_number = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if not (has_letter and has_number and has_symbol):
        return False, "Password must contain letters, numbers, and symbols"
    
    # No puede contener información personal
    password_lower = password.lower()
    personal_data = [
        personal_info.get('nombres', '').lower(),
        personal_info.get('apellidos', '').lower(),
        personal_info.get('cedula', ''),
        personal_info.get('celular', ''),
    ]
    
    for data in personal_data:
        if data and len(data) >= 3 and data in password_lower:
            return False, "Password cannot contain personal information"
    
    return True, "Valid password"