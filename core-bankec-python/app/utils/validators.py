# app/utils/validators.py
"""
Validadores de datos para el sistema bancario.
Incluye validaciones específicas para parámetros de entrada.
"""

import re
from typing import Any, Dict, List

def validar_parametros_requeridos(data: Dict[str, Any], campos_requeridos: List[str]) -> List[str]:
    """
    Valida que todos los campos requeridos estén presentes en los datos.
    
    Args:
        data (Dict[str, Any]): Datos a validar
        campos_requeridos (List[str]): Lista de campos requeridos
        
    Returns:
        List[str]: Lista de errores encontrados
    """
    errores = []
    
    if not isinstance(data, dict):
        errores.append("Los datos deben ser un objeto JSON válido")
        return errores
    
    for campo in campos_requeridos:
        if campo not in data:
            errores.append(f"El campo '{campo}' es requerido")
        elif data[campo] is None or (isinstance(data[campo], str) and data[campo].strip() == ""):
            errores.append(f"El campo '{campo}' no puede estar vacío")
    
    return errores

def validar_tipos_datos(data: Dict[str, Any], tipos_esperados: Dict[str, type]) -> List[str]:
    """
    Valida que los datos sean del tipo esperado.
    
    Args:
        data (Dict[str, Any]): Datos a validar
        tipos_esperados (Dict[str, type]): Diccionario con los tipos esperados
        
    Returns:
        List[str]: Lista de errores encontrados
    """
    errores = []
    
    for campo, tipo_esperado in tipos_esperados.items():
        if campo in data:
            if not isinstance(data[campo], tipo_esperado):
                errores.append(f"El campo '{campo}' debe ser de tipo {tipo_esperado.__name__}")
    
    return errores

def validar_rangos_numericos(data: Dict[str, Any], rangos: Dict[str, tuple]) -> List[str]:
    """
    Valida que los valores numéricos estén dentro de rangos válidos.
    
    Args:
        data (Dict[str, Any]): Datos a validar
        rangos (Dict[str, tuple]): Diccionario con rangos (min, max) para cada campo
        
    Returns:
        List[str]: Lista de errores encontrados
    """
    errores = []
    
    for campo, (min_val, max_val) in rangos.items():
        if campo in data:
            valor = data[campo]
            if isinstance(valor, (int, float)):
                if valor < min_val or valor > max_val:
                    errores.append(f"El campo '{campo}' debe estar entre {min_val} y {max_val}")
    
    return errores

def validar_formato_string(data: Dict[str, Any], patrones: Dict[str, str]) -> List[str]:
    """
    Valida que los strings cumplan con patrones específicos.
    
    Args:
        data (Dict[str, Any]): Datos a validar
        patrones (Dict[str, str]): Diccionario con patrones regex para cada campo
        
    Returns:
        List[str]: Lista de errores encontrados
    """
    errores = []
    
    for campo, patron in patrones.items():
        if campo in data:
            valor = str(data[campo])
            if not re.match(patron, valor):
                errores.append(f"El campo '{campo}' tiene un formato inválido")
    
    return errores

def sanitizar_entrada(valor: Any) -> str:
    """
    Sanitiza una entrada para prevenir inyecciones.
    
    Args:
        valor (Any): Valor a sanitizar
        
    Returns:
        str: Valor sanitizado
    """
    if valor is None:
        return ""
    
    # Convertir a string y eliminar caracteres peligrosos
    valor_str = str(valor)
    
    # Remover caracteres de control y caracteres especiales peligrosos
    caracteres_peligrosos = ['<', '>', '"', "'", '&', '\x00', '\n', '\r', '\t']
    for char in caracteres_peligrosos:
        valor_str = valor_str.replace(char, '')
    
    # Limitar longitud
    return valor_str[:500]  # Máximo 500 caracteres
