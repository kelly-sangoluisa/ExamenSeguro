# app/logging/__init__.py
"""
Módulo de logging personalizado para el sistema bancario.
Implementación propia sin librerías externas de logging.
"""

from .logger import registrar_evento, registrar_warning, registrar_error, registrar_info, registrar_debug

__all__ = ['registrar_evento', 'registrar_warning', 'registrar_error', 'registrar_info', 'registrar_debug']
