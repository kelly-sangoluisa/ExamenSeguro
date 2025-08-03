# app/logging/__init__.py
"""
Módulo de logging personalizado para el sistema bancario.
Implementación propia sin librerías externas de logging.
"""

from .logger import registrar_evento

__all__ = ['registrar_evento']
