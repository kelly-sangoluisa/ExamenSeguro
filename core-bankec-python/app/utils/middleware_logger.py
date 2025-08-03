# app/utils/middleware_logger.py
"""
Middleware de logging para interceptar y registrar todas las peticiones HTTP.

Características:
- Intercepta todas las peticiones HTTP automáticamente
- Obtiene IP remota (considerando proxies con X-Forwarded-For)
- Identifica usuario autenticado o 'anon'
- Registra método HTTP, ruta accedida y código de respuesta
- Se ejecuta después del envío de respuesta para capturar status_code
"""

from flask import Flask, request, g
from ..logging.logger import registrar_evento

class LoggingMiddleware:
    """
    Middleware personalizado para registrar automáticamente todas las peticiones HTTP.
    """
    
    def __init__(self, app: Flask):
        """
        Inicializa el middleware y lo registra en la aplicación Flask.
        
        Args:
            app (Flask): Instancia de la aplicación Flask
        """
        self.app = app
        self.init_app(app)
    
    def init_app(self, app: Flask):
        """
        Registra los hooks before_request y after_request en la aplicación Flask.
        
        Args:
            app (Flask): Instancia de la aplicación Flask
        """
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def before_request(self):
        """
        Se ejecuta antes de procesar cada petición.
        Captura información inicial de la petición.
        """
        # Almacenar información de la petición en g para uso posterior
        g.log_info = {
            'ip_remota': self.obtener_ip_remota(),
            'usuario': self.obtener_usuario(),
            'metodo': request.method,
            'ruta': request.path,
            'query_params': dict(request.args),
            'user_agent': request.headers.get('User-Agent', 'unknown')
        }
    
    def after_request(self, response):
        """
        Se ejecuta después de procesar cada petición y antes de enviar la respuesta.
        Registra el evento completo en el sistema de logs.
        
        Args:
            response: Objeto de respuesta Flask
            
        Returns:
            response: El mismo objeto de respuesta (sin modificaciones)
        """
        try:
            # Obtener información almacenada en before_request
            log_info = getattr(g, 'log_info', {})
            
            if not log_info:
                # Si no hay información previa, obtener datos básicos
                log_info = {
                    'ip_remota': self.obtener_ip_remota(),
                    'usuario': self.obtener_usuario(),
                    'metodo': request.method,
                    'ruta': request.path
                }
            
            # Construir descripción de la acción
            accion = self.construir_descripcion_accion(log_info, response.status_code)
            
            # Determinar tipo de log basado en el código de respuesta
            tipo_log = self.determinar_tipo_log(response.status_code)
            
            # Registrar el evento en el sistema de logs
            registrar_evento(
                tipo_log=tipo_log,
                ip_remota=log_info['ip_remota'],
                usuario=log_info['usuario'],
                accion=accion,
                codigo_http=response.status_code
            )
            
        except Exception as e:
            # En caso de error en el logging, no afectar la respuesta principal
            print(f"Error en middleware de logging: {e}")
        
        return response
    
    def obtener_ip_remota(self) -> str:
        """
        Obtiene la dirección IP remota del cliente.
        Considera proxies reversos y Docker port mapping.
        
        Returns:
            str: Dirección IP del cliente
        """
        # 1. Intentar obtener IP real desde headers de proxy (más común en producción)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # X-Forwarded-For puede contener múltiples IPs separadas por comas
            # La primera es la IP original del cliente
            ip_cliente = forwarded_for.split(',')[0].strip()
            # Validar que no sea una IP privada de Docker
            if not ip_cliente.startswith(('172.', '10.', '192.168.')):
                return ip_cliente
        
        # 2. Intentar otros headers comunes de proxy
        real_ip = request.headers.get('X-Real-IP')
        if real_ip and not real_ip.startswith(('172.', '10.', '192.168.')):
            return real_ip.strip()
        
        # 3. Para desarrollo local con Docker, intentar obtener la IP del host
        remote_addr = request.remote_addr or 'unknown'
        
        # Si es una IP de Docker (172.x.x.x), intentar obtener la IP real
        if remote_addr.startswith('172.'):
            # En desarrollo local con Docker, podemos usar la IP del gateway
            forwarded_host = request.headers.get('X-Forwarded-Host')
            if forwarded_host:
                return forwarded_host
            
            # Intentar detectar si viene de localhost
            host_header = request.headers.get('Host', '')
            if 'localhost' in host_header or '127.0.0.1' in host_header:
                return '127.0.0.1'  # IP local de desarrollo
            
            # Si no podemos determinar la IP real, usar la que tenemos
            return remote_addr
        
        return remote_addr
    
    def obtener_usuario(self) -> str:
        """
        Obtiene el nombre del usuario autenticado.
        
        Returns:
            str: Nombre de usuario o 'anon' si no está autenticado
        """
        try:
            # Verificar si hay información de usuario en g (colocada por token_required)
            user_info = getattr(g, 'user', None)
            if user_info and isinstance(user_info, dict):
                return user_info.get('username', 'anon')
            
            # Verificar si hay token en el header Authorization
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                # Si hay token pero no hay usuario en g, significa que el token es inválido
                return 'token_invalido'
            
            return 'anon'
            
        except Exception:
            return 'anon'
    
    def construir_descripcion_accion(self, log_info: dict, status_code: int) -> str:
        """
        Construye una descripción detallada de la acción realizada.
        
        Args:
            log_info (dict): Información de la petición
            status_code (int): Código de respuesta HTTP
            
        Returns:
            str: Descripción de la acción
        """
        metodo = log_info.get('metodo', 'UNKNOWN')
        ruta = log_info.get('ruta', '/unknown')
        query_params = log_info.get('query_params', {})
        
        # Construir descripción base
        descripcion = f"{metodo} {ruta}"
        
        # Agregar parámetros de consulta si existen (sin valores sensibles)
        if query_params:
            params_seguros = {k: '***' if self.es_parametro_sensible(k) else v 
                             for k, v in query_params.items()}
            if params_seguros:
                params_str = '&'.join([f"{k}={v}" for k, v in params_seguros.items()])
                descripcion += f"?{params_str}"
        
        # Agregar información del cuerpo de la petición para POST/PUT
        if metodo in ['POST', 'PUT', 'PATCH']:
            try:
                if request.is_json:
                    # Para requests JSON, registrar las claves sin valores sensibles
                    data = request.get_json(silent=True)
                    if isinstance(data, dict):
                        keys = [k if not self.es_parametro_sensible(k) else f"{k}:***" 
                               for k in data.keys()]
                        descripcion += f" | datos: {{{', '.join(keys)}}}"
                elif request.form:
                    # Para datos de formulario
                    keys = [k if not self.es_parametro_sensible(k) else f"{k}:***" 
                           for k in request.form.keys()]
                    descripcion += f" | form: {{{', '.join(keys)}}}"
            except Exception:
                descripcion += " | datos: [no_parseables]"
        
        # Agregar información del código de respuesta
        status_text = self.obtener_texto_status(status_code)
        descripcion += f" | respuesta: {status_code} {status_text}"
        
        return descripcion
    
    def es_parametro_sensible(self, nombre_param: str) -> bool:
        """
        Determina si un parámetro contiene información sensible.
        
        Args:
            nombre_param (str): Nombre del parámetro
            
        Returns:
            bool: True si el parámetro es sensible
        """
        parametros_sensibles = [
            'password', 'pass', 'pwd', 'token', 'secret', 'key', 'auth',
            'credit', 'card', 'pin', 'cvv', 'ssn', 'account_number'
        ]
        
        nombre_lower = nombre_param.lower()
        return any(sensible in nombre_lower for sensible in parametros_sensibles)
    
    def determinar_tipo_log(self, status_code: int) -> str:
        """
        Determina el tipo de log basado en el código de respuesta HTTP.
        
        Args:
            status_code (int): Código de respuesta HTTP
            
        Returns:
            str: Tipo de log (INFO, DEBUG, WARNING, ERROR)
        """
        if 200 <= status_code < 300:
            return 'INFO'
        elif 300 <= status_code < 400:
            return 'INFO'  # Redirecciones como INFO
        elif 400 <= status_code < 500:
            if status_code == 401:
                return 'WARNING'  # No autorizado
            elif status_code == 403:
                return 'WARNING'  # Prohibido
            elif status_code == 404:
                return 'INFO'     # No encontrado (común, no es error grave)
            else:
                return 'WARNING'  # Otros errores de cliente
        else:  # 500+
            return 'ERROR'    # Errores de servidor
    
    def obtener_texto_status(self, status_code: int) -> str:
        """
        Obtiene el texto descriptivo del código de estado HTTP.
        
        Args:
            status_code (int): Código de estado HTTP
            
        Returns:
            str: Texto descriptivo del código
        """
        status_texts = {
            200: 'OK', 201: 'Created', 204: 'No Content',
            301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
            400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 
            404: 'Not Found', 409: 'Conflict', 422: 'Unprocessable Entity',
            500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
        }
        return status_texts.get(status_code, 'Unknown')
