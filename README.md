Examen de desarrollo software seguro by Grupo 1
---
[📄 TRG-01 - Análisis Estático de Código](https://github.com/kelly-sangoluisa/ExamenSeguro/blob/main/TRG-01-AnalisisEstaticoCodigo-Grupo1.pdf)


[💻 Codigo fuente core-bankec-python](https://github.com/kelly-sangoluisa/ExamenSeguro/tree/main/core-bankec-python)

### **Recomendacion**
Se recomienda borrar los volumnes anteriores ya que se hicieron modificaciones en el esquema de la base de datos 

## 🔑 Configuración de Variables de Entorno

Crear core-bankec-python/.env
Estas variables son necesarias para la configuración de autenticación JWT y FERNET:
```plaintext
# Configuración JWT
JWT_SECRET_KEY=8a7f4e2b9c1d6f3a5e8b2c4f7a1d9e6b3c8f2a5e7b4c1f9d6a3e8c5b2f7a4d1e9
JWT_EXPIRATION_HOURS=0.25

# Clave para cifrado Fernet
FERNET_KEY=8YkA_gl5178_46ldpAcm1KmyGC95Q3msGKVOtFLXca0=
