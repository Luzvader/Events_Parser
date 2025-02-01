# modules/web_attacks.py

# Diccionario de presets para detectar ataques web.
# Las expresiones regulares aquí son ejemplos básicos y pueden necesitar ajustes según el entorno real.
PRESETS = {
    # XSS: Detecta etiquetas <script> (insensible a mayúsculas/minúsculas).
    'xss': r'(?i)<script\b[^>]*>(.*?)</script>',

    # SQL Injection: Busca patrones comunes de inyección SQL.
    'sql_injection': r'(?i)(\bUNION\b\s+\bSELECT\b|\bSELECT\b\s+.*\bFROM\b|\bINSERT\b\s+INTO\b|\bUPDATE\b\s+\bSET\b|\bDELETE\b\s+\bFROM\b|\bDROP\b\s+\bTABLE\b)',

    # LFI (Local File Inclusion): Detecta intentos de inclusión de archivos mediante rutas relativas.
    'lfi': r'(\.\./)+',

    # RFI (Remote File Inclusion): Busca patrones que indiquen inclusión remota.
    'rfi': r'(?i)(http[s]?://.*?\.(php|asp|jsp)(\?.*)?)',

    # CSRF (Cross-Site Request Forgery): Busca menciones a "csrf" o "token".
    'csrf': r'(?i)(csrf|token)',

    # Command Injection: Se requiere la presencia de un operador (;) o (&&) o (||)
    # seguido de un comando sospechoso (cat, chmod, chown, wget o curl).
    'command_injection': r'(?i)(?:;|&&|\|\|)\s*(?:cat|chmod|chown|wget|curl)\b',

    # XXE (XML External Entity): Detecta definiciones de entidades externas en XML.
    'xxe': r'(?i)<!ENTITY\s+',

    # XML Injection: Detecta posibles inyecciones en XML.
    'xml_injection': r'(?i)<\?xml\s+.*\?>',

    # Path Traversal: Busca secuencias de "../" que indiquen un intento de acceder a directorios superiores.
    'path_traversal': r'(\.\./)+',

    # SSRF (Server-Side Request Forgery): Detecta intentos de acceso a direcciones internas (ejemplo básico).
    'ssrf': r'(?i)(http[s]?://(127\.0\.0\.1|localhost))',

    # SharePoint (CVE-2023-29357): Detecta solicitudes sospechosas dirigidas a endpoints de SharePoint
    # que se han relacionado con el CVE-2023-29357. Se capturan rutas como:
    # /_api/web/siteusers, /_api/web/siteusers/... o /_api/web/currentuser.
    'sharepoint': r'(?i)/_api/web/(siteusers|currentuser)(/.*)?'
}

def get_preset(attack_type):
    """
    Retorna la expresión regular asociada al preset del ataque web indicado.
    
    :param attack_type: Nombre del ataque (ej: 'xss', 'sql_injection', 'sharepoint', etc.)
    :return: Cadena con la expresión regular correspondiente.
    :raises Exception: Si no se encuentra el preset para el ataque indicado.
    """
    key = attack_type.lower()
    if key in PRESETS:
        return PRESETS[key]
    else:
        raise Exception("Preset no encontrado: " + attack_type)
