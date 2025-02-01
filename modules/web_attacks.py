# modules/web_attacks.py

# Diccionario de presets para detectar ataques web.
# Las expresiones regulares a continuación son ejemplos básicos y pueden necesitar ajustes según el entorno real.
PRESETS = {
    # XSS: Detecta etiquetas <script> (insensible a mayúsculas/minúsculas).
    'xss': r'(?i)<script\b[^>]*>(.*?)</script>',

    # SQL Injection: Busca patrones comunes de inyección SQL, permitiendo que los separadores sean espacios o "%20".
    'sql_injection': (
        r'(?i)(\bUNION\b(?:\s+|%20)+\bSELECT\b|'
        r'\bSELECT\b(?:\s+|%20)+.*\bFROM\b|'
        r'\bINSERT\b(?:\s+|%20)+INTO\b|'
        r'\bUPDATE\b(?:\s+|%20)+\bSET\b|'
        r'\bDELETE\b(?:\s+|%20)+\bFROM\b|'
        r'\bDROP\b(?:\s+|%20)+\bTABLE\b)'
    ),

    # LFI (Local File Inclusion): Detecta intentos de inclusión de archivos mediante rutas relativas,
    # ya sea en forma literal ("../") o URL encoded (por ejemplo, ".%2e/" o "%2e%2e/").
    'lfi': r'(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+',

    # RFI (Remote File Inclusion): Busca patrones que indiquen inclusión remota.
    'rfi': r'(?i)(http[s]?://.*?\.(php|asp|jsp)(\?.*)?)',

    # CSRF (Cross-Site Request Forgery): Busca menciones a "csrf" o "token".
    'csrf': r'(?i)(csrf|token)',

    # Command Injection: Detecta un operador (literal o URL encoded) seguido de comandos sospechosos.
    'command_injection': r'(?i)(?:(?:;|%3[Bb])|(?:&&|%26%26)|(?:\|\||%7C%7C))\s*(?:cat|chmod|chown|wget|curl)\b',

    # XXE (XML External Entity): Detecta definiciones de entidades externas en XML.
    'xxe': r'(?i)<!ENTITY\s+',

    # XML Injection: Detecta posibles inyecciones en XML.
    'xml_injection': r'(?i)<\?xml\s+.*\?>',

    # Path Traversal: Detecta intentos de acceder a directorios superiores,
    # ya sea en forma literal ("../") o URL encoded (por ejemplo, ".%2e/" o "%2f").
    'path_traversal': r'(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+',

    # SSRF (Server-Side Request Forgery): Detecta intentos de acceso a direcciones internas (ejemplo básico).
    'ssrf': r'(?i)(http[s]?://(127\.0\.0\.1|localhost)(?::\d+)?(?:/[^\s"]*)?)',

    # SharePoint (CVE-2023-29357): Detecta solicitudes sospechosas dirigidas a endpoints de SharePoint,
    # por ejemplo: /_api/web/siteusers o /_api/web/currentuser.
    'sharepoint': r'(?i)/_api/web/(siteusers|currentuser)(/.*)?',

    # Log4j: Detecta intentos de explotación de vulnerabilidades en log4j mediante patrones JNDI,
    # por ejemplo: ${jndi:ldap://malicious.example.com/a}
    'log4j': r'(?i)\$\{jndi:(?:ldap|rmi|dns):\/\/[^\}]+\}',

    # IDOR: Detecta accesos directos a objetos, por ejemplo, URLs con /user/123 o parámetros ?id=456.
    'idor': r'(?i)(?:/user/\d+|[?&](?:id|uid|user_id|account_id)=\d+)',

    # Open Redirect: Detecta parámetros de redirección en URLs, como "redirect", "next" o "url",
    # apuntando a cualquier dirección externa.
    'open_redirect': r'(?i)[?&](redirect|next|url)=https?:\/\/[^\s]+',

    # RCE (Remote Code Execution): Detecta intentos de ejecución remota de código mediante
    # funciones comunes (system, exec, shell_exec, passthru o popen) seguidas de un paréntesis
    # que puede estar en forma literal o URL encoded (%28).
    'rce': r'(?i)(?:system|exec|shell_exec|passthru|popen)\s*(?:\(|%28)',

    # Ingress-nginx (CVE-2024-7646): Detecta bypass de validación de anotaciones en ingress-nginx.
    # Busca la anotación "nginx.ingress.kubernetes.io/configuration-snippet" que contiene un comando rewrite
    # malicioso, por ejemplo, que reescriba rutas que comiencen por "/evil/" a "/admin permanent;".
    'ingress_nginx': r'(?si)"nginx\.ingress\.kubernetes\.io/configuration-snippet"\s*:\s*".*rewrite\s+\^\/evil\/.*permanent;.*"',

    # HTTP/3 Crash (CVE-2024-31079): Detecta solicitudes HTTP/3 que resultan en un código 500,
    # lo cual puede ser indicativo de un crash en Apache HTTP/3 QUIC.
    'http3_crash': r'(?i)HTTP\/3".*?\s500\s',
}

def get_preset(attack_type):
    """
    Retorna la expresión regular asociada al preset del ataque web indicado.
    
    :param attack_type: Nombre del ataque (ej: 'xss', 'sql_injection', 'sharepoint', 'log4j', 'idor', 'open_redirect', 'rce', etc.)
    :return: Cadena con la expresión regular correspondiente.
    :raises Exception: Si no se encuentra el preset para el ataque indicado.
    """
    key = attack_type.lower()
    if key in PRESETS:
        return PRESETS[key]
    else:
        raise Exception("Preset no encontrado: " + attack_type)
