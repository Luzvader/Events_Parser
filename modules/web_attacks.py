# modules/web_attacks.py

PRESETS = {
    # XSS: Detecta intentos de inyección de código JavaScript mediante etiquetas <script>.
    "xss": {
        "regex": r"(?i)<script\b[^>]*>(.*?)</script>",
        "level": 3,
        "description": "Detecta intentos de inyección de código JavaScript a través de etiquetas <script>.",
        "remediation": "Sanitiza las entradas de usuario y utiliza políticas de seguridad de contenido (CSP) robustas."
    },
    # SQL Injection: Detecta patrones comunes de inyección SQL, permitiendo que los separadores sean espacios o '%20'.
    "sql_injection": {
        "regex": (
            r"(?i)(\bUNION\b(?:\s+|%20)+\bSELECT\b|"
            r"\bSELECT\b(?:\s+|%20)+.*\bFROM\b|"
            r"\bINSERT\b(?:\s+|%20)+INTO\b|"
            r"\bUPDATE\b(?:\s+|%20)+\bSET\b|"
            r"\bDELETE\b(?:\s+|%20)+\bFROM\b|"
            r"\bDROP\b(?:\s+|%20)+\bTABLE\b)"
        ),
        "level": 0,
        "description": "Detecta patrones comunes de inyección SQL, permitiendo separadores literales o URL encoded (%20).",
        "remediation": "Utiliza consultas parametrizadas y sanitiza las entradas de usuario para prevenir la inyección SQL."
    },
    # LFI (Local File Inclusion): Detecta intentos de inclusión de archivos mediante rutas relativas,
    # ya sea en forma literal ("../") o URL encoded (por ejemplo, ".%2e/" o "%2e%2e/").
    "lfi": {
        "regex": r"(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+",
        "level": 0,
        "description": "Detecta intentos de Local File Inclusion (LFI) usando secuencias de '../' o sus variantes URL encoded.",
        "remediation": "Normaliza y valida las rutas de archivos y restringe el acceso a directorios sensibles."
    },
    # RFI (Remote File Inclusion): Detecta intentos de inclusión remota de archivos.
    "rfi": {
        "regex": r"(?i)(http[s]?://.*?\.(php|asp|jsp)(\?.*)?)",
        "level": 2,
        "description": "Detecta intentos de inclusión remota de archivos (RFI) mediante URL a scripts potencialmente peligrosos.",
        "remediation": "Valida las URLs de entrada y restringe la inclusión de archivos externos."
    },
    # CSRF (Cross-Site Request Forgery): Detecta la presencia de tokens CSRF.
    "csrf": {
        "regex": r"(?i)(csrf|token)",
        "level": 3,
        "description": "Detecta intentos de CSRF al identificar la presencia de tokens en las solicitudes.",
        "remediation": "Implementa tokens CSRF únicos y verifica su validez en cada petición."
    },
    # Command Injection: Detecta intentos de inyección de comandos utilizando operadores (literal o URL encoded)
    # seguidos de comandos peligrosos.
    "command_injection": {
        "regex": r"(?i)(?:(?:;|%3[Bb])|(?:&&|%26%26)|(?:\|\||%7C%7C))(?:\s|(?:%20))*(?:cat|chmod|chown|wget|curl)\b",
        "level": 0,
        "description": "Detecta intentos de inyección de comandos a través de operadores seguidos de comandos como cat, wget, etc.",
        "remediation": "Sanitiza y valida las entradas de usuario y evita ejecutar comandos del sistema con datos sin filtrar."
    },
    # XXE (XML External Entity): Detecta intentos de explotación de XML External Entity.
    "xxe": {
        "regex": r"(?i)<!ENTITY\s+",
        "level": 3,
        "description": "Detecta intentos de explotación de vulnerabilidades XXE mediante definiciones de entidades externas.",
        "remediation": "Desactiva la resolución de entidades externas en el procesamiento XML o utiliza bibliotecas seguras."
    },
    # XML Injection: Detecta posibles intentos de inyección en XML.
    "xml_injection": {
        "regex": r"(?i)<\?xml\s+.*\?>",
        "level": 3,
        "description": "Detecta intentos de inyección en archivos XML.",
        "remediation": "Valida y sanitiza los datos XML antes de procesarlos."
    },
    # Path Traversal: Detecta intentos de acceder a directorios superiores (path traversal).
    "path_traversal": {
        "regex": r"(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+",
        "level": 0,
        "description": "Detecta intentos de path traversal mediante el uso de secuencias '../' o sus variantes URL encoded.",
        "remediation": "Normaliza y valida las rutas de entrada y restringe el acceso a directorios críticos."
    },
    # SSRF (Server-Side Request Forgery): Detecta intentos de SSRF a direcciones internas.
    "ssrf": {
        "regex": r"(?i)(http[s]?://(127\.0\.0\.1|localhost)(?::\d+)?(?:/[^\s\"]*)?)",
        "level": 2,
        "description": "Detecta intentos de SSRF mediante solicitudes a direcciones internas (127.0.0.1 o localhost).",
        "remediation": "Utiliza listas blancas para URLs y restringe el acceso a servicios internos."
    },
    # SharePoint (CVE-2023-29357): Detecta solicitudes a endpoints de SharePoint.
    "sharepoint": {
        "regex": r"(?i)/_api/web/(siteusers|currentuser)(/.*)?",
        "level": 2,
        "description": "Detecta solicitudes a endpoints de SharePoint asociadas a vulnerabilidades como CVE-2023-29357.",
        "remediation": "Revisa las configuraciones de seguridad de SharePoint y aplica los parches correspondientes."
    },
    # Log4j: Detecta intentos de explotación de vulnerabilidades en Log4j mediante patrones JNDI.
    "log4j": {
        "regex": r"(?i)\$\{jndi:(?:ldap|rmi|dns):\/\/[^\}]+\}",
        "level": 2,
        "description": "Detecta intentos de explotación de la vulnerabilidad Log4j mediante patrones JNDI.",
        "remediation": "Actualiza Log4j a una versión segura y revisa las configuraciones de logging."
    },
    # IDOR: Detecta accesos directos a objetos a través de URLs o parámetros.
    "idor": {
        "regex": r"(?i)(?:/user/\d+|[?&](?:id|uid|user_id|account_id)=\d+)",
        "level": 1,
        "description": "Detecta intentos de Insecure Direct Object Reference (IDOR) mediante identificadores en la URL o parámetros.",
        "remediation": "Implementa controles de acceso robustos y verifica la autorización en cada solicitud."
    },
    # Open Redirect: Detecta parámetros que redirigen a URLs externas.
    "open_redirect": {
        "regex": r"(?i)[?&](redirect|next|url)=https?:\/\/[^\s]+",
        "level": 1,
        "description": "Detecta intentos de redirección abierta mediante parámetros que apuntan a URLs externas.",
        "remediation": "Valida y restringe los destinos de redirección utilizando listas blancas."
    },
    # RCE (Remote Code Execution): Detecta intentos de ejecución remota de código a través de funciones peligrosas.
    "rce": {
        "regex": r"(?i)(?:system|exec|shell_exec|passthru|popen)\s*(?:\(|%28)",
        "level": 0,
        "description": "Detecta intentos de ejecución remota de código mediante funciones peligrosas.",
        "remediation": "Evita la ejecución directa de comandos y utiliza métodos seguros para el procesamiento de entradas."
    },
    # Ingress-nginx (CVE-2024-7646): Detecta bypass de validación de anotaciones en ingress-nginx.
    "ingress_nginx": {
        "regex": r'(?si)"nginx\.ingress\.kubernetes\.io/configuration-snippet"\s*:\s*".*rewrite\s+\^\/evil\/.*permanent;.*"',
        "level": 2,
        "description": "Detecta bypass de validación de anotaciones en ingress-nginx. Se analiza la anotación 'nginx.ingress.kubernetes.io/configuration-snippet' en busca de comandos rewrite maliciosos que redirijan a rutas no autorizadas.",
        "remediation": "Revisa y restringe las anotaciones permitidas en el Ingress, actualiza la configuración de seguridad y aplica parches según corresponda."
    },
    # HTTP/3 Crash (CVE-2024-31079): Detecta solicitudes HTTP/3 que generan un error 500.
    "http3_crash": {
        "regex": r'(?i)HTTP\/3".*?\s500\s',
        "level": 1,
        "description": "Detecta solicitudes HTTP/3 que resultan en un código 500, lo que puede indicar un crash en Apache HTTP/3 QUIC.",
        "remediation": "Verifica la versión de Apache HTTP/3, aplica los parches disponibles y revisa la configuración de QUIC para mitigar la vulnerabilidad."
    },
    "glassfish": {
    "regex": r"(?i)POST\s+/.*(asadmin|domain-admin).*?(exec|deploy|command)",
    "level": 0,
    "description": "Detecta intentos de explotación de GlassFish mediante vulnerabilidad CVE-2011-0807 y RCE. Se basa en solicitudes maliciosas dirigidas a endpoints de la consola de administración, como 'asadmin' o 'domain-admin'.",
    "remediation": "Actualiza GlassFish a la última versión, restringe el acceso a la consola de administración y refuerza la configuración de seguridad."
    },
    "nmap": {
    "regex": r"(?i)(nmap|nmap\s+scan|nmap\s+scripting\s+engine)",
    "level": 1,
    "description": "Detecta indicios de escaneos de red realizados con Nmap, buscando cadenas típicas como 'nmap', 'nmap scan' o 'nmap scripting engine'.",
    "remediation": "Revisa las solicitudes sospechosas, identifica la fuente del escaneo y considera configurar reglas de firewall o sistemas IDS/IPS para bloquear o alertar sobre escaneos no autorizados."
    },

}

def get_preset(attack_type):
    """
    Retorna la estructura asociada al preset del ataque web indicado.

    Parámetro:
      - attack_type (str): Nombre del ataque (ej: 'xss', 'sql_injection', 'lfi', etc.)

    Retorna:
      - dict: Contiene 'regex', 'level', 'description' y 'remediation' del preset.

    Lanza:
      - Exception: Si no se encuentra el preset para el ataque indicado.
    """
    key = attack_type.lower()
    if key in PRESETS:
        return PRESETS[key]
    else:
        raise Exception("Preset no encontrado: " + attack_type)
