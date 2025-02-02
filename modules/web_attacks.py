# modules/web_attacks.py

PRESETS = {
    "xss": {
        "regex": r"(?i)<script\b[^>]*>(.*?)</script>",
        "level": 3,
        "description": "Detecta intentos de inyección de código JavaScript a través de etiquetas <script>.",
        "remediation": "Sanitiza las entradas de usuario y utiliza políticas de seguridad de contenido (CSP) robustas."
    },
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
    "lfi": {
        "regex": r"(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+",
        "level": 0,
        "description": "Detecta intentos de Local File Inclusion (LFI) usando secuencias de '../' o sus variantes URL encoded.",
        "remediation": "Normaliza y valida las rutas de archivos y restringe el acceso a directorios sensibles."
    },
    "rfi": {
        "regex": r"(?i)(http[s]?://.*?\.(php|asp|jsp)(\?.*)?)",
        "level": 2,
        "description": "Detecta intentos de inclusión remota de archivos (RFI) mediante URL a scripts potencialmente peligrosos.",
        "remediation": "Valida las URLs de entrada y restringe la inclusión de archivos externos."
    },
    "csrf": {
        "regex": r"(?i)(csrf|token)",
        "level": 3,
        "description": "Detecta intentos de CSRF al identificar la presencia de tokens en las solicitudes.",
        "remediation": "Implementa tokens CSRF únicos y verifica su validez en cada petición."
    },
    "command_injection": {
        "regex": r"(?i)(?:(?:;|%3[Bb])|(?:&&|%26%26)|(?:\|\||%7C%7C))(?:\s|(?:%20))*(?:cat|chmod|chown|wget|curl)\b",
        "level": 0,
        "description": "Detecta intentos de inyección de comandos mediante operadores (literal o URL encoded) seguidos de comandos peligrosos.",
        "remediation": "Sanitiza y valida las entradas de usuario y evita ejecutar comandos del sistema con datos sin filtrar."
    },
    "xxe": {
        "regex": r"(?i)<!ENTITY\s+",
        "level": 3,
        "description": "Detecta intentos de explotación de vulnerabilidades XXE mediante definiciones de entidades externas.",
        "remediation": "Desactiva la resolución de entidades externas en el procesamiento XML o utiliza bibliotecas seguras."
    },
    "xml_injection": {
        "regex": r"(?i)<\?xml\s+.*\?>",
        "level": 3,
        "description": "Detecta intentos de inyección en archivos XML.",
        "remediation": "Valida y sanitiza los datos XML antes de procesarlos."
    },
    "path_traversal": {
        "regex": r"(?i)(?:(?:\.|%2e){2}(?:\/|%2f))+",
        "level": 0,
        "description": "Detecta intentos de path traversal mediante el uso de secuencias '../' o sus variantes URL encoded.",
        "remediation": "Normaliza y valida las rutas de entrada y restringe el acceso a directorios críticos."
    },
    "ssrf": {
        "regex": r"(?i)(http[s]?://(127\.0\.0\.1|localhost)(?::\d+)?(?:/[^\s\"]*)?)",
        "level": 2,
        "description": "Detecta intentos de SSRF mediante solicitudes a direcciones internas (127.0.0.1 o localhost).",
        "remediation": "Utiliza listas blancas para URLs y restringe el acceso a servicios internos."
    },
    "sharepoint": {
        "regex": r"(?i)/_api/web/(siteusers|currentuser)(/.*)?",
        "level": 2,
        "description": "Detecta solicitudes a endpoints de SharePoint asociadas a vulnerabilidades (ej. CVE-2023-29357).",
        "remediation": "Revisa las configuraciones de seguridad de SharePoint y aplica los parches correspondientes."
    },
    "log4j": {
        "regex": r"(?i)\$\{jndi:(?:ldap|rmi|dns):\/\/[^\}]+\}",
        "level": 2,
        "description": "Detecta intentos de explotación de la vulnerabilidad Log4j mediante patrones JNDI.",
        "remediation": "Actualiza Log4j a una versión segura y revisa las configuraciones de logging."
    },
    "idor": {
        "regex": r"(?i)(?:/user/\d+|[?&](?:id|uid|user_id|account_id)=\d+)",
        "level": 1,
        "description": "Detecta intentos de Insecure Direct Object Reference (IDOR) mediante identificadores en la URL o parámetros.",
        "remediation": "Implementa controles de acceso robustos y verifica la autorización en cada solicitud."
    },
    "open_redirect": {
        "regex": r"(?i)[?&](redirect|next|url)=https?:\/\/[^\s]+",
        "level": 1,
        "description": "Detecta intentos de redirección abierta mediante parámetros que apuntan a URLs externas.",
        "remediation": "Valida y restringe los destinos de redirección utilizando listas blancas."
    },
    "rce": {
        "regex": r"(?i)(?:system|exec|shell_exec|passthru|popen)\s*(?:\(|%28)",
        "level": 0,
        "description": "Detecta intentos de ejecución remota de código mediante funciones peligrosas.",
        "remediation": "Evita la ejecución directa de comandos y utiliza métodos seguros para el procesamiento de entradas."
    },
    "ingress_nginx": {
        "regex": r'(?si)"nginx\.ingress\.kubernetes\.io/configuration-snippet"\s*:\s*".*rewrite\s+\^\/evil\/.*permanent;.*"',
        "level": 2,
        "description": "Detecta bypass de validación de anotaciones en ingress-nginx. Se analiza la anotación de configuración en busca de comandos rewrite maliciosos.",
        "remediation": "Revisa las anotaciones permitidas en el Ingress, actualiza la configuración de seguridad y aplica los parches correspondientes."
    },
    "http3_crash": {
        "regex": r'(?i)HTTP\/3".*?\s500\s',
        "level": 1,
        "description": "Detecta solicitudes HTTP/3 que resultan en un código 500, lo que puede indicar un crash en Apache HTTP/3 QUIC.",
        "remediation": "Verifica la versión de Apache HTTP/3, aplica parches disponibles y revisa la configuración de QUIC."
    },
    "glassfish": {
        "regex": r"(?i)POST\s+/.*(asadmin|domain-admin).*?(exec|deploy|command)",
        "level": 0,
        "description": "Detecta intentos de explotación en GlassFish basados en CVE-2011-0807 y RCE, buscando endpoints administrativos y comandos peligrosos.",
        "remediation": "Actualiza GlassFish a la versión más reciente, restringe el acceso a la consola administrativa y refuerza la configuración de seguridad."
    },
    "nmap": {
        "regex": r"(?i)(nmap|nmap\s+scan|nmap\s+scripting\s+engine)",
        "level": 1,
        "description": "Detecta indicios de escaneos de red realizados con Nmap, buscando términos comunes asociados al escaneo.",
        "remediation": "Monitorea y bloquea escaneos no autorizados, implementa reglas de firewall y utiliza sistemas IDS/IPS."
    },
    "api_attack": {
        "regex": r"(?i)(/graphql.*__schema|/api/.*\[\$(ne|regex)\])",
        "level": 1,
        "description": "Detecta intentos de ataques contra APIs, ya sea mediante consultas GraphQL de introspección (indicadas por __schema) o el uso de operadores MongoDB ([$ne] o [$regex]) en parámetros de endpoints de API.",
        "remediation": "Revisa las configuraciones de tus endpoints de API. Si la introspección de GraphQL no es necesaria, deshabilítala. Además, valida y sanitiza todos los parámetros de entrada, especialmente aquellos que usen operadores especiales."
    },
    "solarwinds": {
        "regex": r"(?i)/SolarWinds/InformationService/v3/Json/Query",
        "level": 2,
        "description": "Detecta solicitudes a endpoints de SolarWinds que pueden estar relacionados con vulnerabilidades conocidas, como las explotadas en el ataque de SolarWinds.",
        "remediation": "Actualiza SolarWinds a la versión más reciente, revisa las configuraciones de seguridad y aplica los parches correspondientes."
    },
    "joomla": {
        "regex": r"(?i)(option=com|task=|view=|Itemid=|layout=|format=|type=|lang=|id=|catid=|path=|func=|limit=|start=|filter=|search=|sort=|order=|by=|page=|redirect=|return=|goto=|redirect_to=|return_to=|goto=|redirect_url=|return_url=|goto_url=|redirect_path=|return_path=|goto_path=|redirect_page=|return_page=|goto_page=|redirect_file=|return_file=|goto_file=|redirect_item=|return_item=|goto_item=|redirect_view=|return_view=|goto_view=|redirect_layout=|return_layout=|goto_layout=|redirect_format=|return_format=|goto_format=|redirect_type=|return_type=|goto_type=|redirect_lang=|return_lang=|goto_lang=|redirect_id=|return_id=|goto_id=|redirect_catid=|return_catid=|goto_catid=|redirect_path=|return_path=|goto_path=|redirect_func=|return_func=|goto_func=|redirect_limit=|return_limit=|goto_limit=|redirect_start=|return_start=|goto_start=|redirect_filter=|return_filter=|goto_filter=|redirect_search=|return_search=|goto_search=|redirect_sort=|return_sort=|goto_sort=|redirect_order=|return_order=|goto_order=|redirect_by=|return_by=|goto_by=|redirect_page=|return_page=|goto_page=|redirect_redirect=|return_redirect=|goto_redirect=|redirect_return=|return_return=|goto_return=|redirect_goto=|return_goto=|goto_goto=|redirect_redirect_to=|return_redirect_to=|goto_redirect_to=|redirect_return_to=|return_return_to=|goto_return_to=|redirect_goto_url=|return_goto_url=|goto_goto_url=|redirect_goto_path=|return_goto_path=|goto_goto_path=|redirect_goto_page=|return_goto_page=|goto_goto_page=|redirect_goto_file=|return_goto_file=|goto_goto_file=|redirect_goto_item=|return_goto_item=|goto_goto_item=|redirect_goto_view=|return_goto_view=|goto_goto_view=|redirect_goto_layout=|return_goto_layout=|goto_goto_layout=|redirect_goto_format=|return_goto_format=|goto_goto_format=|redirect_goto_type=|return_goto_type=|goto_goto_type=|redirect_goto_lang=|return_goto_lang=|goto_goto_lang=|redirect_goto_id=|return_goto_id=|goto_goto_id=|redirect_goto_catid=|return_goto_catid=|goto_goto_catid=|redirect_goto_path=|return_goto_path=|goto_goto_path=|redirect_goto_func=|return_goto_func=|goto_goto_func=|redirect_goto_limit=|return_goto_limit=|goto_goto_limit=|redirect_goto_start=|return_goto_start=|goto_goto_start=|redirect_goto_filter=|return_goto_filter=|goto_goto_filter=|redirect_goto_search=|return_goto_search=|goto_goto_search=|redirect_goto_sort=|return_goto_sort=|goto_goto_sort=|redirect_goto_order=|return_goto_order=|goto_goto_order=|redirect_goto_by=|return_goto_by=|goto_goto_by=|redirect_goto_page=|return_goto_page=|goto_goto_page=|redirect_goto_redirect=|return_goto_redirect=|goto_goto_redirect=|redirect_goto_return=|return_goto_return=|goto_goto_return=|redirect_goto_goto=|return_goto_goto=|goto_goto_goto=|redirect_goto_redirect_to=|return_goto_redirect_to=|goto_goto_redirect_to=|redirect_goto_return_to=|return_goto_return_to=|goto_goto_return_to=|redirect_goto_goto_url=|return_goto_goto_url=|goto_goto_goto_url=|redirect_goto_goto_path=|return_goto_goto_path=|goto_goto_goto_path=|redirect_goto_goto_page=|return_goto_goto_page=|goto_goto_goto_page=|redirect_goto_goto_file=|return_goto_goto_file=|goto_goto_goto_file=|redirect_goto_goto_item=|return_goto_goto_item=|goto_goto_goto_item=|redirect_goto_goto_view=|return_goto_goto_view=|goto_goto_goto_view=|redirect_goto_goto_layout=|return_goto_goto_layout=|goto_goto_goto_layout=|redirect_goto_goto_format=|return_goto_goto_format=|goto_goto_goto_format=|redirect_goto_goto_type=|return_goto_goto_type=|goto_goto_goto_type=|redirect_goto_goto_lang=|return_goto_goto_lang=|goto_goto_goto_lang=|redirect_goto_goto_id=|return_goto_goto_id=|goto_goto_goto_id=|redirect_goto_goto_catid=|return_goto_goto_catid=|goto_goto_goto_catid=|redirect_goto_goto_path=|return_goto_goto_path=|goto_goto_goto_path=|redirect_goto_goto_func=|return_goto_goto_func=|goto_goto_goto_func=|redirect_goto_goto_limit=|return_goto_goto_limit=|goto_goto_goto_limit=|redirect_goto_goto_start=|return_goto_goto_start=|goto_goto_goto_start=|redirect_goto_goto_filter=|return_goto_goto_filter=|goto_goto_goto_filter=|redirect_goto_goto_search=|return_goto_goto_search=|goto_goto_goto_search=|redirect_goto_goto_sort=|return_goto_goto_sort=|goto_goto_goto_sort=|redirect_goto_goto_order=|return_goto_goto_order=|goto_goto_goto_order=|redirect_goto_goto_by=|return_goto_goto_by=|goto_goto_goto_by=|redirect_goto_goto_page=|return_goto_goto_page=|goto_goto_goto_page=|redirect_goto_goto_redirect=|return_goto_goto_redirect=|goto_goto_goto_redirect=|redirect_goto_goto_return=|return_goto_goto_return=|goto_goto_goto_return=|redirect_goto_goto_goto=|return_goto_goto_goto=|goto_goto_goto_goto=)",
        "level": 2,
        "description": "Detecta parámetros comunes en URLs de Joomla que pueden ser utilizados para ataques de inyección de SQL, XSS, CSRF y otros.",
        "remediation": "Actualiza Joomla a la versión más reciente, revisa las configuraciones de seguridad y aplica los parches correspondientes."
    },
    "wp_admin": {
        "regex": r"(?i)/wp-admin/?",
        "level": 1,
        "description": "Detecta accesos al panel administrativo de WordPress, lo que puede indicar un intento de escaneo o ataque.",
        "remediation": "Protege la URL de administración de WordPress con autenticación fuerte, restricciones IP y otras medidas de seguridad."
    },
    "php_exploits": {
        "regex": r"(?i)/(phpmyadmin|pma|info\.php|test\.php|config\.php|admin\.php|wp-config\.php|shell\.php|cmd\.php|backdoor\.php|CVE-2012-1823)",
        "level": 1,
        "description": (
            "Detecta intentos de explotación en aplicaciones PHP, incluyendo accesos a herramientas "
            "administrativas (como phpMyAdmin, wp-config.php, admin.php) y la presencia de indicadores "
            "relacionados con vulnerabilidades documentadas (por ejemplo, CVE-2012-1823)."
        ),
        "remediation": (
            "Actualiza tus aplicaciones PHP y CMS a las últimas versiones, restringe el acceso a herramientas "
            "administrativas mediante autenticación robusta y listas blancas de IP, y aplica los parches "
            "de seguridad correspondientes para mitigar vulnerabilidades conocidas."
        )
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
      - Exception: Si no se encuentra el preset.
    """
    key = attack_type.lower()
    if key in PRESETS:
        return PRESETS[key]
    else:
        raise Exception("Preset no encontrado: " + attack_type)
