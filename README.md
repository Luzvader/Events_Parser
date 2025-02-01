# Events_Parser

Este proyecto es una herramienta de línea de comandos en Python para parsear y analizar logs de diferentes fuentes (como Apache, Nginx o ISS). La herramienta permite:

- **Detectar patrones de ataques web** mediante presets (por ejemplo: XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, etc.).
- **Extraer y agrupar los user agents** de los eventos, permitiendo incluso filtrar por una IP específica para detectar si una misma IP utiliza distintos user agents (posible indicio de evasión o manipulación).

## Estructura del Proyecto

La estructura de directorios es la siguiente:

```
log_parser/
├── parser.py
├── README.md
└── modules/
    ├── __init__.py
    ├── htaccess_parser.py
    ├── nginx_parser.py
    ├── iss_parser.py
    ├── web_attacks.py
    └── user_agents.py
```

- **parser.py:** Es el programa principal que interpreta los comandos y llama a los módulos correspondientes.
- **modules/**: Contiene los módulos específicos para cada tipo de log y el submódulo con presets para ataques web, así como el módulo para extraer user agents.

## Requisitos

- Python 3.6 o superior.
- El proyecto utiliza únicamente librerías estándar, por lo que no es necesario instalar dependencias externas adicionales.

## Uso

La sintaxis general es:

```bash
python3 parser.py <comando> <ruta_al_log> [parámetros adicionales] [output]
```

### Comandos Disponibles

1. **Procesar Logs**

   **htaccess**: Procesa logs de Apache (htaccess).

   Ejemplo:

   ```bash
   python3 parser.py htaccess access_test_100.log xss output
   ```

   Este comando analiza el archivo `access_test_100.log` en búsqueda del preset `xss` y guarda los resultados en la carpeta `output`.

   **nginx**: Procesa logs de Nginx.

   Ejemplo:

   ```bash
   python3 parser.py nginx access_test_100.log sql_injection output
   ```

   **iss**: Procesa logs de ISS (IIS).

   Ejemplo:

   ```bash
   python3 parser.py iss access_test_100.log sharepoint output
   ```

   Nota: En estos comandos, el parámetro `<search_pattern>` puede ser un preset definido en el submódulo `web_attacks.py` (por ejemplo: xss, sql_injection, lfi, command_injection, sharepoint, log4j, idor, open_redirect, rce, ingress_nginx, http3_crash, etc.).

2. **Listar Presets de Ataques Web**

   El comando `webattacks` muestra los presets actualmente definidos para detectar ataques web.

   Ejemplo:

   ```bash
   python3 parser.py webattacks
   ```

3. **Extraer y Agrupar User Agents**

   El comando `useragents` extrae y agrupa los user agents de cada IP del log. Además, puedes filtrar los resultados para una IP específica usando el argumento `--ip`.

   Para extraer y agrupar todos los user agents:

   ```bash
   python3 parser.py useragents access_test_100.log output
   ```

   Para filtrar por una IP en concreto (por ejemplo, 203.0.113.1):

   ```bash
   python3 parser.py useragents access_test_100.log output --ip 203.0.113.1
   ```

## Ejemplo de Log de Prueba

Un ejemplo de log de prueba (`access_test_100.log`) se ha creado para simular un entorno real. Este archivo contiene 100 líneas con entradas normales y varias simulaciones de ataques web (XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, SSRF, etc.) y varía los user agents para mostrar casos donde una IP pueda usar distintos user agents.

Puedes utilizar este archivo para probar las funcionalidades del parser.

## Cómo Ejecutar

1. Abre una terminal y navega hasta el directorio raíz del proyecto (donde se encuentra `parser.py`).
2. Ejecuta cualquiera de los comandos anteriores según lo que desees probar.

## Licencia

Este proyecto se distribuye bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.

¡Disfruta utilizando el Log Parser Tool y ajusta los presets o módulos según tus necesidades!
