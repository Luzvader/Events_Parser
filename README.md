```markdown
# Events_Parser

Events_Parser es una herramienta de línea de comandos en Python para analizar logs de Apache, Nginx, IIS y Tomcat. Permite:

- Detectar patrones de ataques web mediante presets (XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, SSRF, etc.).
- Extraer y agrupar los user agents de los eventos, con la opción de filtrar por IP para comprobar si una misma IP usa distintos agentes (indicando posible manipulación).

La herramienta es flexible, ya que permite aplicar un filtro de patrón (preset o regex) y, opcionalmente, filtrar por IP sin necesidad de valor especial al omitir --pattern.

## Estructura del Proyecto

```
log_parser/
├── parser.py
├── README.md
└── modules/
   ├── __init__.py
   ├── apache_parser.py
   ├── nginx_parser.py
   ├── iis_parser.py
   ├── tomcat_parser.py
   ├── web_attacks.py
   └── user_agents.py
```

- **parser.py**: Programa principal que interpreta los argumentos y llama a los módulos según la aplicación indicada.
- **modules/**: Contiene módulos específicos para cada tipo de log, los presets de ataques web y la extracción de user agents.

## Requisitos

- Python 3.6 o superior.
- Se usan únicamente librerías estándar, sin dependencias externas.

## Uso

```bash
python3 parser.py --app <APP> <subcommand> <ruta.log> <output> [--pattern <ataque|regex>] [--ip <IP>] [--level <0-3>] [--explained]
```

Parámetros principales:

- **--app <APP>**: aplicación/servidor (apache, nginx, iis, tomcat).
- **<subcommand>**:
  - **logs**: procesa el log aplicando un patrón o todo el archivo si se omite --pattern.
  - **useragents**: extrae y agrupa los user agents, con filtrado opcional por IP.
  - **webattacks**: análisis de ataques web usando un preset o todos hasta el nivel indicado. Incluye modo --explained (documentación adicional). Admite filtrado por IP.

- **<ruta.log>**: ruta al archivo de log.
- **<output>**: carpeta de salida (por defecto, output).
- **[--pattern <ataque|regex>]**: (opcional) preset o expresión regular para filtrar (logs/webattacks).
- **[--ip <IP>]**: (opcional) filtra resultados por IP.
- **[--level <0-3>]**: (solo en webattacks) nivel de análisis (0 = ataques críticos, 3 = analiza todo).
- **[--explained]**: (solo en webattacks) agrega documentación y recomendaciones.

## Ejemplos

1. Listado de presets:  
   ```bash
   python3 parser.py webattacks
   ```
2. Procesar logs con patrón preset o regex y filtrado por IP:  
   ```bash
   python3 parser.py --app apache logs access_test.log output --pattern lfi --ip 192.0.2.1
   ```
3. Extraer user agents en IIS sin filtrado:  
   ```bash
   python3 parser.py --app iis useragents access_test.log output
   ```
4. Análisis global en modo “botón gordo”:  
   ```bash
   python3 parser.py --app apache webattacks access_test.log output --level 3 --explained
   ```

## Ejemplo de Log

El archivo access_test_100.log incluye 100 líneas con ejemplos de tráfico legítimo, ataques web simulados (XSS, SQLi, LFI, etc.) y variaciones en user agents para probar funcionalidades.

## Cómo Ejecutar

1. Ubicarse en el directorio raíz del proyecto (donde está parser.py).
2. Ejecutar uno de los comandos anteriores según la necesidad.

## Licencia

Proyecto bajo Licencia MIT. Consulta el archivo LICENSE para más detalles.

Disfruta usando Events_Parser y ajusta los presets, niveles y módulos según tus necesidades.
```
