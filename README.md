```markdown
# Events_Parser

Events_Parser es una herramienta de línea de comandos en Python para parsear y analizar logs de diferentes fuentes, como Apache, Nginx, IIS y Tomcat. La herramienta permite:

- **Detectar patrones de ataques web** mediante presets (por ejemplo: XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, SSRF, etc.).
- **Extraer y agrupar los user agents** de los eventos, con la posibilidad de filtrar por una IP específica para identificar si una misma IP usa distintos user agents (posible indicio de evasión o manipulación).

Además, el uso de la herramienta es muy flexible, ya que se puede aplicar un filtro de patrón (preset o expresión regular) y, opcionalmente, filtrar las entradas por IP sin necesidad de indicar un patrón cuando solo se desea filtrar por IP.

## Estructura del Proyecto

La estructura de directorios es la siguiente:

```
log_parser/
├── parser.py
├── README.md
└── modules/
   ├── __init__.py
   ├── apache_parser.py    # Para logs de Apache
   ├── nginx_parser.py     # Para logs de Nginx
   ├── iis_parser.py       # Para logs de IIS
   ├── tomcat_parser.py    # Para logs de Tomcat
   ├── web_attacks.py      # Presets para ataques web
   └── user_agents.py      # Extracción y agrupación de user agents
```

- **parser.py:** Programa principal que interpreta los argumentos y llama a los módulos correspondientes según la aplicación seleccionada.
- **modules/**: Contiene los módulos específicos para cada tipo de log, el submódulo con presets de ataques web y el módulo para extraer user agents.

## Requisitos

- Python 3.6 o superior.
- El proyecto utiliza únicamente librerías estándar, por lo que no es necesario instalar dependencias externas adicionales.

## Uso

La sintaxis general es:

```bash
python3 parser.py --app <APP> <subcommand> <ruta.log> <output> [--pattern <ataque|regex>] [--ip <IP>]
```

donde:

- **`--app <APP>`**: Especifica la aplicación/servidor. Los valores permitidos son:
  - `apache` (para logs de Apache)
  - `nginx` (para logs de Nginx)
  - `iis` (para logs de IIS)
  - `tomcat` (para logs de Tomcat)

- **`<subcommand>`**: Es la acción a realizar y puede ser:
  - **`logs`**: Procesa el log aplicando un patrón (preset o regex).  
   - Si se **omite** el parámetro `--pattern`, se procesarán todas las líneas (equivalente a usar el patrón `.*`).
   - Se puede utilizar la opción `--ip` para filtrar las líneas de salida que comiencen con la IP indicada.
  - **`useragents`**: Extrae y agrupa los user agents por IP.  
   - El parámetro posicional se usa para indicar la ruta del log y la carpeta de salida.
   - Con `--ip` se filtran los user agents de una IP específica.
  - **`webattacks`**: Muestra la lista de presets de ataques web actualmente definidos.  
   - En este caso, los demás argumentos se ignoran.

- **`<ruta.log>`**: Ruta al archivo de log a procesar.
- **`<output>`**: Carpeta de salida donde se guardarán los resultados (por defecto, se usará `output` si no se especifica).
- **`[--pattern <ataque|regex>]`**: (Opcional para `logs`) Patrón de búsqueda que puede ser un preset (ej.: `xss`, `sql_injection`, etc.) o una expresión regular personalizada.
- **`[--ip <IP>]`**: (Opcional para `logs` y `useragents`) Filtra los resultados para la IP indicada. Si se omite, se procesan todas las entradas.

## Ejemplos de Uso

### 1. Listar Presets de Ataques Web

Muestra la lista de presets actualmente definidos:

```bash
python3 parser.py webattacks
```

### 2. Procesar Logs

#### a) Con patrón (preset o regex)

Procesar un log de **Apache** en búsqueda del preset `lfi` y filtrar por la IP `192.0.2.1`:

```bash
python3 parser.py --app apache logs access_test_100.log output --pattern lfi --ip 192.0.2.1
```

Procesar un log de **Tomcat** usando un regex personalizado (por ejemplo, `"attack_pattern"`):

```bash
python3 parser.py --app tomcat logs tomcat.log output --pattern "attack_pattern"
```

#### b) Solo filtrar por IP (sin especificar un patrón)

Si lo único que se desea es filtrar el log por una IP, se omite el parámetro `--pattern`:

```bash
python3 parser.py --app apache logs access_test_100.log output --ip 192.0.2.1
```

En este caso, el parser procesa todo el log y luego filtra las líneas para que solo se guarden aquellas que comiencen con la IP `192.0.2.1`.

### 3. Extraer y Agrupar User Agents

Extraer y agrupar todos los user agents de un log de **IIS**:

```bash
python3 parser.py --app iis useragents access_test_100.log output
```

Extraer y agrupar user agents filtrando por la IP `203.0.113.1` (por ejemplo, de un log de Nginx):

```bash
python3 parser.py --app nginx useragents access_test_100.log output --ip 203.0.113.1
```

## Ejemplo de Log de Prueba

Se ha creado un ejemplo de log de prueba (`access_test_100.log`) para simular un entorno real. Este archivo contiene 100 líneas con:
- Entradas normales (páginas, solicitudes estáticas).
- Simulaciones de ataques web (XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, SSRF, etc.).
- Variaciones en los user agents para mostrar casos en los que una IP pueda utilizar distintos agentes.

Puedes utilizar este archivo para probar las funcionalidades del parser, tanto en la detección de ataques mediante presets/regex como en la extracción y agrupación de user agents.

## Cómo Ejecutar

1. Abre una terminal y navega hasta el directorio raíz del proyecto (donde se encuentra `parser.py`).
2. Ejecuta cualquiera de los comandos anteriores según la funcionalidad que desees probar.

## Licencia

Este proyecto se distribuye bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para más detalles.

---

¡Disfruta utilizando **Events_Parser** y ajusta los presets o módulos según tus necesidades!
```
