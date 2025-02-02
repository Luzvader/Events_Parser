```markdown
# Events_Parser

Este proyecto es una herramienta de línea de comandos en Python para parsear y analizar logs de diferentes fuentes (como Apache, Nginx, ISS o Tomcat). La herramienta permite:

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
   ├── apache_parser.py
   ├── nginx_parser.py
   ├── iss_parser.py
   ├── tomcat_parser.py
   ├── web_attacks.py
   └── user_agents.py
```

- **parser.py:** Es el programa principal que interpreta los argumentos y llama a los módulos específicos según la aplicación indicada.  
- **modules/**: Contiene los módulos específicos para cada tipo de log (Apache, Nginx, ISS, Tomcat), el submódulo con presets para ataques web (`web_attacks.py`) y el módulo para extraer user agents (`user_agents.py`).

## Requisitos

- Python 3.6 o superior.
- El proyecto utiliza únicamente librerías estándar, por lo que no es necesario instalar dependencias externas adicionales.

## Uso General

La sintaxis general sigue este **nuevo flujo**:

```bash
python3 parser.py --app <APP> <subcommand> <ruta.log> <argumento_ataque_o_IP> <carpeta_salida>
```

donde `<APP>` puede ser:
- **apache**: para logs de Apache.
- **nginx**: para logs de Nginx.
- **iss**: para logs de ISS (IIS).
- **tomcat**: para logs de Tomcat.

y `<subcommand>` puede ser:
- **logs**: Procesa el log indicado aplicando el patrón (ataque, preset, o regex).
- **useragents**: Extrae y agrupa user agents, con opción de filtrar por IP.
- **webattacks**: Muestra los presets de ataques web disponibles.

### 1. Subcomando `logs`

- **Comando:**
  ```bash
  python3 parser.py --app <APP> logs <ruta.log> <ataque|regex> <output>
  ```
  - `--app <APP>`: Selecciona la aplicación (apache, nginx, iss o tomcat).
  - `logs`: Indica que procesaremos el archivo en busca de un ataque/preset/regex.
  - `<ruta.log>`: Ruta del archivo de log.
  - `<ataque|regex>`: Puede ser un **preset** definido en `web_attacks.py` (ej: `xss`, `sql_injection`, `lfi`, etc.) o una expresión regular personalizada.
  - `<output>`: Carpeta donde se guardarán los resultados (por defecto, `output` si no se especifica).

**Ejemplos:**
- Procesar un log de **Apache** buscando `sql_injection`:
  ```bash
  python3 parser.py --app apache logs access_test_100.log sql_injection output
  ```
- Procesar un log de **Tomcat** usando un regex personalizado:
  ```bash
  python3 parser.py --app tomcat logs tomcat.log "attack_pattern" myfolder
  ```

### 2. Subcomando `useragents`

- **Comando:**
  ```bash
  python3 parser.py --app <APP> useragents <ruta.log> <IP|none> <output>
  ```
  - `--app <APP>`: Selecciona la aplicación, aunque en la práctica el módulo `useragents` es independiente del tipo de app.  
  - `useragents`: Extrae y agrupa user agents por IP.
  - `<ruta.log>`: Ruta del archivo de log.
  - `<IP|none>`: IP concreta para filtrar. Si no deseas filtrar, usa `none`.
  - `<output>`: Carpeta donde se guardarán los resultados (por defecto `output` si no se especifica).

**Ejemplos:**
- Extraer **todos los user agents** de un log:
  ```bash
  python3 parser.py --app apache useragents access_test_100.log none output
  ```
- Extraer **solo user agents de la IP** `203.0.113.1`:
  ```bash
  python3 parser.py --app nginx useragents access_test_100.log 203.0.113.1 my_results
  ```

### 3. Subcomando `webattacks`

- **Comando:**
  ```bash
  python3 parser.py webattacks
  ```
  - Muestra la lista de presets actualmente definidos (no requiere `--app`, ni más argumentos).

**Ejemplo:**
```bash
python3 parser.py webattacks
```

## Ejemplo de Log de Prueba

Un ejemplo de log de prueba (`access_test_100.log`) se ha creado para simular un entorno real. Este archivo contiene 100 líneas con entradas normales y varias simulaciones de ataques web (XSS, SQL Injection, LFI, Command Injection, SharePoint, Log4j, IDOR, Open Redirect, RCE, Ingress‑nginx, HTTP/3 Crash, SSRF, etc.) y varía los user agents para mostrar casos donde una IP pueda usar distintos user agents.

Puedes utilizar este archivo para probar las funcionalidades del parser y ver cómo se agrupan los user agents o se detectan ataques mediante los presets.

## Ejecución y Casos de Uso

1. **Listar presets disponibles** (no usa `--app`):
   ```bash
   python3 parser.py webattacks
   ```
2. **Procesar logs** (ej: Apache) para detectar LFI:
   ```bash
   python3 parser.py --app apache logs access_test_100.log lfi output
   ```
3. **Extraer user agents** (sin filtrar) de un log de ISS:
   ```bash
   python3 parser.py --app iss useragents access_test_100.log none output
   ```
4. **Extraer user agents** (filtrando una IP en Tomcat):
   ```bash
   python3 parser.py --app tomcat useragents tomcat.log 192.168.1.10 output
   ```

## Licencia

Este proyecto se distribuye bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para más detalles.

---

¡Disfruta utilizando **Events_Parser** y ajusta los presets o módulos según tus necesidades!
```