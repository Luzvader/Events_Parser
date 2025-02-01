"""
Módulo para extraer y agrupar los User Agents de un log por IP.

Este módulo asume que el log está en formato combinado, donde:
  - La primera parte de cada línea (separada por espacios) es la IP.
  - El User Agent es el último campo entre comillas.
  
Ejemplo de línea de log (formato combinado):
  192.168.1.10 - - [11/Oct/2021:08:35:20 +0000] "GET /index.html HTTP/1.1" 200 1984 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

La función `extract_user_agents` devuelve un diccionario en el que cada clave es una IP y
el valor asociado es un conjunto (set) de user agents encontrados en las líneas correspondientes.
"""

import re

def extract_user_agents(log_file_path):
    """
    Extrae los user agents agrupados por IP de un archivo de log.

    Args:
        log_file_path (str): Ruta del archivo de log.

    Returns:
        dict: Diccionario donde la clave es la IP y el valor es un set de user agents.
    """
    ip_to_agents = {}
    
    # Expresión regular para capturar la IP (primer token) y el User Agent (último campo entre comillas)
    # Esta regex asume que el log está en formato combinado.
    # La IP se captura en el primer grupo y el User Agent en el segundo.
    regex = re.compile(r'^(?P<ip>\S+).*"(?P<ua>[^"]+)"\s*$')
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Método 1: Utilizando regex que asume que el user agent es el último campo entre comillas.
            # Debido a que en el formato combinado pueden haber varios campos entre comillas (por ejemplo,
            # el request, el referer y el user agent), usaremos un enfoque que divida la línea por comillas.
            # Se espera que el User Agent sea el penúltimo elemento de la lista resultante.
            parts = line.split('"')
            if len(parts) >= 6:
                # Por convención, en el formato combinado:
                # parts[0] contiene la IP y otros campos no entre comillas.
                # parts[1] es la petición.
                # parts[3] es el referer.
                # parts[5] es el user agent.
                ip = parts[0].split()[0]
                user_agent = parts[5].strip()
            else:
                # Si el formato no cumple, se puede intentar usar la regex como fallback.
                match = regex.match(line)
                if match:
                    ip = match.group('ip')
                    user_agent = match.group('ua').strip()
                else:
                    continue  # No se pudo parsear la línea

            # Agregar el user agent a la agrupación por IP.
            if ip not in ip_to_agents:
                ip_to_agents[ip] = set()
            if user_agent:
                ip_to_agents[ip].add(user_agent)
                
    return ip_to_agents

if __name__ == "__main__":
    # Ejemplo de uso: ejecutar el módulo directamente para ver los user agents agrupados.
    import sys
    if len(sys.argv) != 2:
        print("Uso: python3 user_agents.py <ruta_al_log>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    agents_by_ip = extract_user_agents(log_file)
    
    # Mostrar los resultados
    for ip, agents in agents_by_ip.items():
        print(f"IP: {ip}")
        for agent in agents:
            print(f"  - {agent}")
