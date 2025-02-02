#!/usr/bin/env python3
import re

def parse_log(log_path, search_pattern):
    """
    Procesa un log de Tomcat y devuelve las líneas que coincidan con el search_pattern.
    El search_pattern puede ser una expresión regular o un preset (definido en web_attacks).

    Parámetros:
      - log_path (str): Ruta al archivo de log de Tomcat.
      - search_pattern (str): Patrón de búsqueda (regex).
    
    Retorna:
      - List[str]: Lista de líneas que cumplen con el patrón.
    """
    resultados = []
    try:
        with open(log_path, "r", encoding="utf-8") as file:
            pattern = re.compile(search_pattern)
            for line in file:
                if pattern.search(line):
                    resultados.append(line)
    except FileNotFoundError:
        raise Exception(f"Archivo no encontrado: {log_path}")
    return resultados
