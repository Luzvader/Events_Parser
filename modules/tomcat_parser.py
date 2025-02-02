# modules/tomcat_parser.py

import re

def parse_log(log_path, search_pattern):
    """
    Procesa un log de Tomcat y devuelve las líneas que coincidan con el search_pattern.
    El search_pattern puede ser una expresión regular o un preset (regex) obtenido
    de web_attacks.

    :param log_path: Ruta del archivo de log de Tomcat.
    :param search_pattern: Patrón de búsqueda (regex).
    :return: Lista de líneas que cumplen el patrón.
    """
    resultados = []
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            pattern = re.compile(search_pattern)
            for line in file:
                if pattern.search(line):
                    resultados.append(line)
    except FileNotFoundError:
        raise Exception(f"Archivo no encontrado: {log_path}")
    return resultados
