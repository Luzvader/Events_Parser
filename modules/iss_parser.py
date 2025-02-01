import re

def parse_log(log_path, search_pattern):
    """
    Procesa un log de ISS (IIS) en formato TXT, ignorando las líneas de encabezado (que comienzan con '#')
    y devuelve una lista de líneas que coincidan con el patrón de búsqueda.

    :param log_path: Ruta del archivo de log (ej: iss.log)
    :param search_pattern: Patrón de búsqueda (expresión regular)
    :return: Lista de líneas que cumplen con el patrón
    """
    resultados = []
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            # Compilamos la expresión regular para eficiencia
            pattern = re.compile(search_pattern)
            for line in file:
                # Ignorar líneas de encabezado (por ejemplo, "#Software: Microsoft Internet Information Services")
                if line.startswith("#"):
                    continue
                if pattern.search(line):
                    resultados.append(line)
    except FileNotFoundError:
        raise Exception("Archivo no encontrado: " + log_path)
    return resultados
