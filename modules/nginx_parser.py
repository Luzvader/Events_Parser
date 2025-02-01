import re

def parse_log(log_path, search_pattern):
    """
    Procesa un log de Nginx (formato TXT, línea por línea) y devuelve una lista
    con las líneas que coincidan con el patrón de búsqueda (expresión regular).

    :param log_path: Ruta del archivo de log (por ejemplo, access.log).
    :param search_pattern: Patrón de búsqueda (expresión regular).
    :return: Lista de líneas que cumplen con el patrón.
    """
    resultados = []
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            # Compilamos la expresión regular para una búsqueda más eficiente
            pattern = re.compile(search_pattern)
            for line in file:
                if pattern.search(line):
                    resultados.append(line)
    except FileNotFoundError:
        raise Exception("Archivo no encontrado: " + log_path)
    return resultados
