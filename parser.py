#!/usr/bin/env python3
import os
import sys
import argparse
import importlib
import subprocess

def list_web_attack_presets():
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        if presets:
            print("Presets de ataques web disponibles:")
            for preset, regex in presets.items():
                print(f"  - {preset}: {regex}")
        else:
            print("No se han definido presets de ataques web.")
    except ImportError:
        print("El módulo 'modules.web_attacks' no se encontró.")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Parser de logs con módulos específicos y presets para ataques web"
    )
    
    # Subparsers para elegir el módulo a cargar según el tipo de log o para listar presets.
    subparsers = parser.add_subparsers(dest="log_type", help="Tipo de log a procesar o comando especial")

    # Subparser para logs Apache (htaccess)
    parser_htaccess = subparsers.add_parser("htaccess", help="Procesa logs de Apache (htaccess)")
    parser_htaccess.add_argument("log_file", help="Ruta del archivo de log (ej: htaccess.txt)")
    parser_htaccess.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, command_injection)")
    parser_htaccess.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")
    
    # Subparser para logs Nginx
    parser_nginx = subparsers.add_parser("nginx", help="Procesa logs de Nginx")
    parser_nginx.add_argument("log_file", help="Ruta del archivo de log (ej: access.log)")
    parser_nginx.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, command_injection)")
    parser_nginx.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")
    
    # Subparser para logs ISS (IIS)
    parser_iss = subparsers.add_parser("iss", help="Procesa logs de ISS (IIS)")
    parser_iss.add_argument("log_file", help="Ruta del archivo de log (ej: iss.log)")
    parser_iss.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, command_injection)")
    parser_iss.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")

    # Nuevo subparser para listar los presets de ataques web
    parser_webattacks = subparsers.add_parser("webattacks", help="Muestra los presets de ataques web actualmente disponibles")
    # No se requieren argumentos adicionales para este subcomando.

    args = parser.parse_args()
    
    if not args.log_type:
        parser.print_help()
        sys.exit(0)
    
    # Si se invoca el subcomando "webattacks", listamos los presets y salimos.
    if args.log_type == "webattacks":
        list_web_attack_presets()

    # Si el parámetro search_pattern coincide con un preset definido en el módulo web_attacks,
    # se reemplaza por la expresión regular correspondiente.
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        key = args.search_pattern.lower()
        if key in presets:
            print(f"Usando preset '{args.search_pattern}' con regex: {presets[key]}")
            args.search_pattern = presets[key]
    except ImportError:
        # Si el módulo web_attacks no está disponible, se continúa sin usar presets.
        pass
    
    # Construir el nombre del módulo a importar dinámicamente.
    module_name = f"modules.{args.log_type}_parser"
    try:
        log_module = importlib.import_module(module_name)
    except ImportError as e:
        missing_module = str(e).split("No module named ")[-1].strip("'")
        print(f"Error: El módulo requerido '{missing_module}' para '{args.log_type}' no está instalado.")
        respuesta = input(f"¿Desea instalar el paquete '{missing_module}'? [S/n]: ").strip().lower()
        if respuesta in ['', 's', 'si']:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", missing_module])
                print(f"Paquete '{missing_module}' instalado. Reiniciando la carga del módulo...")
                log_module = importlib.import_module(module_name)
            except subprocess.CalledProcessError as pip_error:
                print(f"Error al instalar '{missing_module}': {pip_error}")
                return
        else:
            print("Abortando ejecución.")
            return
    
    # Procesar el log usando la función parse_log del módulo correspondiente.
    try:
        resultados = log_module.parse_log(args.log_file, args.search_pattern)
    except Exception as e:
        print("Error al procesar el log:", e)
        return
    
    # Crear la carpeta de salida si no existe.
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    
    base_name = os.path.basename(args.log_file)
    output_file_path = os.path.join(args.output, f"parsed_{base_name}")
    
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f_out:
            f_out.writelines(resultados)
        print(f"Se han guardado {len(resultados)} línea(s) en: {output_file_path}")
    except Exception as e:
        print("Error al escribir el archivo de salida:", e)

if __name__ == '__main__':
    main()
