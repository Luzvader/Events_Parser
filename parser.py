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

def run_user_agents(log_file, output, filter_ip=None):
    try:
        user_agents_module = importlib.import_module("modules.user_agents")
    except ImportError:
        print("Error: El módulo 'modules.user_agents' no está instalado o no se pudo importar.")
        sys.exit(1)
    
    results = user_agents_module.extract_user_agents(log_file)
    
    # Si se especifica una IP para filtrar, se selecciona solo esa clave.
    if filter_ip:
        if filter_ip in results:
            results = {filter_ip: results[filter_ip]}
        else:
            print(f"No se encontraron registros para la IP: {filter_ip}")
            sys.exit(0)
    
    if output:
        # Crear la carpeta de salida si no existe.
        if not os.path.exists(output):
            os.makedirs(output)
        base_name = os.path.basename(log_file)
        output_file = os.path.join(output, f"user_agents_{base_name}.txt")
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for ip, agents in results.items():
                    f.write(f"IP: {ip}\n")
                    for agent in agents:
                        f.write(f"  - {agent}\n")
                    f.write("\n")
            print(f"User agents agrupados se han guardado en: {output_file}")
        except Exception as e:
            print("Error al escribir el archivo de salida:", e)
            sys.exit(1)
    else:
        for ip, agents in results.items():
            print(f"IP: {ip}")
            for agent in agents:
                print(f"  - {agent}")
            print()

def main():
    parser = argparse.ArgumentParser(
        description="Parser de logs con módulos específicos, presets para ataques web y análisis de user agents."
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")
    
    # Subcomandos para parseo de logs con diferentes módulos:
    parser_htaccess = subparsers.add_parser("htaccess", help="Procesa logs de Apache (htaccess)")
    parser_htaccess.add_argument("log_file", help="Ruta del archivo de log")
    parser_htaccess.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, sql_injection, etc.)")
    parser_htaccess.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")
    
    parser_nginx = subparsers.add_parser("nginx", help="Procesa logs de Nginx")
    parser_nginx.add_argument("log_file", help="Ruta del archivo de log")
    parser_nginx.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, sql_injection, etc.)")
    parser_nginx.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")
    
    parser_iss = subparsers.add_parser("iss", help="Procesa logs de ISS (IIS)")
    parser_iss.add_argument("log_file", help="Ruta del archivo de log")
    parser_iss.add_argument("search_pattern", help="Patrón de búsqueda o preset (ej: xss, sql_injection, etc.)")
    parser_iss.add_argument("output", nargs="?", default="output", help="Carpeta de salida (default: output)")
    
    # Subcomando para listar los presets de ataques web.
    parser_webattacks = subparsers.add_parser("webattacks", help="Muestra los presets de ataques web actualmente disponibles")
    
    # Nuevo subcomando para extraer y agrupar user agents por IP, con opción de filtrar por IP.
    parser_useragents = subparsers.add_parser("useragents", help="Extrae y agrupa los user agents por IP del log")
    parser_useragents.add_argument("log_file", help="Ruta del archivo de log")
    parser_useragents.add_argument("output", nargs="?", default=None,
                                   help="Carpeta de salida para guardar resultados (opcional; si no se especifica, se imprime por pantalla)")
    parser_useragents.add_argument("--ip", dest="filter_ip", help="Filtra los resultados para una IP específica", default=None)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Manejar cada subcomando
    if args.command == "webattacks":
        list_web_attack_presets()
    elif args.command == "useragents":
        run_user_agents(args.log_file, args.output, args.filter_ip)
    else:
        # Para los subcomandos htaccess, nginx, iss: intentar usar presets si el patrón coincide.
        try:
            web_attacks = importlib.import_module("modules.web_attacks")
            presets = getattr(web_attacks, "PRESETS", {})
            key = args.search_pattern.lower()
            if key in presets:
                print(f"Usando preset '{args.search_pattern}' con regex: {presets[key]}")
                args.search_pattern = presets[key]
        except ImportError:
            # Si el módulo web_attacks no está disponible, continuar sin preset.
            pass
        
        module_name = f"modules.{args.command}_parser"
        try:
            log_module = importlib.import_module(module_name)
        except ImportError as e:
            missing_module = str(e).split("No module named ")[-1].strip("'")
            print(f"Error: El módulo requerido '{missing_module}' para '{args.command}' no está instalado.")
            respuesta = input(f"¿Desea instalar el paquete '{missing_module}'? [S/n]: ").strip().lower()
            if respuesta in ['', 's', 'si']:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", missing_module])
                    print(f"Paquete '{missing_module}' instalado. Reiniciando la carga del módulo...")
                    log_module = importlib.import_module(module_name)
                except subprocess.CalledProcessError as pip_error:
                    print(f"Error al instalar '{missing_module}': {pip_error}")
                    sys.exit(1)
            else:
                print("Abortando ejecución.")
                sys.exit(1)
        
        try:
            resultados = log_module.parse_log(args.log_file, args.search_pattern)
        except Exception as e:
            print("Error al procesar el log:", e)
            sys.exit(1)
        
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
            sys.exit(1)

if __name__ == '__main__':
    main()
