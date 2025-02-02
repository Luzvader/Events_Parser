#!/usr/bin/env python3
import os
import sys
import argparse
import importlib
import subprocess

def list_web_attack_presets():
    """Lista los presets disponibles en el módulo web_attacks."""
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
    """Extrae y agrupa los user agents por IP; guarda el resultado en un archivo."""
    try:
        user_agents_module = importlib.import_module("modules.user_agents")
    except ImportError:
        print("Error: El módulo 'modules.user_agents' no está instalado o no se pudo importar.")
        sys.exit(1)
    
    results = user_agents_module.extract_user_agents(log_file)
    
    # Si se especifica una IP, se filtra el diccionario.
    if filter_ip:
        if filter_ip in results:
            results = {filter_ip: results[filter_ip]}
        else:
            print(f"No se encontraron registros para la IP: {filter_ip}")
            sys.exit(0)
    
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

def run_log_analysis(app, log_file, pattern, output, ip_filter=None):
    """
    Carga el módulo correspondiente a 'app' (apache, nginx, iss, tomcat) y procesa
    el log aplicando el patrón (preset o regex). Opcionalmente filtra las líneas por IP.
    """
    # Si no se proporcionó patrón, se usa '.*' para procesar todas las líneas.
    if not pattern:
        pattern = ".*"
    
    # Intentar cargar presets (si el patrón coincide con uno definido en web_attacks)
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        key = pattern.lower()
        if key in presets:
            print(f"Usando preset '{pattern}' con regex: {presets[key]}")
            pattern = presets[key]
    except ImportError:
        pass

    # Cargar el módulo de la aplicación indicada
    module_name = f"modules.{app}_parser"
    try:
        log_module = importlib.import_module(module_name)
    except ImportError as e:
        missing_module = str(e).split("No module named ")[-1].strip("'")
        print(f"Error: El módulo requerido '{missing_module}' para '{app}' no está instalado.")
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
        resultados = log_module.parse_log(log_file, pattern)
    except Exception as e:
        print("Error al procesar el log:", e)
        sys.exit(1)
    
    # Filtrado opcional por IP: se asume que la IP es el primer token de cada línea.
    if ip_filter:
        filtered_results = []
        for line in resultados:
            tokens = line.split()
            if tokens and tokens[0] == ip_filter:
                filtered_results.append(line)
        resultados = filtered_results

    if not os.path.exists(output):
        os.makedirs(output)
    
    base_name = os.path.basename(log_file)
    output_file_path = os.path.join(output, f"parsed_{base_name}")
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f_out:
            f_out.writelines(resultados)
        print(f"Se han guardado {len(resultados)} línea(s) en: {output_file_path}")
    except Exception as e:
        print("Error al escribir el archivo de salida:", e)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Events_Parser: Una herramienta de análisis de logs.\n\n"
                    "Sintaxis:\n"
                    "  python3 parser.py --app <APP> <subcommand> <ruta.log> <output> [--pattern <ataque|regex>] [--ip <IP>]\n\n"
                    "Donde <APP> puede ser: apache, nginx, iss o tomcat; y <subcommand> es uno de: logs, useragents, webattacks.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Argumento global --app (requerido para logs y useragents)
    parser.add_argument("--app", choices=["apache", "nginx", "iss", "tomcat"],
                        required=False, default=None,
                        help="Aplicación/servidor: apache, nginx, iss o tomcat (Requerido para 'logs' y 'useragents')")
    
    # Subcomando: logs, useragents, webattacks
    parser.add_argument("subcommand", choices=["logs", "useragents", "webattacks"],
                        help="Acción a realizar: logs / useragents / webattacks")
    
    # Posicionales generales:
    # Para 'logs' y 'useragents': log_file y output son requeridos.
    parser.add_argument("log_file", nargs="?", default=None,
                        help="Ruta al archivo de log (requerido para 'logs' y 'useragents')")
    parser.add_argument("output", nargs="?", default="output",
                        help="Carpeta de salida (por defecto: output)")
    
    # Opciones opcionales:
    parser.add_argument("--pattern", "-p", default=None,
                        help="(Solo para 'logs') Patrón de búsqueda (preset o regex). Si se omite, se procesan todas las líneas.")
    parser.add_argument("--ip", "-i", default=None,
                        help="Filtra los resultados para la IP especificada (aplica para 'logs' y 'useragents')")
    
    args = parser.parse_args()
    
    # Si el subcomando es 'webattacks', ignorar los demás argumentos
    if args.subcommand == "webattacks":
        list_web_attack_presets()
    
    # Para 'logs' y 'useragents', el archivo de log es obligatorio
    if args.subcommand in ["logs", "useragents"] and not args.log_file:
        parser.print_help()
        sys.exit(1)
    
    # Si se usa 'logs' o 'useragents', se requiere --app
    if args.subcommand in ["logs", "useragents"] and not args.app:
        print("Error: Debes especificar --app <apache|nginx|iss|tomcat> para 'logs' y 'useragents'.")
        sys.exit(1)
    
    if args.subcommand == "logs":
        # Para 'logs', se usan:
        #   - log_file: args.log_file
        #   - output: args.output
        #   - pattern: args.pattern (si no se proporciona, se usará '.*')
        #   - ip_filter: args.ip (si se proporciona)
        run_log_analysis(args.app, args.log_file, args.pattern, args.output, args.ip)
    
    elif args.subcommand == "useragents":
        # Para 'useragents', se usan:
        #   - log_file: args.log_file
        #   - output: args.output
        #   - ip_filter: args.ip (si se proporciona)
        run_user_agents(args.log_file, args.output, args.ip)

if __name__ == '__main__':
    main()
