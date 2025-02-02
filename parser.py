#!/usr/bin/env python3
import os
import sys
import argparse
import importlib
import subprocess
import re

def list_web_attack_presets():
    """Lista los presets disponibles en el módulo web_attacks con su documentación."""
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        if presets:
            print("Presets de ataques web disponibles:")
            for name, data in presets.items():
                print(f"  - {name}:")
                print(f"      Regex: {data.get('regex','')}")
                print(f"      Nivel: {data.get('level','')}")
                print(f"      Descripción: {data.get('description','')}")
                print(f"      Remediación: {data.get('remediation','')}")
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
        print("Error: El módulo 'modules.user_agents' no se encontró.")
        sys.exit(1)
    
    results = user_agents_module.extract_user_agents(log_file)
    
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
        print(f"User agents guardados en: {output_file}")
    except Exception as e:
        print("Error al escribir la salida:", e)
        sys.exit(1)

def run_log_analysis(app, log_file, pattern, output, ip_filter=None):
    """
    Procesa el log usando el módulo correspondiente a 'app' y un patrón (preset o regex).
    Opcionalmente filtra las líneas por IP.
    """
    if not pattern:
        pattern = ".*"
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        key = pattern.lower()
        if key in presets:
            print(f"Usando preset '{pattern}' con regex: {presets[key]['regex']}")
            pattern = presets[key]['regex']
    except ImportError:
        pass

    module_name = f"modules.{app}_parser"
    try:
        log_module = importlib.import_module(module_name)
    except ImportError as e:
        missing_module = str(e).split("No module named ")[-1].strip("'")
        print(f"Error: El módulo '{missing_module}' para '{app}' no se encontró.")
        sys.exit(1)
    
    try:
        resultados = log_module.parse_log(log_file, pattern)
    except Exception as e:
        print("Error procesando el log:", e)
        sys.exit(1)
    
    if ip_filter:
        resultados = [line for line in resultados if line.split()[0] == ip_filter]

    if not os.path.exists(output):
        os.makedirs(output)
    
    base_name = os.path.basename(log_file)
    output_file_path = os.path.join(output, f"parsed_{base_name}")
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f_out:
            f_out.writelines(resultados)
        print(f"Se han guardado {len(resultados)} línea(s) en: {output_file_path}")
    except Exception as e:
        print("Error al escribir la salida:", e)
        sys.exit(1)

def run_webattacks(app, log_file, output, level, explained, pattern, ip_filter):
    """
    Realiza un análisis integral ("botón gordo") de ataques web.
    
    Si se especifica --pattern, se analiza únicamente ese preset específico;
    de lo contrario, se analizan todos los presets cuyo nivel sea <= level.
    
    Además, si se activa --explained, se añade documentación (descripción y recomendaciones)
    en el informe.
    """
    try:
        web_attacks_mod = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks_mod, "PRESETS", {})
    except ImportError:
        print("Error: No se pudo importar el módulo web_attacks.")
        sys.exit(1)
    
    # Leer el log completo
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            log_lines = f.readlines()
    except Exception as e:
        print("Error leyendo el log:", e)
        sys.exit(1)
    
    selected_presets = {}
    if pattern:
        # Si se especifica --pattern, buscar ese preset en particular
        for name, data in presets.items():
            if name.lower() == pattern.lower():
                selected_presets[name] = data
                break
        if not selected_presets:
            print(f"No se encontró el preset '{pattern}'.")
            sys.exit(1)
    else:
        # Seleccionar todos los presets con level <= level
        for name, data in presets.items():
            if data.get("level", 3) <= level:
                selected_presets[name] = data
    
    results = {}
    for preset, data in selected_presets.items():
        regex = data.get("regex")
        try:
            compiled = re.compile(regex)
        except re.error as e:
            print(f"Error compilando la regex para preset '{preset}': {e}")
            continue
        matches = [line for line in log_lines if compiled.search(line)]
        if ip_filter:
            matches = [line for line in matches if line.split()[0] == ip_filter]
        if matches:
            results[preset] = {
                "matches": matches,
                "description": data.get("description", "Sin descripción."),
                "remediation": data.get("remediation", "Sin recomendaciones.")
            }
    
    if not os.path.exists(output):
        os.makedirs(output)
    
    base_name = os.path.basename(log_file)
    output_file_path = os.path.join(output, f"webattacks_report_{base_name}.txt")
    
    try:
        with open(output_file_path, "w", encoding="utf-8") as f_out:
            for preset, info in results.items():
                f_out.write(f"=== {preset.upper()} ===\n")
                f_out.write(f"Ocurrencias: {len(info['matches'])}\n")
                if explained:
                    f_out.write(f"Descripción: {info['description']}\n")
                    f_out.write(f"Recomendaciones: {info['remediation']}\n")
                f_out.write("Líneas:\n")
                for line in info["matches"]:
                    f_out.write(line)
                f_out.write("\n\n")
        print(f"Informe webattacks generado en: {output_file_path}")
    except Exception as e:
        print("Error generando el informe:", e)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Events_Parser: Herramienta de análisis de logs.\n\n"
                    "Sintaxis:\n"
                    "  python3 parser.py --app <APP> <subcommand> <ruta.log> <output> [--pattern <ataque|regex>]\n"
                    "                                  [--ip <IP>] [--level <0-3>] [--explained]\n\n"
                    "Donde <APP> puede ser: apache, nginx, iss o tomcat; y <subcommand> es uno de: logs, useragents, webattacks.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--app", choices=["apache", "nginx", "iss", "tomcat"],
                        required=False, default=None,
                        help="Aplicación/servidor: apache, nginx, iss o tomcat (Requerido para 'logs', 'useragents' y 'webattacks')")
    
    parser.add_argument("subcommand", choices=["logs", "useragents", "webattacks"],
                        help="Acción a realizar: logs / useragents / webattacks")
    
    parser.add_argument("log_file", nargs="?", default=None,
                        help="Ruta al archivo de log (requerido para 'logs', 'useragents' y 'webattacks')")
    
    parser.add_argument("output", nargs="?", default="output",
                        help="Carpeta de salida (por defecto: output)")
    
    parser.add_argument("--pattern", "-p", default=None,
                        help="(Para 'logs' y 'webattacks') Patrón de búsqueda (preset o regex). Si se omite, se procesa todo el log o se analiza globalmente según --level.")
    
    parser.add_argument("--ip", "-i", default=None,
                        help="Filtra los resultados para la IP especificada (aplica para 'logs', 'useragents' y 'webattacks')")
    
    parser.add_argument("--level", "-l", type=int, choices=range(0, 4), default=3,
                        help="(Para 'webattacks') Nivel de análisis del 0 al 3. Nivel 0: ataques críticos; Nivel 3: todos (por defecto: 3)")
    
    parser.add_argument("--explained", "-e", action="store_true",
                        help="(Para 'webattacks') Incluye documentación y recomendaciones en el informe.")
    
    args = parser.parse_args()
    
    if not args.subcommand:
        parser.print_help()
        sys.exit(0)
    
    if args.subcommand == "webattacks":
        if not args.log_file:
            print("Error: Debes especificar la ruta al log para 'webattacks'.")
            sys.exit(1)
        run_webattacks(args.app if args.app else "apache", args.log_file, args.output, args.level, args.explained, args.pattern, args.ip)
    
    elif args.subcommand == "useragents":
        if not args.log_file:
            parser.print_help()
            sys.exit(1)
        run_user_agents(args.log_file, args.output, args.ip)
    
    elif args.subcommand == "logs":
        if not args.log_file:
            parser.print_help()
            sys.exit(1)
        if not args.app:
            print("Error: Debes especificar --app <apache|nginx|iss|tomcat> para 'logs'.")
            sys.exit(1)
        run_log_analysis(args.app, args.log_file, args.pattern, args.output, args.ip)

if __name__ == '__main__':
    main()
