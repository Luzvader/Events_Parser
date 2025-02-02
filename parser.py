#!/usr/bin/env python3
import os
import sys
import argparse
import importlib
import subprocess

def list_web_attack_presets():
    """
    Lista los presets disponibles en el módulo web_attacks.
    """
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

def run_user_agents(app, log_file, ip_filter, output):
    """
    Extrae y agrupa los user agents por IP. El cuarto argumento puede ser la IP a filtrar (o 'none').
    Se guarda en un archivo dentro de 'output'.
    """
    # 'app' no se usa directamente en useragents, pero la dejamos como ejemplo de parámetro global
    try:
        user_agents_module = importlib.import_module("modules.user_agents")
    except ImportError:
        print("Error: El módulo 'modules.user_agents' no está instalado o no se pudo importar.")
        sys.exit(1)
    
    results = user_agents_module.extract_user_agents(log_file)
    
    # Filtrado opcional por IP, si ip_filter != 'none'
    if ip_filter and ip_filter.lower() != "none":
        if ip_filter in results:
            results = {ip_filter: results[ip_filter]}
        else:
            print(f"No se encontraron registros para la IP: {ip_filter}")
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

def run_log_analysis(app, log_file, search_pattern, output):
    """
    Carga dinámicamente el módulo correspondiente a 'app' (apache, nginx, iss, tomcat)
    y filtra las líneas del log que coincidan con 'search_pattern'.
    """
    # Intentar cargar presets, por si search_pattern coincide con uno
    try:
        web_attacks = importlib.import_module("modules.web_attacks")
        presets = getattr(web_attacks, "PRESETS", {})
        key = search_pattern.lower()
        if key in presets:
            print(f"Usando preset '{search_pattern}' con regex: {presets[key]}")
            search_pattern = presets[key]
    except ImportError:
        # Si no está web_attacks, se continúa sin preset
        pass
    
    # Cargar el módulo según el valor de app
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
    
    # Procesar el log con el parse_log del módulo cargado
    try:
        resultados = log_module.parse_log(log_file, search_pattern)
    except Exception as e:
        print("Error al procesar el log:", e)
        sys.exit(1)
    
    # Guardar los resultados en un archivo
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
        description="Parser de logs más user-friendly: python parser.py --app <APP> <subcommand> <ruta.log> <patron/IP> <output>"
    )
    
    # Argumento global '--app'
    parser.add_argument("--app", choices=["apache","nginx","iss","tomcat"],
                        required=False, default=None,
                        help="Aplicación/servidor: apache, nginx, iss o tomcat (Requerido para 'logs' y 'useragents')")
    
    # Subcomando => logs | useragents | webattacks
    parser.add_argument("subcommand", choices=["logs","useragents","webattacks"],
                        help="Acción a realizar: logs / useragents / webattacks")
    
    # Argumentos posicionales principales, algunos pueden ser ignorados según subcommand
    parser.add_argument("arg2", nargs="?", default=None,
                        help="Si subcommand=logs/useragents => ruta al log; Si webattacks => se ignora")
    parser.add_argument("arg3", nargs="?", default=None,
                        help="Si subcommand=logs => ataque/preset; Si useragents => IP a filtrar (o 'none'); Si webattacks => se ignora")
    parser.add_argument("arg4", nargs="?", default=None,
                        help="Si subcommand=logs/useragents => carpeta de salida; Si webattacks => se ignora")
    
    args = parser.parse_args()
    
    # Manejar los tres subcommands
    if args.subcommand == "webattacks":
        # Ignoramos arg2, arg3, arg4
        list_web_attack_presets()
    
    elif args.subcommand == "logs":
        # Requerimos --app
        if not args.app:
            print("Error: Debes especificar --app <apache|nginx|iss|tomcat> para 'logs'.")
            sys.exit(1)
        if not args.arg2 or not args.arg3:
            print("Uso: python parser.py --app <APP> logs <ruta.log> <ataque|regex> <output>")
            sys.exit(1)
        
        log_file = args.arg2
        pattern = args.arg3
        output_folder = args.arg4 if args.arg4 else "output"
        run_log_analysis(args.app, log_file, pattern, output_folder)
    
    elif args.subcommand == "useragents":
        # Requerimos --app
        if not args.app:
            print("Error: Debes especificar --app <apache|nginx|iss|tomcat> para 'useragents'.")
            sys.exit(1)
        if not args.arg2:
            print("Uso: python parser.py --app <APP> useragents <ruta.log> [IP|none] <output>")
            sys.exit(1)
        
        log_file = args.arg2
        ip_filter = args.arg3 if args.arg3 else "none"
        output_folder = args.arg4 if args.arg4 else "output"
        run_user_agents(args.app, log_file, ip_filter, output_folder)

if __name__ == '__main__':
    main()
