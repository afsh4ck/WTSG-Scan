#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OWASP Web Security Testing Scanner
Web Security Testing (WSTG) Scanner - Interactive & Authenticated Edition
Author: afsh4ck
Description: Full web spidering, directory fuzzing (ffuf with progress), injections, API tests, user enumeration & bruteforce.
"""

import argparse
import base64
import getpass
import re
import signal
import sys
import ssl
import socket
import tempfile
import time
import json
import os
import subprocess
import shutil
import platform
import html
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser


# ===== INPUT CON AUTOCOMPLETADO DE RUTAS (TAB) =====
if os.name == 'nt':
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import PathCompleter
        def input_path(prompt_text):
            return prompt(prompt_text, completer=PathCompleter(), complete_while_typing=True)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)
else:
    try:
        import readline
        import glob
        readline.set_history_length(100)
        class FilePathCompleter:
            def complete(self, text, state):
                line = readline.get_line_buffer().split()
                if not line:
                    return [None][state]
                else:
                    matches = glob.glob(text+'*')
                    try:
                        return matches[state]
                    except IndexError:
                        return None
        readline.set_completer_delims(' \t\n;')
        readline.set_completer(FilePathCompleter().complete)
        readline.parse_and_bind('tab: complete')
        def input_path(prompt_text):
            return input(prompt_text)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[!] BeautifulSoup4 no instalado. Usando parsing básico.")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = LIGHTBLACK_EX = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:
        def __init__(self, iterable=None, total=None, **kwargs):
            self.iterable = iterable
            self.total = total
        def __iter__(self):
            return iter(self.iterable or [])
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def update(self, n=1):
            pass
        def set_postfix(self, *a, **k):
            pass
        def close(self):
            pass

# ========== BANNER ==========
BANNER = r"""
 _       __       __         _____                   
| |     / /_____ / /_ ____ _/ ___/ _____ ____ _ ____ 
| | /| / // ___// __// __ `/\__ \ / ___// __ `// __ \
| |/ |/ /(__  )/ /_ / /_/ /___/ // /__ / /_/ // / / /
|__/|__//____/ \__/ \__, //____/ \___/ \__,_//_/ /_/ 
                   /____/                            
"""
DESCRIPTION = "OWASP Web Security Testing Scanner"
DEVELOPER = "developed by @afsh4ck"
VERSION = "1.2.0"

# ========== CONFIGURACIÓN ==========
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10
THREADS = 5
AUTHENTICATED = False
AUTH_SESSION = None
TARGET_URL = ""
REQUEST_DELAY = 0.0  # Delay entre requests (segundos)
OUTPUT_FILE = None   # Ruta del archivo de reporte
VERIFY_TLS = True    # Verificación TLS (desactivable con --insecure)
FINDINGS = []        # Hallazgos acumulados para el reporte
SCAN_DATA = {
    "general": {},
    "robots_paths": [],
    "http_methods": [],
    "nmap": {},
    "vhosts": [],
    "directory_hits": [],
    "injection": {},
    "api_endpoints": [],
    "users": [],
    "emails": [],
    "bruteforce_credentials": [],
    "wordpress_detection": {},
    "wordpress": {},
    "spider": {},
    "source_code_analysis": {},
    "stats": {},
}

COMMON_DIRS = [
    "admin", "backup", "cgi-bin", "css", "js", "images", "uploads", "download",
    "include", "inc", "config", "api", "v1", "old", "test", "dev", "hidden",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.backup",
    "phpinfo.php", "info.php", "backup.zip", "backup.sql", "dump.sql",
    "wp-admin", "wp-content", "administrator", "phpmyadmin", "adminer.php",
    ".htaccess", ".htpasswd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "package.json", "composer.json", "server-status"
]

SECLISTS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
SECLISTS_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
SECLISTS_PASSWORDS = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
ROCKYOU_WORDLIST = "/usr/share/wordlists/rockyou.txt"
ROCKYOU_WORDLIST_GZ = "/usr/share/wordlists/rockyou.txt.gz"
SECLISTS_DNS = "/usr/share/seclists/Discovery/DNS/namelist.txt"
DEFAULT_PASSWORDS = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome"
]

# Payloads
SQL_PAYLOADS = [
    "'", "''", "\"", "\\", "' OR '1'='1", "' OR 1=1--",
    "1 AND 1=1", "1 AND 1=2", "' UNION SELECT NULL--", "'; DROP TABLE users--",
    "' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "javascript:alert('XSS')",
    "<svg/onload=alert(1)>", "'-alert(1)-'", "\"-alert(1)-\""
]

PATH_TRAVERSAL = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "....//....//....//etc/passwd"
]

COMMAND_INJECT = [
    "; ls", "| dir", "|| ping -c 1 127.0.0.1", "& whoami",
    "$(whoami)", "`whoami`", "| net user"
]

OPEN_REDIRECT = ["https://evil.com", "//evil.com", "/redirect?url=https://evil.com"]

API_ENDPOINTS = [
    # Raíces de API
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    # Recursos comunes
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/admin", "/api/me", "/api/profile", "/api/whoami",
    "/api/config", "/api/settings", "/api/flags", "/api/data",
    "/api/keys", "/api/tokens", "/api/secrets", "/api/credentials",
    "/api/debug", "/api/test", "/api/internal",
    "/rest/users", "/rest/user", "/rest/admin", "/rest/profile",
    # Documentación OpenAPI / Swagger
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/docs", "/api/docs", "/api/swagger",
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/query", "/api/query",
    # Spring Actuator / monitoring
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/httptrace", "/actuator/loggers",
    "/health", "/metrics", "/info", "/status", "/ping",
    # Rutas de autenticación
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/register", "/api/signup",
    # Rutas sensibles
    "/.well-known/", "/api/version", "/api/changelog",
    "/console", "/api/console", "/h2-console",
]

MASS_ASSIGNMENT_FIELDS = [
    {"is_admin": True},
    {"role": "admin"},
    {"admin": True},
    {"isAdmin": True},
    {"privilege": "admin"},
    {"user_role": "administrator"},
    {"account_type": "premium"},
    {"verified": True},
    {"status": "active"},
    {"credits": 9999},
    {"balance": 9999},
    {"permissions": ["admin", "superuser"]},
]

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/logon", "/login.php", "/login.html",
    "/user/login", "/account/login", "/admin/login", "/wp-login.php"
]

# Prefijos típicos de API que sirven de base para fuzzing recursivo
API_BASE_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/services", "/services/api",
]

# Recursos REST típicos. Se prueban bajo cada prefijo de API activo
# (p. ej. /api/v1/users, /api/v1/transfer, etc.)
API_RESOURCES = [
    # Identidad / cuentas
    "users", "user", "accounts", "account", "me", "profile", "whoami",
    "auth", "login", "logout", "register", "signup", "signin",
    "token", "tokens", "refresh", "session", "sessions",
    "password", "reset-password", "forgot-password", "2fa", "mfa", "otp",
    # Admin / configuración
    "admin", "config", "settings", "flags", "feature-flags",
    "permissions", "roles", "groups", "privileges",
    "audit", "audit-log", "logs", "events",
    # Datos / negocio
    "data", "items", "products", "orders", "invoices", "payments",
    "transactions", "transfer", "transfers", "wallets", "balance",
    "subscriptions", "plans", "billing", "cart", "checkout",
    "notes", "messages", "chats", "comments", "posts", "articles",
    "files", "uploads", "documents", "attachments", "media", "images",
    # Búsqueda / metadatos
    "search", "filter", "query", "tags", "categories",
    # Operacional / oculto
    "stats", "metrics", "health", "status", "version", "info",
    "debug", "test", "internal", "private", "hidden",
    "keys", "secrets", "credentials", "api-keys",
    "export", "import", "backup", "dump", "report", "reports",
    "notifications", "webhooks", "callbacks", "subscribe",
    "feed", "feeds", "activity", "history",
]

# ========== UTILIDADES ==========
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def check_ffuf():
    return shutil.which("ffuf") is not None

def check_wpscan():
    return shutil.which("wpscan")

def install_wpscan():
    """Ofrece instalar WPScan con gem si no esta disponible."""
    print_warning("WPScan no esta instalado o no esta en PATH.")
    if os.name == 'nt':
        print_info("Instalalo manualmente con Ruby/Gem o ejecuta el scanner desde Kali/WSL: gem install wpscan")
        return False
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar WPScan automaticamente con sudo gem install wpscan? [s/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp != 's':
        return False
    try:
        print_info("Ejecutando: sudo gem install wpscan")
        subprocess.run(["sudo", "gem", "install", "wpscan"], check=True)
        if check_wpscan():
            print_good("WPScan instalado correctamente.")
            return True
        print_error("La instalacion parece haber fallado.")
        return False
    except Exception as e:
        print_error(f"No se pudo instalar WPScan: {e}")
        return False

def _wait_for_interrupted_child(process, name="proceso", grace_seconds=5):
    """Give an interrupted child process time to flush files before killing it."""
    if not process:
        return None
    if process.poll() is not None:
        return process.returncode

    try:
        return process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass

    if os.name != 'nt' and process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
            return process.wait(timeout=2)
        except Exception:
            pass

    if process.poll() is None:
        print_warning(f"{name} no terminó tras Ctrl+C; terminando proceso.")
        try:
            process.terminate()
            return process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                return process.wait(timeout=2)
            except Exception:
                return process.returncode
        except Exception:
            return process.returncode
    return process.returncode

def _load_ffuf_json_results(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) <= 2:
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        results = data.get('results', [])
        return results if isinstance(results, list) else []
    if isinstance(data, list):
        return data
    return []

def check_whatweb():
    return shutil.which("whatweb") is not None

def install_whatweb():
    """Ofrece instalar WhatWeb via apt si no está disponible."""
    print_warning("WhatWeb no está instalado.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar WhatWeb automáticamente? (requiere sudo) [s/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp != 's':
        return False
    try:
        print_info("Ejecutando: sudo apt-get install -y whatweb")
        ret = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "whatweb"],
            check=True
        )
        if check_whatweb():
            print_good("WhatWeb instalado correctamente.")
            return True
        else:
            print_error("La instalación parece haber fallado.")
            return False
    except Exception as e:
        print_error(f"No se pudo instalar WhatWeb: {e}")
        return False

def run_whatweb(target):
    """Ejecuta WhatWeb y formatea su salida."""
    if not check_whatweb():
        if not install_whatweb():
            return None

    # Categorías de color
    CATEGORY_COLOR = {
        'cms':         Fore.MAGENTA,
        'framework':   Fore.MAGENTA,
        'language':    Fore.CYAN,
        'server':      Fore.CYAN,
        'javascript':  Fore.YELLOW,
        'jquery':      Fore.YELLOW,
        'analytics':   Fore.YELLOW,
        'security':    Fore.GREEN,
        'email':       Fore.WHITE,
        'country':     Fore.WHITE,
        'ip':          Fore.WHITE,
        'title':       Fore.WHITE,
        'httpserver':  Fore.CYAN,
        'x-powered-by':Fore.CYAN,
    }

    try:
        cmd = ["whatweb", "--color=never", target]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        if not raw:
            print_warning("WhatWeb no devolvió resultados.")
            return []

        # WhatWeb brief format: URL [STATUS] Plugin1[val], Plugin2[val], ...
        technologies = []
        SEP = "─" * 60
        print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  WHATWEB — Detección de tecnologías{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Extraer plugins de la línea
            # Formato: http://host [200 OK] Plugin1, Plugin2[value], ...
            bracket_match = re.match(r'^(https?://\S+)\s+\[([^\]]+)\]\s*(.*)', line)
            if not bracket_match:
                # Línea sin parsear → mostrar cruda
                print(f"  {line}")
                continue

            url_part    = bracket_match.group(1)
            status_part = bracket_match.group(2)
            plugins_raw = bracket_match.group(3)

            # Color del código HTTP
            http_code = status_part.split()[0] if status_part else ''
            if http_code.startswith('2'):
                sc = Fore.GREEN
            elif http_code.startswith('3'):
                sc = Fore.CYAN
            elif http_code.startswith('4'):
                sc = Fore.YELLOW
            elif http_code.startswith('5'):
                sc = Fore.RED
            else:
                sc = Fore.WHITE

            print(f"  {Fore.WHITE}{url_part}{Style.RESET_ALL}  "
                  f"{sc}[{status_part}]{Style.RESET_ALL}")

            if not plugins_raw:
                continue

            # Separar plugins respetando corchetes anidados
            plugins = []
            depth, start = 0, 0
            for i, ch in enumerate(plugins_raw):
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    p = plugins_raw[start:i].strip()
                    if p:
                        plugins.append(p)
                    start = i + 1
            tail = plugins_raw[start:].strip()
            if tail:
                plugins.append(tail)

            for plugin in plugins:
                # Separar nombre del valor entre corchetes
                pm = re.match(r'^([A-Za-z0-9_\-\./ ]+?)(?:\[(.+)\])?$', plugin, re.DOTALL)
                if pm:
                    name = pm.group(1).strip()
                    value = pm.group(2).strip() if pm.group(2) else ''
                else:
                    name, value = plugin.strip(), ''

                technologies.append({"name": name, "detail": value})
                key = name.lower().replace(' ', '').replace('-', '')
                color = next(
                    (v for k, v in CATEGORY_COLOR.items() if k in key),
                    Fore.WHITE
                )
                if value:
                    print(f"    {color}▸ {name:<28}{Style.RESET_ALL}  "
                          f"{Fore.WHITE}{value[:60]}{Style.RESET_ALL}")
                else:
                    print(f"    {color}▸ {name}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}\n")
        # Eliminar duplicados por (name, detail)
        seen = set()
        unique_techs = []
        for t in technologies:
            key = (t['name'], t['detail'])
            if key not in seen:
                seen.add(key)
                unique_techs.append(t)
        return unique_techs

    except subprocess.TimeoutExpired:
        print_error("WhatWeb tardó demasiado (timeout 30s).")
        return None
    except Exception as e:
        print_error(f"Error ejecutando WhatWeb: {e}")
        return None

def check_nmap():
    return shutil.which("nmap")

def install_nmap():
    """Ofrece instalar nmap vía apt si no está disponible."""
    print_warning("nmap no está instalado.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar nmap automáticamente? (requiere sudo) [s/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp != 's':
        return False
    try:
        print_info("Ejecutando: sudo apt-get install -y nmap")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
        if check_nmap():
            print_good("nmap instalado correctamente.")
            return True
        print_error("La instalación parece haber fallado.")
        return False
    except Exception as e:
        print_error(f"No se pudo instalar nmap: {e}")
        return False

def run_nmap_scan(target):
    """Ejecuta `nmap -sV` sobre el host del target y guarda los puertos en SCAN_DATA["nmap"].

    Parsea el XML de salida (-oX -) para una extracción robusta de puerto, estado,
    servicio, producto y versión. Muestra tabla visual al terminar.
    """
    print_phase("ESCANEO DE PUERTOS (NMAP)")
    nmap_path = check_nmap()
    if not nmap_path:
        if not install_nmap():
            print_warning("Saltando escaneo de puertos.")
            return None
        nmap_path = check_nmap()
        if not nmap_path:
            return None

    host = urlparse(target).hostname or target
    if not host:
        print_error("No se pudo extraer el host del target.")
        return None

    print_info(f"Ejecutando: nmap -sV {host}")
    print()
    try:
        # Aumentado timeout porque 600s puede quedarse corto en targets con muchos puertos
        proc = subprocess.run(
            [nmap_path, "-sV", "-oX", "-", host],
            capture_output=True, text=True, timeout=1800
        )
    except subprocess.TimeoutExpired:
        print_error("nmap excedió el timeout de 600s.")
        return None
    except KeyboardInterrupt:
        print_warning("Escaneo de puertos interrumpido por el usuario.")
        return None
    except Exception as e:
        print_error(f"Error ejecutando nmap: {e}")
        return None

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        # Mostrar el stderr / stdout para diagnóstico
        if proc.stderr:
            print_error(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"nmap rc={proc.returncode}")
        else:
            print_error(f"nmap rc={proc.returncode}")
        return None

    ports = []
    host_info = {"address": host, "hostnames": [], "status": ""}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_out)
        for h in root.findall("host"):
            status_el = h.find("status")
            if status_el is not None:
                host_info["status"] = status_el.get("state", "")
            for addr in h.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    host_info["address"] = addr.get("addr") or host_info["address"]
            for hn in h.findall("hostnames/hostname"):
                name = hn.get("name")
                if name:
                    host_info["hostnames"].append(name)
            for p in h.findall("ports/port"):
                state_el = p.find("state")
                svc_el = p.find("service")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue
                entry = {
                    "port": int(p.get("portid", 0)),
                    "protocol": p.get("protocol", ""),
                    "state": state,
                    "service": (svc_el.get("name") if svc_el is not None else "") or "",
                    "product": (svc_el.get("product") if svc_el is not None else "") or "",
                    "version": (svc_el.get("version") if svc_el is not None else "") or "",
                    "extrainfo": (svc_el.get("extrainfo") if svc_el is not None else "") or "",
                }
                ports.append(entry)
    except Exception as e:
        print_error(f"Error parseando XML de nmap: {e}")
        return None

    ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "")))

    # Tabla visual
    if ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        rows = []
        for p in ports:
            color = STATE_COLOR.get(p["state"], Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join([v for v in version_parts if v]).strip() or "-"
            if len(version_str) > 60:
                version_str = version_str[:57] + "..."
            rows.append([
                f"{p['port']}/{p['protocol']}",
                f"{color}{p['state']}{Style.RESET_ALL}",
                p.get("service", "") or "-",
                version_str,
            ])
        print_table(
            headers=["PUERTO", "ESTADO", "SERVICIO", "VERSIÓN"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Puertos abiertos ({len(ports)}):",
        )
        # Registrar en FINDINGS los puertos abiertos para que aparezcan
        # también en las secciones de hallazgos clasificados.
        for p in ports:
            label = p.get("service", "") or "?"
            version_str = " ".join(
                [v for v in (p.get("product", ""), p.get("version", "")) if v]
            ).strip()
            FINDINGS.append(
                f"[PORT] {host_info['address']}:{p['port']}/{p['protocol']} "
                f"{label}" + (f" ({version_str})" if version_str else "")
            )
    else:
        print_info("nmap no encontró puertos abiertos visibles.")

    SCAN_DATA["nmap"] = {
        "host": host_info["address"],
        "hostnames": host_info["hostnames"],
        "status": host_info["status"],
        "ports": ports,
        "command": f"nmap -sV {host}",
    }
    return SCAN_DATA["nmap"]


def check_nuclei():
    return shutil.which("nuclei")

def install_nuclei():
    """Ofrece instalar Nuclei via apt si no está disponible."""
    print_warning("Nuclei no está instalado.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar Nuclei automáticamente? (requiere sudo) [s/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp != 's':
        return False
    try:
        print_info("Ejecutando: sudo apt-get install -y nuclei")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nuclei"], check=True)
        if check_nuclei():
            print_good("Nuclei instalado correctamente.")
            return True
        print_error("La instalación parece haber fallado.")
        return False
    except Exception as e:
        print_error(f"No se pudo instalar Nuclei: {e}")
        return False

def run_nuclei_scan(target):
    """Ejecuta Nuclei sobre el objetivo y acumula resultados en SCAN_DATA."""
    print_phase("ANÁLISIS DE VULNERABILIDADES")
    nuclei_path = check_nuclei()
    if not nuclei_path:
        if not install_nuclei():
            print_warning("Saltando análisis Nuclei.")
            return None
        nuclei_path = check_nuclei()
        if not nuclei_path:
            return None

    print_info(f"Ejecutando Nuclei sobre {target}...")
    findings = []
    process = None
    json_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_json:
            json_path = tmp_json.name
        # Usamos -jsonl-export (jsonlines, una línea JSON por hallazgo) para robustez.
        cmd = [nuclei_path, "-u", target, "-jsonl-export", json_path]
        # IMPORTANTE: stdout en modo binario para evitar UnicodeDecodeError con
        # banners/símbolos no-UTF8 que emite Nuclei. Decodificamos tolerante.
        # Filtramos líneas ruidosas del backend Interactsh (bytes corruptos en stderr).
        NOISE_PATTERNS = (
            b"Could not unmarshal interaction data",
        )
        def _stream(proc):
            for raw_line in iter(proc.stdout.readline, b""):
                if any(pat in raw_line for pat in NOISE_PATTERNS):
                    continue
                try:
                    print(raw_line.decode("utf-8", errors="replace"), end='')
                except Exception:
                    pass
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _stream(process)
        process.wait()

        # Si la versión de Nuclei no soporta -jsonl-export, reintentar con -json-export
        if (not os.path.isfile(json_path) or os.path.getsize(json_path) == 0):
            try:
                cmd_alt = [nuclei_path, "-u", target, "-json-export", json_path]
                proc2 = subprocess.Popen(cmd_alt, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _stream(proc2)
                proc2.wait()
            except Exception:
                pass

        # Leer el JSON/JSONL generado de forma robusta (una entrada JSON por línea
        # o un array JSON completo según versión)
        if os.path.isfile(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore").strip()
            # Caso 1: array JSON
            if content.startswith("["):
                try:
                    arr = json.loads(content)
                    if isinstance(arr, list):
                        for data in arr:
                            if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                                findings.append(data)
                except Exception:
                    pass
            # Caso 2: JSONL (una entrada por línea)
            if not findings:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                            findings.append(data)
                    except Exception:
                        continue
    except KeyboardInterrupt:
        if process:
            process.terminate()
        print_warning("Nuclei interrumpido por el usuario.")
        return []
    except Exception as e:
        print_error(f"Error ejecutando Nuclei: {e}")
        return []
    finally:
        if json_path:
            try:
                os.unlink(json_path)
            except Exception:
                pass

    # Normalizar hallazgos a un formato estable para reportes
    def _extract(item):
        info = item.get('info') if isinstance(item.get('info'), dict) else {}
        return {
            'template_id': item.get('template-id') or item.get('templateID') or item.get('template') or 'unknown',
            'name': info.get('name') or item.get('name') or '',
            'severity': (info.get('severity') or item.get('severity') or 'unknown').lower(),
            'url': item.get('matched-at') or item.get('host') or item.get('url') or '',
            'type': item.get('type') or info.get('type') or '',
            'tags': info.get('tags') or [],
            'description': (info.get('description') or '').strip(),
            'reference': info.get('reference') or [],
        }

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    # Deduplicar por (template_id, url, severity) — Nuclei puede emitir el mismo
    # hallazgo varias veces (p. ej. headers de seguridad faltantes, uno por header).
    normalized = []
    seen_dedup = set()
    for it in findings:
        ext = _extract(it)
        key = (ext['template_id'], ext['url'], ext['severity'])
        if key in seen_dedup:
            continue
        seen_dedup.add(key)
        normalized.append(ext)
    normalized.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 99), x['template_id']))

    # Resumen por severidad
    summary = {}
    for n in normalized:
        summary.setdefault(n['severity'], []).append(n['template_id'])

    print_info(f"Total vulnerabilidades detectadas por Nuclei: {len(normalized)}")
    if normalized:
        # Tabla resumen por severidad
        sum_rows = []
        for sev in sorted(summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            unique_str = ', '.join(sorted(set(summary[sev])))
            display = unique_str if len(unique_str) <= 100 else unique_str[:97] + '...'
            color = SEV_COLOR.get(sev, Fore.WHITE)
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(summary[sev])),
                display,
            ])
        print_table(
            headers=["Severidad", "Cantidad", "Templates únicos"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Resumen de vulnerabilidades por severidad:",
        )

        # Tabla de hallazgos relevantes (críticos/altos/medios/bajos)
        relevant = [n for n in normalized if n['severity'] in ('critical', 'high', 'medium', 'low')]
        if relevant:
            rel_rows = []
            for n in relevant[:50]:
                color = SEV_COLOR.get(n['severity'], Fore.WHITE)
                rel_rows.append([
                    f"{color}{n['severity'].upper()}{Style.RESET_ALL}",
                    n['template_id'],
                    n['name'] or '-',
                    n['url'] or '-',
                ])
            print_table(
                headers=["Severidad", "Template", "Nombre", "URL"],
                rows=rel_rows,
                alignments=['<', '<', '<', '<'],
                title="Hallazgos relevantes:",
            )
            if len(relevant) > 50:
                print(f"  ... y {len(relevant) - 50} hallazgos relevantes más (ver reporte)")

        # Persistir cada hallazgo en FINDINGS para que aparezca en TXT/HTML
        for n in normalized:
            FINDINGS.append(
                f"[NUCLEI:{n['severity'].upper()}] {n['template_id']}"
                + (f" — {n['name']}" if n['name'] else "")
                + (f" @ {n['url']}" if n['url'] else "")
            )
    else:
        print("\nNo se detectaron vulnerabilidades con Nuclei.")

    # Acumular en SCAN_DATA: detalle + resumen
    if 'nuclei_findings' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_findings'], list):
        SCAN_DATA['nuclei_findings'] = []
    SCAN_DATA['nuclei_findings'].extend(normalized)

    if 'nuclei_summary' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_summary'], dict):
        SCAN_DATA['nuclei_summary'] = {}
    for sev, tids in summary.items():
        if sev not in SCAN_DATA['nuclei_summary']:
            SCAN_DATA['nuclei_summary'][sev] = []
        prev = set(SCAN_DATA['nuclei_summary'][sev])
        nuevos = [tid for tid in tids if tid not in prev]
        SCAN_DATA['nuclei_summary'][sev].extend(nuevos)
        SCAN_DATA['nuclei_summary'][sev] = list(sorted(set(SCAN_DATA['nuclei_summary'][sev])))
    return normalized

def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def print_good(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def print_vuln(msg):
    FINDINGS.append(f"[VULN] {msg}")
    print(f"{Fore.MAGENTA}[VULN]{Style.RESET_ALL} {msg}")

def print_phase(title):
    """Imprime una cabecera de fase: [INFO] ======= TITLE ======= con espacio arriba y abajo."""
    print()
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} ======= {title} =======")
    print()

# Regex para descontar códigos ANSI al medir ancho visible
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_BOX_DRAWING_FALLBACK = str.maketrans({
    chr(0x2500): "-",
    chr(0x2502): "|",
    chr(0x250c): "+",
    chr(0x2510): "+",
    chr(0x2514): "+",
    chr(0x2518): "+",
    chr(0x251c): "+",
    chr(0x2524): "+",
    chr(0x252c): "+",
    chr(0x2534): "+",
    chr(0x253c): "+",
})

def _safe_print_line(text=""):
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        fallback = str(text).translate(_BOX_DRAWING_FALLBACK)
        fallback = fallback.encode(encoding, errors="replace").decode(encoding, errors="replace")
        sys.stdout.write(fallback + os.linesep)

def _visible_len(s):
    return len(_ANSI_RE.sub('', str(s)))

def _pad_cell(cell, width, align='<'):
    """Pad una celda al ancho dado, ignorando códigos ANSI para el cálculo."""
    cell_str = str(cell)
    pad = width - _visible_len(cell_str)
    if pad <= 0:
        return cell_str
    if align == '<':
        return cell_str + ' ' * pad
    if align == '>':
        return ' ' * pad + cell_str
    left = pad // 2
    return ' ' * left + cell_str + ' ' * (pad - left)

def print_table(headers, rows, alignments=None, title=None, border_color=None, footer=None):
    """Imprime una tabla box-drawing con anchos dinámicos.

    headers: list[str]
    rows: list[list[str]] (las celdas pueden contener códigos ANSI)
    alignments: list[str] con '<', '>' o '^' por columna (default '<')
    title: cadena opcional encima de la tabla
    footer: cadena opcional debajo de la tabla
    """
    if not headers:
        return
    n_cols = len(headers)
    alignments = alignments or ['<'] * n_cols
    if len(alignments) < n_cols:
        alignments = list(alignments) + ['<'] * (n_cols - len(alignments))
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(n_cols):
            if i < len(r):
                widths[i] = max(widths[i], _visible_len(r[i]))
    color = border_color if border_color is not None else Fore.CYAN
    rc = Style.RESET_ALL
    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    mid = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"
    if title:
        _safe_print_line(f"\n{color}{title}{rc}")
    _safe_print_line(f"{color}{top}{rc}")
    header_line = " │ ".join(_pad_cell(h, widths[i], alignments[i]) for i, h in enumerate(headers))
    _safe_print_line(f"{color}│{rc} {color}{header_line}{rc} {color}│{rc}")
    _safe_print_line(f"{color}{mid}{rc}")
    for r in rows:
        cells = [
            _pad_cell(r[i] if i < len(r) else '', widths[i], alignments[i])
            for i in range(n_cols)
        ]
        line = f" {color}│{rc} ".join(cells)
        _safe_print_line(f"{color}│{rc} {line} {color}│{rc}")
    _safe_print_line(f"{color}{bot}{rc}")
    if footer:
        _safe_print_line(footer)

def _safe_filename_from_url(target_url):
    """Genera un nombre de archivo estable en base a la URL objetivo."""
    parsed = urlparse(target_url or "")
    host = (parsed.netloc or parsed.path or "target").strip().lower()
    path = parsed.path.strip('/') if parsed.netloc else ""
    raw = f"{host}_{path}" if path else host
    safe = re.sub(r'[^a-zA-Z0-9._-]+', '_', raw).strip('._-')
    return safe or "target"

def _default_report_txt_name(target_url):
    return f"{_safe_filename_from_url(target_url)}.txt"

def _normalize_output_paths(output_file, target_url):
    """Devuelve rutas estables para TXT/JSON/HTML/MD. Siempre sobrescribe por objetivo."""
    # Carpeta base de reportes
    reports_dir = os.path.join(os.getcwd(), "reports")
    # Nombre de subcarpeta por host/url
    host_dir = _safe_filename_from_url(target_url)
    out_dir = os.path.join(reports_dir, host_dir)
    os.makedirs(out_dir, exist_ok=True)
    base_name = _default_report_txt_name(target_url)
    txt_file = os.path.join(out_dir, base_name)
    base, ext = os.path.splitext(txt_file)
    if not ext:
        txt_file = txt_file + ".txt"
        base = txt_file[:-4]
    return txt_file, base + ".json", base + ".html", base + ".md"

def _to_serializable(value):
    """Convierte objetos no serializables (cookies, sets, etc.) en tipos JSON simples."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(v) for v in value]
    if hasattr(value, 'items'):
        try:
            return {str(k): _to_serializable(v) for k, v in value.items()}
        except Exception:
            pass
    return str(value)

def _html_escape(value):
    return html.escape(str(value), quote=True)

def _build_html_report(report_data):
    """Genera reporte HTML con modo light/dark y secciones relevantes del escaneo."""
    scan_data = report_data.get("scan_data", {})
    findings = report_data.get("findings", [])
    technologies = scan_data.get("general", {}).get("technologies", []) or []
    users = scan_data.get("users", [])
    emails = scan_data.get("emails", [])
    endpoints = scan_data.get("api_endpoints", [])
    vhosts_list = scan_data.get("vhosts", [])
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []
    dirs = scan_data.get("directory_hits", [])
    creds = scan_data.get("bruteforce_credentials", [])
    wordpress = scan_data.get("wordpress", {}) or {}
    spider = scan_data.get("spider", {})
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings") or []
    meta = scan_data.get("stats", {})

    nuclei_summary = scan_data.get('nuclei_summary', {})
    nuclei_findings_list = scan_data.get('nuclei_findings', []) or []
    nuclei_html = ""
    if nuclei_summary or nuclei_findings_list:
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        nuclei_html = "<div class='card' id='nuclei'><h3>Análisis Nuclei</h3>"
        if nuclei_summary:
            nuclei_html += "<h4>Resumen por severidad</h4><ul>"
            for sev in sorted(nuclei_summary.keys(), key=lambda s: sev_order.get(s, 99)):
                tids = nuclei_summary[sev]
                nuclei_html += (
                    f"<li><b>{_html_escape(sev.upper())}</b>: {len(tids)} hallazgos "
                    f"({', '.join(_html_escape(t) for t in tids)})</li>"
                )
            nuclei_html += "</ul>"
        if nuclei_findings_list:
            sorted_findings = sorted(
                nuclei_findings_list,
                key=lambda x: (sev_order.get((x.get('severity') or 'unknown'), 99),
                               x.get('template_id', ''))
            )
            nuclei_html += (
                "<h4>Detalle de hallazgos</h4>"
                "<table><thead><tr><th>Severidad</th><th>Template</th>"
                "<th>Nombre</th><th>URL afectada</th></tr></thead><tbody>"
            )
            for n in sorted_findings:
                nuclei_html += (
                    "<tr>"
                    f"<td>{_html_escape((n.get('severity') or '').upper())}</td>"
                    f"<td>{_html_escape(n.get('template_id', ''))}</td>"
                    f"<td>{_html_escape(n.get('name', ''))}</td>"
                    f"<td>{_html_escape(n.get('url', ''))}</td>"
                    "</tr>"
                )
            nuclei_html += "</tbody></table>"
        nuclei_html += "</div>"

    # ── Hallazgos agrupados por categoría ───────────────────────────────
    def _classify(item):
        s = str(item)
        if s.startswith('[NUCLEI:'):
            try:
                sev = s.split('[NUCLEI:', 1)[1].split(']', 1)[0].strip()
            except Exception:
                sev = 'INFO'
            return f"Nuclei — {sev}"
        if s.startswith('[VULN]'):
            return "Vulnerabilidades"
        if s.startswith('[DIR]'):
            return "Directorios / Endpoints"
        if s.startswith('[VHOST]'):
            return "Subdominios (vhosts)"
        if s.startswith('[PORT]'):
            return "Puertos abiertos (Nmap)"
        if s.startswith('[WP'):
            return "WordPress"
        if s.startswith('[CRED'):
            return "Credenciales"
        return "Otros"

    CAT_ORDER = [
        "Vulnerabilidades",
        "Nuclei — CRITICAL", "Nuclei — HIGH", "Nuclei — MEDIUM",
        "Nuclei — LOW", "Nuclei — INFO", "Nuclei — UNKNOWN",
        "Puertos abiertos (Nmap)",
        "WordPress",
        "Credenciales",
        "Subdominios (vhosts)",
        "Directorios / Endpoints",
        "Otros",
    ]
    grouped = {}
    for item in findings:
        grouped.setdefault(_classify(item), []).append(str(item))
    if grouped:
        sections = []
        cats_present = [c for c in CAT_ORDER if c in grouped] + \
                       [c for c in grouped if c not in CAT_ORDER]
        for cat in cats_present:
            items = grouped[cat]
            section = (
                f"<details open><summary><b>{_html_escape(cat)}</b> "
                f"<span class='muted'>({len(items)})</span></summary><ul>"
                + "\n".join(f"<li>{_html_escape(i)}</li>" for i in items)
                + "</ul></details>"
            )
            sections.append(section)
        findings_items = "\n".join(sections)
    else:
        findings_items = "<span class='muted'>Sin hallazgos.</span>"

    # ── Tecnologías como chips agrupados (más legibles) ────────────────
    if technologies:
        if isinstance(technologies[0], dict):
            chips = []
            for t in technologies:
                name = _html_escape(str(t.get('name', '')).strip())
                detail = _html_escape(str(t.get('detail', '')).strip())
                if not name:
                    continue
                if detail:
                    chips.append(
                        f"<span class='tech-chip'><b>{name}</b>"
                        f"<span class='tech-detail'>{detail}</span></span>"
                    )
                else:
                    chips.append(f"<span class='tech-chip'><b>{name}</b></span>")
            technologies_html = "<div class='tech-grid'>" + "".join(chips) + "</div>"
        else:
            technologies_html = "<div class='tech-grid'>" + "".join(
                f"<span class='tech-chip'><b>{_html_escape(str(t))}</b></span>"
                for t in technologies
            ) + "</div>"
    else:
        technologies_html = "<span class='muted'>No detectadas</span>"
    users_html = "<ul class='user-list'>" + "\n".join(
        f"<li><span class='tag'>{_html_escape(u)}</span></li>" for u in users
    ) + "</ul>" if users else "<span class='muted'>Sin usuarios</span>"
    emails_html = "<ul class='email-list'>" + "\n".join(
        f"<li><span class='tag'>{_html_escape(e)}</span></li>" for e in emails
    ) + "</ul>" if emails else "<span class='muted'>Sin emails</span>"

    endpoint_rows = "\n".join(
        "<tr>"
        f"<td>{_html_escape(ep.get('status', ''))}</td>"
        f"<td>{_html_escape(ep.get('endpoint', ''))}</td>"
        f"<td>{_html_escape(ep.get('url', ''))}</td>"
        f"<td>{_html_escape(ep.get('content_type', ''))}</td>"
        "</tr>"
        for ep in endpoints
    ) or "<tr><td colspan='4'>Sin endpoints detectados.</td></tr>"

    vhost_rows = "\n".join(
        "<tr>"
        f"<td>{_html_escape(v.get('status', ''))}</td>"
        f"<td>{_html_escape(v.get('fqdn') or v.get('subdomain', ''))}</td>"
        f"<td>{_html_escape(v.get('size', ''))}</td>"
        "</tr>"
        for v in vhosts_list if isinstance(v, dict)
    ) or "<tr><td colspan='3'>Sin subdominios detectados.</td></tr>"

    def _nmap_version(p):
        parts = [p.get('product', ''), p.get('version', ''), p.get('extrainfo', '')]
        return ' '.join(x for x in parts if x).strip()

    nmap_rows = "\n".join(
        "<tr>"
        f"<td>{_html_escape(p.get('port', ''))}/{_html_escape(p.get('protocol', ''))}</td>"
        f"<td>{_html_escape(p.get('state', ''))}</td>"
        f"<td>{_html_escape(p.get('service', ''))}</td>"
        f"<td>{_html_escape(_nmap_version(p))}</td>"
        "</tr>"
        for p in nmap_ports if isinstance(p, dict)
    ) or "<tr><td colspan='4'>Sin puertos detectados.</td></tr>"

    dir_rows = ""
    if dirs:
        for hit in dirs:
            if isinstance(hit, dict):
                dir_rows += (
                    "<tr>"
                    f"<td>{_html_escape(hit.get('status', ''))}</td>"
                    f"<td>{_html_escape(hit.get('url', ''))}</td>"
                    f"<td>{_html_escape(hit.get('size', ''))}</td>"
                    "</tr>"
                )
            else:
                dir_rows += (
                    "<tr>"
                    f"<td></td>"
                    f"<td>{_html_escape(str(hit))}</td>"
                    f"<td></td>"
                    "</tr>"
                )
    if not dir_rows:
        dir_rows = "<tr><td colspan='3'>Sin directorios encontrados.</td></tr>"

    creds_rows = "\n".join(
        "<tr>"
        f"<td>{_html_escape(c.get('username', ''))}</td>"
        f"<td>{_html_escape(c.get('password', ''))}</td>"
        "</tr>"
        for c in creds
    ) or "<tr><td colspan='2'>Sin credenciales válidas detectadas.</td></tr>"

    sample_urls_html = "\n".join(
        f"<li>{_html_escape(u)}</li>" for u in spider.get("sample_urls", [])
    ) or "<li>Sin URLs capturadas.</li>"

    # ── Análisis de código fuente ───────────────────────────────────────
    src_sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    src_html = ""
    if src_code:
        sev_stats = src_code.get("summary") or {}
        sorted_src = sorted(
            src_findings,
            key=lambda x: src_sev_order.get((x.get("severity") or "low").lower(), 9),
        )
        src_kpi = (
            "<div class='kpi'>"
            f"<div><span class='muted'>Páginas</span><b>{src_code.get('pages_analyzed', 0)}</b></div>"
            f"<div><span class='muted'>Recursos JS/JSON</span><b>{src_code.get('assets_analyzed', 0)}</b></div>"
            f"<div><span class='muted'>Total</span><b>{len(src_findings)}</b></div>"
            f"<div><span class='muted'>Critical</span><b>{sev_stats.get('critical', 0)}</b></div>"
            f"<div><span class='muted'>High</span><b>{sev_stats.get('high', 0)}</b></div>"
            f"<div><span class='muted'>Medium</span><b>{sev_stats.get('medium', 0)}</b></div>"
            f"<div><span class='muted'>Low</span><b>{sev_stats.get('low', 0)}</b></div>"
            "</div>"
        )
        if sorted_src:
            src_rows = "\n".join(
                "<tr>"
                f"<td>{_html_escape((f.get('severity') or '').upper())}</td>"
                f"<td>{_html_escape(f.get('type', ''))}</td>"
                f"<td><code>{_html_escape(f.get('value', ''))}</code></td>"
                f"<td>{_html_escape(f.get('url', ''))}</td>"
                f"<td><code>{_html_escape(f.get('snippet', ''))}</code></td>"
                "</tr>"
                for f in sorted_src
            )
        else:
            src_rows = "<tr><td colspan='5'>Sin hallazgos en el código fuente.</td></tr>"
        src_html = (
            "<div class='card' id='codigo'>"
            "<h3>Análisis de código fuente</h3>"
            f"{src_kpi}"
            "<table><thead><tr>"
            "<th>Severidad</th><th>Tipo</th><th>Valor detectado</th><th>URL</th><th>Contexto</th>"
            "</tr></thead><tbody>"
            f"{src_rows}"
            "</tbody></table>"
            "</div>"
        )

    # WordPress / WPScan
    wordpress_html = ""
    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_plugins = wordpress.get("plugins") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_creds = wordpress.get("credentials") or []
        wp_user_rows = "\n".join(
            "<tr>"
            f"<td>{_html_escape(u.get('username', ''))}</td>"
            f"<td>{_html_escape(u.get('name', '') or '')}</td>"
            f"<td>{_html_escape(u.get('found_by', '') or '')}</td>"
            "</tr>"
            for u in wp_users if isinstance(u, dict)
        ) or "<tr><td colspan='3'>Sin usuarios WordPress detectados.</td></tr>"
        wp_vuln_rows = "\n".join(
            "<tr>"
            f"<td>{_html_escape(v.get('component_type', ''))}</td>"
            f"<td>{_html_escape(v.get('component', ''))}</td>"
            f"<td>{_html_escape(v.get('title', ''))}</td>"
            f"<td>{_html_escape(v.get('fixed_in', ''))}</td>"
            "</tr>"
            for v in wp_vulns if isinstance(v, dict)
        ) or "<tr><td colspan='4'>Sin vulnerabilidades WordPress reportadas.</td></tr>"
        wordpress_html = (
            "<div class='card' id='wordpress'>"
            "<h3>WordPress / WPScan</h3>"
            "<div class='kpi'>"
            f"<div><span class='muted'>Detectado</span><b>{'Si' if wordpress.get('detected') else 'No'}</b></div>"
            f"<div><span class='muted'>Version</span><b>{_html_escape(wp_version.get('number') or '-')}</b></div>"
            f"<div><span class='muted'>Plugins</span><b>{len(wp_plugins)}</b></div>"
            f"<div><span class='muted'>Usuarios</span><b>{len(wp_users)}</b></div>"
            f"<div><span class='muted'>Vulns</span><b>{len(wp_vulns)}</b></div>"
            f"<div><span class='muted'>Credenciales</span><b>{len(wp_creds)}</b></div>"
            "</div>"
            f"<p><b>Tema principal:</b> {_html_escape(wp_theme.get('name') or '-')}</p>"
            "<h4>Usuarios</h4>"
            "<table><thead><tr><th>Usuario</th><th>Nombre</th><th>Encontrado por</th></tr></thead><tbody>"
            f"{wp_user_rows}"
            "</tbody></table>"
            "<h4>Vulnerabilidades</h4>"
            "<table><thead><tr><th>Tipo</th><th>Componente</th><th>Titulo</th><th>Fixed in</th></tr></thead><tbody>"
            f"{wp_vuln_rows}"
            "</tbody></table>"
            "</div>"
        )

    # Navegación por secciones
    nav_sections = [
        ("Resumen", "resumen"),
        ("Información general", "info"),
        ("Puertos (Nmap)", "nmap"),
        ("Hallazgos", "hallazgos"),
        ("API", "api"),
        ("Subdominios", "vhosts"),
        ("Directorios", "directorios"),
        ("WordPress", "wordpress"),
        ("Credenciales", "credenciales"),
        ("Spidering", "spidering"),
        ("Código fuente", "codigo"),
    ]
    nav_html = "<nav class='nav-pills'>" + "\n".join(
        f"<a href='#{sec_id}' class='pill'>{sec_name}</a>" for sec_name, sec_id in nav_sections
    ) + "</nav>"

    return f"""<!doctype html>
<html lang=\"es\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>WSTG Report - {_html_escape(report_data.get('target', ''))}</title>
    <style>
        :root {{
            --bg:#f5f7fb; --panel:#ffffff; --text:#0b1320; --muted:#5c687a; --border:#d8deea;
            --accent:#0b7fab; --tag:#e9f5fb; --code:#eef1f7;
        }}
        [data-theme=\"dark\"] {{
            --bg:#0e1622; --panel:#141f2f; --text:#dce7ff; --muted:#9fb0ce; --border:#26344c;
            --accent:#5bc0eb; --tag:#1d3147; --code:#1a283b;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin:0; font-family:\"Segoe UI\",\"Noto Sans\",sans-serif; background:var(--bg); color:var(--text); }}
        .wrap {{ max-width: 1180px; margin: 24px auto; padding: 0 14px 40px; }}
        .card {{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px; margin-bottom:12px; overflow:auto; }}
        .top {{ display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; }}
        .btn {{ border:none; background:var(--panel); color:var(--text); border-radius:50%; padding:10px; cursor:pointer; font-size:1.5rem; box-shadow:0 2px 8px #0001; transition:background 0.2s; }}
        .btn:hover {{ background:var(--tag); }}
        .nav-pills {{ display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 10px 0; }}
        .pill {{ display:inline-block; padding:7px 18px; border-radius:999px; background:var(--tag); color:var(--accent); text-decoration:none; font-weight:500; border:1px solid var(--border); transition:background 0.2s, color 0.2s; }}
        .pill:hover, .pill:focus {{ background:var(--accent); color:#fff; }}
        .kpi {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap:10px; }}
        .kpi div {{ background:var(--code); border:1px solid var(--border); border-radius:10px; padding:8px; }}
        .kpi b {{ display:block; color:var(--accent); font-size:1.25rem; }}
        .tag {{ display:inline-block; margin:4px 6px 0 0; background:var(--tag); padding:4px 8px; border-radius:999px; font-size:.85rem; }}
        .muted {{ color:var(--muted); }}
        table {{ width:100%; border-collapse:collapse; }}
        th, td {{ text-align:left; border-bottom:1px solid var(--border); padding:8px 6px; vertical-align:top; }}
        th {{ color:var(--accent); }}
        pre {{ background:var(--code); border:1px solid var(--border); border-radius:10px; padding:10px; overflow:auto; }}
        .tech-list, .user-list, .email-list {{ list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:0; }}
        .tech-list li, .user-list li, .email-list li {{ margin:0 8px 4px 0; }}
        .tech-grid {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:6px; }}
        .tech-chip {{ display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:999px; background:var(--tag); border:1px solid var(--border); font-size:.9rem; }}
        .tech-chip b {{ color:var(--accent); font-weight:600; }}
        .tech-detail {{ background:var(--code); padding:2px 8px; border-radius:999px; font-size:.8rem; color:var(--muted); font-family:Consolas,monospace; }}
        details {{ margin-bottom:10px; }}
        details summary {{ cursor:pointer; padding:6px 0; font-size:1rem; user-select:none; }}
        details summary:hover {{ color:var(--accent); }}
        details ul {{ margin:6px 0 6px 18px; }}
        .target-card {{ display:flex; align-items:center; gap:18px; }}
        .target-icon {{ font-size:2.2rem; color:var(--accent); margin-right:8px; }}
        .target-meta {{ font-size:1.1rem; color:var(--muted); }}
    </style>
</head>
<body>
    <div class="wrap">
        <h1 style='font-size:2.4rem; color:var(--accent); margin-bottom:10px; text-align:center;'>OWASP WSTG Security Scanner</h1>
        <h2 style='font-size:1.7rem; color:var(--muted); margin-bottom:18px; text-align:center;'>WstgScan</h2>
        <div class="card top">
            <div class='target-card'>
                <span class='target-icon'>🌐</span>
                <div>
                    <div style='font-size:1.35rem; font-weight:600; color:var(--accent);'>{_html_escape(report_data.get('target', ''))}</div>
                    <div class='target-meta'>Fecha: {_html_escape(report_data.get('date', ''))}</div>
                </div>
            </div>
            <button id="themeBtn" class="btn" title='Cambiar tema'><span id='themeIcon'>🌙</span></button>
        </div>

        {nav_html}

        <div class="card" id='resumen'>
            <h3>Resumen</h3>
            <div class="kpi">
                <div><span class="muted">Hallazgos</span><b>{len(findings)}</b></div>
                <div><span class="muted">Tecnologías</span><b>{len(technologies)}</b></div>
                <div><span class="muted">API</span><b>{len(endpoints)}</b></div>
                <div><span class="muted">VHosts</span><b>{len(vhosts_list)}</b></div>
                <div><span class="muted">Puertos</span><b>{len(nmap_ports)}</b></div>
                <div><span class="muted">Directorios</span><b>{len(dirs)}</b></div>
                <div><span class="muted">Usuarios</span><b>{len(users)}</b></div>
                <div><span class="muted">Credenciales</span><b>{len(creds)}</b></div>
                <div><span class="muted">WordPress vulns</span><b>{len(wordpress.get('vulnerabilities') or [])}</b></div>
                <div><span class="muted">Código fuente</span><b>{len(src_findings)}</b></div>
            </div>
            <pre>{_html_escape(json.dumps(meta, indent=2, ensure_ascii=False))}</pre>
        </div>

        <div class="card" id='info'>
            <h3>Información general</h3>
            <p><b>Servidor:</b> {_html_escape(scan_data.get('general', {}).get('server', 'N/A'))}</p>
            <p><b>Status:</b> {_html_escape(scan_data.get('general', {}).get('status_code', 'N/A'))}</p>
            <p><b>Tecnologías:</b><br>{technologies_html}</p>
            <p><b>Usuarios:</b><br>{users_html}</p>
            <p><b>Emails:</b><br>{emails_html}</p>
        </div>

        <div class="card" id='nmap'>
            <h3>Escaneo de puertos (Nmap)</h3>
            <p class='muted'>Comando: <code>{_html_escape(nmap_data.get('command', 'nmap -sV'))}</code> · Host: <code>{_html_escape(nmap_data.get('host', '-'))}</code></p>
            <table><thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Versión</th></tr></thead><tbody>{nmap_rows}</tbody></table>
        </div>

        <div class="card" id='hallazgos'><h3>Hallazgos</h3>{findings_items}</div>
        {nuclei_html}

        <div class="card" id='api'>
            <h3>Endpoints API detectados</h3>
            <table><thead><tr><th>Status</th><th>Endpoint</th><th>URL</th><th>Content-Type</th></tr></thead><tbody>{endpoint_rows}</tbody></table>
        </div>

        <div class=\"card\" id='vhosts'>
            <h3>Subdominios (vhosts) descubiertos</h3>
            <table><thead><tr><th>Status</th><th>VHost</th><th>Tamaño</th></tr></thead><tbody>{vhost_rows}</tbody></table>
        </div>

        <div class=\"card\" id='directorios'>
            <h3>Directorios/archivos descubiertos</h3>
            <table><thead><tr><th>Status</th><th>URL</th><th>Tamaño</th></tr></thead><tbody>{dir_rows}</tbody></table>
        </div>

        {wordpress_html}

        <div class=\"card\" id='credenciales'>
            <h3>Credenciales válidas (bruteforce)</h3>
            <table><thead><tr><th>Usuario</th><th>Contraseña</th></tr></thead><tbody>{creds_rows}</tbody></table>
        </div>

        <div class=\"card\" id='spidering'>
            <h3>Spidering (muestra de URLs)</h3>
            <ul>{sample_urls_html}</ul>
        </div>

        {src_html}
    </div>

    <script>
        (function() {{
            var root = document.documentElement;
            var key = 'wstg_theme';
            var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            var initial = localStorage.getItem(key) || (prefersDark ? 'dark' : 'light');
            root.setAttribute('data-theme', initial);
            var themeBtn = document.getElementById('themeBtn');
            var themeIcon = document.getElementById('themeIcon');
            function updateIcon() {{
                var curr = root.getAttribute('data-theme') || 'light';
                themeIcon.textContent = curr === 'dark' ? '☀️' : '🌙';
            }}
            updateIcon();
            themeBtn.addEventListener('click', function() {{
                var curr = root.getAttribute('data-theme') || 'light';
                var next = curr === 'dark' ? 'light' : 'dark';
                root.setAttribute('data-theme', next);
                localStorage.setItem(key, next);
                updateIcon();
            }});
        }})();
    </script>
</body>
</html>
"""

def _md_escape_cell(value):
    """Escapa el contenido de una celda de tabla markdown."""
    text = str(value) if value is not None else ""
    # Sin saltos de línea ni pipes literales
    text = text.replace('\r', ' ').replace('\n', '<br>')
    text = text.replace('|', '\\|')
    return text or "-"

def _md_table(headers, rows):
    """Genera una tabla markdown estándar (con escape de pipes y saltos)."""
    if not headers:
        return ""
    header_line = "| " + " | ".join(_md_escape_cell(h) for h in headers) + " |"
    sep_line = "| " + " | ".join("---" for _ in headers) + " |"
    lines = [header_line, sep_line]
    for r in rows:
        cells = [_md_escape_cell(r[i] if i < len(r) else "") for i in range(len(headers))]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)

def _build_markdown_report(report_data):
    """Construye el resumen completo del pentest en markdown (compatible GitBook/GitHub)."""
    scan_data = report_data.get("scan_data", {}) or {}
    findings = report_data.get("findings", []) or []
    target = report_data.get("target", "")
    date = report_data.get("date", "")

    general = scan_data.get("general", {}) or {}
    nuclei_summary = scan_data.get("nuclei_summary", {}) or {}
    nuclei_findings_list = scan_data.get("nuclei_findings", []) or []
    spider = scan_data.get("spider", {}) or {}
    injection = scan_data.get("injection", {}) or {}
    vhosts = scan_data.get("vhosts", []) or []
    dir_hits = scan_data.get("directory_hits", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    users = scan_data.get("users", []) or []
    emails = scan_data.get("emails", []) or []
    creds = scan_data.get("bruteforce_credentials", []) or []
    wordpress = scan_data.get("wordpress", {}) or {}
    robots_paths = scan_data.get("robots_paths", []) or []
    http_methods = scan_data.get("http_methods", []) or []
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings") or []
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []

    def _tech_str(item):
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "")).strip()
            return f"{name} ({detail})" if name and detail else (name or detail or "")
        return str(item)

    def _count_label(total, limit):
        """'(N)' si total <= limit; '(top limit de total)' en caso contrario."""
        if total <= limit:
            return f"({total})"
        return f"(top {limit} de {total})"

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}

    parts = []
    parts.append(f"# OWASP WSTG Scanner — Reporte de Pentesting")
    parts.append("")
    parts.append(f"- **Objetivo:** `{target}`")
    parts.append(f"- **Fecha:** {date}")
    parts.append(f"- **Herramienta:** WSTG Scanner v{report_data.get('tool', '')}")
    parts.append("")

    # 1. Resumen ejecutivo
    parts.append("## Resumen ejecutivo")
    parts.append("")
    techs = general.get("technologies", []) or []
    tech_str = ", ".join(_tech_str(t) for t in techs) or "-"
    overview_rows = [
        ["Status HTTP", str(general.get("status_code", "-"))],
        ["Servidor", str(general.get("server", "-"))],
        ["Tecnologías", tech_str],
        ["Hallazgos (FINDINGS)", str(len(findings))],
        ["Puertos abiertos (nmap)", str(len(nmap_ports))],
        ["Vulnerabilidades Nuclei", str(len(nuclei_findings_list))],
        ["URLs spider", str(spider.get("total_urls", 0))],
        ["Subdominios (vhosts)", str(len(vhosts))],
        ["Directorios encontrados", str(len(dir_hits))],
        ["Endpoints API", str(len(api_endpoints))],
        ["Usuarios", str(len(users))],
        ["Emails", str(len(emails))],
        ["Credenciales válidas", str(len(creds))],
        ["WordPress vulnerabilidades", str(len(wordpress.get("vulnerabilities") or []))],
        ["Hallazgos en código fuente", str(len(src_findings))],
    ]
    parts.append(_md_table(["Campo", "Valor"], overview_rows))
    parts.append("")

    # 2. Cabeceras de seguridad
    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        sec_rows.append([h, "OK" if present else "AUSENTE", v])
    parts.append("## Cabeceras de seguridad")
    parts.append("")
    parts.append(_md_table(["Header", "Estado", "Valor"], sec_rows))
    parts.append("")

    # 3. Cookies
    cookies = general.get("cookies") or []
    if cookies:
        parts.append("## Cookies detectadas")
        parts.append("")
        parts.append(_md_table(["Cookie"], [[c] for c in cookies]))
        parts.append("")

    # 4. HTTP methods + robots
    misc_rows = []
    if http_methods:
        misc_rows.append(["HTTP Methods permitidos", ", ".join(http_methods)])
    if robots_paths:
        misc_rows.append([f"Rutas robots/sitemap ({len(robots_paths)})", ", ".join(robots_paths[:15])])
    if misc_rows:
        parts.append("## Información HTTP adicional")
        parts.append("")
        parts.append(_md_table(["Categoría", "Valor"], misc_rows))
        parts.append("")

    # 4b. Nmap (puertos abiertos)
    if nmap_ports:
        parts.append(f"## Escaneo de puertos (Nmap) ({len(nmap_ports)})")
        parts.append("")
        if nmap_data.get("command"):
            parts.append(f"- **Comando:** `{nmap_data['command']}`")
        if nmap_data.get("host"):
            parts.append(f"- **Host:** `{nmap_data['host']}`")
        if nmap_data.get("hostnames"):
            parts.append(f"- **Hostnames:** {', '.join(nmap_data['hostnames'])}")
        parts.append("")
        nm_rows = []
        for p in nmap_ports:
            vparts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in vparts if v).strip() or "-"
            nm_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                str(p.get("state", "-")),
                str(p.get("service", "") or "-"),
                version_str,
            ])
        parts.append(_md_table(["Puerto", "Estado", "Servicio", "Versión"], nm_rows))
        parts.append("")

    # 5. Spider
    if spider:
        parts.append("## Spidering")
        parts.append("")
        spider_rows = [
            ["URLs totales", str(spider.get("total_urls", 0))],
            ["Parámetros únicos", str(spider.get("total_params", 0))],
            ["Formularios", str(spider.get("total_forms", 0))],
        ]
        parts.append(_md_table(["Métrica", "Valor"], spider_rows))
        parts.append("")
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            parts.append(f"### URLs descubiertas ({len(sample_urls)})")
            parts.append("")
            parts.append(_md_table(["URL"], [[u] for u in sample_urls]))
            parts.append("")

    # 5b. Análisis de código fuente
    if src_code:
        sev_stats = src_code.get("summary") or {}
        parts.append("## Análisis de código fuente")
        parts.append("")
        code_overview = [
            ["Páginas analizadas", str(src_code.get("pages_analyzed", 0))],
            ["Recursos JS/JSON analizados", str(src_code.get("assets_analyzed", 0))],
            ["Hallazgos totales", str(len(src_findings))],
            ["Critical", str(sev_stats.get("critical", 0))],
            ["High", str(sev_stats.get("high", 0))],
            ["Medium", str(sev_stats.get("medium", 0))],
            ["Low", str(sev_stats.get("low", 0))],
        ]
        parts.append(_md_table(["Métrica", "Valor"], code_overview))
        parts.append("")
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            parts.append(f"### Detalle de hallazgos en código fuente ({len(sorted_src)})")
            parts.append("")
            rows = [[
                (f.get("severity") or "").upper(),
                str(f.get("type", "-")),
                str(f.get("value", "-")),
                str(f.get("url", "-")),
            ] for f in sorted_src]
            parts.append(_md_table(["Severidad", "Tipo", "Valor detectado", "URL"], rows))
            parts.append("")

    # 6a. Subdominios (vhosts)
    if vhosts:
        parts.append(f"## Subdominios (vhosts) encontrados ({len(vhosts)})")
        parts.append("")
        rows = [[str(v.get("status", "-")),
                 str(v.get("fqdn") or v.get("subdomain", "-")),
                 str(v.get("size", "-"))]
                for v in vhosts]
        parts.append(_md_table(["Status", "VHost", "Tamaño"], rows))
        parts.append("")

    # 6b. Directorios
    if dir_hits:
        parts.append(f"## Directorios encontrados ({len(dir_hits)})")
        parts.append("")
        rows = [[str(h.get("status", "-")), str(h.get("url", "-")), str(h.get("size", "-"))]
                for h in dir_hits]
        parts.append(_md_table(["Status", "URL", "Tamaño"], rows))
        parts.append("")

    # 6c. WordPress / WPScan
    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_plugins = wordpress.get("plugins") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_creds = wordpress.get("credentials") or []
        parts.append("## WordPress / WPScan")
        parts.append("")
        wp_rows = [
            ["Detectado", "Sí" if wordpress.get("detected") else "No confirmado"],
            ["Versión", str(wp_version.get("number") or "-")],
            ["Estado versión", str(wp_version.get("status") or "-")],
            ["Tema principal", str(wp_theme.get("name") or "-")],
            ["Plugins detectados", str(len(wp_plugins))],
            ["Usuarios WPScan", str(len(wp_users))],
            ["Vulnerabilidades", str(len(wp_vulns))],
            ["Credenciales WP", str(len(wp_creds))],
        ]
        parts.append(_md_table(["Campo", "Valor"], wp_rows))
        parts.append("")
        if wp_users:
            parts.append("### Usuarios WordPress")
            parts.append("")
            parts.append(_md_table(["Usuario", "Nombre"], [[u.get("username", "-"), u.get("name", "-")] for u in wp_users]))
            parts.append("")
        if wp_vulns:
            parts.append("### Vulnerabilidades WordPress")
            parts.append("")
            rows = [[
                v.get("component_type", "-"),
                v.get("component", "-"),
                v.get("title", "-"),
                v.get("fixed_in", "-"),
            ] for v in wp_vulns]
            parts.append(_md_table(["Tipo", "Componente", "Título", "Fixed in"], rows))
            parts.append("")

    # 7. API endpoints
    if api_endpoints:
        parts.append(f"## Endpoints API descubiertos ({len(api_endpoints)})")
        parts.append("")
        rows = [[str(ep.get("status", "-")),
                 str(ep.get("endpoint") or ep.get("url", "-")),
                 str(ep.get("content_type", "-"))]
                for ep in api_endpoints]
        parts.append(_md_table(["Status", "Endpoint", "Content-Type"], rows))
        parts.append("")

    # 8. Usuarios y emails
    if users or emails:
        parts.append("## Usuarios y emails descubiertos")
        parts.append("")
        ue_rows = []
        if users:
            ue_rows.append(["Usuarios", ", ".join(users)])
        if emails:
            ue_rows.append(["Emails", ", ".join(emails)])
        parts.append(_md_table(["Categoría", "Valores"], ue_rows))
        parts.append("")

    # 9. Inyección
    if injection.get("executed"):
        parts.append("## Pruebas de inyección")
        parts.append("")
        inj_rows = [
            ["Formularios detectados", str(injection.get("forms_found", 0))],
            ["Parámetros GET detectados", str(injection.get("url_params_found", 0))],
            ["Parámetros GET probados", str(len(injection.get("tested_get_params", [])))],
            ["Inputs de formulario probados", str(len(injection.get("tested_form_inputs", [])))],
        ]
        parts.append(_md_table(["Métrica", "Valor"], inj_rows))
        parts.append("")

    # 10. Credenciales válidas
    if creds:
        parts.append("## Credenciales válidas encontradas")
        parts.append("")
        rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            rows.append([str(user), str(pwd)])
        parts.append(_md_table(["Usuario", "Contraseña"], rows))
        parts.append("")

    # 11. Nuclei
    if nuclei_summary:
        parts.append("## Vulnerabilidades por severidad (Nuclei)")
        parts.append("")
        rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            rows.append([sev.upper(), str(len(tids)), ", ".join(sorted(set(map(str, tids))))])
        parts.append(_md_table(["Severidad", "Cantidad", "Templates únicos"], rows))
        parts.append("")

    relevant_nuclei = [n for n in nuclei_findings_list
                       if (n.get('severity') or '').lower() in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        sorted_rel = sorted(relevant_nuclei,
                            key=lambda x: (SEV_ORDER.get((x.get('severity') or 'unknown').lower(), 99),
                                           str(x.get('template_id', ''))))
        parts.append(f"## Hallazgos Nuclei relevantes ({len(sorted_rel)})")
        parts.append("")
        rows = [[(n.get('severity') or '').upper(),
                 str(n.get('template_id', '-')),
                 str(n.get('name', '-')),
                 str(n.get('url', '-'))]
                for n in sorted_rel]
        parts.append(_md_table(["Severidad", "Template", "Nombre", "URL"], rows))
        parts.append("")

    # 12. Hallazgos clasificados (FINDINGS)
    if findings:
        cats = {}
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]', str(f))
            cat = m.group(1) if m else "OTROS"
            cats.setdefault(cat, []).append(str(f))
        parts.append(f"## Hallazgos clasificados (total: {len(findings)})")
        parts.append("")
        cat_rows = [[cat, str(len(cats[cat]))] for cat in sorted(cats.keys())]
        parts.append(_md_table(["Categoría", "Cantidad"], cat_rows))
        parts.append("")
        parts.append(f"### Detalle de hallazgos ({len(findings)})")
        parts.append("")
        rows = []
        for f in findings:
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', str(f))
            if m:
                rows.append([m.group(1), m.group(2)])
            else:
                rows.append(["OTROS", str(f)])
        parts.append(_md_table(["Categoría", "Detalle"], rows))
        parts.append("")

    parts.append("---")
    parts.append("")
    parts.append("_Generado automáticamente por WSTG Scanner._")
    return "\n".join(parts)


def save_report(output_file=None):
    """Guarda hallazgos y datos relevantes en TXT, JSON, HTML y MD."""
    txt_file, json_file, html_file, md_file = _normalize_output_paths(output_file, TARGET_URL)
    scan_stats = {
        "authenticated": AUTHENTICATED,
        "threads": THREADS,
        "timeout": DEFAULT_TIMEOUT,
        "delay": REQUEST_DELAY,
        "total_findings": len(FINDINGS),
        "total_api_endpoints": len(SCAN_DATA.get("api_endpoints", [])),
        "total_vhosts": len(SCAN_DATA.get("vhosts", [])),
        "total_open_ports": len((SCAN_DATA.get("nmap") or {}).get("ports", [])),
        "total_dir_hits": len(SCAN_DATA.get("directory_hits", [])),
        "injection_forms_found": SCAN_DATA.get("injection", {}).get("forms_found", 0),
        "injection_get_params_found": SCAN_DATA.get("injection", {}).get("url_params_found", 0),
        "injection_get_params_tested": len(SCAN_DATA.get("injection", {}).get("tested_get_params", [])),
        "injection_form_inputs_tested": len(SCAN_DATA.get("injection", {}).get("tested_form_inputs", [])),
        "total_users": len(SCAN_DATA.get("users", [])),
        "total_emails": len(SCAN_DATA.get("emails", [])),
        "total_bruteforce_credentials": len(SCAN_DATA.get("bruteforce_credentials", [])),
        "wordpress_detected": bool((SCAN_DATA.get("wordpress") or {}).get("detected")),
        "wordpress_users": len((SCAN_DATA.get("wordpress") or {}).get("users", [])),
        "wordpress_vulnerabilities": len((SCAN_DATA.get("wordpress") or {}).get("vulnerabilities", [])),
        "wordpress_credentials": len((SCAN_DATA.get("wordpress") or {}).get("credentials", [])),
        "total_spider_urls": SCAN_DATA.get("spider", {}).get("total_urls", 0),
        "total_source_code_findings": len((SCAN_DATA.get("source_code_analysis") or {}).get("findings", [])),
        "source_code_pages_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("pages_analyzed", 0),
        "source_code_assets_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("assets_analyzed", 0),
    }
    SCAN_DATA["stats"] = scan_stats

    report_data = {
        "tool": VERSION,
        "target": TARGET_URL,
        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "findings": list(FINDINGS),
        "scan_data": _to_serializable(SCAN_DATA),
    }

    try:
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(f"WSTG Scanner v{VERSION} - Reporte de Escaneo\n")
            f.write(f"Objetivo : {TARGET_URL}\n")
            f.write(f"Fecha    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Modo auth: {'Sí' if AUTHENTICATED else 'No'}\n")
            f.write("=" * 60 + "\n\n")

            f.write("[RESUMEN]\n")
            for k, v in scan_stats.items():
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            general = report_data["scan_data"].get("general", {})
            f.write("[INFORMACIÓN GENERAL]\n")
            f.write(f"- Status: {general.get('status_code', 'N/A')}\n")
            f.write(f"- Servidor: {general.get('server', 'N/A')}\n")
            techs = general.get('technologies', [])
            if techs:
                if isinstance(techs[0], dict):
                    tech_str = ', '.join(f"{t.get('name','')}{'['+t.get('detail','')+']' if t.get('detail') else ''}" for t in techs)
                else:
                    tech_str = ', '.join(str(t) for t in techs)
            else:
                tech_str = 'N/A'
            f.write(f"- Tecnologías: {tech_str}\n")
            f.write(f"- Métodos HTTP: {', '.join(report_data['scan_data'].get('http_methods', [])) or 'N/A'}\n")
            f.write(f"- robots/sitemap: {', '.join(report_data['scan_data'].get('robots_paths', [])) or 'N/A'}\n\n")

            nmap_data = report_data['scan_data'].get('nmap') or {}
            nmap_ports = nmap_data.get('ports') or []
            f.write("[ESCANEO DE PUERTOS (NMAP)]\n")
            if nmap_data.get('command'):
                f.write(f"- Comando: {nmap_data['command']}\n")
            if nmap_data.get('host'):
                f.write(f"- Host: {nmap_data['host']}\n")
            if nmap_ports:
                for p in nmap_ports:
                    parts = [p.get('product', ''), p.get('version', ''), p.get('extrainfo', '')]
                    version_str = ' '.join(v for v in parts if v).strip()
                    f.write(
                        f"- {p.get('port')}/{p.get('protocol')} [{p.get('state', '')}] "
                        f"{p.get('service', '') or '?'}"
                        + (f" — {version_str}" if version_str else "")
                        + "\n"
                    )
            else:
                f.write("- Sin puertos visibles\n")
            f.write("\n")

            f.write("[ENUMERACIÓN]\n")
            f.write(f"- Usuarios: {', '.join(report_data['scan_data'].get('users', [])) or 'N/A'}\n")
            f.write(f"- Emails: {', '.join(report_data['scan_data'].get('emails', [])) or 'N/A'}\n\n")

            wordpress_data = report_data['scan_data'].get('wordpress') or {}
            f.write("[WORDPRESS / WPSCAN]\n")
            if wordpress_data:
                wp_version = wordpress_data.get('version') or {}
                wp_theme = wordpress_data.get('main_theme') or {}
                f.write(f"- Detectado: {'Si' if wordpress_data.get('detected') else 'No confirmado'}\n")
                f.write(f"- Version: {wp_version.get('number') or 'N/A'} ({wp_version.get('status') or 'estado desconocido'})\n")
                f.write(f"- Tema principal: {wp_theme.get('name') or 'N/A'}\n")
                f.write(f"- Plugins detectados: {len(wordpress_data.get('plugins') or [])}\n")
                f.write(f"- Usuarios WPScan: {', '.join(u.get('username','') for u in wordpress_data.get('users', []) if isinstance(u, dict)) or 'N/A'}\n")
                wp_vulns = wordpress_data.get('vulnerabilities') or []
                f.write(f"- Vulnerabilidades: {len(wp_vulns)}\n")
                for vuln in wp_vulns:
                    f.write(
                        f"  * [{vuln.get('component_type')}] {vuln.get('component')}: "
                        f"{vuln.get('title')}"
                        + (f" (fixed in {vuln.get('fixed_in')})" if vuln.get('fixed_in') else "")
                        + "\n"
                    )
                wp_creds = wordpress_data.get('credentials') or []
                if wp_creds:
                    f.write("- Credenciales WPScan:\n")
                    for cred in wp_creds:
                        f.write(f"  * {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- No ejecutado\n")
            f.write("\n")

            spider = report_data["scan_data"].get("spider", {})
            f.write("[SPIDERING]\n")
            f.write(f"- Total URLs: {spider.get('total_urls', 0)}\n")
            f.write(f"- Total parámetros: {spider.get('total_params', 0)}\n")
            f.write(f"- Total formularios: {spider.get('total_forms', 0)}\n")
            for u in spider.get('sample_urls', []):
                f.write(f"  * {u}\n")
            f.write("\n")

            f.write("[ENDPOINTS API]\n")
            for ep in report_data['scan_data'].get('api_endpoints', []):
                f.write(f"- [{ep.get('status')}] {ep.get('url')} ({ep.get('content_type', '')})\n")
            f.write("\n")

            f.write("[SUBDOMINIOS (VHOSTS)]\n")
            vhosts_list = report_data['scan_data'].get('vhosts', [])
            if vhosts_list:
                for v in vhosts_list:
                    fqdn = v.get('fqdn') or v.get('subdomain', '')
                    f.write(f"- [{v.get('status')}] {fqdn} size={v.get('size', 'N/A')}\n")
            else:
                f.write("- Ninguno\n")
            f.write("\n")

            f.write("[DIRECTORIOS ENCONTRADOS]\n")
            for hit in report_data['scan_data'].get('directory_hits', []):
                f.write(f"- [{hit.get('status')}] {hit.get('url')} size={hit.get('size', 'N/A')}\n")
            f.write("\n")

            f.write("[CREDENCIALES BRUTEFORCE]\n")
            creds = report_data['scan_data'].get('bruteforce_credentials', [])
            if creds:
                for cred in creds:
                    f.write(f"- {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- Ninguna\n")
            f.write("\n")

            src_code_data = report_data['scan_data'].get('source_code_analysis') or {}
            src_code_findings = src_code_data.get('findings') or []
            f.write("[ANÁLISIS DE CÓDIGO FUENTE]\n")
            f.write(f"- Páginas analizadas: {src_code_data.get('pages_analyzed', 0)}\n")
            f.write(f"- Recursos JS/JSON analizados: {src_code_data.get('assets_analyzed', 0)}\n")
            f.write(f"- Hallazgos: {len(src_code_findings)}\n")
            sev_stats = src_code_data.get('summary') or {}
            if sev_stats:
                f.write(
                    f"- Severidad: CRITICAL={sev_stats.get('critical',0)} "
                    f"HIGH={sev_stats.get('high',0)} "
                    f"MEDIUM={sev_stats.get('medium',0)} "
                    f"LOW={sev_stats.get('low',0)}\n"
                )
            if src_code_findings:
                src_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                for item in sorted(src_code_findings,
                                   key=lambda x: src_order.get(x.get('severity', 'low'), 9)):
                    f.write(
                        f"- [{(item.get('severity') or '').upper()}] {item.get('type','')} "
                        f"@ {item.get('url','')} | valor: {item.get('value','')}\n"
                    )
            else:
                f.write("- Ninguno\n")
            f.write("\n")

            f.write("[HALLAZGOS]\n")
            if FINDINGS:
                for finding in FINDINGS:
                    f.write(finding + "\n")
            else:
                f.write("Sin hallazgos registrados.\n")

            nuclei_summary = report_data["scan_data"].get("nuclei_summary", {})
            nuclei_findings_list = report_data["scan_data"].get("nuclei_findings", []) or []
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
            if nuclei_summary:
                f.write("\n[NUCLEI] Resumen de vulnerabilidades:\n")
                for sev in sorted(nuclei_summary.keys(), key=lambda s: sev_order.get(s, 99)):
                    tids = nuclei_summary[sev]
                    f.write(f"- {sev.upper()}: {len(tids)} hallazgos ({', '.join(tids)})\n")
            if nuclei_findings_list:
                f.write("\n[NUCLEI] Detalle de hallazgos:\n")
                sorted_findings = sorted(
                    nuclei_findings_list,
                    key=lambda x: (sev_order.get((x.get('severity') or 'unknown'), 99),
                                   x.get('template_id', ''))
                )
                for n in sorted_findings:
                    sev = (n.get('severity') or 'unknown').upper()
                    tid = n.get('template_id', '')
                    name = n.get('name', '')
                    url = n.get('url', '')
                    f.write(f"- [{sev}] {tid}" + (f" — {name}" if name else "") +
                            (f" @ {url}" if url else "") + "\n")

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        html_content = _build_html_report(report_data)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        md_content = _build_markdown_report(report_data)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        base_path = os.path.splitext(txt_file)[0]
        print_good(
            f"Reportes guardados en {base_path}.{{txt,json,html,md}}"
        )
    except Exception as e:
        print_error(f"No se pudo guardar el reporte: {e}")

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def get_session(user_agent=None):
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    session.verify = VERIFY_TLS
    session.max_redirects = MAX_REDIRECTS
    return session

def check_seclists():
    if os.path.exists(SECLISTS_SMALL):
        return SECLISTS_SMALL
    elif os.path.exists(SECLISTS_MEDIUM):
        print_warning("No se encontró la wordlist small, usando medium (más grande y lenta).")
        return SECLISTS_MEDIUM
    else:
        print_warning("No se encontró SecLists en las rutas por defecto.")
        response = input_path(f"¿Deseas instalar SecLists automáticamente? (requiere sudo) [s/N]: ").strip().lower()
        if response == 's':
            try:
                print_info("Ejecutando: sudo apt update && sudo apt install seclists -y")
                subprocess.run(["sudo", "apt", "update"], check=True, capture_output=True)
                subprocess.run(["sudo", "apt", "install", "seclists", "-y"], check=True, capture_output=True)
                if os.path.exists(SECLISTS_SMALL):
                    print_good("SecLists instalado correctamente.")
                    return SECLISTS_SMALL
                elif os.path.exists(SECLISTS_MEDIUM):
                    return SECLISTS_MEDIUM
                else:
                    print_error("La instalación parece haber fallado.")
            except Exception as e:
                print_error(f"No se pudo instalar SecLists: {e}")
        print_warning("Usando wordlist interna reducida para fuzzing.")
        return None

# ========== FUNCIONES DE AUTENTICACIÓN ==========
def setup_authentication():
    global AUTHENTICATED, AUTH_SESSION, TARGET_URL
    print_info("Configuración de autenticación")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} URL de login (dejar vacío si es la misma que la objetivo):")
    login_url = input("> ").strip()
    if not login_url:
        login_url = TARGET_URL
    else:
        login_url = normalize_url(login_url)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Usuario:")
    username = input("> ")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Contraseña:")
    password = getpass.getpass("> ")

    temp_session = get_session()
    try:
        resp = temp_session.get(login_url, auth=(username, password), timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            print_good("Autenticación Basic Auth exitosa")
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            return
    except requests.RequestException as e:
        print_warning(f"Basic Auth no aplicable ({type(e).__name__}). Probando formularios...")

    try:
        resp = temp_session.get(login_url, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').upper()
                inputs = form.find_all(['input', 'textarea'])
                user_field = None
                pass_field = None
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if 'user' in name or 'email' in name or 'login' in name:
                        user_field = inp.get('name')
                    if 'pass' in name:
                        pass_field = inp.get('name')
                if user_field and pass_field and method == 'POST':
                    form_url = urljoin(login_url, action) if action else login_url
                    data = {user_field: username, pass_field: password}
                    for inp in inputs:
                        if inp.get('type') == 'hidden' and inp.get('name'):
                            data[inp.get('name')] = inp.get('value', '')
                    resp2 = temp_session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT)
                    if resp2.status_code == 302 or "dashboard" in resp2.url or "welcome" in resp2.text.lower():
                        print_good("Autenticación exitosa mediante formulario")
                        AUTH_SESSION = temp_session
                        AUTHENTICATED = True
                        return
                    else:
                        print_error("Falló la autenticación con el formulario detectado.")
    except Exception as e:
        print_error(f"Error durante autenticación: {e}")
    
    print_warning("No se pudo autenticar. Las pruebas se realizarán sin autenticación.")
    AUTHENTICATED = False
    AUTH_SESSION = None

def get_active_session():
    global AUTH_SESSION, AUTHENTICATED
    if AUTHENTICATED and AUTH_SESSION:
        return AUTH_SESSION
    else:
        return get_session()

# ========== FUNCIONES DE PRUEBA ==========
def safe_execute(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_error(f"Error en {func.__name__}: {str(e)[:100]}")
        return None

def gather_info(target, session):
    try:
        info = {}
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        info['status_code'] = resp.status_code
        info['headers'] = dict(resp.headers)
        info['cookies'] = resp.cookies
        info['server'] = resp.headers.get('Server', 'No revelado')

        # Detección de tecnologías con WhatWeb
        print_info("Detectando tecnologías con WhatWeb...")
        ww_result = run_whatweb(target)
        if ww_result is not None:
            info['technologies'] = ww_result
            info['technologies_source'] = 'whatweb'
        else:
            # Fallback: detección básica por cabeceras
            tech = []
            if 'Set-Cookie' in resp.headers and 'PHPSESSID' in resp.headers['Set-Cookie']:
                tech.append('PHP')
            if 'X-Powered-By' in resp.headers:
                tech.append(resp.headers['X-Powered-By'])
            if 'ASP.NET' in str(resp.headers):
                tech.append('ASP.NET')
            info['technologies'] = list(set(tech))
            info['technologies_source'] = 'headers'
            if info['technologies']:
                print_info(f"Tecnologías (fallback): {', '.join(info['technologies'])}")

        return info
    except Exception as e:
        print_error(f"No se pudo obtener información: {e}")
        return None

def check_robots_sitemap(target, session):
    try:
        paths = []
        for p in ['/robots.txt', '/sitemap.xml']:
            url = urljoin(target, p)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    print_good(f"Encontrado: {url}")
                    paths.append(url)
                    if 'robots.txt' in p:
                        lines = resp.text.splitlines()
                        for line in lines:
                            if line.startswith('Disallow:') or line.startswith('Allow:'):
                                parts = line.split(':')
                                if len(parts) > 1:
                                    path = parts[1].strip()
                                    if path and path != '/':
                                        print_info(f"  Ruta en robots.txt: {path}")
            except:
                pass
        return paths
    except Exception as e:
        print_error(f"Error en check_robots_sitemap: {e}")
        return []

def check_http_methods(target, session):
    try:
        allowed = []
        resp = session.options(target, timeout=DEFAULT_TIMEOUT)
        if 'Allow' in resp.headers:
            allowed = [m.strip() for m in resp.headers['Allow'].split(',')]
            print_info(f"Métodos HTTP permitidos: {', '.join(allowed)}")
        trace_resp = session.request('TRACE', target, timeout=DEFAULT_TIMEOUT)
        if trace_resp.status_code == 200:
            print_vuln("Método TRACE habilitado (Cross-Site Tracing)")
            allowed.append('TRACE')
        return allowed
    except Exception as e:
        print_error(f"Error en check_http_methods: {e}")
        return []

def vhost_bruteforce(target, session, base_domain, wordlist=None, threads=THREADS,
                     use_ffuf=True, request_timeout=5, rate=0, use_fs_filter=True):
    """Fuzzing de subdominios (virtual hosts) usando ffuf con técnica de Content-Length.

    Manda una request con Host inválido (defnotvalid.<base_domain>) para obtener la
    longitud baseline de "no encontrado" y, si `use_fs_filter` es True, ffuf filtra
    por `-fs <baseline>` descartando todas las respuestas que coincidan.
    """
    results = []
    try:
        if not base_domain:
            print_error("Dominio base vacío. No se puede hacer fuzzing de subdominios.")
            return results

        if wordlist is None and os.path.isfile(SECLISTS_DNS):
            wordlist = SECLISTS_DNS
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"No se pudo leer la wordlist '{wordlist}'.")
            wordlist = None
        if not wordlist:
            print_error("No hay wordlist disponible para vhost fuzzing.")
            return results

        # 1) Baseline: enviar un Host inválido al target y leer Content-Length
        bogus_host = f"defnotvalid{int(time.time()) % 100000}.{base_domain}"
        baseline_size = None
        try:
            print_info(f"Baseline con Host inválido: {bogus_host}")
            base_resp = session.get(
                target,
                headers={"Host": bogus_host},
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            # Preferir Content-Length si está presente, si no usar len(content)
            cl_header = base_resp.headers.get('Content-Length')
            if cl_header and cl_header.isdigit():
                baseline_size = int(cl_header)
            else:
                baseline_size = len(base_resp.content)
            print_info(f"Baseline status={base_resp.status_code} Content-Length={baseline_size}")
        except Exception as e:
            print_warning(f"No se pudo calcular baseline ({e}); ffuf no filtrará por tamaño.")

        if use_ffuf and check_ffuf():
            # Contar entradas válidas de la wordlist para informar al usuario
            wl_count = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as wlf:
                    for line in wlf:
                        s = line.strip()
                        if s and not s.startswith('#'):
                            wl_count += 1
            except Exception:
                pass
            if wl_count:
                # ETA aproximado: cada hilo procesa ~10 req/s en promedio
                est_seconds = max(1, int(wl_count / max(1, threads * 10)))
                est_min = est_seconds // 60
                eta = f"~{est_min}m" if est_min >= 1 else f"~{est_seconds}s"
                print_info(f"Wordlist: {wl_count:,} entradas · threads: {threads} · timeout: {request_timeout}s · ETA: {eta}")
                if wl_count > 50_000 and threads < 40:
                    print_warning(
                        f"Wordlist grande ({wl_count:,}) con pocos threads ({threads}). "
                        "Considera Ctrl+C y subir threads o usar una wordlist más corta."
                    )

            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)
            ffuf_cmd = [
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", target.rstrip('/') + '/',
                "-H", f"Host: FUZZ.{base_domain}",
                "-t", str(threads),
                "-timeout", str(request_timeout),
                "-o", tmp_path, "-of", "json",
            ]
            if rate and rate > 0:
                ffuf_cmd += ["-rate", str(rate)]
            if baseline_size is not None and use_fs_filter:
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Ejecutando: {' '.join(ffuf_cmd[:11])} ...")
            print()
            process = None
            try:
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()

                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)
                        STATUS_COLOR = {
                            200: Fore.GREEN, 201: Fore.GREEN, 204: Fore.GREEN,
                            301: Fore.CYAN,  302: Fore.CYAN,  307: Fore.CYAN, 308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED, 503: Fore.RED,
                        }
                        if not hits:
                            print(f"\n  {Fore.YELLOW}Sin subdominios encontrados (todo filtrado por baseline).{Style.RESET_ALL}\n")
                        else:
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                sub = hit.get('input', {}).get('FUZZ', '')
                                status = hit.get('status', 0)
                                size = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns = hit.get('duration', 0)
                                dur_ms = dur_ns // 1_000_000 if dur_ns else 0
                                fqdn = f"{sub}.{base_domain}"
                                color = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    fqdn,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                ])
                                results.append({
                                    'subdomain': sub,
                                    'fqdn': fqdn,
                                    'status': status,
                                    'size': size,
                                })
                                FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                            print_table(
                                headers=["STATUS", "VHOST", "SIZE", "WORDS", "DUR"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} subdominio(s) encontrados\n",
                            )
                    except Exception as e:
                        print_error(f"Error leyendo JSON de ffuf: {e}")
                if rc not in (0, 1):
                    print_error(f"ffuf terminó con código {rc}")
            except KeyboardInterrupt:
                print_warning("Fuzzing de subdominios interrumpido por el usuario; esperando a que ffuf guarde resultados parciales...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('fqdn'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        sub = hit.get('input', {}).get('FUZZ', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        fqdn = f"{sub}.{base_domain}"
                        key = (fqdn, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({
                            'subdomain': sub,
                            'fqdn': fqdn,
                            'status': status,
                            'size': size,
                        })
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                except Exception as e:
                    print_error(f"Error leyendo JSON parcial de ffuf: {e}")
                print_good(f"Se han guardado {len(results)} vhosts encontrados hasta el momento.")
                SCAN_DATA["vhosts"] = results
                return results
            except Exception as e:
                print_error(f"Error ejecutando ffuf: {e}")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            return results

        # Método interno (sin ffuf)
        print_warning("ffuf no disponible, usando método interno (más lento).")
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subs = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            print_error(f"Error leyendo wordlist: {e}")
            return results
        print_info(f"Probando {len(subs)} subdominios contra {base_domain}...")

        def test_sub(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                if REQUEST_DELAY > 0:
                    time.sleep(REQUEST_DELAY)
                r = session.get(target, headers={"Host": fqdn},
                                timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                cl = r.headers.get('Content-Length')
                size = int(cl) if cl and cl.isdigit() else len(r.content)
                if baseline_size is not None and use_fs_filter and size == baseline_size:
                    return None
                return (sub, fqdn, r.status_code, size)
            except Exception:
                return None

        iterator = subs
        if HAS_TQDM:
            pbar = tqdm(total=len(subs), desc="VHost fuzzing", unit="req", ncols=80)
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for res in ex.map(test_sub, iterator):
                    if HAS_TQDM:
                        pbar.update(1)
                    if res:
                        sub, fqdn, status, size = res
                        print_good(f"[{status}] {fqdn} (size={size})")
                        results.append({'subdomain': sub, 'fqdn': fqdn,
                                        'status': status, 'size': size})
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
        finally:
            if HAS_TQDM:
                pbar.close()
        return results
    except Exception as e:
        print_error(f"Error en vhost_bruteforce: {e}")
        return results


def dir_bruteforce(target, session, wordlist=None, threads=THREADS, use_ffuf=True):
    try:
        if wordlist is None:
            default_wl = check_seclists()
            if default_wl:
                wordlist = default_wl
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"No se pudo leer la wordlist '{wordlist}'. Usando lista interna.")
            wordlist = None

        if use_ffuf and check_ffuf() and wordlist and os.path.isfile(wordlist):
            # Archivo temporal para resultados JSON limpios (sin ruido de calibración)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)

            # Pre-filtrar wordlist: descartar comentarios (#), líneas vacías y
            # entradas con espacios/caracteres no válidos para rutas web.
            clean_fd, clean_wl = tempfile.mkstemp(suffix='.txt', prefix='wstg_wl_')
            os.close(clean_fd)
            kept = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as src, \
                     open(clean_wl, 'w', encoding='utf-8') as dst:
                    for line in src:
                        entry = line.strip()
                        if not entry or entry.startswith('#'):
                            continue
                        # Una ruta web no debe contener espacios en blanco internos
                        if any(ch.isspace() for ch in entry):
                            continue
                        dst.write(entry + '\n')
                        kept += 1
                print_info(f"Wordlist limpia: {kept} entradas válidas (descartados comentarios y líneas inválidas)")
            except Exception as e:
                print_warning(f"No se pudo limpiar la wordlist ({e}); se usará la original.")
                clean_wl = wordlist

            # Calcular tamaño baseline de la raíz para descartar páginas-comodín
            baseline_size = None
            try:
                base_resp = session.get(target, timeout=DEFAULT_TIMEOUT)
                if base_resp.status_code == 200:
                    baseline_size = len(base_resp.content)
            except Exception:
                pass

            ffuf_cmd = [
                "ffuf", "-u", f"{target}/FUZZ", "-w", clean_wl,
                "-t", str(threads), "-fc", "404,403", "-ac",
                "-o", tmp_path, "-of", "json",
            ]
            if baseline_size:
                # Filtrar respuestas con el mismo tamaño exacto que la página raíz
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Ejecutando: {' '.join(ffuf_cmd[:7])}")
            print()  # línea en blanco antes de la barra nativa de ffuf

            results = []
            process = None
            try:
                # Sin piping: ffuf escribe directamente al terminal → su barra de
                # progreso funciona correctamente (necesita TTY para actualizarse).
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()  # línea en blanco tras la barra de ffuf

                # ── Leer resultados limpios desde el JSON ─────────────────────
                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)

                        STATUS_COLOR = {
                            200: Fore.GREEN,  201: Fore.GREEN,  204: Fore.GREEN,
                            301: Fore.CYAN,   302: Fore.CYAN,   307: Fore.CYAN,   308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED,    503: Fore.RED,
                        }

                        if not hits:
                            print(f"\n  {Fore.YELLOW}Sin resultados (todos filtrados por auto-calibración){Style.RESET_ALL}\n")
                        else:
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                path    = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                                status  = hit.get('status', 0)
                                size    = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns  = hit.get('duration', 0)
                                dur_ms  = dur_ns // 1_000_000 if dur_ns else 0
                                url_hit = hit.get('url', urljoin(target, path))
                                color   = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    path,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                ])
                                results.append({'url': url_hit, 'status': status, 'size': size})
                                FINDINGS.append(f"[DIR] {url_hit} [{status}]")
                            print_table(
                                headers=["STATUS", "PATH", "SIZE", "WORDS", "DUR"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} endpoint(s) encontrados\n",
                            )
                    except Exception as e:
                        print_error(f"Error leyendo JSON de ffuf: {e}")

                if rc not in (0, 1):
                    print_error(f"ffuf terminó con código {rc}")

            except KeyboardInterrupt:
                print_warning("Fuzzing interrumpido por el usuario; esperando a que ffuf guarde resultados parciales...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('url'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        path = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        url_hit = hit.get('url', urljoin(target, path))
                        key = (url_hit, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({'url': url_hit, 'status': status, 'size': size})
                        FINDINGS.append(f"[DIR] {url_hit} [{status}]")
                except Exception as e:
                    print_error(f"Error leyendo JSON parcial de ffuf: {e}")
                # Guardar resultados parciales en SCAN_DATA (mutación, no necesita global)
                SCAN_DATA["directory_hits"] = results
                print_good(f"Se han guardado {len(results)} directorios encontrados hasta el momento.")
                return results
            except Exception as e:
                print_error(f"Error ejecutando ffuf: {e}")
                print_warning("Fallando a método interno...")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                # Eliminar wordlist limpia temporal (sólo si fue creada)
                if clean_wl and clean_wl != wordlist:
                    try:
                        os.unlink(clean_wl)
                    except Exception:
                        pass

            return results
        else:
            if use_ffuf and not check_ffuf():
                print_warning("ffuf no está instalado. Usando método interno (más lento).")
            if wordlist is None:
                paths = COMMON_DIRS
                print_info(f"Usando lista interna reducida ({len(paths)} rutas)")
            else:
                with open(wordlist, 'r') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print_info(f"Usando wordlist: {wordlist} ({len(paths)} entradas)")
            
            results = []
            print_info(f"Iniciando fuzzing de directorios (método interno)...")

            def test_path(path):
                url = urljoin(target, path)
                try:
                    if REQUEST_DELAY > 0:
                        time.sleep(REQUEST_DELAY)
                    resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code < 400:
                        return (url, resp.status_code, len(resp.content))
                except Exception:
                    pass
                return None

            if HAS_TQDM:
                with tqdm(total=len(paths), desc="Fuzzing directorios", unit="req", ncols=80) as pbar:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        future_to_path = {executor.submit(test_path, p): p for p in paths}
                        for future in as_completed(future_to_path):
                            res = future.result()
                            if res:
                                url, code, size = res
                                print_good(f"Encontrado: {url} (código {code}, tamaño {size})")
                                results.append({'url': url, 'status': code, 'size': size})
                            pbar.update(1)
            else:
                completed = 0
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    future_to_path = {executor.submit(test_path, p): p for p in paths}
                    for future in as_completed(future_to_path):
                        completed += 1
                        if completed % 50 == 0 or completed == len(paths):
                            print_info(f"Progreso: {completed}/{len(paths)} rutas probadas")
                        res = future.result()
                        if res:
                            url, code, size = res
                            print_good(f"Encontrado: {url} (código {code}, tamaño {size})")
                            results.append({'url': url, 'status': code, 'size': size})
            return results
    except Exception as e:
        print_error(f"Error en fuzzing: {e}")
        return []

def extract_forms_and_params(target, session):
    def _extract_from_single_page(page_url):
        forms = []
        params = set()
        try:
            resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 400:
                return forms, params
            content_type = (resp.headers.get('Content-Type', '') or '').lower()
            if 'html' not in content_type and '<form' not in resp.text.lower():
                return forms, params

            if HAS_BS4:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    action = form.get('action')
                    method = form.get('method', 'get').upper()
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if not name:
                            continue
                        input_type = (inp.get('type') or '').lower()
                        if input_type in ('submit', 'button', 'image', 'reset', 'file'):
                            continue
                        inputs.append(name)
                    if inputs:
                        forms.append({
                            'page_url': page_url,
                            'action': action,
                            'method': method,
                            'inputs': sorted(set(inputs))
                        })

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    parsed = urlparse(href)
                    if parsed.query:
                        for key in parse_qs(parsed.query).keys():
                            params.add(key)
            else:
                form_regex = re.compile(r'<form.*?action=["\'](.*?)["\'].*?method=["\'](.*?)["\'].*?>', re.I)
                for match in form_regex.finditer(resp.text):
                    action = match.group(1)
                    method = match.group(2).upper()
                    forms.append({'page_url': page_url, 'action': action, 'method': method, 'inputs': []})
                param_regex = re.compile(r'<a\s+href=["\'][^"\']*\?(.*?)(?:["\']|#)', re.I)
                for match in param_regex.finditer(resp.text):
                    query = match.group(1)
                    for key in parse_qs(query).keys():
                        params.add(key)

            parsed_page = urlparse(page_url)
            if parsed_page.query:
                for key in parse_qs(parsed_page.query).keys():
                    params.add(key)
        except Exception:
            pass
        return forms, params

    try:
        forms = []
        params = set()
        form_keys = set()

        print_info("Crawling para detectar formularios e inputs de forma exhaustiva...")
        discovered_urls, spider_params, spider_forms = spider_website(
            target,
            session,
            max_pages=250,
            max_depth=3,
            use_robots=True,
        )

        params.update(spider_params or set())

        # Reutilizar los formularios ya detectados por el spider (con inputs)
        for f in spider_forms or []:
            action_url = f.get('action') or f.get('url') or f.get('page_url') or target
            method = (f.get('method') or 'GET').upper()
            inputs = sorted(set(f.get('inputs', [])))
            if not inputs:
                continue
            key = (action_url, method, tuple(inputs))
            if key in form_keys:
                continue
            form_keys.add(key)
            forms.append({
                'page_url': f.get('page_url', action_url),
                'action': action_url,
                'method': method,
                'inputs': inputs,
            })

        print_info(f"Formularios encontrados: {len(forms)}")
        print_info(f"Parámetros únicos en enlaces: {len(params)}")
        return forms, list(params)
    except Exception as e:
        print_error(f"Error extrayendo formularios/parámetros: {e}")
        return [], []

def advanced_injection_tests(url, param, session, method='GET'):
    try:
        # SQLi
        for payload in ['\' OR SLEEP(5)-- ', '1\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--']:
            try:
                start = time.time()
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    session.get(test_url, timeout=DEFAULT_TIMEOUT+2)
                else:
                    session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT+2)
                elapsed = time.time() - start
                if elapsed > 4:
                    print_vuln(f"Posible SQLi time-based en {param} (retraso {elapsed:.2f}s)")
                    return True
            except KeyboardInterrupt:
                print_warning("Prueba de inyección interrumpida por el usuario.")
                return False
            except:
                pass
        # XSS
        for payload in XSS_PAYLOADS:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if payload in resp.text and ('<script>' in payload or 'onerror=' in payload):
                    print_vuln(f"Posible XSS en {param} con payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Prueba de inyección interrumpida por el usuario.")
                return False
            except:
                pass
        # Command Injection
        for payload in COMMAND_INJECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "uid=" in resp.text or "Directory of" in resp.text:
                    print_vuln(f"Posible Command Injection en {param} con payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Prueba de inyección interrumpida por el usuario.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error en advanced_injection_tests para {param}: {e}")
        return False

def test_path_traversal(url, param, session, method='GET'):
    try:
        for payload in PATH_TRAVERSAL:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "root:" in resp.text or "[extensions]" in resp.text:
                    print_vuln(f"Path Traversal en {param}: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Prueba de Path Traversal interrumpida por el usuario.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error en path traversal: {e}")
        return False

def test_open_redirect(url, param, session, method='GET'):
    try:
        for payload in OPEN_REDIRECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if resp.status_code in [301,302,303,307]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or '//' in location:
                        print_vuln(f"Open Redirect en {param} -> {location}")
                        return True
            except KeyboardInterrupt:
                print_warning("Prueba de Open Redirect interrumpida por el usuario.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error en open redirect: {e}")
        return False

def check_security_headers(headers):
    try:
        checks = {
            'Strict-Transport-Security': 'HSTS no implementado',
            'Content-Security-Policy': 'CSP no implementado',
            'X-Frame-Options': 'Clickjacking: falta X-Frame-Options',
            'X-Content-Type-Options': 'Falta X-Content-Type-Options',
            'Referrer-Policy': 'Falta Referrer-Policy'
        }
        for header, warning in checks.items():
            if header not in headers:
                print_warning(warning)
            else:
                print_good(f"{header}: {headers[header]}")
    except Exception as e:
        print_error(f"Error revisando cabeceras: {e}")

def check_cookie_security(cookies):
    try:
        for cookie in cookies:
            name = cookie.name
            if not cookie.secure:
                print_warning(f"Cookie '{name}' sin flag Secure")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print_warning(f"Cookie '{name}' sin flag HttpOnly")
    except Exception as e:
        print_error(f"Error revisando cookies: {e}")

def check_info_disclosure(resp_text):
    try:
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp_text)
        if emails:
            print_warning(f"Emails expuestos: {', '.join(set(emails))}")
        internal_paths = re.findall(r'(?:C:\\|/home/|/var/www/|/etc/)[^\s\'"<>]+', resp_text, re.I)
        if internal_paths:
            print_warning(f"Rutas internas expuestas: {set(internal_paths)}")
        comments = re.findall(r'<!--(.*?)-->', resp_text, re.DOTALL)
        suspicious = [c for c in comments if re.search(r'todo|fixme|debug|password|key|token', c, re.I)]
        if suspicious:
            print_warning("Información sensible en comentarios HTML")
    except Exception as e:
        print_error(f"Error en info disclosure: {e}")

def check_directory_listing(url, session):
    try:
        test_url = urljoin(url, 'images/')
        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200 and ('Index of /' in resp.text or 'Parent Directory' in resp.text):
            print_vuln(f"Directory listing en {test_url}")
    except:
        pass

def check_ssl_tls(target):
    try:
        parsed = urlparse(target)
        if parsed.scheme != 'https':
            print_info("No se evaluará SSL/TLS (no HTTPS)")
            return
        hostname = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print_info(f"Certificado para: {cert.get('subject')}")
                version = ssock.version()
                if version and version not in ('TLSv1.2', 'TLSv1.3'):
                    print_warning(f"Protocolo TLS inseguro: {version}")
                else:
                    print_good(f"Protocolo TLS: {version}")
    except Exception as e:
        print_error(f"SSL/TLS error: {e}")

def test_cors_advanced(target, session):
    """OWASP API8 / WSTG-CLNT-007: Verifica configuraciones CORS inseguras."""
    try:
        parsed = urlparse(target)
        evil_origins = [
            "https://evil.com",
            "null",
            f"https://{parsed.netloc}.evil.com",
            f"https://evil.{parsed.netloc}",
        ]
        for origin in evil_origins:
            try:
                resp = session.get(target, timeout=DEFAULT_TIMEOUT, headers={'Origin': origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
                if acao == '*' and acac == 'true':
                    print_vuln(f"CORS crítico: wildcard + Allow-Credentials=true [{origin}]")
                elif acao == origin:
                    if acac == 'true':
                        print_vuln(f"CORS: origen reflejado con credenciales permitidas -> {origin}")
                    else:
                        print_warning(f"CORS: origen reflejado sin credenciales -> {origin}")
                elif acao == '*':
                    print_warning("CORS: wildcard (*) sin Allow-Credentials")
                # Verificar preflight OPTIONS
                try:
                    pre = session.options(target, timeout=DEFAULT_TIMEOUT, headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'Authorization',
                    })
                    pre_acao = pre.headers.get('Access-Control-Allow-Origin', '')
                    if pre_acao == origin or pre_acao == '*':
                        print_info(f"  Preflight CORS acepta POST+Authorization desde {origin}")
                except Exception:
                    pass
            except Exception:
                pass
    except Exception as e:
        print_error(f"Error en test CORS avanzado: {e}")


# ========== API PENTESTING (OWASP API Top 10) ==========

def discover_api_endpoints(target, session):
    """OWASP API9: Descubre endpoints expuestos y analiza documentación OpenAPI/Swagger.
    Realiza también fuzzing recursivo bajo prefijos /api/v1, /api/v2, /v1, etc."""
    found = []
    seen_urls = set()

    # Códigos que indican "el endpoint existe" (no 404)
    INTERESTING = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    def _probe(endpoint, depth_label=""):
        """Prueba un endpoint con GET. Devuelve dict si es interesante, None si no."""
        url = urljoin(target, endpoint)
        if url in seen_urls:
            return None
        seen_urls.add(url)
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        except Exception:
            return None
        st = resp.status_code
        if st not in INTERESTING:
            return None
        ct = resp.headers.get('Content-Type', '').split(';')[0].strip()
        item = {'url': url, 'endpoint': endpoint, 'status': st, 'content_type': ct}

        prefix = f"  {depth_label}" if depth_label else ""
        if st in (200, 201, 202, 204):
            print_good(f"{prefix}[{st}] {url}  ({ct})")
        elif st in (301, 302, 307, 308):
            loc = resp.headers.get('Location', '')
            print_info(f"{prefix}[{st}] {url} -> {loc}")
        elif st == 401:
            print_warning(f"{prefix}[401] {url}  (requiere autenticación)")
        elif st == 403:
            print_warning(f"{prefix}[403] {url}  (prohibido)")
        elif st == 405:
            allow = resp.headers.get('Allow', '')
            print_warning(f"{prefix}[405] {url}  (método no permitido; Allow: {allow or 'N/A'})")
        elif st == 500:
            print_error(f"{prefix}[500] {url}  (error interno — posible parámetro no manejado)")

        # Si es Swagger/OpenAPI/API docs, parsear y registrar rutas
        if st == 200 and any(x in endpoint for x in ('swagger', 'openapi', 'api-docs')):
            try:
                doc = resp.json()
                paths = list(doc.get('paths', {}).keys())
                if paths:
                    print_info(f"  Rutas documentadas ({len(paths)}): {', '.join(paths[:12])}")
                    for path in paths:
                        extra_url = urljoin(target, path)
                        if extra_url not in seen_urls:
                            seen_urls.add(extra_url)
                            found.append({'url': extra_url, 'endpoint': path,
                                          'status': 0, 'content_type': ''})
            except Exception:
                pass
        return item

    try:
        print_info(f"Escaneando {len(API_ENDPOINTS)} rutas de API conocidas...")
        for ep in API_ENDPOINTS:
            item = _probe(ep)
            if item:
                found.append(item)

        # Fuzzing recursivo bajo prefijos típicos de API. Lo hacemos siempre
        # (no solo si la raíz del prefijo responde) porque muchas apps devuelven
        # 404 en /api/v1 pero sí exponen /api/v1/users, /api/v1/login, etc.
        prefixes_to_fuzz = list(API_BASE_PREFIXES)

        # Derivar prefijos adicionales desde endpoints ya encontrados o
        # documentados (p. ej. /api/users → añade /api y /api/v1)
        for item in list(found):
            ep = item.get('endpoint', '')
            if not ep or not ep.startswith('/'):
                continue
            parts = [p for p in ep.split('/') if p]
            for i in range(1, len(parts)):
                candidate = '/' + '/'.join(parts[:i])
                if candidate not in prefixes_to_fuzz:
                    prefixes_to_fuzz.append(candidate)

        # Deduplicar manteniendo orden
        seen_pref = set()
        prefixes_to_fuzz = [p for p in prefixes_to_fuzz if not (p in seen_pref or seen_pref.add(p))]

        print_info(
            f"Fuzzing recursivo: {len(API_RESOURCES)} recursos × "
            f"{len(prefixes_to_fuzz)} prefijos ({', '.join(prefixes_to_fuzz[:8])}"
            f"{', ...' if len(prefixes_to_fuzz) > 8 else ''})"
        )
        for prefix in prefixes_to_fuzz:
            for resource in API_RESOURCES:
                endpoint = f"{prefix.rstrip('/')}/{resource}"
                item = _probe(endpoint, depth_label="↳ ")
                if item:
                    found.append(item)

        print_info(f"Total endpoints API encontrados/accesibles: {len(found)}")
        if found:
            STATUS_COLOR = {
                200: Fore.GREEN, 201: Fore.GREEN, 202: Fore.GREEN, 204: Fore.GREEN,
                301: Fore.CYAN, 302: Fore.CYAN, 307: Fore.CYAN, 308: Fore.CYAN,
                401: Fore.YELLOW, 403: Fore.YELLOW, 405: Fore.YELLOW,
                500: Fore.RED, 503: Fore.RED,
            }
            rows = []
            for item in sorted(found, key=lambda x: (x.get('status', 0), x.get('endpoint', ''))):
                st = item.get('status', 0)
                color = STATUS_COLOR.get(st, Fore.WHITE)
                rows.append([
                    f"{color}[{st}]{Style.RESET_ALL}",
                    item.get('endpoint', ''),
                    item.get('url', ''),
                    item.get('content_type', '') or '-',
                ])
            print_table(
                headers=["STATUS", "ENDPOINT", "URL", "CONTENT-TYPE"],
                rows=rows,
                alignments=['<', '<', '<', '<'],
                title="Endpoints API descubiertos:",
            )
    except Exception as e:
        print_error(f"Error descubriendo endpoints: {e}")
    return found


def test_api_auth_bypass(found_endpoints, session):
    """OWASP API5/BFLA: Detecta endpoints restringidos accesibles sin autenticación."""
    try:
        unauth_session = get_session()
        bypass_headers_list = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
        ]
        restricted = [item for item in found_endpoints if item['status'] in (401, 403)]
        if not restricted:
            print_info("Sin endpoints restringidos encontrados para probar bypass.")
            return
        for item in restricted:
            url = item['url']
            try:
                resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200 and len(resp.content) > 50:
                    print_vuln(f"BFLA: accesible sin auth -> {url}")
                    continue
            except Exception:
                pass
            for hdrs in bypass_headers_list:
                try:
                    resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT, headers=hdrs)
                    if resp.status_code == 200:
                        print_vuln(f"Auth bypass con {list(hdrs.keys())[0]} en {url}")
                        break
                except Exception:
                    pass
    except Exception as e:
        print_error(f"Error en test auth bypass: {e}")


def test_api_idor(found_endpoints, session):
    """OWASP API1/BOLA: Prueba IDOR modificando IDs en rutas y query params."""
    try:
        id_patterns = [
            (r'((?:/[a-zA-Z_-]+)/)(\d{1,10})(/|$)', 2),
            (r'([?&](?:id|user_id|uid|account_id|object_id)=)(\d+)', 2),
            (r'((?:/[a-zA-Z_-]+)/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 2),
        ]
        alt_ids = ['0', '1', '2', '-1', '9999', '../1']
        tested = set()
        hits = 0
        for item in found_endpoints:
            url = item['url']
            for pattern, group in id_patterns:
                match = re.search(pattern, url)
                if not match:
                    continue
                original_id = match.group(group)
                prefix = url[:match.start(group)]
                suffix = url[match.end(group):]
                try:
                    base_resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                    if base_resp.status_code != 200:
                        continue
                    base_len = len(base_resp.content)
                except Exception:
                    continue
                for alt in alt_ids:
                    if alt == original_id:
                        continue
                    test_url = prefix + alt + suffix
                    if test_url in tested:
                        continue
                    tested.add(test_url)
                    try:
                        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                        if resp.status_code == 200 and base_len > 0:
                            diff_ratio = abs(len(resp.content) - base_len) / base_len
                            if diff_ratio < 0.4:
                                print_vuln(f"IDOR: {url} -> ID={alt} devuelve {resp.status_code} "
                                           f"({len(resp.content)}B, ratio_diff={diff_ratio:.2f})")
                                hits += 1
                    except Exception:
                        pass
        if hits == 0:
            print_info("Sin evidencias claras de IDOR en los endpoints encontrados.")
    except Exception as e:
        print_error(f"Error en test IDOR: {e}")


def test_api_mass_assignment(found_endpoints, session):
    """OWASP API6: Inyecta campos privilegiados en endpoints que aceptan JSON."""
    try:
        targets = [item for item in found_endpoints
                   if item['status'] in (200, 201, 0)
                   and any(x in item['endpoint'] for x in
                           ('user', 'profile', 'account', 'register', 'update', 'me', 'signup'))]
        if not targets:
            print_info("Sin endpoints candidatos a Mass Assignment.")
            return
        method_map = [('POST', 'post'), ('PUT', 'put'), ('PATCH', 'patch')]
        for item in targets:
            url = item['url']
            for fields in MASS_ASSIGNMENT_FIELDS[:6]:
                for method_name, method_attr in method_map:
                    try:
                        method = getattr(session, method_attr)
                        resp = method(url, json=fields, timeout=DEFAULT_TIMEOUT)
                        if resp.status_code in (200, 201, 202, 204):
                            key = list(fields.keys())[0]
                            resp_lower = resp.text.lower()
                            if key in resp_lower or 'admin' in resp_lower or 'success' in resp_lower:
                                print_vuln(f"Mass Assignment en {url} [{method_name}] con {fields}")
                                break
                    except Exception:
                        pass
    except Exception as e:
        print_error(f"Error en test Mass Assignment: {e}")


def test_graphql(target, session):
    """OWASP API8: Introspección GraphQL habilitada y queries peligrosas."""
    try:
        gql_endpoints = [urljoin(target, ep)
                         for ep in ('/graphql', '/graphiql', '/api/graphql', '/query', '/api/query')]
        introspection = {'query': '{ __schema { types { name } } }'}
        user_enum = {'query': '{ users { id username email password } }'}
        found_any = False
        for gql_url in gql_endpoints:
            try:
                resp = session.post(gql_url, json=introspection,
                                    headers={'Content-Type': 'application/json'},
                                    timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if 'data' in data and '__schema' in str(data.get('data', {})):
                    found_any = True
                    print_vuln(f"GraphQL Introspección habilitada: {gql_url}")
                    types = [t['name'] for t in data['data']['__schema']['types']
                             if not t['name'].startswith('__')]
                    print_info(f"  Tipos expuestos ({len(types)}): {', '.join(types[:15])}")
                elif 'errors' not in data:
                    found_any = True
                    print_warning(f"GraphQL activo (introspección deshabilitada): {gql_url}")
                if found_any:
                    try:
                        r2 = session.post(gql_url, json=user_enum,
                                          headers={'Content-Type': 'application/json'},
                                          timeout=DEFAULT_TIMEOUT)
                        d2 = r2.json()
                        if 'data' in d2 and d2['data'] and 'users' in str(d2['data']):
                            print_vuln(f"GraphQL expone listado de usuarios en {gql_url}")
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        if not found_any:
            print_info("Sin endpoints GraphQL detectados o activos.")
    except Exception as e:
        print_error(f"Error en test GraphQL: {e}")


def test_api_verbose_errors(found_endpoints, session):
    """OWASP API7: Detecta respuestas de error con información interna expuesta."""
    try:
        error_payloads = ["'", '"', '{}', '-1', '../', '%00']
        sensitive_patterns = [
            re.compile(r'exception|traceback|stack.?trace|at \w+\.java:\d+', re.I),
            re.compile(r'sql(?:state)?|mysql|postgresql|sqlite|ora-\d{4,5}', re.I),
            re.compile(r'internal.?server.?error|unhandled.?exception|fatal.?error', re.I),
            re.compile(r'/var/www|c:\\\\inetpub|/home/\w+/|/etc/passwd', re.I),
        ]
        hits = 0
        for item in found_endpoints:
            if item['status'] not in (200, 0):
                continue
            url = item['url']
            for payload in error_payloads[:4]:
                test_url = url.rstrip('/') + payload
                try:
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code in (500, 503):
                        for pat in sensitive_patterns:
                            if pat.search(resp.text):
                                print_vuln(f"Error verbose [{resp.status_code}]: {test_url}")
                                hits += 1
                                break
                except Exception:
                    pass
        if hits == 0:
            print_info("Sin errores verbose detectados en los endpoints probados.")
    except Exception as e:
        print_error(f"Error en test verbose errors: {e}")


def test_api_rate_limiting(target, session):
    """OWASP API4: Verifica si existe rate limiting en endpoints de autenticación."""
    try:
        candidates = [
            urljoin(target, '/api/v1/login'),
            urljoin(target, '/api/login'),
            urljoin(target, '/api/auth'),
            urljoin(target, '/login'),
        ]
        for test_url in candidates:
            statuses = []
            for _ in range(20):
                try:
                    resp = session.post(test_url,
                                        json={'username': 'test', 'password': 'test'},
                                        timeout=DEFAULT_TIMEOUT)
                    statuses.append(resp.status_code)
                    if resp.status_code == 429:
                        break
                except Exception:
                    break
            if not statuses:
                continue
            if 429 in statuses:
                print_good(f"Rate limiting activo (HTTP 429) en {test_url}")
            elif all(s not in (429, 503) for s in statuses):
                print_warning(f"Sin rate limiting: {len(statuses)} requests sin bloqueo en {test_url}")
            break
    except Exception as e:
        print_error(f"Error en test rate limiting: {e}")


def test_jwt_tokens(target, session):
    """OWASP API2: Detecta JWT en cabeceras/cookies y analiza algoritmo y campos."""
    try:
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        jwt_regex = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        jwt_candidates = set()
        for header_val in resp.headers.values():
            jwt_candidates.update(jwt_regex.findall(header_val))
        for cookie in resp.cookies:
            jwt_candidates.update(jwt_regex.findall(cookie.value))
        if not jwt_candidates:
            print_info("Sin JWT detectados en cabeceras/cookies de la página principal.")
            return
        for jwt in jwt_candidates:
            try:
                parts = jwt.split('.')
                if len(parts) < 3:
                    continue
                def _b64_decode(s):
                    s += '=' * (4 - len(s) % 4)
                    return json.loads(base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore'))
                header_data = _b64_decode(parts[0])
                payload_data = _b64_decode(parts[1])
                alg = header_data.get('alg', '').upper()
                print_info(f"JWT detectado — alg: {alg}  kid: {header_data.get('kid', 'N/A')}")
                if alg in ('NONE', ''):
                    print_vuln("JWT con alg:none — firma ignorada completamente")
                elif alg in ('HS256', 'HS384', 'HS512'):
                    print_warning(f"JWT HMAC ({alg}) — revisar secreto débil manualmente")
                sensitive_keys = {'admin', 'role', 'is_admin', 'permission', 'privilege', 'scope'}
                exposed = [k for k in payload_data if k.lower() in sensitive_keys]
                if exposed:
                    print_warning(f"  JWT contiene campos de privilegio: {exposed}")
                    for k in exposed:
                        print_info(f"    {k} = {payload_data[k]}")
                exp = payload_data.get('exp')
                if exp and exp < time.time():
                    print_warning("  JWT caducado todavía aceptado por el servidor")
            except Exception:
                pass
    except Exception as e:
        print_error(f"Error en test JWT: {e}")



def enumerate_users_from_endpoints(target, session):
    try:
        users = []
        emails = []
        endpoints_to_try = ["/api/users", "/users", "/rest/users", "/api/user/list", "/admin/users"]
        for endpoint in endpoints_to_try:
            url = urljoin(target, endpoint)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list):
                            for item in data:
                                if 'username' in item: users.append(item['username'])
                                if 'email' in item: emails.append(item['email'])
                        elif isinstance(data, dict):
                            for key, val in data.items():
                                if key.lower() in ['users','items'] and isinstance(val, list):
                                    for item in val:
                                        if 'username' in item: users.append(item['username'])
                                        if 'email' in item: emails.append(item['email'])
                    except:
                        emails.extend(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            except:
                pass
        return list(set(users)), list(set(emails))
    except Exception as e:
        print_error(f"Error enumerando usuarios: {e}")
        return [], []

def test_user_enumeration_form(target, session):
    try:
        print_info("Comprobando posible enumeración de usuarios en formularios...")
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').upper()
                if method != 'POST':
                    continue
                inputs = {inp.get('name'): inp for inp in form.find_all('input') if inp.get('name')}
                user_field = None
                for name in inputs:
                    if 'user' in name.lower() or 'email' in name.lower():
                        user_field = name
                        break
                if user_field:
                    form_url = urljoin(target, action) if action else target
                    data = {user_field: 'nonexistent_user_xyz_999'}
                    if 'pass' in str(inputs):
                        data['password'] = 'dummy'
                    resp_test = session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT)
                    if "user not found" in resp_test.text.lower() or "no existe" in resp_test.text.lower():
                        print_vuln("Posible enumeración de usuarios detectada (mensaje diferencial)")
    except Exception as e:
        print_error(f"Error en test de enumeración: {e}")

def bruteforce_login(target, session, usernames, passlist, max_threads=5):
    """
    Detecta formulario de login principal y realiza fuerza bruta con
    validación estricta para minimizar falsos positivos.
    """
    try:
        result_data = {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

        if not usernames:
            usernames = ['admin', 'test']

        # Permitir al usuario elegir método y parámetros avanzados
        print_info("\n=== Bruteforce avanzado ===")
        use_hydra = False
        hydra_path = shutil.which("hydra")
        if hydra_path:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar hydra para el bruteforce? [S/n]:")
            resp = input("> ").strip().lower()
            use_hydra = (resp != 'n')
        else:
            print_warning("hydra no está instalado o no está en PATH. Usando método interno.")

        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Introduce la URL real del login (dejar vacío para autodetección):")
        login_url = input("> ").strip()
        print_info("El mensaje de error de login mejora MUCHO la precisión (evita falsos positivos).")
        print_info("Si lo dejas vacío, se intentará autodetectar enviando credenciales imposibles.")
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Mensaje de error exacto de login fallido (vacío = autodetectar):")
        error_msg = input("> ").strip()
        # Flag para endurecer la heurística cuando no haya error_msg ni candidatos autodetectados
        strict_heuristic = False

        # Si no se especifica, autodetectar como antes
        login_forms_map = {}
        urls_to_check = [login_url] if login_url else [target] + [urljoin(target, path) for path in LOGIN_PATHS]

        def _is_login_like(path):
            p = (path or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _score_form(form_url, page_url, user_field, pass_field):
            score = 0
            full = f"{form_url} {page_url}".lower()
            if _is_login_like(full):
                score += 4
            uf = (user_field or '').lower()
            pf = (pass_field or '').lower()
            if uf in ('username', 'user', 'email', 'login'):
                score += 2
            elif uf:
                score += 1
            if pf in ('password', 'pass', 'passwd'):
                score += 2
            elif pf:
                score += 1
            return score

        for page_url in urls_to_check:
            try:
                resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action')
                        method = form.get('method', 'get').upper()
                        if method != 'POST':
                            continue
                        inputs = form.find_all(['input', 'textarea'])
                        user_field = None
                        pass_field = None
                        for inp in inputs:
                            name = inp.get('name', '').lower()
                            if 'user' in name or 'email' in name or 'login' in name or 'username' in name:
                                user_field = inp.get('name')
                            if 'pass' in name or 'password' in name:
                                pass_field = inp.get('name')
                        if user_field and pass_field:
                            form_url = urljoin(page_url, action) if action else page_url
                            hidden_fields = {}
                            for inp in inputs:
                                iname = inp.get('name')
                                itype = (inp.get('type') or '').lower()
                                if iname and itype == 'hidden':
                                    hidden_fields[iname] = inp.get('value', '')
                            score = _score_form(form_url, page_url, user_field, pass_field)
                            form_data = {
                                'url': form_url,
                                'user_field': user_field,
                                'pass_field': pass_field,
                                'hidden_fields': hidden_fields,
                                'score': score,
                                'source_page': page_url,
                            }
                            key = (form_url, user_field, pass_field)
                            prev = login_forms_map.get(key)
                            if prev is None or form_data['score'] > prev['score']:
                                login_forms_map[key] = form_data
            except:
                continue

        login_forms = list(login_forms_map.values())
        for f in login_forms:
            print_good(
                f"Formulario de login detectado en {f['url']} "
                f"(usuario: {f['user_field']}, pass: {f['pass_field']}, score={f['score']})"
            )

        if not login_forms:
            print_warning("No se detectaron formularios de login automáticamente.")
            manual = input("¿Deseas introducir los datos manualmente? (s/n): ").strip().lower()
            if manual == 's':
                login_url2 = input("URL completa del formulario de login: ").strip()
                user_field = input("Nombre del campo de usuario: ").strip()
                pass_field = input("Nombre del campo de contraseña: ").strip()
                if login_url2 and user_field and pass_field:
                    login_forms.append({
                        'url': normalize_url(login_url2),
                        'user_field': user_field,
                        'pass_field': pass_field,
                        'hidden_fields': {},
                        'score': 10,
                        'source_page': normalize_url(login_url2),
                    })
                    print_good("Formulario manual agregado.")
                else:
                    print_error("Datos incompletos. No se realizará bruteforce.")
                    return result_data
            else:
                print_info("Continuando sin bruteforce.")
                return result_data

        primary_form = max(
            login_forms,
            key=lambda f: (f.get('score', 0), -len(urlparse(f.get('url', '')).path or '/'))
        )
        print_info(
            f"Usando formulario principal: {primary_form['url']} "
            f"({primary_form['user_field']}/{primary_form['pass_field']})"
        )

        # --- Autodetección del mensaje de error de login ---
        if not error_msg:
            print_info("Autodetectando mensaje de error con credenciales imposibles...")
            ERROR_KEYWORDS = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied', 'bad credentials',
                'authentication', 'unauthorized', 'forbidden', 'try again',
                'inválido', 'invalido', 'incorrecto', 'incorrecta', 'denegado',
                'no encontrado', 'usuario o contrase', 'contraseña incorrecta',
                'fallo', 'falló', 'intentar de nuevo', 'no válido', 'no valido',
            ]
            candidates = []
            try:
                _probe_payload = {}
                _probe_payload.update(primary_form.get('hidden_fields', {}))
                _probe_payload[primary_form['user_field']] = "__wstg_x7z9q__"
                _probe_payload[primary_form['pass_field']] = "__wstg_x7z9q__"
                _probe_resp = session.post(
                    primary_form['url'], data=_probe_payload,
                    timeout=DEFAULT_TIMEOUT, allow_redirects=True
                )
                _probe_text = _probe_resp.text
                if HAS_BS4:
                    try:
                        _probe_soup = BeautifulSoup(_probe_text, 'html.parser')
                        for _t in _probe_soup(['script', 'style', 'noscript']):
                            _t.decompose()
                        _probe_text = _probe_soup.get_text(separator='\n')
                    except Exception:
                        pass
                _seen = set()
                for _raw in _probe_text.splitlines():
                    _line = re.sub(r'\s+', ' ', _raw).strip()
                    if not _line or len(_line) < 5 or len(_line) > 200:
                        continue
                    _low = _line.lower()
                    if any(k in _low for k in ERROR_KEYWORDS):
                        if _line not in _seen:
                            _seen.add(_line)
                            candidates.append(_line)
                    if len(candidates) >= 10:
                        break
            except Exception as e:
                print_warning(f"No se pudo autodetectar mensaje de error: {e}")

            if candidates:
                print_good(f"Candidatos de mensaje de error detectados ({len(candidates)}):")
                for i, c in enumerate(candidates, 1):
                    print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}. {c}")
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Elige número [1-{len(candidates)}] (Enter = #1, 'n' = ninguno / heurística estricta):")
                choice = input("> ").strip().lower()
                if choice == 'n':
                    strict_heuristic = True
                    print_warning("Sin mensaje de error: se aplicará heurística estricta (menos falsos positivos).")
                else:
                    try:
                        idx = int(choice) - 1 if choice else 0
                        if 0 <= idx < len(candidates):
                            error_msg = candidates[idx]
                        else:
                            error_msg = candidates[0]
                    except ValueError:
                        error_msg = candidates[0]
                    print_good(f"Mensaje de error seleccionado: '{error_msg}'")
            else:
                strict_heuristic = True
                print_warning("No se detectaron candidatos. Se aplicará heurística estricta.")

        # Cargar lista de contraseñas
        passwords = DEFAULT_PASSWORDS
        if passlist and os.path.isfile(passlist):
            with open(passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif passlist:
            print_warning(f"No se pudo leer {passlist}, usando lista por defecto.")
        else:
            # Si no se proporcionó wordlist, intentar usar la de SecLists
            if os.path.exists(SECLISTS_PASSWORDS):
                print_info(f"Usando wordlist de contraseñas por defecto: {SECLISTS_PASSWORDS}")
                with open(SECLISTS_PASSWORDS, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            else:
                print_warning("No se encontró la wordlist de SecLists, usando lista pequeña por defecto.")

        total_combinations = len(usernames) * len(passwords)
        result_data["total_combinations"] = total_combinations
        result_data["total_passwords"] = len(passwords)
        result_data["total_users"] = len(usernames)
        result_data["login_forms"] = [{
            "url": primary_form.get("url", ""),
            "user_field": primary_form.get("user_field", ""),
            "pass_field": primary_form.get("pass_field", ""),
        }]

        if use_hydra:
            # Crear archivos temporales para usuarios y contraseñas
            import tempfile
            with tempfile.NamedTemporaryFile('w+', delete=False) as ufile:
                for u in usernames:
                    ufile.write(u + '\n')
                ufile_path = ufile.name
            with tempfile.NamedTemporaryFile('w+', delete=False) as pfile:
                for p in passwords:
                    pfile.write(p + '\n')
                pfile_path = pfile.name

            # Detectar tipo de formulario (POST)
            login_url_hydra = primary_form['url']
            user_field = primary_form['user_field']
            pass_field = primary_form['pass_field']
            parsed_url = urlparse(login_url_hydra)
            host = parsed_url.hostname
            path = parsed_url.path or '/'
            # Construir string de datos POST
            post_data = f"{user_field}=^USER^&{pass_field}=^PASS^"
            for k, v in primary_form.get('hidden_fields', {}).items():
                post_data += f"&{k}={v}"
            # Mensaje de error personalizado
            fail_flag = error_msg if error_msg else "login failed"
            # -t 4: limitar concurrencia (evita duplicados por race entre workers)
            # -I  : ignorar restorefile previo (sin esperar 10s)
            # -u  : recorrer usuarios primero por contraseña (mejor cobertura)
            hydra_cmd = [
                "hydra", "-L", ufile_path, "-P", pfile_path,
                "-t", "4", "-I", "-u",
                host,
                "http-post-form",
                f"{path}:{post_data}:{fail_flag}"
            ]
            print_info(f"Ejecutando hydra: {' '.join(hydra_cmd)}")
            seen_creds = set()
            try:
                process = subprocess.Popen(hydra_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    print(line, end='')
                    if ("login:" in line and "password:" in line):
                        m = re.search(r'login:\s*(\S+)\s*password:\s*(\S+)', line)
                        if m:
                            user, pwd = m.group(1), m.group(2)
                        else:
                            login_idx = line.find("login:")
                            pass_idx = line.find("password:")
                            if login_idx == -1 or pass_idx == -1:
                                continue
                            user = line[login_idx+len("login:"):pass_idx].strip().split()[0]
                            pwd = line[pass_idx+len("password:"):].strip().split()[0]
                        # Deduplicar (hydra puede reportar el mismo par 2+ veces)
                        if (user, pwd) in seen_creds:
                            continue
                        seen_creds.add((user, pwd))
                        result_data["credentials"].append({"username": user, "password": pwd})
                process.wait()
                print_info("Hydra finalizado.")
            except Exception as e:
                print_error(f"Error ejecutando hydra: {e}")
            finally:
                try:
                    os.unlink(ufile_path)
                    os.unlink(pfile_path)
                except Exception:
                    pass

            # Verificar credenciales con el método interno (sesión real)
            # para detectar usuarios que hydra no encontró por CSRF/cookies/rate-limit.
            usernames_pendientes = [u for u in usernames if u not in {c["username"] for c in result_data["credentials"]}]
            if usernames_pendientes:
                print_info(
                    f"Hydra no encontró credenciales para {len(usernames_pendientes)} usuario(s) "
                    f"({', '.join(usernames_pendientes)}). Reintentando con sesión real (CSRF-aware)..."
                )
                # Cae al método interno con la lista reducida
                usernames = usernames_pendientes
                total_combinations = len(usernames) * len(passwords)
                result_data["total_combinations"] = (result_data.get("total_combinations") or 0) + total_combinations
            else:
                return result_data

        # --- Método interno clásico ---
        print_info(f"Iniciando bruteforce con {len(usernames)} usuarios y {len(passwords)} contraseñas (total {total_combinations} combinaciones)...")
        found_credentials = set()

        _IMPOSSIBLE_USER = "__wstg_x7z9q__"
        _IMPOSSIBLE_PASS = "__wstg_x7z9q__"

        SUCCESS_KEYWORDS = [
            'logout', 'log out', 'sign out', 'cerrar sesión', 'cerrar sesion',
            'dashboard', 'panel', 'welcome', 'bienvenido', 'my account', 'mi cuenta',
            'profile', 'perfil'
        ]
        FAILURE_KEYWORDS = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
            'authentication failed', 'login failed', 'inválido', 'incorrecto',
            'usuario no encontrado', 'contraseña incorrecta'
        ]

        def _normalize_path(url_value):
            return (urlparse(url_value).path.rstrip('/') or '/').lower()

        def _is_login_path(path_value):
            p = (path_value or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _build_payload(user, pwd):
            payload = {}
            payload.update(primary_form.get('hidden_fields', {}))
            payload[primary_form['user_field']] = user
            payload[primary_form['pass_field']] = pwd
            return payload

        baseline_status = -1
        baseline_path = _normalize_path(primary_form['url'])
        fail_lengths = []
        for seed_user in [_IMPOSSIBLE_USER, usernames[0] if usernames else _IMPOSSIBLE_USER, _IMPOSSIBLE_USER]:
            try:
                r = session.post(
                    primary_form['url'],
                    data=_build_payload(seed_user, _IMPOSSIBLE_PASS),
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if baseline_status == -1:
                    baseline_status = r.status_code
                    baseline_path = _normalize_path(r.url)
                fail_lengths.append(len(r.content))
            except Exception:
                pass

        if fail_lengths:
            fail_min = min(fail_lengths)
            fail_max = max(fail_lengths)
            margin = max(int((fail_max - fail_min) * 0.35), 250)
            fail_min = max(0, fail_min - margin)
            fail_max = fail_max + margin
        else:
            fail_min, fail_max = 0, 0

        print_info(
            f"Baseline login: status={baseline_status} path={baseline_path} "
            f"len=[{fail_min},{fail_max}]"
        )

        def is_successful_login(resp_no_redirect, resp_follow):
            body = resp_follow.text.lower()
            final_path = _normalize_path(resp_follow.url)
            final_len = len(resp_follow.content)
            if error_msg and error_msg.lower() in body:
                return False
            if any(k in body for k in FAILURE_KEYWORDS):
                return False

            # Señales positivas independientes
            has_success_kw = any(k in body for k in SUCCESS_KEYWORDS)
            status_changed = (baseline_status != -1
                              and resp_follow.status_code != baseline_status
                              and final_path != baseline_path)
            location = resp_no_redirect.headers.get('Location', '')
            location_path = _normalize_path(urljoin(primary_form['url'], location)) if location else ''
            redirect_off_login = (
                resp_no_redirect.status_code in (301, 302, 303, 307, 308)
                and location and not _is_login_path(location_path)
            )
            size_outlier = fail_max > 0 and (final_len < fail_min or final_len > fail_max)
            path_left_login = final_path != baseline_path and not _is_login_path(final_path)

            # Modo estricto (sin error_msg): exige ≥2 señales positivas distintas
            # o al menos una señal "fuerte" (keyword de éxito + cambio de path/status).
            if strict_heuristic:
                strong = has_success_kw and (status_changed or path_left_login or redirect_off_login)
                signals = sum([has_success_kw, status_changed, redirect_off_login,
                               size_outlier, path_left_login])
                return strong or signals >= 2

            # Heurística normal (cuando tenemos error_msg confirmado)
            if _is_login_path(final_path):
                if size_outlier:
                    return True
                return False
            if has_success_kw:
                return True
            if status_changed:
                return True
            if redirect_off_login:
                return True
            if size_outlier:
                return True
            if path_left_login:
                return True
            return False

        def try_cred(user, pwd):
            try:
                if REQUEST_DELAY > 0:
                    time.sleep(REQUEST_DELAY)
                payload = _build_payload(user, pwd)
                resp_no_redirect = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False
                )
                resp_follow = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if is_successful_login(resp_no_redirect, resp_follow):
                    found_credentials.add((user, pwd))
                    return True
            except Exception:
                pass
            return False

        if HAS_TQDM:
            with tqdm(total=total_combinations, desc="Bruteforce", unit="comb", ncols=80) as pbar:
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = []
                    for user in usernames:
                        for pwd in passwords:
                            futures.append(executor.submit(try_cred, user, pwd))
                    for future in as_completed(futures):
                        future.result()
                        pbar.update(1)
        else:
            completed = 0
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for user in usernames:
                    for pwd in passwords:
                        futures.append(executor.submit(try_cred, user, pwd))
                for future in as_completed(futures):
                    completed += 1
                    if completed % 100 == 0 or completed == total_combinations:
                        print_info(f"Progreso bruteforce: {completed}/{total_combinations} combinaciones probadas")
                    future.result()

        # Combinar con credenciales previas (p. ej. encontradas por hydra antes del fallback)
        prev_creds = {(c["username"], c["password"]) for c in result_data.get("credentials", [])}
        all_creds = prev_creds | found_credentials
        if all_creds:
            print_good(f"Bruteforce completado. Credenciales únicas encontradas: {len(all_creds)}")
            rows = [
                [f"{Fore.MAGENTA}{u}{Style.RESET_ALL}", f"{Fore.MAGENTA}{p}{Style.RESET_ALL}"]
                for u, p in sorted(all_creds)
            ]
            print_table(
                headers=["USUARIO", "CONTRASEÑA"],
                rows=rows,
                title="Credenciales válidas:",
            )
            # Registrar también en FINDINGS
            for u, p in sorted(all_creds):
                FINDINGS.append(f"[CRED] {u}:{p}")
            result_data["credentials"] = [
                {"username": u, "password": p}
                for u, p in sorted(all_creds)
            ]
        else:
            print_info("Bruteforce completado. No se encontraron credenciales válidas.")
        return result_data
    except Exception as e:
        print_error(f"Error en bruteforce: {e}")
        return {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

# ========== WORDPRESS / WPSCAN ==========
def _append_finding_once(text):
    if text and text not in FINDINGS:
        FINDINGS.append(text)

def _format_external_command(cmd):
    masked_next = {"--api-token", "--cookie-string"}
    out = []
    hide = False
    for part in cmd:
        if hide:
            out.append("***")
            hide = False
            continue
        out.append(part)
        if part in masked_next:
            hide = True
    return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in out)

def _stream_process_output(process):
    output = []
    if not process or not process.stdout:
        return ""
    for raw_line in iter(process.stdout.readline, b""):
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace")
        output.append(line)
        print(line, end="")
    return "".join(output)

def _write_process_bytes(data):
    if not data:
        return
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Exception:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        sys.stdout.flush()

def _decode_process_output(chunks):
    if not chunks:
        return ""
    return b"".join(chunks).decode("utf-8", errors="replace")

def _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="proceso"):
    """Run a command while printing its raw output.

    On POSIX, a PTY is used when possible so CLI tools keep their native colour
    decisions. The pipe fallback still preserves any ANSI sequences emitted.
    """
    chunks = []
    process = None
    master_fd = None
    slave_fd = None

    if prefer_pty and os.name != "nt":
        try:
            import pty
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            slave_fd = None
            while True:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                if capture:
                    chunks.append(data)
                _write_process_bytes(data)
            process.wait()
            return process.returncode, _decode_process_output(chunks)
        except KeyboardInterrupt:
            print_warning(f"{interrupt_label} interrumpido; esperando a que finalice...")
            _wait_for_interrupted_child(process, interrupt_label)
            return process.returncode if process else None, _decode_process_output(chunks)
        except Exception as e:
            print_warning(f"No se pudo usar PTY para {interrupt_label} ({type(e).__name__}); usando pipe.")
        finally:
            for fd in (slave_fd, master_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while process.stdout:
            try:
                data = os.read(process.stdout.fileno(), 4096)
            except OSError:
                break
            if not data:
                break
            if capture:
                chunks.append(data)
            _write_process_bytes(data)
        process.wait()
        return process.returncode, _decode_process_output(chunks)
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrumpido; esperando a que finalice...")
        _wait_for_interrupted_child(process, interrupt_label)
        return process.returncode if process else None, _decode_process_output(chunks)

def _capture_command_output(cmd, interrupt_label="proceso"):
    process = None
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = process.communicate()
        return process.returncode, (stdout or b"").decode("utf-8", errors="replace")
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrumpido; esperando a que finalice...")
        _wait_for_interrupted_child(process, interrupt_label)
        return process.returncode if process else None, ""

def _load_json_file(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return {}
    with open(path, "rb") as f:
        content = f.read().decode("utf-8", errors="ignore").strip()
    if not content:
        return {}
    try:
        return json.loads(content)
    except Exception:
        pass
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except Exception:
            continue
    return {}

def _session_cookie_string(session):
    try:
        pairs = []
        for cookie in session.cookies:
            if cookie.name and cookie.value:
                pairs.append(f"{cookie.name}={cookie.value}")
        return "; ".join(pairs)
    except Exception:
        return ""

def _default_wordpress_password_wordlist():
    if os.path.isfile(ROCKYOU_WORDLIST):
        return ROCKYOU_WORDLIST
    if os.path.isfile(SECLISTS_PASSWORDS):
        return SECLISTS_PASSWORDS
    if os.path.isfile(ROCKYOU_WORDLIST_GZ):
        print_warning(f"rockyou existe comprimida en {ROCKYOU_WORDLIST_GZ}; descomprímela para usarla con WPScan.")
    return None

def _wpscan_component_version(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict):
        return str(version.get("number") or version.get("value") or version.get("version") or "")
    if version is None:
        return ""
    return str(version)

def _wpscan_component_confidence(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict) and version.get("confidence") is not None:
        return str(version.get("confidence"))
    if component.get("confidence") is not None:
        return str(component.get("confidence"))
    return ""

def _wpscan_reference_list(vuln):
    refs = []
    raw_refs = vuln.get("references") if isinstance(vuln, dict) else None
    if isinstance(raw_refs, dict):
        for key, value in raw_refs.items():
            values = value if isinstance(value, list) else [value]
            for item in values:
                if item:
                    refs.append(f"{key}:{item}")
    elif isinstance(raw_refs, list):
        refs.extend(str(r) for r in raw_refs if r)
    return refs

def _extract_wpscan_users(data):
    users = []
    raw = data.get("users") if isinstance(data, dict) else None

    def add_user(username, info=None):
        username = str(username or "").strip()
        if not username:
            return
        info = info if isinstance(info, dict) else {}
        users.append({
            "username": username,
            "id": info.get("id"),
            "name": info.get("name") or info.get("display_name") or info.get("display_name_public"),
            "found_by": info.get("found_by") or info.get("found_by_text") or "",
        })

    if isinstance(raw, dict):
        for key, item in raw.items():
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or key, item)
            else:
                add_user(key)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or item.get("name"), item)
            else:
                add_user(item)

    deduped = []
    seen = set()
    for user in users:
        key = user["username"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(user)
    return deduped

def _normalize_wpscan_components(raw_components):
    components = []
    if isinstance(raw_components, dict):
        iterable = raw_components.items()
    elif isinstance(raw_components, list):
        iterable = [(None, item) for item in raw_components]
    else:
        iterable = []
    for slug, item in iterable:
        if not isinstance(item, dict):
            continue
        name = item.get("slug") or item.get("name") or slug or ""
        components.append({
            "name": str(name),
            "location": item.get("location") or "",
            "version": _wpscan_component_version(item),
            "confidence": _wpscan_component_confidence(item),
            "found_by": item.get("found_by") or item.get("found_by_text") or "",
            "latest_version": item.get("latest_version") or "",
            "last_updated": item.get("last_updated") or "",
            "vulnerabilities_count": len(item.get("vulnerabilities") or []),
        })
    return components

def _extract_wpscan_vulnerabilities(data):
    vulnerabilities = []

    def add_vulns(component_type, component_name, raw_vulns):
        if not raw_vulns:
            return
        for vuln in raw_vulns:
            if isinstance(vuln, dict):
                title = vuln.get("title") or vuln.get("name") or vuln.get("id") or "Vulnerabilidad WPScan"
                fixed_in = vuln.get("fixed_in")
                if isinstance(fixed_in, list):
                    fixed_in = ", ".join(str(x) for x in fixed_in)
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(title),
                    "fixed_in": str(fixed_in or ""),
                    "references": _wpscan_reference_list(vuln),
                })
            else:
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(vuln),
                    "fixed_in": "",
                    "references": [],
                })

    version = data.get("version") if isinstance(data, dict) else {}
    if isinstance(version, dict):
        core_name = "WordPress"
        if version.get("number"):
            core_name = f"WordPress {version.get('number')}"
        add_vulns("core", core_name, version.get("vulnerabilities"))

    main_theme = data.get("main_theme") if isinstance(data, dict) else {}
    if isinstance(main_theme, dict):
        add_vulns("theme", main_theme.get("slug") or main_theme.get("name") or "main_theme", main_theme.get("vulnerabilities"))

    for collection_name, component_type in (("plugins", "plugin"), ("themes", "theme")):
        raw_components = data.get(collection_name) if isinstance(data, dict) else {}
        if isinstance(raw_components, dict):
            for slug, item in raw_components.items():
                if isinstance(item, dict):
                    add_vulns(component_type, item.get("slug") or item.get("name") or slug, item.get("vulnerabilities"))

    add_vulns("wordpress", "general", data.get("vulnerabilities") if isinstance(data, dict) else None)
    return vulnerabilities

def _normalize_wpscan_scan(data, target):
    if not isinstance(data, dict):
        data = {}
    version_raw = data.get("version") if isinstance(data.get("version"), dict) else {}
    plugins = _normalize_wpscan_components(data.get("plugins") or {})
    themes = _normalize_wpscan_components(data.get("themes") or {})
    main_theme_raw = data.get("main_theme") if isinstance(data.get("main_theme"), dict) else {}
    main_theme = {}
    if main_theme_raw:
        main_theme = {
            "name": main_theme_raw.get("slug") or main_theme_raw.get("name") or "",
            "location": main_theme_raw.get("location") or "",
            "version": _wpscan_component_version(main_theme_raw),
            "confidence": _wpscan_component_confidence(main_theme_raw),
            "found_by": main_theme_raw.get("found_by") or main_theme_raw.get("found_by_text") or "",
            "latest_version": main_theme_raw.get("latest_version") or "",
            "last_updated": main_theme_raw.get("last_updated") or "",
            "vulnerabilities_count": len(main_theme_raw.get("vulnerabilities") or []),
        }
    users = _extract_wpscan_users(data)
    vulnerabilities = _extract_wpscan_vulnerabilities(data)
    interesting = []
    for item in data.get("interesting_findings") or []:
        if isinstance(item, dict):
            interesting.append({
                "type": item.get("type") or "",
                "url": item.get("url") or "",
                "to_s": item.get("to_s") or item.get("interesting_entry") or item.get("type") or "",
                "confidence": item.get("confidence"),
            })
        else:
            interesting.append({"type": "", "url": "", "to_s": str(item), "confidence": None})

    detected = bool(version_raw or plugins or themes or main_theme or users or interesting)
    return {
        "target": target,
        "detected": detected,
        "version": {
            "number": version_raw.get("number") or "",
            "status": version_raw.get("status") or "",
            "found_by": version_raw.get("found_by") or "",
        },
        "main_theme": main_theme,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "interesting_findings": interesting,
        "vulnerabilities": vulnerabilities,
        "credentials": [],
        "bruteforce": {},
    }

def _extract_wpscan_credentials(data, stdout_text=""):
    credentials = set()
    stdout_text = _ANSI_RE.sub("", stdout_text or "")

    def add(user, pwd):
        user = str(user or "").strip()
        pwd = str(pwd or "").strip()
        if user and pwd and len(user) <= 128 and len(pwd) <= 256:
            credentials.add((user, pwd))

    for match in re.finditer(r"\[SUCCESS\]\s*-\s*([^\s/]+)\s*/\s*([^\r\n]+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))
    for match in re.finditer(r"Username:\s*([^,\s]+)\s*,\s*Password:\s*(\S+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))

    def walk(obj):
        if isinstance(obj, dict):
            user = obj.get("username") or obj.get("login") or obj.get("user")
            pwd = obj.get("password") or obj.get("pass")
            if user and pwd:
                add(user, pwd)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return [{"username": u, "password": p, "source": "wpscan"} for u, p in sorted(credentials)]

def _merge_credentials(global_key, credentials):
    current = SCAN_DATA.get(global_key) or []
    seen = set()
    merged = []
    for item in list(current) + list(credentials or []):
        if not isinstance(item, dict):
            continue
        key = (item.get("username"), item.get("password"))
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    SCAN_DATA[global_key] = merged
    return merged

def _append_wpscan_common_options(cmd, session, api_token=None):
    if api_token:
        cmd += ["--api-token", api_token]
    cookie_string = _session_cookie_string(session)
    if cookie_string:
        cmd += ["--cookie-string", cookie_string]
    if not VERIFY_TLS and "--disable-tls-checks" not in cmd:
        cmd += ["--disable-tls-checks"]
    return cmd

def _wpscan_retry_command(cmd, request_timeout=None):
    retry_cmd = list(cmd)
    for flag in ("--disable-tls-checks", "--random-user-agent", "--follow-redirection"):
        if flag not in retry_cmd:
            retry_cmd.append(flag)
    if request_timeout is not None:
        if "--request-timeout" in retry_cmd:
            idx = retry_cmd.index("--request-timeout")
            if idx + 1 < len(retry_cmd):
                retry_cmd[idx + 1] = str(max(30, int(request_timeout or 15)))
        else:
            retry_cmd += ["--request-timeout", str(max(30, int(request_timeout or 15)))]
    return retry_cmd

def _run_wpscan_visible(cmd, request_timeout=None, label="WPScan"):
    print_info(f"Ejecutando {label} con salida nativa: {_format_external_command(cmd)}")
    rc, stdout_text = _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan retorno codigo 4; reintentando con opciones mas tolerantes.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        print_info(f"Reintentando {label}: {_format_external_command(retry_cmd)}")
        rc2, out2 = _stream_command_output(retry_cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def _run_wpscan_json(cmd, request_timeout=None):
    print_info("Generando JSON de WPScan para construir el resumen final...")
    rc, stdout_text = _capture_command_output(cmd, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan retorno codigo 4 al generar JSON; reintentando con opciones mas tolerantes.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        rc2, out2 = _capture_command_output(retry_cmd, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def run_wpscan_enumeration(target, session, wpscan_path, api_token=None, threads=5, request_timeout=15):
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="wpscan_enum_")
    os.close(tmp_fd)
    # Usar enumerate explicito para evitar ambiguedades con versiones de WPScan
    enum_flags = "u,ap,at"
    base_cmd = [
        wpscan_path,
        "--url", target,
        "--enumerate", enum_flags,
        "--request-timeout", str(max(5, int(request_timeout or 15))),
        "-t", str(max(1, int(threads or 5))),
    ]

    visible_cmd = _append_wpscan_common_options(list(base_cmd) + ["--format", "cli"], session, api_token=api_token)
    json_cmd = _append_wpscan_common_options(
        list(base_cmd) + ["--format", "json", "--output", tmp_path, "--no-banner"],
        session,
        api_token=api_token,
    )

    display_rc, stdout_text = _run_wpscan_visible(
        visible_cmd,
        request_timeout=request_timeout,
        label="WPScan enumeracion",
    )

    json_rc = None
    json_stdout = ""
    if display_rc is not None:
        json_rc, json_stdout = _run_wpscan_json(json_cmd, request_timeout=request_timeout)

    data = _load_json_file(tmp_path)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    scan = _normalize_wpscan_scan(data, target)
    scan["command"] = _format_external_command(visible_cmd)
    scan["json_command"] = _format_external_command(json_cmd)
    scan["return_code"] = json_rc if json_rc is not None else display_rc
    scan["display_return_code"] = display_rc
    scan["json_return_code"] = json_rc
    scan["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    scan["json_stdout_tail"] = json_stdout[-4000:] if json_stdout else ""
    if scan["return_code"] not in (0, None):
        print_warning(f"WPScan termino con codigo {scan['return_code']}. Se guardara lo que haya podido parsearse.")
    return scan

def run_wpscan_bruteforce(target, session, wpscan_path, users, passlist, api_token=None,
                          threads=20, attack_mode="xmlrpc"):
    result = {
        "attack_mode": attack_mode,
        "users": list(users or []),
        "password_wordlist": passlist,
        "credentials": [],
        "return_code": None,
    }
    if not users or not passlist or not os.path.isfile(passlist):
        print_warning("No hay usuarios o wordlist válida para bruteforce WordPress.")
        return result

    user_fd, user_path = tempfile.mkstemp(suffix=".txt", prefix="wpscan_users_")
    os.close(user_fd)
    with open(user_path, "w", encoding="utf-8") as f:
        for user in users:
            f.write(str(user).strip() + "\n")

    cmd = [
        wpscan_path,
        "--url", target,
        "--password-attack", attack_mode,
        "-t", str(max(1, int(threads or 20))),
        "-U", user_path,
        "-P", passlist,
        "--format", "cli",
    ]
    cmd = _append_wpscan_common_options(cmd, session, api_token=api_token)

    stdout_text = ""
    try:
        rc, stdout_text = _run_wpscan_visible(cmd, label="WPScan bruteforce")
        result["return_code"] = rc
        result["credentials"] = _extract_wpscan_credentials({}, stdout_text)
        result["command"] = _format_external_command(cmd)
        result["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    finally:
        try:
            os.unlink(user_path)
        except Exception:
            pass

    if result["return_code"] not in (0, None):
        print_warning(f"WPScan bruteforce terminó con código {result['return_code']}.")
    if result["credentials"]:
        rows = [[f"{Fore.MAGENTA}{c['username']}{Style.RESET_ALL}",
                 f"{Fore.MAGENTA}{c['password']}{Style.RESET_ALL}"]
                for c in result["credentials"]]
        print_table(headers=["USUARIO", "CONTRASEÑA"], rows=rows, title="Credenciales WordPress válidas:")
    else:
        print_info("WPScan no reportó credenciales válidas.")
    return result

def _wp_summary_value(value, width=90):
    if value is None or value == "":
        return "-"
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."

def _wp_component_rows(components):
    rows = []
    for item in components or []:
        if not isinstance(item, dict):
            continue
        try:
            vuln_count = int(item.get("vulnerabilities_count") or 0)
        except Exception:
            vuln_count = 0
        vuln_text = f"{Fore.RED}{vuln_count}{Style.RESET_ALL}" if vuln_count else "0"
        rows.append([
            _wp_summary_value(item.get("name"), 34),
            _wp_summary_value(item.get("version"), 18),
            _wp_summary_value(item.get("latest_version"), 18),
            _wp_summary_value(item.get("confidence"), 8),
            vuln_text,
            _wp_summary_value(item.get("location"), 72),
        ])
    return rows

def print_wpscan_detailed_summary(scan):
    scan = scan or {}
    version = scan.get("version") or {}
    main_theme = scan.get("main_theme") or {}
    plugins = scan.get("plugins") or []
    themes = list(scan.get("themes") or [])
    users = scan.get("users") or []
    vulnerabilities = scan.get("vulnerabilities") or []
    credentials = scan.get("credentials") or []
    interesting = scan.get("interesting_findings") or []

    print_phase("RESUMEN WORDPRESS / WPSCAN")
    core_rows = [
        ["Target", _wp_summary_value(scan.get("target"), 90)],
        ["Detectado", "Si" if scan.get("detected") else "No confirmado"],
        ["Version WordPress", _wp_summary_value(version.get("number"))],
        ["Estado version", _wp_summary_value(version.get("status"))],
        ["Version encontrada por", _wp_summary_value(version.get("found_by"), 90)],
        ["Tema principal", _wp_summary_value(main_theme.get("name"))],
        ["Plugins encontrados", str(len(plugins))],
        ["Temas encontrados", str(len(themes) + (1 if main_theme else 0))],
        ["Usuarios encontrados", str(len(users))],
        ["Vulnerabilidades", str(len(vulnerabilities))],
        ["Credenciales validas", str(len(credentials))],
    ]
    print_table(headers=["Campo", "Valor"], rows=core_rows, title="Resumen general WordPress:")

    if plugins:
        print_table(
            headers=["Plugin", "Version", "Ultima", "Conf.", "Vulns", "Ubicacion"],
            rows=_wp_component_rows(plugins),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"Plugins WordPress encontrados ({len(plugins)}):",
        )
    else:
        print_info("WPScan no reporto plugins.")

    theme_items = []
    seen_themes = set()
    if main_theme:
        item = dict(main_theme)
        item["name"] = f"{item.get('name') or '-'} (principal)"
        theme_items.append(item)
        seen_themes.add((str(main_theme.get("name") or "").lower(), str(main_theme.get("location") or "").lower()))
    for theme in themes:
        if not isinstance(theme, dict):
            continue
        key = (str(theme.get("name") or "").lower(), str(theme.get("location") or "").lower())
        if key in seen_themes:
            continue
        seen_themes.add(key)
        theme_items.append(theme)
    if theme_items:
        print_table(
            headers=["Tema", "Version", "Ultima", "Conf.", "Vulns", "Ubicacion"],
            rows=_wp_component_rows(theme_items),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"Temas WordPress encontrados ({len(theme_items)}):",
        )
    else:
        print_info("WPScan no reporto temas.")

    if users:
        user_rows = [
            [
                _wp_summary_value(u.get("username"), 32),
                _wp_summary_value(u.get("id"), 8),
                _wp_summary_value(u.get("name"), 34),
                _wp_summary_value(u.get("found_by"), 72),
            ]
            for u in users if isinstance(u, dict)
        ]
        print_table(
            headers=["Usuario", "ID", "Nombre", "Encontrado por"],
            rows=user_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Usuarios WordPress encontrados ({len(user_rows)}):",
        )
    else:
        print_info("WPScan no reporto usuarios.")

    if interesting:
        interesting_rows = [
            [
                _wp_summary_value(i.get("type"), 24),
                _wp_summary_value(i.get("to_s"), 84),
                _wp_summary_value(i.get("url"), 84),
                _wp_summary_value(i.get("confidence"), 8),
            ]
            for i in interesting if isinstance(i, dict)
        ]
        print_table(
            headers=["Tipo", "Detalle", "URL", "Conf."],
            rows=interesting_rows,
            alignments=['<', '<', '<', '>'],
            title=f"Hallazgos interesantes WordPress ({len(interesting_rows)}):",
        )

    if vulnerabilities:
        vuln_rows = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            refs = ", ".join(vuln.get("references") or [])
            vuln_rows.append([
                _wp_summary_value(vuln.get("component_type"), 14),
                _wp_summary_value(vuln.get("component"), 30),
                _wp_summary_value(vuln.get("title"), 80),
                _wp_summary_value(vuln.get("fixed_in"), 18),
                _wp_summary_value(refs, 70),
            ])
        print_table(
            headers=["Tipo", "Componente", "Titulo", "Fixed in", "Referencias"],
            rows=vuln_rows,
            alignments=['<', '<', '<', '<', '<'],
            title=f"Vulnerabilidades WordPress ({len(vuln_rows)}):",
        )
    else:
        print_info("WPScan no reporto vulnerabilidades.")

    if credentials:
        cred_rows = [
            [
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('username'), 32)}{Style.RESET_ALL}",
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('password'), 40)}{Style.RESET_ALL}",
                _wp_summary_value(c.get("source") or "wpscan", 16),
            ]
            for c in credentials if isinstance(c, dict)
        ]
        print_table(
            headers=["Usuario", "Password", "Fuente"],
            rows=cred_rows,
            alignments=['<', '<', '<'],
            title=f"Credenciales WordPress validas ({len(cred_rows)}):",
            border_color=Fore.GREEN,
        )

def _technology_to_text(item):
    if isinstance(item, dict):
        return " ".join(str(item.get(k) or "") for k in ("name", "detail", "version", "value"))
    return str(item or "")

def _whatweb_detects_wordpress(technologies):
    matches = []
    for item in technologies or []:
        text = _technology_to_text(item).strip()
        if not text:
            continue
        if re.search(r"\bwordpress\b", text, re.I):
            matches.append(text)
    return bool(matches), matches

def _manual_wordpress_signal(signals, name, evidence, source):
    evidence = str(evidence or "").strip()
    key = (name, evidence[:160], source)
    for item in signals:
        if item.get("key") == key:
            return
    signals.append({
        "key": key,
        "name": name,
        "evidence": evidence[:240],
        "source": source,
    })

def _scan_text_for_wordpress_patterns(text, source, signals):
    if not text:
        return
    patterns = [
        ("meta generator", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress[^"\']*["\']'),
        ("wp-content", r'/(?:wp-content)/(?:plugins|themes|uploads)/[^"\'<>\s]+'),
        ("wp-includes", r'/(?:wp-includes)/[^"\'<>\s]+'),
        ("wp-json", r'(?:/wp-json/|rest_route=/?wp/|wp/v2)'),
        ("wp assets", r'(?:wp-emoji-release|wp-block-library|wp-polyfill|wp-embed|wpApiSettings)'),
        ("wordpress text", r'\bWordPress\b'),
    ]
    for name, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            _manual_wordpress_signal(signals, name, match.group(0), source)

def _manual_wordpress_detection(target, session):
    signals = []
    checked_urls = []

    def fetch(url, method="GET"):
        checked_urls.append(url)
        try:
            if method == "HEAD":
                return session.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            return session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception:
            return None

    resp = fetch(target)
    if resp is not None:
        _scan_text_for_wordpress_patterns(resp.text or "", "html", signals)
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        _scan_text_for_wordpress_patterns(header_text, "headers", signals)
        if "xmlrpc.php" in str(resp.headers.get("X-Pingback", "")).lower():
            _manual_wordpress_signal(signals, "x-pingback", resp.headers.get("X-Pingback"), "headers")

    relative_base = target if str(target).endswith("/") else f"{target}/"
    raw_probes = [
        (urljoin(relative_base, "wp-login.php"), "login"),
        (urljoin(target, "/wp-login.php"), "login"),
        (urljoin(relative_base, "wp-json/"), "rest api"),
        (urljoin(target, "/wp-json/"), "rest api"),
        (urljoin(relative_base, "xmlrpc.php"), "xmlrpc"),
        (urljoin(target, "/xmlrpc.php"), "xmlrpc"),
    ]
    probes = []
    seen_probe_urls = set()
    for url, probe_type in raw_probes:
        if url in seen_probe_urls:
            continue
        seen_probe_urls.add(url)
        probes.append((url, probe_type))
    for url, probe_type in probes:
        probe_resp = fetch(url)
        if probe_resp is None:
            continue
        body = probe_resp.text or ""
        body_low = body.lower()
        if probe_type == "login" and probe_resp.status_code < 500:
            if "wp-submit" in body_low or "wordpress" in body_low or "wp-login.php" in body_low:
                _manual_wordpress_signal(signals, "wp-login.php", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "rest api" and probe_resp.status_code < 500:
            if "wp/v2" in body_low or '"namespaces"' in body_low or '"routes"' in body_low:
                _manual_wordpress_signal(signals, "wp-json api", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "xmlrpc" and probe_resp.status_code in (200, 405):
            if "xml-rpc server accepts post requests only" in body_low or "xmlrpc" in body_low:
                _manual_wordpress_signal(signals, "xmlrpc.php", f"HTTP {probe_resp.status_code}", url)

    for item in signals:
        item.pop("key", None)
    strong_signals = [s for s in signals if s.get("name") != "wordpress text"]
    return {
        "detected": bool(strong_signals) or len(signals) >= 2,
        "source": "manual",
        "signals": signals,
        "checked_urls": checked_urls,
    }

def detect_wordpress_for_full_pentest(target, session):
    general = SCAN_DATA.get("general") or {}
    technologies = general.get("technologies") or []
    tech_source = general.get("technologies_source") or "unknown"

    if tech_source == "whatweb":
        detected, matches = _whatweb_detects_wordpress(technologies)
        if detected:
            detection = {
                "detected": True,
                "source": "whatweb",
                "matches": matches,
            }
            SCAN_DATA["wordpress_detection"] = detection
            print_good(f"WhatWeb detecto WordPress: {', '.join(matches[:3])}")
            return detection
        print_info("WhatWeb no detecto WordPress. Ejecutando deteccion manual por patrones.")
    else:
        print_info("No hay deteccion WhatWeb util para WordPress. Ejecutando deteccion manual por patrones.")

    detection = _manual_wordpress_detection(target, session)
    SCAN_DATA["wordpress_detection"] = detection
    if detection.get("detected"):
        signal_names = sorted({s.get("name", "") for s in detection.get("signals", []) if s.get("name")})
        print_good(f"Deteccion manual compatible con WordPress: {', '.join(signal_names[:5])}")
    else:
        print_info("No se encontraron patrones manuales suficientes de WordPress.")
    return detection

def run_wordpress_attacks_if_detected(target, session):
    detection = detect_wordpress_for_full_pentest(target, session)
    if not detection.get("detected"):
        print_info("Objetivo no identificado como WordPress. Saltando WPScan en pentesting completo.")
        return None
    return run_wordpress_attacks(target, session)

def run_wordpress_attacks(target, session):
    print_phase("ENUMERACIÓN Y ATAQUES WORDPRESS")
    wpscan_path = check_wpscan()
    if not wpscan_path:
        if not install_wpscan():
            print_warning("Saltando WordPress/WPScan.")
            return None
        wpscan_path = check_wpscan()
        if not wpscan_path:
            print_warning("WPScan sigue sin estar disponible.")
            return None

    api_token = os.environ.get("WPSCAN_API_TOKEN") or os.environ.get("WPVULNDB_API_TOKEN") or ""
    if api_token:
        print_info("Usando token API de WPScan/WPVulnDB desde variable de entorno.")
    else:
        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Token API WPVulnDB/WPScan (opcional, Enter para omitir):")
            api_token = getpass.getpass("> ").strip()
        except (KeyboardInterrupt, EOFError):
            api_token = ""

    enum_threads = max(5, THREADS)
    scan = run_wpscan_enumeration(target, session, wpscan_path, api_token=api_token, threads=enum_threads, request_timeout=max(15, DEFAULT_TIMEOUT))
    SCAN_DATA["wordpress"] = scan

    version = scan.get("version") or {}
    users = [u.get("username") for u in scan.get("users") or [] if u.get("username")]
    vulnerabilities = scan.get("vulnerabilities") or []
    plugins = scan.get("plugins") or []
    main_theme = scan.get("main_theme") or {}

    if not scan.get("detected"):
        print_warning("WPScan no confirmó que el objetivo sea WordPress.")
    else:
        summary_rows = [
            ["WordPress", version.get("number") or "detectado"],
            ["Estado version", version.get("status") or "-"],
            ["Tema principal", main_theme.get("name") or "-"],
            ["Plugins detectados", str(len(plugins))],
            ["Usuarios", str(len(users))],
            ["Vulnerabilidades", str(len(vulnerabilities))],
        ]
        print_table(headers=["Campo", "Valor"], rows=summary_rows, title="Resumen WordPress:")

    if version.get("number"):
        _append_finding_once(f"[WP] WordPress {version.get('number')} ({version.get('status') or 'estado desconocido'})")
    for plugin in plugins:
        if isinstance(plugin, dict) and plugin.get("name"):
            _append_finding_once(f"[WP:PLUGIN] {plugin.get('name')} {plugin.get('version') or 'version desconocida'}")
    if main_theme.get("name"):
        _append_finding_once(f"[WP:THEME] {main_theme.get('name')} {main_theme.get('version') or 'version desconocida'}")
    for theme in scan.get("themes") or []:
        if isinstance(theme, dict) and theme.get("name"):
            _append_finding_once(f"[WP:THEME] {theme.get('name')} {theme.get('version') or 'version desconocida'}")
    for user in users:
        _append_finding_once(f"[WP:USER] {user}")
    for vuln in vulnerabilities:
        _append_finding_once(
            f"[WP:VULN] {vuln.get('component_type')}:{vuln.get('component')} - {vuln.get('title')}"
        )

    if users:
        SCAN_DATA["users"] = sorted(set((SCAN_DATA.get("users") or []) + users))
        user_rows = [[u] for u in users]
        print_table(headers=["Usuario"], rows=user_rows, title="Usuarios WordPress identificados:")

        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Lanzar fuerza bruta con WPScan sobre estos usuarios? [S/n]:")
            do_brute = input("> ").strip().lower() != 'n'
        except (KeyboardInterrupt, EOFError):
            do_brute = False
        if do_brute:
            passlist = input_path(
                "Ruta a wordlist de contraseñas (Enter = rockyou/SecLists si existe): "
            ).strip()
            if not passlist:
                passlist = _default_wordpress_password_wordlist()
                if passlist:
                    print_info(f"Usando wordlist por defecto: {passlist}")
            if not passlist or not os.path.isfile(passlist):
                print_warning("No hay wordlist de contraseñas válida. Saltando bruteforce WordPress.")
            else:
                try:
                    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Método de ataque [xmlrpc/wp-login] (default xmlrpc):")
                    mode_in = input("> ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    mode_in = ""
                attack_mode = mode_in if mode_in in ("xmlrpc", "wp-login") else "xmlrpc"
                brute = run_wpscan_bruteforce(
                    target, session, wpscan_path, users, passlist,
                    api_token=api_token, threads=max(20, THREADS),
                    attack_mode=attack_mode,
                )
                scan["bruteforce"] = brute
                scan["credentials"] = brute.get("credentials", [])
                if brute.get("credentials"):
                    _merge_credentials("bruteforce_credentials", brute["credentials"])
                    for cred in brute["credentials"]:
                        _append_finding_once(f"[CRED:WP] {cred.get('username')}:{cred.get('password')}")
    else:
        print_info("WPScan no identificó usuarios; se omite la fuerza bruta automática.")

    SCAN_DATA["wordpress"] = scan
    print_wpscan_detailed_summary(scan)
    return scan

def spider_website(target, session, max_pages=500, max_depth=3, use_robots=True):
    print_info(f"Iniciando spidering en {target} (máx páginas: {max_pages}, profundidad: {max_depth})")
    base_parsed = urlparse(target)
    base_domain = base_parsed.netloc

    robots_parser = None
    if use_robots:
        robots_url = urljoin(target, "/robots.txt")
        try:
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            robots_parser = rp
            print_info("robots.txt cargado correctamente.")
        except (OSError, ValueError) as e:
            print_warning(f"No se pudo cargar robots.txt ({type(e).__name__}: {e}). Continuando sin restricciones.")

    visited = set()
    urls_queue = deque()
    urls_queue.append((target, 0))
    discovered_urls = set()
    all_params = set()
    forms_found = []
    form_keys_seen = set()
    discovered_urls.add(target)
    
    with tqdm(total=max_pages, desc="Spidering", unit="pág", ncols=80, disable=not HAS_TQDM) as pbar:
        while urls_queue and len(visited) < max_pages:
            current_url, depth = urls_queue.popleft()
            if current_url in visited:
                continue
            if depth > max_depth:
                continue
            visited.add(current_url)
            if HAS_TQDM:
                pbar.update(1)
                pbar.set_postfix({"Actual": os.path.basename(current_url)[:30], "Desc": len(discovered_urls)})
            else:
                if len(visited) % 20 == 0:
                    print_info(f"Spidering progreso: {len(visited)} páginas visitadas, {len(discovered_urls)} URLs descubiertas")
            
            try:
                try:
                    resp = session.get(current_url, timeout=DEFAULT_TIMEOUT)
                except requests.exceptions.TooManyRedirects:
                    # Reintentar sin seguir redirecciones para capturar el destino
                    try:
                        resp = session.get(current_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    except Exception:
                        continue
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href'].strip()
                        if not href or href.startswith('#') or href.startswith('javascript:'):
                            continue
                        absolute = urljoin(current_url, href)
                        parsed_abs = urlparse(absolute)
                        if parsed_abs.netloc != base_domain:
                            continue
                        clean_abs = parsed_abs._replace(fragment='')
                        abs_url = urlunparse(clean_abs)
                        if use_robots and robots_parser and not robots_parser.can_fetch("*", abs_url):
                            continue
                        if abs_url not in discovered_urls:
                            discovered_urls.add(abs_url)
                            urls_queue.append((abs_url, depth+1))
                    
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'get').upper()
                        form_action_url = urljoin(current_url, action) if action else current_url
                        if action:
                            parsed_f = urlparse(form_action_url)
                            if parsed_f.netloc == base_domain:
                                clean_f = parsed_f._replace(fragment='')
                                f_url = urlunparse(clean_f)
                                if f_url not in discovered_urls:
                                    discovered_urls.add(f_url)
                                    urls_queue.append((f_url, depth+1))
                        # Extraer inputs útiles (excluyendo submit/button/etc.)
                        form_inputs = []
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            name = inp.get('name')
                            if not name:
                                continue
                            itype = (inp.get('type') or '').lower()
                            if itype in ('submit', 'button', 'image', 'reset', 'file'):
                                continue
                            form_inputs.append(name)
                            all_params.add(name)
                        if not form_inputs:
                            continue
                        # Deduplicar por (action_url, method, tupla de inputs ordenados)
                        form_key = (
                            form_action_url,
                            method,
                            tuple(sorted(set(form_inputs)))
                        )
                        if form_key in form_keys_seen:
                            continue
                        form_keys_seen.add(form_key)
                        forms_found.append({
                            'page_url': current_url,
                            'url': form_action_url,
                            'action': form_action_url,
                            'method': method,
                            'inputs': sorted(set(form_inputs)),
                        })
                    
                    for u in list(discovered_urls):
                        parsed_u = urlparse(u)
                        if parsed_u.query:
                            for key in parse_qs(parsed_u.query).keys():
                                all_params.add(key)
                else:
                    hrefs = re.findall(r'href=["\'](.*?)["\']', resp.text)
                    for href in hrefs:
                        if href and not href.startswith('#') and not href.startswith('javascript:'):
                            absolute = urljoin(current_url, href)
                            parsed_abs = urlparse(absolute)
                            if parsed_abs.netloc != base_domain:
                                continue
                            if absolute not in discovered_urls:
                                discovered_urls.add(absolute)
                                urls_queue.append((absolute, depth+1))
            except Exception as e:
                print_error(f"Error spidering {current_url}: {e}")
                continue
    
    print_good(f"Spidering completado. Páginas visitadas: {len(visited)}, URLs únicas descubiertas: {len(discovered_urls)}")
    if all_params:
        print_info(f"Parámetros únicos encontrados: {len(all_params)} -> {', '.join(list(all_params)[:20])}")
    if forms_found:
        print_info(f"Formularios detectados durante el spidering: {len(forms_found)}")
    return discovered_urls, all_params, forms_found

# ========== ANÁLISIS DE CÓDIGO FUENTE ==========
# Patrones de búsqueda en el código fuente (HTML, JS, JSON, mapas, CSS).
# Cada entrada: (severidad, etiqueta, regex compilada, requiere_value_group).
_SRC_MAX_BYTES = 2 * 1024 * 1024   # cap por archivo (2 MB)
_SRC_SNIPPET_CHARS = 140
_SRC_MAX_FINDINGS_PER_FILE = 30

_SOURCE_PATTERNS = [
    ("critical", "Clave privada PEM",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("critical", "Cadena de conexión BD con credenciales",
     re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqps?|mssql|jdbc:[a-z]+)://[^\s\"'<>]*:[^\s\"'<>@]+@[^\s\"'<>]+", re.IGNORECASE), False),
    ("high", "AWS Access Key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    ("high", "AWS Secret Access Key",
     re.compile(r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,8}[\"']?([A-Za-z0-9/+=]{40})"), True),
    ("high", "Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), False),
    ("high", "GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), False),
    ("high", "Slack token",
     re.compile(r"\bxox[abpros]-[A-Za-z0-9\-]{10,}\b"), False),
    ("high", "Stripe live secret key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), False),
    ("high", "JWT token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"), False),
    ("high", "Credencial hardcoded",
     re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer)[\"'\s:=]{1,8}[\"']([^\"'\s]{4,80})[\"']"), True),
    ("medium", "Basic Auth en URL",
     re.compile(r"\bhttps?://[A-Za-z0-9._\-]+:[^\s\"'<>@/]+@[A-Za-z0-9._\-]+"), False),
    ("medium", "Comentario HTML sensible",
     re.compile(
         r"<!--\s*("
         # Contenido del comentario que NO atraviesa '-->'
         r"(?:(?!-->)[\s\S]){0,400}"
         # Palabra clave realmente sensible
         r"(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|"
         r"private[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer|"
         r"credentials|hardcoded|backdoor|deprecated|do not commit|"
         r"todo[: ]|fixme[: ]|xxx[: ]|hack[: ]|"
         r"backup\s+(?:file|path|server|db)|"
         r"internal\s+(?:use|api|server|tool)|"
         r"debug\s+(?:enabled|mode|key|token))"
         r"(?:(?!-->)[\s\S]){0,400}"
         r")\s*-->",
         re.IGNORECASE), True),
    ("medium", "Source map expuesto",
     re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"']+)"), True),
    ("medium", "IP privada hardcoded",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), False),
    ("low", "Ruta sensible referenciada",
     re.compile(r"[\"'](/(?:admin|adminer|debug|console|h2-console|phpmyadmin|backup|backups|dump|wp-admin|actuator|internal|staging|.git|.env)[A-Za-z0-9_\-/.]*)[\"']"), True),
    ("low", "Email expuesto",
     re.compile(r"\b[A-Za-z0-9_.+\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+\b"), False),
]

_SOURCE_ASSET_EXT = ('.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.map', '.css', '.txt', '.xml', '.yml', '.yaml', '.env')
_SOURCE_TEXT_CT = ('text/', 'application/javascript', 'application/json', 'application/xml',
                   'application/x-yaml', 'application/yaml', 'application/octet-stream')


def _is_source_text_response(content_type, url):
    ct = (content_type or '').lower()
    if any(t in ct for t in _SOURCE_TEXT_CT):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(_SOURCE_ASSET_EXT)


def _download_text_capped(session, url, max_bytes=_SRC_MAX_BYTES):
    """Descarga el cuerpo como texto con un cap de bytes (evita descargas enormes)."""
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, stream=True, allow_redirects=True)
    except requests.RequestException as e:
        return None, None, str(e)
    try:
        if resp.status_code != 200:
            return None, resp.headers.get('Content-Type', ''), f"status {resp.status_code}"
        clen = resp.headers.get('Content-Length')
        if clen and clen.isdigit() and int(clen) > max_bytes:
            return None, resp.headers.get('Content-Type', ''), f"too large ({clen} bytes)"
        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) >= max_bytes:
                break
        encoding = resp.encoding or 'utf-8'
        try:
            text = buf.decode(encoding, errors='replace')
        except (LookupError, TypeError):
            text = buf.decode('utf-8', errors='replace')
        return text, resp.headers.get('Content-Type', ''), None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _extract_linked_assets(html_text, base_url, base_netloc):
    """Devuelve URLs de scripts/links/sources/.map del mismo dominio referenciados en el HTML."""
    assets = set()
    if not html_text:
        return assets
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            for tag in soup.find_all(['script', 'link', 'iframe', 'source', 'img', 'a']):
                src = tag.get('src') or tag.get('href')
                if not src:
                    continue
                absu = urljoin(base_url, src.strip())
                parsed = urlparse(absu)
                if parsed.scheme not in ('http', 'https'):
                    continue
                if parsed.netloc != base_netloc:
                    continue
                path = parsed.path.lower()
                if path.endswith(_SOURCE_ASSET_EXT):
                    assets.add(urlunparse(parsed._replace(fragment='')))
        except Exception:
            pass
    else:
        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            absu = urljoin(base_url, m.group(1).strip())
            parsed = urlparse(absu)
            if parsed.netloc == base_netloc and parsed.path.lower().endswith(_SOURCE_ASSET_EXT):
                assets.add(urlunparse(parsed._replace(fragment='')))
    return assets


def _scan_text_for_secrets(text, source_url):
    """Aplica los patrones del catálogo al texto y devuelve lista de hallazgos."""
    findings = []
    seen = set()
    if not text:
        return findings
    for severity, label, regex, has_group in _SOURCE_PATTERNS:
        try:
            matches = list(regex.finditer(text))
        except re.error:
            continue
        for m in matches:
            value = m.group(1) if (has_group and m.lastindex) else m.group(0)
            value = (value or "").strip()
            if not value:
                continue
            if label == "Email expuesto" and value.lower().endswith(('.png', '.jpg', '.svg', '.gif', '.webp')):
                continue
            # Filtro de boilerplate UI para comentarios HTML: si el comentario
            # es claramente decorativo (footer/header/logo/...) sin contenido
            # realmente sensible alrededor, descartarlo.
            if label == "Comentario HTML sensible":
                low = value.lower()
                ui_only = ("footer", "header", "navbar", "nav bar", "sidebar",
                           "logo", "icon", "button", "banner", "carousel",
                           "modal", "tooltip", "dropdown", "breadcrumb",
                           "container", "wrapper", "section start", "section end",
                           "begin block", "end block", "content start", "content end")
                # Si el comentario contiene alguna keyword UI y NO contiene
                # ninguna palabra realmente sensible (password/secret/token/...),
                # ignorarlo.
                strong = ("password", "passwd", "secret", "api_key", "api-key",
                          "apikey", "private_key", "private-key", "access_key",
                          "access-key", "auth_token", "auth-token", "bearer ",
                          "credentials", "hardcoded", "backdoor", "do not commit")
                if any(u in low for u in ui_only) and not any(s in low for s in strong):
                    continue
            key = (label, value[:80].lower())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].replace('\n', ' ').replace('\r', ' ')
            if len(snippet) > _SRC_SNIPPET_CHARS:
                snippet = snippet[:_SRC_SNIPPET_CHARS - 3] + '...'
            findings.append({
                "severity": severity,
                "type": label,
                "url": source_url,
                "value": value[:160],
                "snippet": snippet,
            })
            if len(findings) >= _SRC_MAX_FINDINGS_PER_FILE:
                return findings
    return findings


def analyze_source_code(target, session, urls=None, max_urls=120, max_assets=200):
    """Analiza el código fuente de las URLs descubiertas en busca de credenciales y datos expuestos.

    Args:
        target: URL base (usada para deducir el dominio).
        session: requests.Session activa (autenticada si procede).
        urls: iterable de URLs (sample del spider). Si None, se usa solo target.
        max_urls: máximo de páginas HTML a descargar.
        max_assets: máximo de recursos JS/JSON/MAP a descargar.

    Devuelve dict con estadísticas y lista de hallazgos.
    """
    base_netloc = urlparse(target).netloc
    seed_urls = list(urls) if urls else [target]
    if target not in seed_urls:
        seed_urls.insert(0, target)
    # Limitar páginas: priorizar URLs HTML
    seed_urls = [u for u in seed_urls if urlparse(u).netloc == base_netloc][:max_urls]

    print_info(f"Analizando código fuente de {len(seed_urls)} páginas (max {max_urls})...")

    findings = []
    pages_analyzed = 0
    assets_to_scan = set()
    pages_iter = tqdm(seed_urls, desc="Páginas", unit="pág", ncols=80,
                      disable=not HAS_TQDM) if HAS_TQDM else seed_urls

    for url in pages_iter:
        text, content_type, err = _download_text_capped(session, url)
        if text is None:
            continue
        pages_analyzed += 1
        if 'html' in (content_type or '').lower() or '<html' in text[:2000].lower():
            assets_to_scan.update(_extract_linked_assets(text, url, base_netloc))
        findings.extend(_scan_text_for_secrets(text, url))

    # Limitar recursos analizados
    assets_list = list(assets_to_scan)[:max_assets]
    if assets_list:
        print_info(f"Analizando {len(assets_list)} recursos JS/JSON/MAP enlazados...")
    assets_iter = tqdm(assets_list, desc="Recursos", unit="archivo", ncols=80,
                       disable=not HAS_TQDM) if HAS_TQDM else assets_list
    assets_analyzed = 0
    for asset_url in assets_iter:
        text, content_type, err = _download_text_capped(session, asset_url)
        if text is None:
            continue
        if not _is_source_text_response(content_type, asset_url):
            continue
        assets_analyzed += 1
        findings.extend(_scan_text_for_secrets(text, asset_url))

    # Deduplicar globalmente
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["type"], (f.get("value") or "")[:80].lower(), f.get("url"))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(f)

    # Resumen por severidad
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in unique_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    # Volcar hallazgos críticos/altos a FINDINGS globales
    for f in unique_findings:
        if f["severity"] in ("critical", "high"):
            FINDINGS.append(
                f"[CODE:{f['severity'].upper()}] {f['type']} en {f['url']} "
                f"— valor: {f['value']}"
            )

    if unique_findings:
        print_good(
            f"Análisis de código fuente completado: {len(unique_findings)} hallazgos "
            f"(C:{sev_count.get('critical',0)} H:{sev_count.get('high',0)} "
            f"M:{sev_count.get('medium',0)} L:{sev_count.get('low',0)}) "
            f"sobre {pages_analyzed} páginas + {assets_analyzed} recursos."
        )
        # Tabla visual con los primeros 50 hallazgos ordenados por severidad
        SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        SEV_COLOR = {
            'critical': Fore.MAGENTA, 'high': Fore.RED,
            'medium': Fore.YELLOW,   'low': Fore.CYAN,
        }
        sorted_findings = sorted(
            unique_findings,
            key=lambda x: (SEV_ORDER.get(x.get('severity', 'low'), 99),
                           x.get('type', ''), x.get('url', ''))
        )
        shown = sorted_findings[:50]
        rows = []
        for f in shown:
            sev = f.get('severity', 'low')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            tipo = (f.get('type') or '-')[:30]
            url = f.get('url') or '-'
            if len(url) > 60:
                url = url[:57] + '...'
            value = (f.get('value') or '-').replace('\n', ' ').replace('\r', ' ')
            if len(value) > 50:
                value = value[:47] + '...'
            rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                tipo, url, value,
            ])
        if len(unique_findings) <= 50:
            title = f"Hallazgos del análisis de código ({len(unique_findings)}):"
        else:
            title = f"Hallazgos del análisis de código (top 50 de {len(unique_findings)}):"
        print_table(
            headers=["SEVERIDAD", "TIPO", "URL", "VALOR"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=title,
        )
    else:
        print_info(
            f"Análisis de código fuente completado sin hallazgos "
            f"({pages_analyzed} páginas, {assets_analyzed} recursos)."
        )

    return {
        "pages_analyzed": pages_analyzed,
        "assets_analyzed": assets_analyzed,
        "total_findings": len(unique_findings),
        "summary": sev_count,
        "findings": unique_findings,
    }

# ========== MENÚ PRINCIPAL ==========
def _has_scan_data():
    """True si se ha ejecutado al menos un módulo y hay datos para reportar."""
    return any([
        bool(FINDINGS),
        bool(SCAN_DATA.get("general")),
        bool(SCAN_DATA.get("injection")),
        bool(SCAN_DATA.get("api_endpoints")),
        bool(SCAN_DATA.get("vhosts")),
        bool(SCAN_DATA.get("directory_hits")),
        bool(SCAN_DATA.get("users")),
        bool(SCAN_DATA.get("emails")),
        bool(SCAN_DATA.get("bruteforce_credentials")),
        bool(SCAN_DATA.get("wordpress")),
        bool(SCAN_DATA.get("spider")),
        bool(SCAN_DATA.get("nuclei_findings")),
        bool((SCAN_DATA.get("source_code_analysis") or {}).get("findings")),
        bool((SCAN_DATA.get("nmap") or {}).get("ports")),
    ])

def show_menu():
    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")
    auth_status = (f"{Fore.GREEN}[Autenticado]{Style.RESET_ALL}" if AUTHENTICATED
                   else f"{Fore.YELLOW}[Sin autenticación]{Style.RESET_ALL}")
    print("=" * 52)
    print(f"  WSTG SCANNER v{VERSION}  {auth_status}")
    print("=" * 52)
    print(" 1. Configurar autenticación (login)")
    print(" 2. Información general y enumeración")
    print(" 3. Escaneo de puertos con Nmap (-sV)")
    print(" 4. Análisis de vulnerabilidades con Nuclei")
    print(" 5. Fuzzing de subdominios (vhost) con ffuf")
    print(" 6. Fuzzing de directorios (usa ffuf si está instalado)")
    print(" 7. Spidering / Mapeo completo del sitio")
    print(" 8. Análisis de código fuente (credenciales/secretos en HTML y JS)")
    print(" 9. Pruebas de inyección (SQLi, XSS, Path Traversal, Command Injection)")
    print("10. Pruebas de API (descubrimiento, IDOR, mass assignment)")
    print("11. Enumeración de usuarios/emails y fuerza bruta de contraseñas")
    print("12. Enumeración y ataques WordPress (WPScan)")
    print("13. PENTESTING COMPLETO (ejecuta todas las pruebas anteriores)")
    if _has_scan_data():
        print("14. Mostrar resumen en Markdown")
        print("15. Mostrar tablas de resultados (formato visual)")
    print("16. Salir")
    print("="*50)

def run_information_gathering(target, session):
    print_phase("RECOLECTANDO INFORMACIÓN GENERAL")
    info = safe_execute(gather_info, target, session)
    if info:
        SCAN_DATA["general"] = {
            "status_code": info.get("status_code"),
            "server": info.get("server"),
            "technologies": info.get("technologies", []),
            "technologies_source": info.get("technologies_source", "unknown"),
            "headers": info.get("headers", {}),
            "cookies": [c.name for c in info.get("cookies", [])],
        }
        print_info(f"Servidor: {info['server']}")
        robots_paths = safe_execute(check_robots_sitemap, target, session) or []
        http_methods = safe_execute(check_http_methods, target, session) or []
        SCAN_DATA["robots_paths"] = robots_paths
        SCAN_DATA["http_methods"] = list(set(http_methods))
        safe_execute(check_security_headers, info['headers'])
        safe_execute(check_cookie_security, info['cookies'])
        resp = safe_execute(session.get, target, timeout=DEFAULT_TIMEOUT)
        if resp:
            safe_execute(check_info_disclosure, resp.text)
        safe_execute(check_directory_listing, target, session)
        safe_execute(check_ssl_tls, target)
        safe_execute(test_cors_advanced, target, session)

def run_vhost_fuzzing(target, session):
    print_phase("FUZZING DE SUBDOMINIOS (VHOST)")
    parsed = urlparse(target)
    host = parsed.hostname or ""
    # Si el target es una IP, hace falta dominio base manual; si es FQDN, sugerirlo
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    if is_ip:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Dominio base (ej: planning.htb) — obligatorio cuando el target es IP:")
        base_domain = input("> ").strip()
    else:
        default = host
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Dominio base [{default}]:")
        base_in = input("> ").strip()
        base_domain = base_in or default
    if not base_domain:
        print_error("Dominio base requerido. Saltando vhost fuzzing.")
        return
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar wordlist por defecto (SecLists DNS/namelist.txt)? [S/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Ruta a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar ffuf? (recomendado) [S/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf no está instalado. Usando método interno.")
    # Para vhost fuzzing, el cuello de botella es el RTT del servidor (no CPU
    # local), así que conviene un default alto. El usuario puede bajarlo si
    # el target tiene WAF/rate-limiting.
    default_threads = max(THREADS, 50)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Threads [{default_threads}]:")
    t_in = input("> ").strip()
    try:
        vhost_threads = int(t_in) if t_in else default_threads
        if vhost_threads < 1:
            vhost_threads = default_threads
    except ValueError:
        vhost_threads = default_threads
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Timeout por request en segundos [5]:")
    timeout_in = input("> ").strip()
    try:
        req_timeout = int(timeout_in) if timeout_in else 5
        if req_timeout < 1:
            req_timeout = 5
    except ValueError:
        req_timeout = 5
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Añadir filtro por File Size detectado (-fs en ffuf)? [S/n]:")
    use_fs = input("> ").strip().lower()
    use_fs_bool = (use_fs != 'n')

    hits = vhost_bruteforce(target, session, base_domain,
                            wordlist=wordlist, threads=vhost_threads,
                            request_timeout=req_timeout,
                            use_ffuf=use_ffuf, use_fs_filter=use_fs_bool) or []
    SCAN_DATA["vhosts"] = hits

def run_directory_fuzzing(target, session):
    print_phase("FUZZING DE DIRECTORIOS")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar wordlist por defecto (raft-small-directories)? [S/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Ruta a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
        else:
            print_warning("No se proporcionó wordlist. Usando lista interna.")
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar ffuf para fuzzing? (recomendado) [S/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf no está instalado. Usando método interno.")
    hits = dir_bruteforce(target, session, wordlist=wordlist, threads=THREADS, use_ffuf=use_ffuf) or []
    SCAN_DATA["directory_hits"] = hits

def run_injection_tests(target, session):
    print_phase("PRUEBAS DE INYECCIÓN AVANZADAS")
    try:
        forms, url_params = safe_execute(extract_forms_and_params, target, session)
        SCAN_DATA["injection"] = {
            "executed": True,
            "forms_found": len(forms or []),
            "url_params_found": len(url_params or []),
            "tested_get_params": [],
            "tested_form_inputs": [],
            "forms": list(forms or []),
        }
        if not forms and not url_params:
            print_warning("No se encontraron parámetros ni formularios para probar.")
            return
        if url_params:
            print_info(f"Probando {len(url_params)} parámetros GET...")
            for param in url_params:
                if advanced_injection_tests(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_path_traversal(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_open_redirect(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                SCAN_DATA["injection"]["tested_get_params"].append(param)
        if forms:
            print_info(f"Probando {len(forms)} formularios...")
            for form in forms:
                action = form['action']
                method = form['method']
                inputs = form['inputs']
                form_url = action if action else form.get('page_url', target)
                for inp in inputs:
                    SCAN_DATA["injection"]["tested_form_inputs"].append({
                        "url": form_url,
                        "method": method,
                        "input": inp,
                    })
                    if method == 'POST':
                        if advanced_injection_tests(form_url, inp, session, 'POST'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'POST'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'POST'):
                            continue
                    else:
                        if advanced_injection_tests(form_url, inp, session, 'GET'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'GET'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'GET'):
                            continue
    except KeyboardInterrupt:
        print_warning("Pruebas de inyección interrumpidas por el usuario.")
        return

def run_api_tests(target, session):
    print_phase("PRUEBAS DE API (OWASP API Top 10)")
    print_info("[1/7] Descubrimiento de endpoints...")
    found = safe_execute(discover_api_endpoints, target, session) or []
    SCAN_DATA["api_endpoints"] = found
    print_info("[2/7] CORS avanzado...")
    safe_execute(test_cors_advanced, target, session)
    print_info("[3/7] GraphQL introspección...")
    safe_execute(test_graphql, target, session)
    print_info("[4/7] JWT & autenticación...")
    safe_execute(test_jwt_tokens, target, session)
    if found:
        print_info("[5/7] IDOR / BOLA...")
        safe_execute(test_api_idor, found, session)
        print_info("[6/7] Mass Assignment...")
        safe_execute(test_api_mass_assignment, found, session)
        print_info("[7/7] Errores verbose + Auth bypass...")
        safe_execute(test_api_verbose_errors, found, session)
        safe_execute(test_api_auth_bypass, found, session)
    else:
        print_info("[5-7/7] Saltando tests de endpoints (ninguno encontrado).")
    safe_execute(test_api_rate_limiting, target, session)
    print_good("Pruebas de API completadas.")

def run_user_enum_bruteforce(target, session):
    print_phase("ENUMERACIÓN DE USUARIOS Y BRUTEFORCE")
    users, emails = safe_execute(enumerate_users_from_endpoints, target, session)
    SCAN_DATA["users"] = sorted(set(users or []))
    SCAN_DATA["emails"] = sorted(set(emails or []))
    if users:
        print_good(f"Usuarios encontrados: {', '.join(users)}")
    if emails:
        print_good(f"Emails encontrados: {', '.join(emails)}")
    safe_execute(test_user_enumeration_form, target, session)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Desea realizar fuerza bruta de contraseñas? (s/n):")
    want_brute = input("> ").strip().lower()
    if want_brute in ('', 's'):
        passlist = input_path("Ruta a wordlist de contraseñas (dejar vacío para usar por defecto de SecLists): ").strip()
        if not users:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Introduce usuarios separados por comas:")
            users_input = input("> ").strip()
            if users_input:
                users = [u.strip() for u in users_input.split(',') if u.strip()]
            else:
                users = ['admin', 'test']
        brute_data = safe_execute(bruteforce_login, target, session, users, passlist if passlist else None)
        if brute_data:
            SCAN_DATA["bruteforce_credentials"] = brute_data.get("credentials", [])

def run_spider(target, session):
    print_phase("SPIDERING / MAPEO COMPLETO DEL SITIO")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Máximo número de páginas a rastrear (default 500):")
    max_pages = input("> ").strip()
    if not max_pages:
        max_pages = 500
    else:
        max_pages = int(max_pages)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Profundidad máxima de rastreo (default 3):")
    max_depth = input("> ").strip()
    if not max_depth:
        max_depth = 3
    else:
        max_depth = int(max_depth)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Respetar robots.txt? [S/n]:")
    use_robots = input("> ").strip().lower() != 'n'
    urls, params, forms = spider_website(target, session, max_pages=max_pages, max_depth=max_depth, use_robots=use_robots)
    SCAN_DATA["spider"] = {
        "total_urls": len(urls),
        "total_params": len(params),
        "total_forms": len(forms),
        "sample_urls": sorted(list(urls)),
        "sample_params": sorted(list(params)),
        "sample_forms": list(forms),
    }
    print_good(f"Total URLs descubiertas: {len(urls)}")
    if params:
        print_info(f"Parámetros únicos encontrados: {len(params)}")
    save = input("¿Guardar lista de URLs en un archivo? (s/n): ").strip().lower()
    if save == 's':
        filename = input("Nombre del archivo (default: spider_output.txt): ").strip()
        if not filename:
            filename = "spider_output.txt"
        with open(filename, 'w') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        print_good(f"URLs guardadas en {filename}")
    return urls

def run_source_code_analysis(target, session, urls=None):
    """Analiza el código fuente de las páginas accesibles en busca de credenciales y scripts expuestos.

    Si no se proporciona `urls`, intenta reutilizar las URLs muestreadas en SCAN_DATA["spider"];
    si tampoco existen, ofrece ejecutar un spider rápido o analizar solo el target.
    """
    print_phase("ANÁLISIS DE CÓDIGO FUENTE")
    if urls is None:
        sample = (SCAN_DATA.get("spider") or {}).get("sample_urls") or []
        if sample:
            urls = list(sample)
            print_info(f"Usando {len(urls)} URLs del último spider.")
        else:
            try:
                ans = input(
                    f"{Fore.YELLOW}[?]{Style.RESET_ALL} No hay spider previo. "
                    f"¿Ejecutar spider rápido (max 50 páginas)? [S/n]: "
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ans = 'n'
            if ans != 'n':
                discovered, _params, _forms = spider_website(
                    target, session, max_pages=50, max_depth=2, use_robots=True
                )
                SCAN_DATA["spider"] = {
                    "total_urls": len(discovered),
                    "total_params": 0,
                    "total_forms": 0,
                    "sample_urls": sorted(list(discovered)),
                    "sample_params": [],
                    "sample_forms": [],
                }
                urls = list(discovered)
            else:
                print_warning("Analizando solo la URL objetivo.")
                urls = [target]
    result = analyze_source_code(target, session, urls=urls)
    SCAN_DATA["source_code_analysis"] = result
    return result

def print_final_summary(target):
    """Imprime una recopilación final con todas las tablas de SCAN_DATA y FINDINGS.

    Se invoca al terminar el pentesting completo (opción 9) para ofrecer una
    vista consolidada de toda la información recopilada antes de guardar el reporte.
    """
    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    def _trim(value, width=80):
        text = str(value) if value is not None else "-"
        return text if len(text) <= width else text[: width - 3] + "..."

    def _stringify(item):
        """Convierte un item (str/dict/otro) a una cadena legible."""
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            name = item.get("name") or item.get("template_id") or item.get("url") or ""
            detail = item.get("detail") or item.get("value") or ""
            if name and detail:
                return f"{name} ({detail})"
            return name or detail or str(item)
        return str(item)

    def _join_safe(items, sep=", "):
        return sep.join(_stringify(i) for i in (items or []))

    def _count_label(total, limit):
        if total <= limit:
            return f"({total})"
        return f"(top {limit} de {total})"

    print_phase("RESUMEN FINAL DEL PENTESTING")

    general = SCAN_DATA.get("general") or {}
    nuclei_summary = SCAN_DATA.get("nuclei_summary") or {}
    nuclei_findings = SCAN_DATA.get("nuclei_findings") or []
    spider = SCAN_DATA.get("spider") or {}
    injection = SCAN_DATA.get("injection") or {}
    vhosts = SCAN_DATA.get("vhosts") or []
    dir_hits = SCAN_DATA.get("directory_hits") or []
    api_endpoints = SCAN_DATA.get("api_endpoints") or []
    users = SCAN_DATA.get("users") or []
    emails = SCAN_DATA.get("emails") or []
    creds = SCAN_DATA.get("bruteforce_credentials") or []
    wordpress = SCAN_DATA.get("wordpress") or {}
    robots_paths = SCAN_DATA.get("robots_paths") or []
    http_methods = SCAN_DATA.get("http_methods") or []
    src_code = SCAN_DATA.get("source_code_analysis") or {}
    src_findings = src_code.get("findings") or []
    nmap_data = SCAN_DATA.get("nmap") or {}
    nmap_ports = nmap_data.get("ports") or []

    # 1. Resumen ejecutivo
    overview_rows = [
        ["Objetivo", _trim(target, 90)],
        ["Status HTTP", str(general.get("status_code", "-"))],
        ["Servidor", _trim(general.get("server", "-"), 90)],
        ["Tecnologías", _trim(_join_safe(general.get("technologies", [])) or "-", 90)],
        ["Hallazgos (FINDINGS)", str(len(FINDINGS))],
        ["Puertos abiertos (nmap)", str(len(nmap_ports))],
        ["Vulnerabilidades Nuclei", str(len(nuclei_findings))],
        ["URLs spider", str(spider.get("total_urls", 0))],
        ["Subdominios (vhosts)", str(len(vhosts))],
        ["Directorios encontrados", str(len(dir_hits))],
        ["Endpoints API", str(len(api_endpoints))],
        ["Usuarios", str(len(users))],
        ["Emails", str(len(emails))],
        ["Credenciales válidas", str(len(creds))],
        ["WordPress vulnerabilidades", str(len(wordpress.get("vulnerabilities") or []))],
        ["Hallazgos en código fuente", str(len(src_findings))],
    ]
    print_table(
        headers=["Campo", "Valor"],
        rows=overview_rows,
        alignments=['<', '<'],
        title="Resumen ejecutivo:",
    )

    # 2. Headers de seguridad
    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        mark = f"{Fore.GREEN}OK{Style.RESET_ALL}" if present else f"{Fore.RED}AUSENTE{Style.RESET_ALL}"
        sec_rows.append([h, mark, _trim(v, 80)])
    print_table(
        headers=["Header", "Estado", "Valor"],
        rows=sec_rows,
        alignments=['<', '<', '<'],
        title="Cabeceras de seguridad:",
    )

    # 3. Cookies
    cookies = general.get("cookies") or []
    if cookies:
        cookie_rows = [[c] for c in cookies]
        print_table(
            headers=["Cookie"],
            rows=cookie_rows,
            alignments=['<'],
            title="Cookies detectadas:",
        )

    # 4. HTTP methods + robots
    misc_rows = []
    if http_methods:
        misc_rows.append(["HTTP Methods permitidos", _trim(_join_safe(http_methods), 90)])
    if robots_paths:
        misc_rows.append([f"Rutas de robots.txt/sitemap ({len(robots_paths)})", _trim(_join_safe(robots_paths[:15]), 90)])
    if misc_rows:
        print_table(
            headers=["Categoría", "Valor"],
            rows=misc_rows,
            alignments=['<', '<'],
            title="Información HTTP adicional:",
        )

    # 4b. Nmap (puertos abiertos)
    if nmap_ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        port_rows = []
        for p in nmap_ports[:50]:
            color = STATE_COLOR.get(p.get("state", ""), Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in version_parts if v).strip() or "-"
            port_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                f"{color}{p.get('state', '-')}{Style.RESET_ALL}",
                _trim(p.get("service", "") or "-", 24),
                _trim(version_str, 60),
            ])
        print_table(
            headers=["Puerto", "Estado", "Servicio", "Versión"],
            rows=port_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Puertos abiertos (nmap) {_count_label(len(nmap_ports), len(port_rows))}:",
        )

    # 5. Spider
    if spider:
        spider_rows = [
            ["URLs totales", str(spider.get("total_urls", 0))],
            ["Parámetros únicos", str(spider.get("total_params", 0))],
            ["Formularios", str(spider.get("total_forms", 0))],
        ]
        print_table(
            headers=["Métrica", "Valor"],
            rows=spider_rows,
            alignments=['<', '>'],
            title="Spidering:",
        )
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            url_rows = [[_trim(u, 110)] for u in sample_urls[:20]]
            print_table(
                headers=["URL"],
                rows=url_rows,
                alignments=['<'],
                title=f"Muestra de URLs descubiertas {_count_label(spider.get('total_urls', 0), len(url_rows))}:",
            )

    # 5b. Análisis de código fuente
    if src_code:
        sev_stats = src_code.get("summary") or {}
        code_overview = [
            ["Páginas analizadas", str(src_code.get("pages_analyzed", 0))],
            ["Recursos JS/JSON analizados", str(src_code.get("assets_analyzed", 0))],
            ["Hallazgos totales", str(len(src_findings))],
            [f"{Fore.MAGENTA}Critical{Style.RESET_ALL}", str(sev_stats.get("critical", 0))],
            [f"{Fore.RED}High{Style.RESET_ALL}", str(sev_stats.get("high", 0))],
            [f"{Fore.YELLOW}Medium{Style.RESET_ALL}", str(sev_stats.get("medium", 0))],
            [f"{Fore.CYAN}Low{Style.RESET_ALL}", str(sev_stats.get("low", 0))],
        ]
        print_table(
            headers=["Métrica", "Valor"],
            rows=code_overview,
            alignments=['<', '>'],
            title="Análisis de código fuente:",
        )
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            code_rows = []
            for f in sorted_src[:30]:
                sev = f.get("severity", "low")
                color = SEV_COLOR.get(sev, Fore.WHITE)
                code_rows.append([
                    f"{color}{sev.upper()}{Style.RESET_ALL}",
                    _trim(f.get("type", "-"), 30),
                    _trim(f.get("value", "-"), 40),
                    _trim(f.get("url", "-"), 60),
                ])
            print_table(
                headers=["Severidad", "Tipo", "Valor detectado", "URL"],
                rows=code_rows,
                alignments=['<', '<', '<', '<'],
                title=f"Hallazgos en código fuente {_count_label(len(sorted_src), len(code_rows))}:",
            )

    # 6a. Subdominios (vhosts)
    if vhosts:
        vh_rows = []
        for v in vhosts[:30]:
            status = str(v.get("status", "-"))
            fqdn = _trim(v.get("fqdn") or v.get("subdomain", "-"), 80)
            size = str(v.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            vh_rows.append([f"{sc}{status}{Style.RESET_ALL}", fqdn, size])
        print_table(
            headers=["Status", "VHost", "Tamaño"],
            rows=vh_rows,
            alignments=['<', '<', '>'],
            title=f"Subdominios encontrados {_count_label(len(vhosts), len(vh_rows))}:",
        )

    # 6b. Directorios
    if dir_hits:
        dir_rows = []
        for h in dir_hits[:30]:
            status = str(h.get("status", "-"))
            url = _trim(h.get("url", "-"), 90)
            size = str(h.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            dir_rows.append([f"{sc}{status}{Style.RESET_ALL}", url, size])
        print_table(
            headers=["Status", "URL", "Tamaño"],
            rows=dir_rows,
            alignments=['<', '<', '>'],
            title=f"Directorios encontrados {_count_label(len(dir_hits), len(dir_rows))}:",
        )

    # 6c. WordPress / WPScan
    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_rows = [
            ["Detectado", "Si" if wordpress.get("detected") else "No confirmado"],
            ["Version", wp_version.get("number") or "-"],
            ["Estado", wp_version.get("status") or "-"],
            ["Tema principal", wp_theme.get("name") or "-"],
            ["Usuarios", str(len(wp_users))],
            ["Vulnerabilidades", str(len(wp_vulns))],
            ["Credenciales", str(len(wordpress.get("credentials") or []))],
        ]
        print_table(
            headers=["Campo", "Valor"],
            rows=wp_rows,
            alignments=['<', '<'],
            title="WordPress / WPScan:",
        )
        if wp_vulns:
            vuln_rows = []
            for v in wp_vulns[:30]:
                vuln_rows.append([
                    _trim(v.get("component_type", "-"), 14),
                    _trim(v.get("component", "-"), 30),
                    _trim(v.get("title", "-"), 70),
                    _trim(v.get("fixed_in", "-"), 20),
                ])
            print_table(
                headers=["Tipo", "Componente", "Titulo", "Fixed in"],
                rows=vuln_rows,
                alignments=['<', '<', '<', '<'],
                title=f"Vulnerabilidades WordPress {_count_label(len(wp_vulns), len(vuln_rows))}:",
            )

    # 7. API endpoints
    if api_endpoints:
        api_rows = []
        for ep in api_endpoints[:30]:
            status = str(ep.get("status", "-"))
            endpoint = _trim(ep.get("endpoint") or ep.get("url", "-"), 60)
            ctype = _trim(ep.get("content_type", "-"), 30)
            api_rows.append([status, endpoint, ctype])
        print_table(
            headers=["Status", "Endpoint", "Content-Type"],
            rows=api_rows,
            alignments=['<', '<', '<'],
            title=f"Endpoints API descubiertos {_count_label(len(api_endpoints), len(api_rows))}:",
        )

    # 8. Usuarios y emails
    if users or emails:
        ue_rows = []
        if users:
            ue_rows.append(["Usuarios", _trim(_join_safe(users), 100)])
        if emails:
            ue_rows.append(["Emails", _trim(_join_safe(emails), 100)])
        print_table(
            headers=["Categoría", "Valores"],
            rows=ue_rows,
            alignments=['<', '<'],
            title="Usuarios y emails descubiertos:",
        )

    # 9. Inyección
    if injection.get("executed"):
        inj_rows = [
            ["Formularios detectados", str(injection.get("forms_found", 0))],
            ["Parámetros GET detectados", str(injection.get("url_params_found", 0))],
            ["Parámetros GET probados", str(len(injection.get("tested_get_params", [])))],
            ["Inputs de formulario probados", str(len(injection.get("tested_form_inputs", [])))],
        ]
        print_table(
            headers=["Métrica", "Valor"],
            rows=inj_rows,
            alignments=['<', '>'],
            title="Pruebas de inyección:",
        )

    # 10. Credenciales válidas
    if creds:
        cred_rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            cred_rows.append([f"{Fore.GREEN}{user}{Style.RESET_ALL}", f"{Fore.GREEN}{pwd}{Style.RESET_ALL}"])
        print_table(
            headers=["Usuario", "Contraseña"],
            rows=cred_rows,
            alignments=['<', '<'],
            title="Credenciales válidas encontradas:",
            border_color=Fore.GREEN,
        )

    # 11. Nuclei
    if nuclei_summary:
        sum_rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            color = SEV_COLOR.get(sev, Fore.WHITE)
            unique_str = _join_safe(sorted(set(tids)))
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(tids)),
                _trim(unique_str, 100),
            ])
        print_table(
            headers=["Severidad", "Cantidad", "Templates únicos"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Vulnerabilidades por severidad (Nuclei):",
        )

    relevant_nuclei = [n for n in nuclei_findings if n.get('severity') in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        rel_rows = []
        for n in relevant_nuclei[:30]:
            sev = n.get('severity', 'info')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            rel_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                _trim(n.get('template_id', '-'), 40),
                _trim(n.get('name', '-'), 50),
                _trim(n.get('url', '-'), 60),
            ])
        print_table(
            headers=["Severidad", "Template", "Nombre", "URL"],
            rows=rel_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Hallazgos Nuclei relevantes {_count_label(len(relevant_nuclei), len(rel_rows))}:",
        )

    # 12. Hallazgos clasificados (FINDINGS)
    if FINDINGS:
        cats = {}
        for f in FINDINGS:
            m = re.match(r'^\[([^\]]+)\]', f)
            cat = m.group(1) if m else "OTROS"
            cats.setdefault(cat, []).append(f)
        cat_rows = []
        for cat in sorted(cats.keys()):
            cat_rows.append([cat, str(len(cats[cat]))])
        print_table(
            headers=["Categoría", "Cantidad"],
            rows=cat_rows,
            alignments=['<', '>'],
            title=f"Hallazgos clasificados (total: {len(FINDINGS)}):",
        )
        find_rows = []
        for f in FINDINGS[:40]:
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', f)
            if m:
                cat = m.group(1)
                msg = m.group(2)
            else:
                cat, msg = "OTROS", f
            color = Fore.RED if cat.startswith(("VULN", "NUCLEI:CRITICAL", "NUCLEI:HIGH", "CRED", "WP:VULN")) else (
                Fore.YELLOW if cat.startswith(("NUCLEI:MEDIUM", "DIR", "VHOST", "WP")) else Fore.CYAN
            )
            find_rows.append([f"{color}{cat}{Style.RESET_ALL}", _trim(msg, 110)])
        print_table(
            headers=["Categoría", "Detalle"],
            rows=find_rows,
            alignments=['<', '<'],
            title=f"Detalle de hallazgos {_count_label(len(FINDINGS), len(find_rows))}:",
        )

    print()
    print_good("Recopilación finalizada. Use 'Guardar reporte' al salir para exportar TXT/JSON/HTML/MD.")


def run_full_pentest(target, session):
    print_phase("INICIANDO PENTESTING COMPLETO")
    # Orden según menú principal:
    run_information_gathering(target, session)         # 2
    safe_execute(run_nmap_scan, target)                # 3
    run_nuclei_scan(target)                            # 4
    run_vhost_fuzzing(target, session)                 # 5
    run_directory_fuzzing(target, session)             # 6
    spider_urls = run_spider(target, session)          # 7
    # 8. Análisis de código fuente sobre todas las URLs descubiertas
    safe_execute(
        run_source_code_analysis,
        target, session,
        urls=list(spider_urls) if spider_urls else None,
    )
    run_injection_tests(target, session)               # 9
    run_api_tests(target, session)                     # 10
    run_user_enum_bruteforce(target, session)          # 11
    run_wordpress_attacks_if_detected(target, session) # 12
    print_good("Pentesting completo finalizado.")
    print_final_summary(target)

def main():
    global TARGET_URL, AUTHENTICATED, AUTH_SESSION, THREADS, DEFAULT_TIMEOUT, REQUEST_DELAY, OUTPUT_FILE, VERIFY_TLS

    parser = argparse.ArgumentParser(
        description=f"WSTG Scanner v{VERSION} - OWASP Web Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplo: python3 wstg-scan.py --url https://example.com --output report.txt"
    )
    parser.add_argument('--url', '-u', metavar='URL',
                        help='URL objetivo (omitir para modo interactivo)')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Archivo de salida para el reporte (ej: report.txt)')
    parser.add_argument('--threads', '-t', type=int, default=THREADS, metavar='N',
                        help=f'Número de hilos (default: {THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, metavar='S',
                        help=f'Timeout por request en segundos (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--delay', '-d', type=float, default=0.0, metavar='S',
                        help='Delay entre requests en segundos para evasión (default: 0)')
    parser.add_argument('--insecure', '-k', action='store_true',
                        help='Desactivar verificación de certificados TLS (uso en labs / entornos de prueba)')
    parser.add_argument('--no-color', action='store_true',
                        help='Desactivar colores en la salida')
    parser.add_argument('--version', '-V', action='version', version=f'WSTG Scanner v{VERSION}')
    args = parser.parse_args()

    THREADS = args.threads
    DEFAULT_TIMEOUT = args.timeout
    REQUEST_DELAY = args.delay
    OUTPUT_FILE = args.output
    VERIFY_TLS = not args.insecure

    if args.no_color:
        global HAS_COLOR
        HAS_COLOR = False

    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")

    if not VERIFY_TLS:
        print_warning("Verificación TLS desactivada (--insecure). Solo para entornos de prueba.")

    if args.url:
        TARGET_URL = normalize_url(args.url)
        print_info(f"Objetivo: {TARGET_URL}")
    else:
        TARGET_URL = input("Introduce la URL objetivo: ").strip()
        TARGET_URL = normalize_url(TARGET_URL)
        print_info(f"Objetivo: {TARGET_URL}")

    session = get_session()

    def _exit_gracefully():
        """Cierra el programa mostrando el reporte y el mensaje final."""
        print()
        has_scan_data = _has_scan_data()
        if has_scan_data:
            auto_save = OUTPUT_FILE is not None
            if not auto_save:
                try:
                    auto_save = input(
                        f"\n¿Guardar reporte del escaneo ({len(FINDINGS)} hallazgos)? [S/n]: "
                    ).strip().lower() != 'n'
                except (KeyboardInterrupt, EOFError):
                    auto_save = False
            if auto_save:
                save_report(OUTPUT_FILE)
        print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)
        sys.exit(0)

    while True:
        try:
            show_menu()
            # Ya está en el menú principal
            option = input("Selecciona una opción: ").strip()
        except (KeyboardInterrupt, EOFError):
            try:
                print()
                confirm = input("\n¿Salir del programa? [S/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue

        try:
            if option == '1':
                setup_authentication()
                if AUTHENTICATED:
                    session = AUTH_SESSION
                    print_good("Sesión autenticada activa para futuras pruebas.")
                else:
                    print_warning("No se pudo autenticar. Continuando sin autenticación.")
            elif option == '2':
                run_information_gathering(TARGET_URL, session)
            elif option == '3':
                run_nmap_scan(TARGET_URL)
            elif option == '4':
                run_nuclei_scan(TARGET_URL)
            elif option == '5':
                run_vhost_fuzzing(TARGET_URL, session)
            elif option == '6':
                run_directory_fuzzing(TARGET_URL, session)
            elif option == '7':
                run_spider(TARGET_URL, session)
            elif option == '8':
                run_source_code_analysis(TARGET_URL, session)
            elif option == '9':
                run_injection_tests(TARGET_URL, session)
            elif option == '10':
                run_api_tests(TARGET_URL, session)
            elif option == '11':
                run_user_enum_bruteforce(TARGET_URL, session)
            elif option == '12':
                run_wordpress_attacks(TARGET_URL, session)
            elif option == '13':
                run_full_pentest(TARGET_URL, session)
            elif option == '14':
                if not _has_scan_data():
                    print_warning("Aún no hay datos. Ejecuta primero algún módulo o el pentesting completo.")
                else:
                    report_data = {
                        "tool": VERSION,
                        "target": TARGET_URL,
                        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "findings": list(FINDINGS),
                        "scan_data": _to_serializable(SCAN_DATA),
                    }
                    md = _build_markdown_report(report_data)
                    print()
                    print("=" * 70)
                    print(" RESUMEN EN MARKDOWN (copia desde la línea siguiente):")
                    print("=" * 70)
                    print(md)
                    print("=" * 70)
                    print_good("Fin del markdown. Copia el bloque anterior.")
            elif option == '15':
                if not _has_scan_data():
                    print_warning("Aún no hay datos. Ejecuta primero algún módulo o el pentesting completo.")
                else:
                    print_final_summary(TARGET_URL)
            elif option == '16':
                _exit_gracefully()
            else:
                print_error("Opción no válida. Intenta de nuevo.")
        except KeyboardInterrupt:
            try:
                print()
                confirm = input("\n¿Salir del programa? [S/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue
        except Exception as e:
            print_error(f"Error inesperado: {e}")

        try:
            input("\nPresiona Enter para continuar...")
        except (KeyboardInterrupt, EOFError):
            _exit_gracefully()

    _exit_gracefully()

if __name__ == "__main__":
    main()
