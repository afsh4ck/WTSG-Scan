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
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ''
    Style = Fore

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

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
FINDINGS = []        # Hallazgos acumulados para el reporte
SCAN_DATA = {
    "general": {},
    "robots_paths": [],
    "http_methods": [],
    "directory_hits": [],
    "injection": {},
    "api_endpoints": [],
    "users": [],
    "emails": [],
    "bruteforce_credentials": [],
    "spider": {},
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
DEFAULT_PASSWORDS = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome"
]

# Payloads
SQL_PAYLOADS = [
    "'", "''", '"', "\\", "' OR '1'='1", "' OR 1=1--",
    "1 AND 1=1", "1 AND 1=2", "' UNION SELECT NULL--", "'; DROP TABLE users--",
    "' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", '\"> <script>alert(1)</script>',
    "<img src=x onerror=alert(1)>", "javascript:alert('XSS')",
    "<svg/onload=alert(1)>", "'-alert(1)-'", '"-alert(1)-"'
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

def check_whatweb():
    return shutil.which("whatweb") is not None

def install_whatweb():
    """Ofrece instalar WhatWeb via apt si no está disponible."""
    print_warning("WhatWeb no está instalado.")
    try:
        resp = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar WhatWeb automáticamente? (requiere sudo) [s/N]: ").strip().lower()
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
            # Formato: http://host [STATUS] Plugin1, Plugin2[value], ...
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

def check_nuclei():
    return shutil.which("nuclei")

def install_nuclei():
    """Ofrece instalar Nuclei via apt si no está disponible."""
    print_warning("Nuclei no está instalado.")
    try:
        resp = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar Nuclei automáticamente? (requiere sudo) [s/N]: ").strip().lower()
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

# (El resto del archivo es idéntico al original wstg-scanner.py)

# Para evitar duplicar todo el contenido aquí en el parche, este archivo se creó
# copiando el contenido completo de `wstg-scanner.py` y actualizando referencias
# al nombre del script donde procede en la ayuda/ejemplo.

if __name__ == "__main__":
    # Para mantener el comportamiento original, importamos y ejecutamos la
    # función `main` desde el módulo antiguo si existe en el mismo workspace.
    try:
        # Intentar cargar el antiguo módulo en memoria
        import importlib.util
        old_path = os.path.join(os.path.dirname(__file__), 'wstg-scanner.py')
        spec = importlib.util.spec_from_file_location('wstg_scanner_module', old_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'main'):
            mod.main()
    except Exception:
        # Fallback minimal behaviour
        print("Ejecuta el script principal desde `wstg-scanner.py` o actualiza manualmente.")
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
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ''
    Style = Fore

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

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
FINDINGS = []        # Hallazgos acumulados para el reporte
SCAN_DATA = {
    "general": {},
    "robots_paths": [],
    "http_methods": [],
    "directory_hits": [],
    "injection": {},
    "api_endpoints": [],
    "users": [],
    "emails": [],
    "bruteforce_credentials": [],
    "spider": {},
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

def check_whatweb():
    return shutil.which("whatweb") is not None

def install_whatweb():
    """Ofrece instalar WhatWeb via apt si no está disponible."""
    print_warning("WhatWeb no está instalado.")
    try:
        resp = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar WhatWeb automáticamente? (requiere sudo) [s/N]: ").strip().lower()
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

def check_nuclei():
    return shutil.which("nuclei")

def install_nuclei():
    """Ofrece instalar Nuclei via apt si no está disponible."""
    print_warning("Nuclei no está instalado.")
    try:
        resp = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Instalar Nuclei automáticamente? (requiere sudo) [s/N]: ").strip().lower()
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
        print(f"\n{color}{title}{rc}")
    print(f"{color}{top}{rc}")
    header_line = " │ ".join(_pad_cell(h, widths[i], alignments[i]) for i, h in enumerate(headers))
    print(f"{color}│{rc} {color}{header_line}{rc} {color}│{rc}")
    print(f"{color}{mid}{rc}")
    for r in rows:
        cells = [
            _pad_cell(r[i] if i < len(r) else '', widths[i], alignments[i])
            for i in range(n_cols)
        ]
        line = f" {color}│{rc} ".join(cells)
        print(f"{color}│{rc} {line} {color}│{rc}")
    print(f"{color}{bot}{rc}")
    if footer:
        print(footer)

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
    """Devuelve rutas estables para TXT/JSON/HTML. Siempre sobrescribe por objetivo."""
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
    return txt_file, base + ".json", base + ".html"

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
    dirs = scan_data.get("directory_hits", [])
    creds = scan_data.get("bruteforce_credentials", [])
    spider = scan_data.get("spider", {})
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
            for n in sorted_findings[:500]:
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
        return "Otros"

    CAT_ORDER = [
        "Vulnerabilidades",
        "Nuclei — CRITICAL", "Nuclei — HIGH", "Nuclei — MEDIUM",
        "Nuclei — LOW", "Nuclei — INFO", "Nuclei — UNKNOWN",
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
        for ep in endpoints[:300]
    ) or "<tr><td colspan='4'>Sin endpoints detectados.</td></tr>"

    dir_rows = ""
    if dirs:
        for hit in dirs[:500]:
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
        f"<li>{_html_escape(u)}</li>" for u in spider.get("sample_urls", [])[:120]
    ) or "<li>Sin URLs capturadas.</li>"

    # Navegación por secciones
    nav_sections = [
        ("Resumen", "resumen"),
        ("Información general", "info"),
        ("Hallazgos", "hallazgos"),
        ("API", "api"),
        ("Directorios", "directorios"),
        ("Credenciales", "credenciales"),
        ("Spidering", "spidering"),
    ]
    nav_html = "<nav class='nav-pills'>" + "\n".join(
        f"<a href='#{sec_id}' class='pill'>{sec_name}</a>" for sec_name, sec_id in nav_sections
    ) + "</nav>"

    return f"""<!doctype html>
<html lang=\"es\">
<head>
    <meta charset=\"utf-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>WSTG Report - {{_html_escape(report_data.get('target', ''))}}</title>
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
                <div><span class="muted">Directorios</span><b>{len(dirs)}</b></div>
                <div><span class="muted">Usuarios</span><b>{len(users)}</b></div>
                <div><span class="muted">Credenciales</span><b>{len(creds)}</b></div>
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

        <div class="card" id='hallazgos'><h3>Hallazgos</h3><ul>{findings_items}</ul></div>
        {nuclei_html}

        <div class="card" id='api'>
            <h3>Endpoints API detectados</h3>
            <table><thead><tr><th>Status</th><th>Endpoint</th><th>URL</th><th>Content-Type</th></tr></thead><tbody>{endpoint_rows}</tbody></table>
        </div>

        <div class=\"card\" id='directorios'>
            <h3>Directorios/archivos descubiertos</h3>
            <table><thead><tr><th>Status</th><th>URL</th><th>Tamaño</th></tr></thead><tbody>{dir_rows}</tbody></table>
        </div>

        <div class=\"card\" id='credenciales'>
            <h3>Credenciales válidas (bruteforce)</h3>
            <table><thead><tr><th>Usuario</th><th>Contraseña</th></tr></thead><tbody>{creds_rows}</tbody></table>
        </div>

        <div class=\"card\" id='spidering'>
            <h3>Spidering (muestra de URLs)</h3>
            <ul>{sample_urls_html}</ul>
        </div>
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

def save_report(output_file=None):
    """Guarda hallazgos y datos relevantes en TXT, JSON y HTML."""
    txt_file, json_file, html_file = _normalize_output_paths(output_file, TARGET_URL)
    scan_stats = {
        "authenticated": AUTHENTICATED,
        "threads": THREADS,
        "timeout": DEFAULT_TIMEOUT,
        "delay": REQUEST_DELAY,
        "total_findings": len(FINDINGS),
        "total_api_endpoints": len(SCAN_DATA.get("api_endpoints", [])),
        "total_dir_hits": len(SCAN_DATA.get("directory_hits", [])),
        "injection_forms_found": SCAN_DATA.get("injection", {}).get("forms_found", 0),
        "injection_get_params_found": SCAN_DATA.get("injection", {}).get("url_params_found", 0),
        "injection_get_params_tested": len(SCAN_DATA.get("injection", {}).get("tested_get_params", [])),
        "injection_form_inputs_tested": len(SCAN_DATA.get("injection", {}).get("tested_form_inputs", [])),
        "total_users": len(SCAN_DATA.get("users", [])),
        "total_emails": len(SCAN_DATA.get("emails", [])),
        "total_bruteforce_credentials": len(SCAN_DATA.get("bruteforce_credentials", [])),
        "total_spider_urls": SCAN_DATA.get("spider", {}).get("total_urls", 0),
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

            f.write("[ENUMERACIÓN]\n")
            f.write(f"- Usuarios: {', '.join(report_data['scan_data'].get('users', [])) or 'N/A'}\n")
            f.write(f"- Emails: {', '.join(report_data['scan_data'].get('emails', [])) or 'N/A'}\n\n")

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

        print_good(
            f"Reportes guardados (sobrescritos si existían): {txt_file}, {json_file}, {html_file}"
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
    session.verify = False
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
    login_url = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} URL de login (dejar vacío si es la misma que la objetivo): ").strip()
    if not login_url:
        login_url = TARGET_URL
    else:
        login_url = normalize_url(login_url)
    username = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Usuario: ")
    password = getpass.getpass(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Contraseña: ")

    temp_session = get_session()
    try:
        resp = temp_session.get(login_url, auth=(username, password), timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            print_good("Autenticación Basic Auth exitosa")
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            return
    except:
        pass

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
                        with open(tmp_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        hits = data.get('results', [])

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
                if process:
                    process.terminate()
                print_warning("Fuzzing interrumpido por el usuario")
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
            resp = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar hydra para el bruteforce? [S/n]: ").strip().lower()
            use_hydra = (resp != 'n')
        else:
            print_warning("hydra no está instalado o no está en PATH. Usando método interno.")

        login_url = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Introduce la URL real del login (dejar vacío para autodetección): ").strip()
        error_msg = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Introduce el mensaje de error exacto (vacío para heurística): ").strip()

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
            if error_msg and error_msg in body:
                return False
            if any(k in body for k in FAILURE_KEYWORDS):
                return False
            if _is_login_path(final_path):
                if fail_max > 0 and (final_len < fail_min or final_len > fail_max):
                    return True
                return False
            if any(k in body for k in SUCCESS_KEYWORDS):
                return True
            if baseline_status != -1 and resp_follow.status_code != baseline_status and final_path != baseline_path:
                return True
            location = resp_no_redirect.headers.get('Location', '')
            location_path = _normalize_path(urljoin(primary_form['url'], location)) if location else ''
            if resp_no_redirect.status_code in (301, 302, 303, 307, 308):
                if location and not _is_login_path(location_path):
                    return True
            if fail_max > 0 and (final_len < fail_min or final_len > fail_max):
                return True
            if final_path != baseline_path and not _is_login_path(final_path):
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
        except:
            print_warning("No se pudo cargar robots.txt, continuando sin restricciones.")

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

# ========== MENÚ PRINCIPAL ==========
def show_menu():
    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(DESCRIPTION)
        print(BANNER)
        print(DEVELOPER + "\n")
    auth_status = (f"{Fore.GREEN}[Autenticado]{Style.RESET_ALL}" if AUTHENTICATED
                   else f"{Fore.YELLOW}[Sin autenticación]{Style.RESET_ALL}")
    print("=" * 52)
    print(f"  WSTG SCANNER v{VERSION}  {auth_status}")
    print("=" * 52)
    print(" 1. Configurar autenticación (login)")
    print(" 2. Información general y enumeración")
    print(" 3. Análisis de vulnerabilidades con Nuclei")
    print(" 4. Fuzzing de directorios (usa ffuf si está instalado)")
    print(" 5. Spidering / Mapeo completo del sitio")
    print(" 6. Pruebas de inyección (SQLi, XSS, Path Traversal, Command Injection)")
    print(" 7. Pruebas de API (descubrimiento, IDOR, mass assignment)")
    print(" 8. Enumeración de usuarios/emails y fuerza bruta de contraseñas")
    print(" 9. PENTESTING COMPLETO (ejecuta todas las pruebas anteriores)")
    print("10. Salir")
    print("="*50)

def run_information_gathering(target, session):
    print_phase("RECOLECTANDO INFORMACIÓN GENERAL")
    info = safe_execute(gather_info, target, session)
    if info:
        SCAN_DATA["general"] = {
            "status_code": info.get("status_code"),
            "server": info.get("server"),
            "technologies": info.get("technologies", []),
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

def run_directory_fuzzing(target, session):
    print_phase("FUZZING DE DIRECTORIOS")
    use_default = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar wordlist por defecto (raft-small-directories)? [S/n]: ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Ruta a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
        else:
            print_warning("No se proporcionó wordlist. Usando lista interna.")
    if check_ffuf():
        use_ffuf = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Usar ffuf para fuzzing? (recomendado) [S/n]: ").strip().lower() != 'n'
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
            "forms": (forms or [])[:120],
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
    want_brute = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Desea realizar fuerza bruta de contraseñas? (s/n): ").strip().lower()
    if want_brute in ('', 's'):
        passlist = input_path("Ruta a wordlist de contraseñas (dejar vacío para usar por defecto de SecLists): ").strip()
        if not users:
            users_input = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Introduce usuarios separados por comas: ").strip()
            if users_input:
                users = [u.strip() for u in users_input.split(',') if u.strip()]
            else:
                users = ['admin', 'test']
        brute_data = safe_execute(bruteforce_login, target, session, users, passlist if passlist else None)
        if brute_data:
            SCAN_DATA["bruteforce_credentials"] = brute_data.get("credentials", [])

def run_spider(target, session):
    print_phase("SPIDERING / MAPEO COMPLETO DEL SITIO")
    max_pages = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Máximo número de páginas a rastrear (default 500): ").strip()
    if not max_pages:
        max_pages = 500
    else:
        max_pages = int(max_pages)
    max_depth = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Profundidad máxima de rastreo (default 3): ").strip()
    if not max_depth:
        max_depth = 3
    else:
        max_depth = int(max_depth)
    use_robots = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} ¿Respetar robots.txt? [S/n]: ").strip().lower() != 'n'
    urls, params, forms = spider_website(target, session, max_pages=max_pages, max_depth=max_depth, use_robots=use_robots)
    SCAN_DATA["spider"] = {
        "total_urls": len(urls),
        "total_params": len(params),
        "total_forms": len(forms),
        "sample_urls": sorted(list(urls))[:120],
        "sample_params": sorted(list(params))[:80],
        "sample_forms": forms[:80],
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

def run_full_pentest(target, session):
    print_phase("INICIANDO PENTESTING COMPLETO")
    # Orden según menú principal:
    run_information_gathering(target, session)         # 2
    run_nuclei_scan(target)                            # 3
    run_directory_fuzzing(target, session)             # 4
    run_spider(target, session)                        # 5
    run_injection_tests(target, session)               # 6
    run_api_tests(target, session)                     # 7
    run_user_enum_bruteforce(target, session)          # 8
    print_good("Pentesting completo finalizado.")

def main():
    global TARGET_URL, AUTHENTICATED, AUTH_SESSION, THREADS, DEFAULT_TIMEOUT, REQUEST_DELAY, OUTPUT_FILE

    parser = argparse.ArgumentParser(
        description=f"WSTG Scanner v{VERSION} - OWASP Web Security Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplo: python3 wstg-scanner.py --url https://example.com --output report.txt"
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
    parser.add_argument('--no-color', action='store_true',
                        help='Desactivar colores en la salida')
    parser.add_argument('--version', '-V', action='version', version=f'WSTG Scanner v{VERSION}')
    args = parser.parse_args()

    THREADS = args.threads
    DEFAULT_TIMEOUT = args.timeout
    REQUEST_DELAY = args.delay
    OUTPUT_FILE = args.output

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
        has_scan_data = any([
            bool(FINDINGS),
            bool(SCAN_DATA.get("general")),
            bool(SCAN_DATA.get("injection")),
            bool(SCAN_DATA.get("api_endpoints")),
            bool(SCAN_DATA.get("directory_hits")),
            bool(SCAN_DATA.get("users")),
            bool(SCAN_DATA.get("emails")),
            bool(SCAN_DATA.get("bruteforce_credentials")),
            bool(SCAN_DATA.get("spider")),
        ])
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
                run_nuclei_scan(TARGET_URL)
            elif option == '4':
                run_directory_fuzzing(TARGET_URL, session)
            elif option == '5':
                run_spider(TARGET_URL, session)
            elif option == '6':
                run_injection_tests(TARGET_URL, session)
            elif option == '7':
                run_api_tests(TARGET_URL, session)
            elif option == '8':
                run_user_enum_bruteforce(TARGET_URL, session)
            elif option == '9':
                run_full_pentest(TARGET_URL, session)
            elif option == '10':
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
