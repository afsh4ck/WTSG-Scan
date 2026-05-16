# 🔐 OWASP WSTG Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-lightgrey.svg" alt="Platform">
</p>

<p align="center">
  <strong>Herramienta interactiva y completa de pruebas de seguridad web</strong> basada en la metodología OWASP WSTG.
</p>

<p align="center">
  <a href="#-características">Características</a> •
  <a href="#-instalación">Instalación</a> •
  <a href="#-uso-rápido">Uso</a> •
  <a href="#-reportes">Reportes</a> •
  <a href="#-contribuciones">Contribuir</a>
</p>

---

<img width="2062" height="1258" alt="image" src="https://github.com/user-attachments/assets/2f1cc379-f672-429f-978c-d70b1f201fff" />

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Menú Principal](#-menú-principal)
- [Reportes](#-reportes)
- [Configuración Avanzada](#-configuración-avanzada)
- [Solución de Problemas](#-solución-de-problemas)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)
- [Disclaimer](#-️-disclaimer)

---

## 📝 Descripción

**WSTG Scanner** es una herramienta de pentesting web **interactiva y comprehensiva** que implementa las mejores prácticas del [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) y el [OWASP API Top 10](https://owasp.org/API-Security/).

Diseñada para bug bounty hunters y pentesters, automatiza tareas comunes de reconocimiento, análisis y pentesting web:
- 🕷️ Mapeo completo y exhaustivo de aplicaciones web (spidering con detección de formularios e inputs)
- 🔬 **Análisis del código fuente** de páginas y scripts JS expuestos (credenciales, API keys, JWT, claves PEM, comentarios sensibles)
- 🛡️ Análisis de vulnerabilidades con **Nuclei** (10.000+ templates)
- 🔍 Fuzzing rápido de directorios con **ffuf** (pre-filtrado de wordlist + baseline anti-falsos positivos)
- 💉 Pruebas de inyección avanzadas (SQLi, XSS, LFI, RCE, Open Redirect)
- 🔌 Detección y testing de APIs (IDOR, Mass Assignment, GraphQL, JWT, CORS)
- 🔍 **Escaneo de puertos con Nmap** (`-sV` para detección de servicios y versiones)
- 🌐 **Fuzzing de subdominios (vhost)** con `ffuf` y baseline `Content-Length`
 - 🌐 **Fuzzing de subdominios (vhost)** con `ffuf` y baseline `Content-Length`
 - 🧩 **WordPress / WPScan** – Integración opcional con `wpscan` para enumeración de usuarios, detección de plugins/themes vulnerables y ataques dirigidos a instalaciones WordPress.
- 👤 Enumeración de usuarios y emails
- 🔐 Fuerza bruta con **hydra** + fallback CSRF-aware y **autodetección del mensaje de error**
- 📊 Reportes en **TXT, JSON, HTML y Markdown** (con tema light/dark, hallazgos agrupados por categoría)

---

## ⭐ Características

### 🔐 Autenticación
- **Pre-autenticación** – Login automático con credenciales (Basic Auth o formulario)
- **Sesión persistente** – Todas las pruebas posteriores usan la sesión autenticada
- Manejo de cookies y campos hidden (CSRF tokens)

### 🔎 Reconocimiento
- **Información general** – Server, headers, cookies, SSL/TLS, métodos HTTP, robots.txt / sitemap.xml
- **Detección de tecnologías** – Integración con `whatweb` (auto-instalación) con fallback por cabeceras
- **Análisis de cabeceras de seguridad** – HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Seguridad de cookies** – Flags `Secure`, `HttpOnly`, `SameSite`
- **CORS avanzado** – Wildcard + Credentials, origen reflejado, preflight con orígenes maliciosos

### 🔍 Escaneo de Puertos con Nmap
- Ejecuta `nmap -sV` sobre el host del objetivo (extraído de la URL)
- **Auto-instalación de nmap** vía `apt` si no está presente
- Parsing **XML** (`-oX -`) robusto: extrae puerto, protocolo, estado, servicio, producto, versión y `extrainfo`
- Tabla visual con colores por estado (open / open|filtered) al terminar el escaneo
- Cada puerto abierto se registra en `FINDINGS` con prefijo `[PORT]` y queda agrupado en una categoría propia en los reportes
- Timeout configurable (600s por defecto), interrumpible con Ctrl+C

### 🛡️ Análisis de Vulnerabilidades con Nuclei
- **Auto-instalación de Nuclei** vía `apt` si no está presente
- Soporte para `-jsonl-export` (formato actual) con fallback a `-json-export`
- **Deduplicación** automática por `(template_id, url, severity)`
- **Tabla resumen** por severidad y **listado de hallazgos relevantes** (critical/high/medium/low)
- Ruido del backend Interactsh (`Could not unmarshal interaction data`) filtrado
- Resultados integrados directamente en los reportes (TXT/JSON/HTML)

### 🕷️ Spidering
- Crawling BFS configurable (profundidad, número de páginas, respeto a robots.txt)
- Detección de **formularios con inputs reales** (excluye submit/button/file)
- Deduplicación por `(action, method, inputs)` — no infla con el form de login del navbar
- Manejo robusto de redirecciones (`TooManyRedirects` no aborta la fase)
- Resultados reutilizados por las pruebas de inyección y el análisis de código fuente

### 🔬 Análisis del Código Fuente
- **Reutiliza las URLs descubiertas por el spider** (o lanza un spider rápido si no hay datos previos)
- Descarga el HTML de cada página y los recursos enlazados del mismo dominio: **JS, JSON, source maps (`.map`), CSS, YAML, XML, `.env`**
- Cap de **2 MB por archivo** y `stream=True` para evitar descargas masivas
- 15 catálogos de patrones con severidad ponderada:
  - **Critical** – claves PEM privadas, cadenas de conexión de BD con credenciales embebidas
  - **High** – AWS Access Key/Secret, Google API Key, GitHub/Slack/Stripe tokens, JWT, credenciales hardcoded genéricas (`password=`, `api_key=`, `bearer=`, …)
  - **Medium** – comentarios HTML sensibles (`TODO password`, `FIXME admin`, …), Basic Auth en URL, source maps expuestos, IPs privadas (10/8, 172.16/12, 192.168/16)
  - **Low** – rutas internas (`/admin`, `/.git`, `/.env`, `/actuator`, …), emails expuestos
- Los hallazgos **critical/high se vuelcan a `FINDINGS`** con el prefijo `[CODE:SEV]`
- Snippet de **contexto (±30 caracteres)** alrededor de cada coincidencia, deduplicación global por `(tipo, valor, url)`
- Resumen por severidad, tablas visuales, exportación a TXT/JSON/MD/HTML (card dedicado en el reporte)

### 🌐 Fuzzing de Subdominios (VHost)
- **Detección de vhosts** con `ffuf` enviando `Host: FUZZ.<dominio>`
- **Baseline por Content-Length** – envía un Host inválido (`defnotvalid<rnd>.<dominio>`) para obtener el tamaño base y filtrar con `-fs` todas las respuestas que coincidan
- **Autodetección del dominio base** si el target es un FQDN; pide manual si es una IP
- Wordlist por defecto: `Discovery/DNS/namelist.txt` (SecLists)
- Fallback a método interno multihilo si no hay `ffuf`

### 🔀 Fuzzing de Directorios & Enumeración
- **Fuzzing de directorios** con `ffuf` (ultra-rápido) o método interno multihilo
- **Pre-filtrado de wordlist** – descarta comentarios (`#`), líneas vacías y entradas con espacios
- **Filtro `-fs` por baseline** – descarta páginas-comodín (apps que devuelven 200 con el index para cualquier ruta)
- **Auto-calibración** (`-ac`) habilitada
- Wordlist por defecto: `raft-small-directories.txt` (SecLists)
- Tabla con anchos dinámicos y separación por status code

### 💉 Pruebas de Inyección
- **SQLi** – Error-based, time-based blind, boolean-based
- **XSS** – Reflejado con análisis contextual
- **Path Traversal / LFI** – `/etc/passwd`, `win.ini`, encodings y bypass
- **Command Injection** – Linux y Windows
- **Open Redirect** – Detección de redirecciones a hosts arbitrarios
- Reutiliza los formularios e inputs detectados por el spider (eficiente)

---

## 🐘 WordPress & WPScan

Si trabajas con objetivos WordPress, `WPScan` es una herramienta complementaria muy útil para enumeración y pruebas dirigidas. `WSTG Scanner` soporta integración manual (ejecuta `wpscan` por separado y añade los resultados a los reportes), y en futuras versiones se puede automatizar la ejecución desde el propio script.

Qué puedes hacer con `wpscan`:
- Enumerar usuarios descubiertos y rutas de login.
- Detectar versiones de core, plugins y temas.
- Buscar vulnerabilidades conocidas (CVE) en plugins/themes.
- Realizar fuerza bruta del login con wordlists.

Instalación rápida:

```bash
sudo apt install wpscan
# o via gem:
sudo gem install wpscan
```

Ejemplos básicos:

```bash
# Enumeración básica (plugins/themes/users)
wpscan --url https://target.example.com --enumerate ap,at,u

# Fuerza bruta con wordlist
wpscan --url https://target.example.com --usernames admin --passwords /path/to/passwords.txt

# Guardar en JSON para importar al reporte
wpscan --url https://target.example.com -o wpscan-output.json --format json
```

Integración con `WSTG Scanner`:
- Ejecuta `wpscan` y guarda `wpscan-output.json` en `reports/<host>/` para conservar los hallazgos.
- Si quieres que automatice la ejecución de `wpscan` desde `wstg-scan.py`, puedo añadir esa opción (parseo JSON y volcado a `FINDINGS`).

Advertencia legal:
- Solo ejecuta `wpscan` contra objetivos para los que tengas permiso explícito.
### 🔌 Testing de APIs (OWASP API Top 10)
- **Descubrimiento de endpoints** (`/api`, `/swagger`, `/graphql`, `/actuator`, etc.) y parsing de OpenAPI
- **IDOR / BOLA (API1)** – Modificación de IDs numéricos, UUID y parámetros
- **JWT (API2)** – Detección, análisis de `alg`, claims de privilegio, expiración
- **Rate Limiting (API4)** – Comprobación con 20 requests consecutivos
- **Auth Bypass (API5)** – Cabeceras `X-Original-URL`, `X-Forwarded-For`, etc.
- **Mass Assignment (API6)** – Inyección de `is_admin`, `role`, `privilege`
- **Verbose Errors (API7)** – Detección de stack traces y rutas internas
- **CORS / GraphQL (API8)** – Introspección habilitada, enumeración de users

### 👥 Enumeración & Fuerza Bruta
- **Enumeración de usuarios** – Desde APIs (`/api/users`, etc.) y formularios diferenciales
- **Fuerza bruta de contraseñas** – Soporta POST forms y Basic Auth
- **Integración con `hydra`** (`-t 4 -I -u` para fiabilidad y deduplicación)
- **Fallback CSRF-aware** al método interno con `requests.Session` (mantiene cookies y hidden fields)
- **Autodetección del mensaje de error de login** – Envía credenciales imposibles, extrae frases candidatas del HTML y las propone para confirmar
- **Heurística estricta** (≥2 señales positivas) cuando no hay mensaje de error confirmado, para evitar falsos positivos
- Wordlists personalizables, soporta SecLists

### 🎨 Experiencia de Usuario
- **Menú interactivo** con autocompletado de rutas (Tab) en Kali
- **Fases visualmente separadas** con cabeceras `[INFO] ======= ... =======`
- **Tablas box-drawing** unificadas con anchos dinámicos y colores por severidad/status
- **Barras de progreso** para spidering, fuzzing y bruteforce (tqdm)
- **Manejo robusto de Ctrl+C** – Cualquier fase se interrumpe limpiamente, guardando hallazgos parciales

---

## 🔧 Requisitos Previos

| Requisito | Versión | Requerido |
|-----------|---------|----------|
| Python | 3.8+ | ✅ Sí |
| pip | Última | ✅ Sí |
| nmap | Última | ❌ Opcional (auto-instalable, requerido para escaneo de puertos) |
| nuclei | 3.x | ❌ Opcional (auto-instalable) |
| ffuf | Última | ❌ Opcional (mejora el fuzzing) |
| hydra | Última | ❌ Opcional (mejora el bruteforce) |
| whatweb | Última | ❌ Opcional (mejora fingerprinting) |
| wpscan | Última | ❌ Opcional (enumeración y ataques WordPress) |
| SecLists | Última | ❌ Opcional (wordlists) |

### Requisitos del Sistema
- **SO**: Kali Linux (recomendado) o cualquier Debian/Ubuntu con SecLists instalado
- **RAM**: 512 MB mínimo, 2 GB recomendado
- **Almacenamiento**: ~500 MB para dependencias y wordlists
- **Red**: Conexión al objetivo (interna o internet)

---

## 📦 Instalación

### 1️⃣ Instalación rápida (Kali Linux)

```bash
git clone https://github.com/afsh4ck/WSTG-Scan.git
cd WSTG-Scan

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Dependencias Python
pip install -r requirements.txt

# Ejecutar
python3 wstg-scan.py
```

### 2️⃣ Instalación con herramientas opcionales (recomendado para máxima cobertura)

```bash
# Tras los pasos de la instalación rápida:
sudo apt update
sudo apt install -y nmap ffuf hydra whatweb seclists

# Nuclei: usa los binarios oficiales (más recientes que apt)
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# O bien:
sudo apt install -y nuclei
nuclei -update-templates
```

> El script ofrecerá instalar Nuclei, WhatWeb y SecLists automáticamente vía `apt` si no los encuentra.

---

## 🚀 Uso Rápido

### Modo interactivo

```bash
python3 wstg-scan.py
```

Se pedirá la URL objetivo y se mostrará el menú principal.

### Modo argumentos CLI

```bash
python3 wstg-scan.py --url https://example.com --output report.html --threads 10 --timeout 15
```

| Argumento | Descripción |
|---|---|
| `--url, -u` | URL objetivo (omitir para modo interactivo) |
| `--output, -o` | Ruta base del reporte (genera TXT/JSON/HTML) |
| `--threads, -t` | Número de hilos (default: 5) |
| `--timeout` | Timeout por request en segundos (default: 10) |
| `--delay, -d` | Delay entre requests para evasión (default: 0) |
| `--insecure, -k` | Desactiva la verificación TLS (uso en labs / certificados auto-firmados) |
| `--no-color` | Desactiva colores ANSI |
| `--version, -V` | Versión del scanner |

### Pre-autenticación

```bash
python3 wstg-scan.py
# Menú → 1. Configurar autenticación (login)
# Introduce usuario, contraseña y URL de login
# Las siguientes pruebas usarán la sesión autenticada
```

---

## 📋 Menú Principal

```
 _       __       __         _____                   
| |     / /_____ / /_ ____ _/ ___/ _____ ____ _ ____ 
| | /| / // ___// __// __ `/\__ \ / ___// __ `// __ \
| |/ |/ /(__  )/ /_ / /_/ /___/ // /__ / /_/ // / / /
|__/|__//____/ \__/ \__, //____/ \___/ \__,_//_/ /_/ 
                   /____/                            

OWASP Web Security Testing Scanner
developed by @afsh4ck

====================================================
  WSTG SCANNER v1.2.0  [Sin autenticación]
====================================================
 1. Configurar autenticación (login)
 2. Información general y enumeración
 3. Escaneo de puertos con Nmap (-sV)
 4. Análisis de vulnerabilidades con Nuclei
 5. Fuzzing de subdominios (vhost) con ffuf
 6. Fuzzing de directorios (usa ffuf si está instalado)
 7. Spidering / Mapeo completo del sitio
 8. Análisis de código fuente (credenciales/secretos en HTML y JS)
 9. Pruebas de inyección (SQLi, XSS, Path Traversal, Command Injection)
10. Pruebas de API (descubrimiento, IDOR, mass assignment)
11. Enumeración de usuarios/emails y fuerza bruta de contraseñas
12. PENTESTING COMPLETO (ejecuta todas las pruebas anteriores)
15. Salir
==================================================
Selecciona una opción:
```

> Tras ejecutar algún módulo o el pentesting completo aparecen también las opciones **13** (`Mostrar resumen en Markdown`) y **14** (`Mostrar tablas de resultados`) para revisar el resumen sin volver a escanear.

> La opción **12** ejecuta secuencialmente: información → **Nmap** → Nuclei → **vhost** → fuzzing dirs → spidering → **análisis de código fuente** → inyección → API → bruteforce, y muestra al final el resumen visual con todas las tablas. Al salir, se ofrece guardar el reporte.
>
> Las opciones **13** y **14** sirven para revisar el resumen tras un escaneo: la 13 imprime todo en Markdown (listo para pegar en GitBook/GitHub) y la 14 reimprime las tablas con el formato visual box-drawing.

---

## 📊 Reportes

Los reportes se generan automáticamente en `reports/<host>/<host>.{txt,json,html,md}` con cuatro formatos:

| Formato | Contenido |
|---|---|
| `*.txt` | Resumen plano + secciones por categoría (general, vhost, spider, **análisis de código fuente**, API, directorios, credenciales, hallazgos, Nuclei) |
| `*.json` | Datos serializados completos (ideal para integración con otras herramientas) |
| `*.html` | Reporte visual con tema **light/dark**, hallazgos agrupados por categoría, tabla detallada de Nuclei, tecnologías como chips |
| `*.md`  | Resumen completo en **Markdown** estándar — copia/pega directo en GitBook, GitHub o Obsidian |

### Estructura del reporte HTML
- **Resumen** – KPIs (hallazgos, tecnologías, endpoints, vhosts, **puertos**, directorios, usuarios, credenciales, **hallazgos en código fuente**)
- **Información general** – Server, status, tecnologías (chips), usuarios y emails
- **Escaneo de puertos (Nmap)** – Tabla con `puerto / estado / servicio / versión` + comando y host usados
- **Hallazgos** – Agrupados en bloques colapsables por categoría (Vulnerabilidades / Nuclei por severidad / Puertos / Subdominios / Directorios / etc.)
- **Análisis Nuclei** – Resumen por severidad + tabla detallada (sin duplicados)
- **Endpoints API descubiertos** – Tabla con status/endpoint/URL/content-type
- **Subdominios (vhosts) descubiertos** – Tabla con status/fqdn/tamaño
- **Directorios encontrados** – Tabla con status/URL/tamaño
- **Credenciales válidas** – Si el bruteforce tuvo éxito
- **Spidering** – Muestra de URLs descubiertas
- **Análisis de código fuente** – KPIs por severidad y tabla con `severidad / tipo / valor detectado / URL / contexto`

---

## ⚙️ Configuración Avanzada

### Personalizar wordlists

Edita las constantes en `wstg-scan.py`:

```python
SECLISTS_SMALL     = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
SECLISTS_MEDIUM    = "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
SECLISTS_PASSWORDS = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
```

### Parámetros de red y concurrencia

```python
DEFAULT_TIMEOUT = 10   # segundos por request
MAX_REDIRECTS   = 10   # redirecciones máximas seguidas
THREADS         = 5    # hilos concurrentes
REQUEST_DELAY   = 0.0  # delay entre requests
```

### Usar Burp Suite como proxy

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python3 wstg-scan.py
```

---

## 🐛 Solución de Problemas

### `ModuleNotFoundError: No module named 'requests'`
```bash
pip install -r requirements.txt
```

### `ffuf: command not found`
```bash
sudo apt install -y ffuf
```

### Nuclei se queda colgado o emite muchos errores Interactsh
Es ruido del backend OAST. El script filtra los `Could not unmarshal interaction data`. Para desactivar Interactsh completamente, edita la llamada a Nuclei y añade `-ni`.

### El bruteforce no encuentra ciertas credenciales
Hydra no maneja CSRF tokens ni sesiones; el script detectará los usuarios pendientes y caerá al método interno (CSRF-aware con `requests.Session`). Si aun así no las encuentra, comprueba account lockout o rate limiting en el servidor.

### Spidering se queda en pocas páginas
Si ves `Exceeded N redirects`, el target tiene cadenas de redirección largas. Sube `MAX_REDIRECTS` en el script.

---

## 📚 Recursos Útiles

- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) – Guía oficial
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [ffuf](https://github.com/ffuf/ffuf) – Web fuzzer
- [hydra](https://github.com/vanhauser-thc/thc-hydra) – Fuerza bruta
- [SecLists](https://github.com/danielmiessler/SecLists) – Listas para pentesting

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas!

1. **Fork** el repositorio
2. Crea una rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Abre un **Pull Request**

### Áreas para Contribuir
- [ ] Imagen Docker oficial
- [ ] Reportes en PDF
- [ ] Tests automatizados (pytest)
- [ ] Soporte WebSocket / Server-Sent Events
- [ ] Plugins de detección de WAF
- [ ] Interfaz gráfica (TUI con Textual)

---

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Ver [LICENSE](LICENSE) para detalles.

---

## 👨‍💻 Autor

**afsh4ck** – Offensive Security Engineer | Pentester

- 🐙 GitHub: [@afsh4ck](https://github.com/afsh4ck)
- 🔗 LinkedIn: [afsh4ck](https://linkedin.com/in/afsh4ck)

---

## ⚠️ Disclaimer

**IMPORTANTE**: Esta herramienta solo debe usarse en sistemas donde tienes permiso explícito para realizar testing de seguridad.

- ❌ **El uso no autorizado es ILEGAL**
- ❌ El autor **NO se hace responsable** del mal uso
- ⚠️ Respeta leyes locales e internacionales
- ✅ Siempre obtén consentimiento escrito antes de testar

```
"This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal."
```

---

<div align="center">

⭐ Si te resulta útil, ¡dale una estrella! ⭐

</div>

---

### Agradecimientos
- [OWASP](https://owasp.org/) por la guía WSTG y el API Top 10
- [ProjectDiscovery](https://github.com/projectdiscovery) por Nuclei
- [Daniel Miessler](https://github.com/danielmiessler) por SecLists
- [van Hauser](https://github.com/vanhauser-thc) por Hydra
ras de progreso, control de errores elegante, mensajes claros y visibles.
- **Configuración avanzada**: Personalización de wordlists, timeout, hilos, delay, uso de proxies, etc.
- **Código limpio y modular**: Fácil de mantener y extender.

---

<div align="center">

⭐ Si te fue útil, ¡dale una estrella! ⭐

</div>

Licencia
MIT License.

Agradecimientos
OWASP por la guía WSTG.

Daniel Miessler por SecLists.
