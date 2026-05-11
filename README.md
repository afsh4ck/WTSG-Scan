# OWASP WSTG Security Scanner

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Herramienta interactiva de pruebas de seguridad web basada en la metodología **OWASP Web Security Testing Guide (WSTG)**. Realiza enumeración, fuzzing, pruebas de inyección (SQLi, XSS, Command Injection), spidering, detección de API, enumeración de usuarios y fuerza bruta de contraseñas.

![Banner](https://raw.githubusercontent.com/tuusuario/wstg-scanner/main/banner.png) *(opcional)*

## Características

- **Spidering completo** – Mapeo de toda la aplicación (enlaces, formularios) respetando `robots.txt`.
- **Fuzzing de directorios** – Usa `ffuf` si está instalado (rápido) o método interno con barra de progreso.
- **Pruebas de inyección**:
  - SQLi (error‑based, time‑based, boolean blind)
  - XSS (reflejado y contextual)
  - Path Traversal / LFI
  - Command Injection
  - Open Redirect
- **Pruebas de API**:
  - Descubrimiento de endpoints (`/api`, `/swagger`, etc.)
  - IDOR (modificación de IDs)
  - Mass Assignment
  - Errores verbose
- **Enumeración**:
  - Cabeceras de seguridad, cookies, métodos HTTP
  - Tecnologías (PHP, ASP.NET, etc.)
  - Emails y usuarios (desde APIs o endpoints comunes)
  - Enumeración de usuarios por diferencia en formularios de login
- **Fuerza bruta de contraseñas** – Con wordlist personalizada o por defecto (SecLists). Soporta formularios POST y Basic Auth.
- **Autenticación previa** – Login con credenciales para probar áreas restringidas.
- **Interfaz interactiva** – Menú principal con colores y barras de progreso.
- **Control de errores** – Captura `Ctrl+C` y muestra mensaje `Happy Hacking :)`.

## Requisitos

- Python 3.6 o superior
- Opcional: `ffuf` instalado en el sistema para fuzzing ultra rápido.
- Opcional: SecLists (se puede instalar automáticamente desde el script con `sudo`).

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tuusuario/wstg-scanner.git
   cd wstg-scanner```
Instala las dependencias Python:

```bash
pip install -r requirements.txt```
(Opcional) Instala ffuf (recomendado):

bash
sudo apt install ffuf   # Debian/Ubuntu
# o descarga desde https://github.com/ffuf/ffuf
Uso
Ejecuta el script:

bash
python3 wstg_scanner.py
Sigue las instrucciones en pantalla para introducir la URL objetivo y seleccionar una opción del menú.

Menú principal
Información general – Servidor, tecnologías, cabeceras, cookies, SSL/TLS, etc.

Fuzzing de directorios – Usa ffuf (si disponible) o método interno.

Pruebas de inyección – SQLi, XSS, Path Traversal, Command Injection.

Pruebas de API – Descubre endpoints, IDOR, Mass Assignment.

Enumeración de usuarios y fuerza bruta – Detecta usuarios y prueba contraseñas.

Spidering – Mapea todo el sitio web (enlaces y formularios).

Pentesting completo – Ejecuta todas las pruebas anteriores.

Configurar autenticación – Inicia sesión en la aplicación antes de las pruebas.

Salir

Ejemplo de fuerza bruta
Si la web tiene un formulario de login en /account/login, el script lo detectará automáticamente. Puedes usar un diccionario de contraseñas como:

text
/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt
Personalización
Wordlist de directorios por defecto: directory-list-2.3-small.txt (SecLists). Se puede cambiar en el menú.

Wordlist de contraseñas por defecto: xato-net-10-million-passwords-10000.txt (SecLists). Si no existe, usa una lista pequeña interna.

Capturas de pantalla
(Puedes añadir capturas mostrando el menú, el fuzzing con ffuf, el progreso del spidering, etc.)

Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue o pull request con tus mejoras.

Advertencia
Esta herramienta solo debe usarse en sistemas con autorización explícita. El uso no autorizado es ilegal y el autor no se hace responsable del mal uso.

Licencia
MIT License.

Agradecimientos
OWASP por la guía WSTG.

Daniel Miessler por SecLists.
