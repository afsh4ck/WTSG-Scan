# 🔐 OWASP WSTG Security Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)

**Herramienta interactiva y completa de pruebas de seguridad web** basada en la metodología OWASP WSTG.

[Características](#-características) • [Instalación](#-instalación) • [Uso](#-uso) • [Ejemplos](#-ejemplos) • [Contribuir](#-contribuciones)

</div>

---

<img width="1855" height="1019" alt="image" src="https://github.com/user-attachments/assets/c6e2449a-a8c6-44c9-a306-56684d2a5239" />


## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Menú Principal](#-menú-principal)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Configuración Avanzada](#-configuración-avanzada)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)
- [Disclaimer](#-⚠️-disclaimer)

---

## 📝 Descripción

**WSTG Scanner** es una herramienta de pentesting web **interactiva y comprehensive** que implementa las mejores prácticas del [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/). 

Diseñada para security researchers y pentesters, automatiza tareas comunes de reconocimiento y testing como:
- 🕷️ Mapeo completo de aplicaciones web
- 🔍 Fuzzing de directorios y endpoints
- 💉 Pruebas de inyección avanzadas
- 🔌 Detección y testing de APIs
- 👤 Enumeración de usuarios
- 🔐 Ataques de fuerza bruta

---

## ⭐ Características

### 🔎 Reconocimiento
- **Spidering completo** – Mapeo exhaustivo de la aplicación (enlaces, formularios, parámetros)
- **Respeto a robots.txt** – Escaneo responsable de aplicaciones
- **Detección de tecnologías** – Identifica servidores, frameworks y versiones

### 🔀 Fuzzing & Enumeración
- **Fuzzing de directorios** – Integración con `ffuf` (ultra-rápido) o método interno con progreso visual
- **Enumeración de cabeceras** – Análisis de headers de seguridad
- **Descubrimiento de cookies** – Análisis de seguridad en cookies
- **Detección de métodos HTTP** – Identifica métodos permitidos

### 💉 Pruebas de Inyección
- **SQLi (SQL Injection)**
  - Error-based detection
  - Time-based blind SQLi
  - Boolean-based blind SQLi
- **XSS (Cross-Site Scripting)**
  - XSS reflejado
  - Análisis contextual
- **Path Traversal / LFI** – Acceso a archivos del sistema
- **Command Injection** – Ejecución de comandos
- **Open Redirect** – Detección de redireccionamientos maliciosos

### 🔌 Testing de APIs
- **Descubrimiento de endpoints** – Busca `/api`, `/swagger`, `/graphql`, etc.
- **IDOR (Insecure Direct Object Reference)** – Modificación de IDs
- **Mass Assignment** – Inyección de parámetros
- **Errores verbose** – Detección de información sensible en errores
- **Token analysis** – Análisis de tokens y autenticación

### 👥 Enumeración & Fuerza Bruta
- **Enumeración de usuarios** – Desde APIs, endpoints comunes y diferencia en respuestas
- **Fuerza bruta de contraseñas** – Soporta POST forms y Basic Auth
- **Wordlists personalizables** – Compatible con SecLists
- **Control de velocidad** – Throttling configurable

### 🔐 Autenticación
- **Pre-autenticación** – Login automático con credenciales
- **Testing de áreas restringidas** – Mantiene sesión durante todos los tests
- **Manejo de cookies y tokens** – Preserva estado de sesión

### 🎨 Experiencia de Usuario
- **Menú interactivo** – Interfaz colorida y fácil de usar
- **Barras de progreso** – Visualización clara del progreso
- **Control de errores** – Manejo elegante de `Ctrl+C`
- **Reportes claros** – Salida estructurada y legible

---

## 🔧 Requisitos Previos

| Requisito | Versión | Requerido |
|-----------|---------|----------|
| Python | 3.6+ | ✅ Sí |
| pip | Última | ✅ Sí |
| ffuf | Última | ❌ Opcional (mejora rendimiento) |
| SecLists | Última | ❌ Opcional (wordlists) 

### Requisitos del Sistema
- **RAM**: Mínimo 512 MB, recomendado 2 GB
- **Almacenamiento**: 500 MB para dependencias
- **Red**: Conexión a internet
- **SO**: Kali Linux

---

## 📦 Instalación
### 1️⃣ Opción A: Instalación Rápida (Recomendado)

```bash
# Clonar repositorio
git clone https://github.com/afsh4ck/WTSG-Scan.git
cd WTSG-Scan

# Crear entorno virtual (opcional pero recomendado)
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias Python
pip install -r requirements.txt

# ¡Listo! Ejecutar
python3 wstg-scanner.py
```

### 2️⃣ Opción B: Instalación Completa (Con Herramientas Opcionales)

```bash
# Clonar y entrar
git clone https://github.com/afsh4ck/WTSG-Scan.git
cd WTSG-Scan

# Entorno virtual
python3 -m venv venv
source venv/bin/activate

# Dependencias Python
pip install -r requirements.txt

# Instalar ffuf (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y build-essential
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz
tar -xvf ffuf_2.1.0_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/

# Instalar SecLists (opcional)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### 3️⃣ Opción C: Docker (Próximamente)

```bash
docker pull wstg-scanner:latest
docker run -it wstg-scanner:latest
```

---

## 🚀 Uso Rápido

### Ejecución Básica

```bash
python3 wstg-scanner.py
```

Se abrirá un menú interactivo pidiendo:
1. **URL objetivo** (ej: `https://example.com`)
2. **Opción de test** (ver menú principal abajo)

### Con Autenticación

```bash
python3 wstg-scanner.py
# En el menú selecciona: "8. Configurar autenticación"
# Ingresa usuario y contraseña
# Luego ejecuta los tests que necesites
```

---

## 📋 Menú Principal

El scanner ofrece las siguientes opciones:

```
┌─ WSTG SCANNER - MENÚ PRINCIPAL ─┐
│                                  │
│ 1. Información General           │ -> Servidores, headers, SSL/TLS
│ 2. Fuzzing de Directorios        │ -> Descubre endpoints ocultos
│ 3. Pruebas de Inyección          │ -> SQLi, XSS, LFI, etc.
│ 4. Pruebas de API                │ -> IDOR, Mass Assignment
│ 5. Enumeración de Usuarios       │ -> Detecta usuarios válidos
│ 6. Fuerza Bruta de Contraseñas   │ -> Ataque de passwords
│ 7. Spidering                     │ -> Mapeo de la aplicación
│ 8. Pentesting Completo           │ -> Ejecuta TODOS los tests
│ 9. Configurar Autenticación      │ -> Login previo
│ 0. Salir                         │ -> Cierra la aplicación
│                                  │
└──────────────────────────────────┘
```

---

## 💡 Ejemplos de Uso

### Ejemplo 1: Test Básico de Seguridad

```bash
$ python3 wstg-scanner.py
Ingresa la URL objetivo: https://testphp.vulnweb.com

Menú Principal:
[1] Información General
Ejecutando...
[+] Servidor: Apache/2.4.41 (Ubuntu)
[+] Headers de seguridad detectados...
```

### Ejemplo 2: Fuzzing de Directorios

```
Menú Principal:
[2] Fuzzing de Directorios
Ingresa wordlist (default: directory-list-2.3-small.txt): 
[✓] /admin
[✓] /api
[✓] /uploads
[✓] /backup
```

### Ejemplo 3: Pruebas de Inyección SQL

```
Menú Principal:
[3] Pruebas de Inyección
Selecciona tipo de inyección:
[1] SQLi
[2] XSS
[3] Path Traversal
[...] 

Ejecutando SQLi...
[!] Posible SQLi en parámetro 'id'
[!] Type: Time-based blind
```

### Ejemplo 4: Pentesting Completo (Recomendado)

```
Menú Principal:
[8] Pentesting Completo
Ejecutando todos los tests...
[████████████████░░░░] 60%
```

---

## ⚙️ Configuración Avanzada

### Personalizar Wordlists

Edita `wstg-scanner.py` y busca estas variables:

```python
DEFAULT_DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
DEFAULT_PASS_WORDLIST = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
```

### Timeout y Velocidad

```python
REQUEST_TIMEOUT = 10  # segundos
THREADING_WORKERS = 10  # hilos simultáneos
FUZZING_DELAY = 0.1  # segundos entre requests
```

### Configurar Proxies

```bash
# Para usar Burp Suite como proxy
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python3 wstg-scanner.py
```

---

## 📊 Estructura del Proyecto

```
wstg-scanner/
├── README.md                 # Este archivo
├── requirements.txt          # Dependencias Python
├── wstg-scanner.py          # Script principal
├── LICENSE                   # Licencia MIT
└── examples/                # Ejemplos de uso
    ├── basic_scan.md
    ├── authenticated_scan.md
    └── full_pentest.md
```

---

## 🐛 Solución de Problemas

### Error: `ModuleNotFoundError: No module named 'requests'`

```bash
pip install -r requirements.txt
```

### Error: `ffuf: command not found`

Instala ffuf manualmente desde [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)

### Scanner lento

- Reduce el número de hilos: Edita `THREADING_WORKERS = 5`
- Aumenta el delay: `FUZZING_DELAY = 0.2`
- Usa `-k` para ignorar advertencias SSL

---

## 📚 Recursos Útiles

- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) - Guía oficial de OWASP
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Top 10 vulnerabilidades
- [ffuf Docs](https://github.com/ffuf/ffuf) - Documentación de ffuf
- [SecLists](https://github.com/danielmiessler/SecLists) - Listas útiles para pentesting

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Para contribuir:

1. **Fork** el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un **Pull Request**

### Áreas para Contribuir
- [ ] Integración con Docker
- [ ] Reportes en PDF/HTML
- [ ] Testing automatizado
- [ ] Traducción a otros idiomas
- [ ] Mejora de wordlists
- [ ] Interfaz gráfica (GUI)

---

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Ver [LICENSE](LICENSE) para detalles.

---

## 👨‍💻 Autor

**afsh4ck** - Security Researcher & Penetration Tester

- 🐙 GitHub: [@afsh4ck](https://github.com/afsh4ck)
- 🔗 LinkedIn: [afsh4ck](https://linkedin.com/in/afsh4ck)
- 📧 Email: afsh4ck@protonmail.com

---

## ⚠️ Disclaimer

**IMPORTANTE**: Esta herramienta solo debe usarse en sistemas donde tienes permiso explícito para realizar testing de seguridad. 

- ❌ **Uso no autorizado es ILEGAL**
- ❌ El autor **NO se hace responsable** del mal uso
- ⚠️ Respeta leyes locales e internacionales
- ✅ Siempre obtén consentimiento escrito antes de testar

```
"This tool is for authorized security testing only.
Unauthorized access to computer systems is illegal."
```

---

## 🚀 Funcionalidades

- **Reconocimiento avanzado**: Spidering, detección de tecnologías (WhatWeb), análisis de headers, cookies y métodos HTTP.
- **Fuzzing de directorios**: Integración con ffuf (opcional) y método interno, con guardado automático y parcial de resultados en caso de interrupción.
- **Pruebas de inyección**: SQLi (error/time/boolean), XSS, Path Traversal/LFI, Command Injection, Open Redirect. Cada payload se detiene en el primer hallazgo por parámetro/input para máxima eficiencia.
- **Manejo robusto de Ctrl+C**: Puedes interrumpir cualquier prueba (fuzzing, inyección, Nuclei, etc.) y se guardan los resultados encontrados hasta ese momento.
- **Testing de APIs**: Descubrimiento de endpoints, pruebas de IDOR, Mass Assignment, errores verbose, análisis de tokens y autenticación.
- **Enumeración y fuerza bruta**: Detección de usuarios, fuerza bruta de contraseñas (POST y Basic Auth), wordlists personalizables.
- **Autenticación avanzada**: Login previo, testing de áreas restringidas, manejo de cookies/tokens, mantiene sesión en todos los tests.
- **Integración con Nuclei**: Análisis de vulnerabilidades con plantillas Nuclei, resumen por severidad y template, integración directa en reportes.
- **Reportes claros y completos**: Generación automática de reportes TXT, JSON y HTML (modo light/dark), con tablas dinámicas de tecnologías, directorios, endpoints, credenciales, etc. Los reportes se guardan en `/reports/<host>`.
- **Tablas y visualización dinámica**: Tablas HTML adaptativas para tecnologías, directorios, endpoints, credenciales, etc. Siempre se muestran aunque no haya hallazgos.
- **Experiencia de usuario mejorada**: Menú interactivo, mensajes coloridos, barras de progreso, control de errores elegante, mensajes claros y visibles.
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
