# Registro de cambios

## Sin publicar - 2026-05-16

- Se anadio deteccion automatica de WordPress en el flujo de pentesting completo: primero se revisan los resultados de WhatWeb y despues se usa deteccion manual por patrones antes de ejecutar WPScan.
- Se anadieron senales de deteccion manual de WordPress para `wp-content`, `wp-includes`, `wp-json`, `wp-login.php`, `xmlrpc.php`, metadatos `generator` y assets comunes de WordPress.
- Se mantiene la ejecucion directa de WPScan desde la opcion manual de WordPress.
- Se anadio salida CLI nativa de WPScan durante la enumeracion y la fuerza bruta de WordPress, conservando el parseo JSON estructurado para el resumen final.
- Se amplio el resumen de WordPress con version del core, plugins, temas, usuarios, hallazgos interesantes, vulnerabilidades y credenciales.
