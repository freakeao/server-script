# Documentación: Script de Seguridad Debian 13 (Trixie)

**Creado por: Victor Leon**

Este script ha sido diseñado para automatizar el proceso de auditoría y fortalecimiento de seguridad (hardening) en servidores Debian 13, basado en las mejores prácticas de la comunidad y la guía "How-To-Secure-A-Linux-Server".

---

## 🚀 Inicio Rápido

1. **Requisitos**: Debian 13 y privilegios de `root`.
2. **Configuración**: Abre `harden.sh` y edita la **Sección de Variables** al inicio con tu usuario administrador deseado (`SUDO_USER`) y otros ajustes.
3. **Descarga**: Coloca el script en tu servidor.
4. **Permisos**: `chmod +x harden.sh`
5. **Ejecución**: `sudo ./harden.sh`

---

## 🛠️ ¿Cómo funciona el script?

El script está diseñado para priorizar la **configuración mediante variables**. Lo ideal es que definas tus preferencias (usuario, puerto, IP) directamente en el código antes de ejecutarlo. De esta forma, el script solo te pedirá confirmaciones mínimas durante el proceso.

### 📋 Módulos de Seguridad

#### 1. Conceptos Básicos y Actualización
*   **Qué hace**: Actualiza el sistema operativo y descarga herramientas de seguridad (`ufw`, `fail2ban`, `lynis`, `rkhunter`).
*   **Por qué**: Un servidor desactualizado es vulnerable a exploits conocidos. Las herramientas descargadas son los cimientos de la defensa.

#### 2. Aseguramiento de Usuarios (No-Root)
*   **Qué hace**: Crea un usuario administrador personalizado y lo añade al grupo de privilegios (`sudo`).
*   **Por qué**: Usar la cuenta `root` para tareas diarias es peligroso. Un usuario limitado con `sudo` añade una capa de registro y previene errores fatales.

#### 3. Fortalecimiento de SSH
*   **Qué hace**: Cambia el puerto SSH (del 22 a uno personalizado), deshabilita el login de `root`, y restringe el acceso a usuarios específicos.
*   **Por qué**: La mayoría de los bots atacan el puerto 22. Cambiarlo y bloquear a `root` detiene ataques de fuerza bruta automatizados.

#### 4. Seguridad de Red (Firewall y Detección)
*   **Qué hace**: Configura `UFW` (firewall) y `Fail2Ban`. Añade **PSAD** para detectar escaneos de puertos y permite activar un modo de tráfico saliente estricto.
*   **Por qué**: Un firewall cierra puertas, PSAD detecta si alguien está "tanteando" esas puertas para encontrar debilidades.

#### 5. Refuerzos Extra (PAM y Auditd)
*   **Qué hace**: Configura políticas de contraseñas robustas (PAM) y habilita el registro de eventos del sistema (Auditd).
*   **Por qué**: Las contraseñas fuertes son la primera defensa y Auditd registra cambios críticos para auditoría forense.

#### 6. Antivirus (ClamAV)
*   **Qué hace**: Instala y configura el antivirus ClamAV para escanear el sistema en busca de malware.
*   **Por qué**: Aunque el servidor sea Linux, el antivirus detecta troyanos y archivos maliciosos que podrían afectar a otros sistemas.

#### 7. Fortalecimiento del Sistema (Núcleo y Parches)
*   **Qué hace**: Ajusta parámetros de `sysctl` para mitigar ataques de red avanzados y activa actualizaciones automáticas de seguridad.
*   **Por qué**: Protege contra ataques de red de bajo nivel y asegura que el sistema siempre tenga los últimos parches de seguridad.

#### 8. Monitoreo y Auditoría
*   **Qué hace**: Configura reportes diarios por email (Logwatch) y realiza escaneos de rootkits (`rkhunter`).
*   **Por qué**: Permite una vigilancia continua para reaccionar rápido ante cualquier anomalía.

---

---

## 🔍 Auditoría Inteligente y Puntuación (Scoring)

El script incluye un sistema de **puntuación de 0 a 100** (Opción 1) que evalúa tu servidor y el estado de tu software:
- **Gestión de Software**: La opción `i` detecta exactamente qué herramientas te faltan y las instala automáticamente.
- **Diagnóstico Preciso**: Explica el **Riesgo** técnico de cada fallo.
- **Nivel de Blindaje**: Clasifica tu servidor como Crítico, Medio o Seguro.

## 🛠️ Herramientas de Vanguardia Incluidas

Además de los básicos, el script integra:
- **AIDE (Advanced Intrusion Detection Environment)**: Para verificar la integridad de los archivos del sistema.
- **Sysstat**: Para monitoreo avanzado de rendimiento y procesos.
- **Log Banners**: Una interfaz visual mejorada mediante banners que te guían paso a paso de forma intuitiva.

---

## ⚙️ Configuración de Variables

Al inicio de `harden.sh` encontrarás una sección de variables. **Es fundamental revisarlas antes de ejecutar el script completo:**

| Variable | Descripción | Recomendación |
| :--- | :--- | :--- |
| `SUDO_USER` | Usuario administrador | No usar 'admin' o 'user'. Usar algo único. |
| `SUDO_GROUP` | Grupo de privilegios | En Debian es 'sudo'. |
| `SSH_PORT` | Puerto de acceso SSH | Elegir un número entre 1024 y 65535. |
| `SSH_LISTEN_IP` | IP de escucha SSH | Usar `0.0.0.0` para todas o una IP de red privada. |
| `ENABLE_PSAD` | Detección de escaneos | Muy recomendado. |
| `ENABLE_CLAMAV` | Antivirus ClamAV | Opcional (usa mucha RAM). |
| `ENABLE_AUDITD` | Auditoría de sistema | Recomendado para servidores críticos. |
| `ENABLE_PWQUALITY` | Calidad de passwords | Recomendado para forzar passwords seguros. |
| `STRICT_OUTGOING`| Salida restringida | Opcional (puede bloquear apps). |

---

## 🛡️ Mejores Prácticas y Consejos

1.  **Prueba antes de cerrar**: Nunca cierres tu terminal actual después de cambiar el puerto SSH. Abre una nueva ventana e intenta entrar con el nuevo puerto: `ssh -p <PUERTO> usuario@ip`.
2.  **Modo Auditoría**: Usa la opción 1 del menú para diagnóstico inicial sin riesgo.
3.  **Interfaces Múltiples**: Si tu servidor tiene IP pública y privada, considera configurar `SSH_LISTEN_IP` con la IP privada para máxima seguridad.
4.  **Passwords**: Tras ejecutar el script, asegúrate de que tu `SUDO_USER` tiene una contraseña robusta (`sudo passwd usuario`).

---

## 📄 Bitácora (Logs)
El script guarda un registro detallado de todas sus acciones en `/var/log/harden_script.log`. Puedes consultarlo si algo no funciona como esperas.
