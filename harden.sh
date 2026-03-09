#!/bin/bash

################################################################################
# Script de Auditoría y Fortalecimiento de Seguridad para Debian 13 (Trixie)
# Creado por: Victor Leon
# Basado en: https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
################################################################################

# ==============================================================================
# 0. SECCIÓN DE VARIABLES (CONFIGURACIÓN)
# ==============================================================================
# Modifica estas variables según tus necesidades antes de ejecutar el script.

# --- Usuario y Acceso ---
SUDO_USER="admin"               # El usuario que tendrá privilegios de administrador
SUDO_GROUP="sudo"               # Nombre del grupo administrativo (por defecto 'sudo' en Debian)
SSH_PORT="2222"                # Nuevo puerto SSH (se recomienda cambiar el 22 por defecto)
SSH_LISTEN_IP="0.0.0.0"        # IP en la que escuchará SSH (0.0.0.0 para todas)
SSH_INTERFACE="all"            # Interfaz de red (se detectará en el proceso completo)
ALLOWED_SSH_USERS="admin"      # Lista de usuarios permitidos para SSH (separados por espacio)

# --- Nginx y Web ---
CHECK_NGINX=true               # Verificar seguridad de Nginx si está instalado
NGINX_CONF="/etc/nginx/nginx.conf"

# --- Red y Cortafuegos ---
ENABLE_UFW=true                # Define si se debe habilitar el cortafuegos UFW
SSH_INBOUND_IP="any"           # Restringir SSH a esta IP (ej: "192.168.1.50" o "any" para todos)

# --- Monitoreo y Defensa ---
ADMIN_EMAIL="root@localhost"   # Correo para recibir reportes de Logwatch y alertas
ENABLE_FAIL2BAN=true           # Define si se instala y configura Fail2Ban (prevención de intrusos)
ENABLE_PSAD=true               # Detectar escaneos de puertos con PSAD
ENABLE_CLAMAV=false            # Instalar antivirus ClamAV (consume memoria)
ENABLE_AUDITD=true             # Habilitar auditoría del sistema (auditd)
ENABLE_PWQUALITY=true          # Forzar calidad de contraseñas con PAM

# --- Sistema y Red ---
AUTO_UPGRADES=true             # Habilitar actualizaciones automáticas de seguridad
TIMEZONE="UTC"                 # Zona horaria del sistema
STRICT_OUTGOING=false          # ¿Restringir tráfico saliente? (Solo permite DNS, NTP, HTTP/S)

# --- Configuración del Script ---
LOG_FILE="/var/log/harden_script.log"
VERBOSE=true
SCORE_TOTAL=0
MAX_SCORE=100

# ==============================================================================
# 1. UTILIDADES Y DEFINICIÓN DE COLORES
# ==============================================================================

# Colores para una salida más legible en terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color (Reset)

# Función para mostrar banners visuales impactantes
log_banner() {
    echo -e "${YELLOW}"
    echo "################################################################"
    echo "# $1"
    echo "################################################################"
    echo -e "${NC}"
}

# Funciones de registro (Logging) adaptadas
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[ADVERTENCIA]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# Verifica que el script se ejecute con privilegios de superusuario
check_root() {
    if [[ $EUID -ne 0 ]]; then
       log_error "Este script debe ejecutarse como root (root)."
       exit 1
    fi
}

# ==============================================================================
# 2. FUNCIONES DE UTILIDAD Y DIAGNÓSTICO
# ==============================================================================

# Función para verificar el estado de un parámetro o servicio
# Uso: check_status "Descripción" "comando_de_verificación"
check_status() {
    local desc="$1"
    local cmd="$2"
    
    echo -n -e "Verificando: $desc... "
    if eval "$cmd" >/dev/null 2>&1; then
        log_success "Cumple"
        return 0
    else
        log_warn "No Cumple"
        return 1
    fi
}

# Helper para verificar si un paquete está instalado
is_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

# Helper para instalar solo si falta o bajo confirmación
install_package() {
    if is_installed "$1"; then
        log_info "El paquete '$1' ya está instalado."
    else
        log_warn "El paquete '$1' NO está instalado."
        read -p "¿Deseas instalar '$1' ahora? (s/n): " confirm
        if [[ $confirm == "s" ]]; then
            apt-get install -y "$1"
            log_success "'$1' instalado con éxito."
        fi
    fi
}

# Nueva función para detectar y seleccionar interfaces de red
select_network_interface() {
    echo -e "\n--- Detección de Interfaces de Red ---"
    local interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"))
    local i=1
    
    echo "Se han detectado las siguientes interfaces:"
    for iface in "${interfaces[@]}"; do
        local ip_addr=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo "$i) $iface (IP: ${ip_addr:-"Sin IP"})"
        ((i++))
    done
    echo "0) Usar todas las interfaces (0.0.0.0)"
    
    read -p "Selecciona la interfaz para SSH [0-${#interfaces[@]}]: " choice
    if [[ "$choice" -gt 0 && "$choice" -le "${#interfaces[@]}" ]]; then
        SSH_INTERFACE="${interfaces[$((choice-1))]}"
        SSH_LISTEN_IP=$(ip -4 addr show "$SSH_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        log_success "Se usará la interfaz '$SSH_INTERFACE' con la IP '$SSH_LISTEN_IP'."
    else
        SSH_LISTEN_IP="0.0.0.0"
        SSH_INTERFACE="all"
        log_info "Se escuchará en todas las interfaces (0.0.0.0)."
    fi
}

# ==============================================================================
# 3. MÓDULOS DE SEGURIDAD
# ==============================================================================

# Sección 1: Gestión de Herramientas y Preparación
module_system_basics() {
    log_banner "SECCIÓN 1: ACTUALIZACIÓN Y HERRAMIENTAS ESENCIALES"
    echo -e "En esta etapa actualizaremos el sistema y aseguraremos que todo el software de"
    echo -e "seguridad esté presente. Sin estas herramientas, el blindaje no es posible.\n"
    
    log_info "Actualizando repositorios y sistema..."
    apt-get update && apt-get upgrade -y
    
    verify_and_install_essential_tools
    
    if is_installed "aide"; then
        log_info "Inicializando base de datos de AIDE (File Integrity)..."
        aideinit --force --quiet
    fi

    log_info "Configurando zona horaria a $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE"
    
    log_success "Preparación básica completada."
}

# Nueva función para verificar e instalar todo el software necesario de una vez
verify_and_install_essential_tools() {
    log_banner "AUDITORÍA DE SOFTWARE NECESARIO"
    local tools=("sudo" "curl" "vim" "git" "ufw" "fail2ban" "unattended-upgrades" "logwatch" "lynis" "rkhunter" "chkrootkit" "auditd" "psad" "libpam-pwquality" "apticron" "aide" "sysstat")
    local missing_tools=()

    echo -e "Estado de las herramientas de seguridad:\n"
    for tool in "${tools[@]}"; do
        if is_installed "$tool"; then
            echo -e "  [${GREEN}INSTALADO${NC}] $tool"
        else
            echo -e "  [${RED}FALTA${NC}] $tool"
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -eq 0 ]; then
        log_success "¡Todo el software necesario está instalado!"
    else
        echo -e "\n${YELLOW}Se han detectado ${#missing_tools[@]} herramientas faltantes.${NC}"
        read -p "¿Deseas instalarlas todas ahora? (s/n): " install_all
        if [[ $install_all == "s" ]]; then
            log_info "Instalando software faltante..."
            apt-get install -y "${missing_tools[@]}"
            log_success "Software instalado correctamente."
        fi
    fi
}

# Sección 2: Gestión de usuarios y permisos
module_user_hardening() {
    log_banner "SECCIÓN 2: ASEGURAMIENTO DE USUARIOS"
    echo -e "Aquí configuraremos un usuario no-root con privilegios de administrador ($SUDO_USER)."
    echo -e "Esto es crucial porque permite administrar el servidor sin usar la cuenta 'root',"
    echo -e "reduciendo el riesgo de errores críticos o ataques directos.\n"
    
    # Verificar si el usuario administrador configurado existe
    if ! id "$SUDO_USER" &>/dev/null; then
        log_warn "El usuario $SUDO_USER no existe. Creándolo..."
        useradd -m -s /bin/bash "$SUDO_USER"
        log_info "Por favor, asigna una contraseña para $SUDO_USER inmediatamente al finalizar."
    fi
    
    # Verificar si el grupo administrativo existe (ej: sudo)
    if getent group "$SUDO_GROUP" > /dev/null; then
        log_info "Añadiendo a $SUDO_USER al grupo $SUDO_GROUP..."
        usermod -aG "$SUDO_GROUP" "$SUDO_USER"
    else
        log_error "El grupo administrativo '$SUDO_GROUP' no existe. Saltando paso de grupo."
    fi
    
    log_success "Aseguramiento de usuarios completado."
}

# Sección 3: Aseguramiento de SSH (Protocolo de acceso remoto)
module_ssh_hardening() {
    log_banner "SECCIÓN 3: FORTALECIMIENTO DE SSH"
    echo -e "SSH es la puerta de entrada al servidor. Cambiaremos el puerto por defecto ($SSH_PORT),"
    echo -e "bloquearemos el acceso directo al usuario 'root' y permitiremos solo a usuarios"
    echo -e "específicos. Esto detiene el 99% de los ataques automatizados de bots.\n"
    
    local ssh_conf="/etc/ssh/sshd_config"
    
    log_info "Creando copia de seguridad de la configuración de SSH..."
    cp "$ssh_conf" "${ssh_conf}.bak"
    
    log_info "Configurando SSH (Puerto $SSH_PORT, IP $SSH_LISTEN_IP, Deshabilitar Root, Habilitar Pubkey)..."
    sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$ssh_conf"
    if grep -q "^ListenAddress" "$ssh_conf"; then
        sed -i "s/^ListenAddress .*/ListenAddress $SSH_LISTEN_IP/" "$ssh_conf"
    else
        echo "ListenAddress $SSH_LISTEN_IP" >> "$ssh_conf"
    fi
    sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" "$ssh_conf"
    sed -i "s/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/" "$ssh_conf"
    
    if [[ -n "$ALLOWED_SSH_USERS" ]]; then
        log_info "Restringiendo acceso SSH a los usuarios: $ALLOWED_SSH_USERS"
        if grep -q "AllowUsers" "$ssh_conf"; then
            sed -i "s/^AllowUsers .*/AllowUsers $ALLOWED_SSH_USERS/" "$ssh_conf"
        else
            echo "AllowUsers $ALLOWED_SSH_USERS" >> "$ssh_conf"
        fi
    fi

    log_info "Validando sintaxis de la nueva configuración de SSH..."
    if sshd -t; then
        log_info "Reiniciando el servicio SSH..."
        systemctl restart ssh
        log_success "Configuración de SSH aplicada. EL PUERTO ACTUAL ES $SSH_PORT."
    else
        log_error "¡Error en la sintaxis de SSH! Restaurando copia de seguridad."
        cp "${ssh_conf}.bak" "$ssh_conf"
    fi
}

# Sección 4: Configuración de Red y Firewalls
module_network_security() {
    log_banner "SECCIÓN 4: SEGURIDAD DE RED Y FIREWALL"
    echo -e "Activaremos el Firewall (UFW) para cerrar todos los puertos que no estemos usando."
    echo -e "También configuraremos Fail2Ban, que monitorea intentos de acceso fallidos y"
    echo -e "bloquea temporalmente las IPs de atacantes detectados.\n"
    
    if $ENABLE_UFW; then
        log_info "Configurando cortafuegos UFW..."
        ufw default deny incoming
        ufw default allow outgoing
        
        if [[ "$SSH_INBOUND_IP" == "any" ]]; then
            ufw allow "$SSH_PORT"/tcp comment 'Puerto SSH'
        else
            ufw allow from "$SSH_INBOUND_IP" to any port "$SSH_PORT" proto tcp comment 'Puerto SSH Restringido'
        fi
        
        echo "y" | ufw enable
        log_success "UFW habilitado y configurado correctamente."
    fi

    if $STRICT_OUTGOING; then
        log_info "Restringiendo tráfico saliente..."
        ufw default deny outgoing
        ufw allow out 53/udp comment 'DNS'
        ufw allow out 80,443/tcp comment 'HTTP/S'
        ufw allow out 123/udp comment 'NTP'
        log_success "Tráfico saliente restringido a puertos esenciales."
    fi
    
    if $ENABLE_FAIL2BAN; then
        log_info "Configurando Fail2Ban..."
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        systemctl enable fail2ban
        systemctl restart fail2ban
        log_success "Servicio Fail2Ban iniciado y activado."
    fi

    if $ENABLE_PSAD; then
        log_info "Configurando PSAD para detección de escaneos de puertos..."
        # Ajustar UFW para que loguee paquetes denegados (requerido por PSAD)
        ufw logging on
        # Configurar email en PSAD
        sed -i "s/EMAIL_ADDRESSES.*/EMAIL_ADDRESSES $ADMIN_EMAIL;/" /etc/psad/psad.conf
        systemctl enable psad
        systemctl restart psad
        log_success "PSAD configurado."
    fi
}

module_extra_hardening() {
    log_banner "SECCIÓN 5: REFUERZOS EXTRA (PAM Y AUDITD)"
    echo -e "En esta sección aplicaremos políticas de contraseñas fuertes y configuraremos"
    echo -e "el sistema de auditoría del núcleo para registrar eventos críticos.\n"

    if $ENABLE_PWQUALITY; then
        log_info "Configurando calidad de contraseñas (PAM pwquality)..."
        # Fuerza longitud mínima de 12 y diferentes clases de caracteres
        sed -i 's/^#\? minlen =.*/minlen = 12/' /etc/security/pwquality.conf
        sed -i 's/^#\? dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf
        sed -i 's/^#\? ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf
        sed -i 's/^#\? ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf
        log_success "PAM pwquality configurado."
    fi

    if $ENABLE_AUDITD; then
        log_info "Habilitando auditoría del sistema (auditd)..."
        systemctl enable auditd
        systemctl restart auditd
        log_success "Auditd activado."
    fi
}

module_antivirus_clamav() {
    echo -e "\n${BLUE}>>> [Sección 6] Iniciando Antivirus (ClamAV)${NC}"
    echo -e "El antivirus ClamAV ayuda a detectar malware y troyanos. Es especialmente útil"
    echo -e "si el servidor va a recibir o procesar archivos de otros usuarios.\n"

    if $ENABLE_CLAMAV; then
        log_info "Configurando y actualizando base de datos de ClamAV (Freshclam)..."
        log_info "Esto puede tardar unos minutos dependiendo de la conexión..."
        systemctl stop clamav-freshclam >/dev/null 2>&1
        if freshclam; then
            log_success "Base de datos de ClamAV actualizada."
        else
            log_warn "Freshclam falló. Es posible que ya se esté ejecutando en segundo plano."
        fi
        systemctl start clamav-freshclam
        log_success "Antivirus ClamAV listo."
    else
        log_info "ClamAV no está habilitado en las variables. Saltando..."
    fi
}

# Sección 7: Ajustes del núcleo (Kernel) y Actualizaciones
module_system_hardening() {
    log_banner "SECCIÓN 7: FORTALECIMIENTO DEL SISTEMA (NÚCLEO)"
    echo -e "Aplicaremos 'parámetros de núcleo' (sysctl) para proteger la red contra ataques"
    echo -e "avanzados (IP Spoofing, etc.) y activaremos las actualizaciones automáticas"
    echo -e "para que el servidor reciba parches de seguridad sin intervención manual.\n"
    
    log_info "Aplicando ajustes de seguridad en el núcleo del sistema (sysctl)..."
    cat > /etc/sysctl.d/99-security-harden.conf <<EOF
# Protección contra IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Ignorar peticiones de broadcast ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Deshabilitar paquetes de enrutamiento fuente
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Ignorar redirecciones ICMP
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Mitigación de ataques SYN Flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# Registro de paquetes con IPs sospechosas
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF
    sysctl -p /etc/sysctl.d/99-security-harden.conf
    
    if $AUTO_UPGRADES; then
        log_info "Activando actualizaciones automáticas de seguridad..."
        dpkg-reconfigure -plow unattended-upgrades
    fi
    
    log_success "Fortalecimiento de sistema aplicado con éxito."
}

# Sección 8: Monitoreo continuo y Auditoría programada
module_monitoring_auditing() {
    log_banner "SECCIÓN 8: MONITOREO Y AUDITORÍA FINAL"
    echo -e "Configuraremos el envío de reportes diarios de actividad por email (Logwatch)"
    echo -e "y realizaremos un escaneo inicial de seguridad para detectar posibles"
    log_info "Configurando Logwatch..."
    sed -i "s/MailTo = .*/MailTo = $ADMIN_EMAIL/" /usr/share/logwatch/default.conf/logwatch.conf
    
    log_info "Ejecutando escaneo preliminar de Rootkits..."
    rkhunter --check --sk --quiet
    
    log_success "Herramientas de monitoreo configuradas."
}

# ==============================================================================
# 4. INTERFAZ PRINCIPAL DEL SCRIPT
# ==============================================================================

show_help() {
    clear
    echo -e "\n${BLUE}========== GUÍA DE SECCIONES DE SEGURIDAD ==========${NC}"
    echo -e "1. ${YELLOW}Básicos:${NC} Actualización total y herramientas de auditoría."
    echo -e "2. ${YELLOW}Usuarios:${NC} Crear administrador no-root para evitar uso de 'root'."
    echo -e "3. ${YELLOW}SSH:${NC} Cambiar puerto 22, bloquear root y limitar usuarios."
    echo -e "4. ${YELLOW}Red:${NC} Firewall UFW, Fail2Ban y detección de escaneos PSAD."
    echo -e "5. ${YELLOW}Refuerzos:${NC} Calidad de contraseñas PAM y Auditd."
    echo -e "6. ${YELLOW}Antivirus:${NC} Instalación y configuración de ClamAV."
    echo -e "7. ${YELLOW}Núcleo:${NC} Protecciones de red sysctl y actualizaciones auto."
    echo -e "8. ${YELLOW}Monitoreo:${NC} Alertas por email y escaneo de malware inicial."
    echo -e "----------------------------------------------------"
    echo -e "PASOS RECOMENDADOS:"
    echo -e "1. Revisa las variables al inicio del archivo."
    echo -e "2. Ejecuta 'Auditar' para ver qué falta."
    echo -e "3. Aplica el 'Fortalecimiento Completo' o uno por uno."
    echo -e "4. ¡NO CIERRES tu sesión hasta probar el nuevo puerto SSH!"
    echo -e "===================================================="
    read -p "Presiona Enter para volver al menú..."
    main_menu
}

setup_admin_user() {
    echo -e "\n--- Configuración de Usuario Administrador ---"
    read -p "Introduce el nombre del nuevo usuario administrador (ej: admin): " input_user
    if [[ -z "$input_user" ]]; then
        log_warn "No se introdujo nada. Se mantendrá el valor actual: $SUDO_USER"
    else
        SUDO_USER="$input_user"
        log_success "Usuario administrador actualizado a: $SUDO_USER"
    fi
    
    read -p "¿Es '$SUDO_GROUP' el nombre correcto del grupo sudo? (s/n): " confirm_group
    if [[ $confirm_group != "s" ]]; then
        read -p "Introduce el nombre del grupo administrativo (ej: sudo, wheel): " input_group
        [[ -n "$input_group" ] ] && SUDO_GROUP="$input_group"
    fi
}

main_menu() {
    echo -e "\n${BLUE}==============================================${NC}"
    echo -e "${BLUE}     Debian 13 Security Hardening & Audit     ${NC}"
    echo -e "${BLUE}==============================================${NC}"
    echo -e "${YELLOW}--- FASE 1: DIAGNÓSTICO ---${NC}"
    echo "1) Auditar Seguridad y Software (Ver estado)"
    echo "2) Mostrar Variables y Red Detectada"
    
    echo -e "\n${YELLOW}--- FASE 2: INSTALACIÓN (CRÍTICO) ---${NC}"
    echo "i) INSTALAR SOFTWARE DE SEGURIDAD FALTANTE"
    
    echo -e "\n${YELLOW}--- FASE 3: CONFIGURACIÓN Y BLINDAJE ---${NC}"
    echo "3) Aplicar Fortalecimiento Completo (Recomendado)"
    echo "4) Ejecución por Módulos (Personalizado)"
    echo "5) Configurar Usuario Administrador (Actual: $SUDO_USER)"
    
    echo -e "\n${YELLOW}--- OTROS ---${NC}"
    echo "6) Guía de Secciones (Ayuda)"
    echo "q) Salir"
    echo "=============================================="
    read -p "Selecciona una opción: " choice

    case $choice in
        1) run_audit ;;
        2) show_variables ;;
        i) verify_and_install_essential_tools; main_menu ;;
        3) 
            read -p "¿Deseas cambiar el usuario administrador ($SUDO_USER) antes de empezar? (s/n): " change
            [[ $change == "s" ]] && setup_admin_user
            run_full_hardening 
            ;;
        4) run_selective ;;
        5) setup_admin_user; main_menu ;;
        6) show_help ;;
        q) exit 0 ;;
        *) main_menu ;;
    esac
}

# Muestra la configuración actual para que el usuario verifique antes de actuar
show_variables() {
    echo -e "\n--- Configuración de Variables Actual ---"
    echo -e "Usuario Admin      : ${YELLOW}$SUDO_USER${NC}"
    echo -e "Grupo Admin        : ${YELLOW}$SUDO_GROUP${NC}"
    echo -e "Puerto SSH         : ${YELLOW}$SSH_PORT${NC}"
    echo -e "Interfaz SSH       : ${YELLOW}$SSH_INTERFACE${NC}"
    echo -e "Escucha SSH (IP)   : ${YELLOW}$SSH_LISTEN_IP${NC}"
    echo -e "Usuarios Permitidos: ${YELLOW}$ALLOWED_SSH_USERS${NC}"
    echo -e "Cortafuegos UFW    : ${YELLOW}$ENABLE_UFW${NC}"
    echo -e "Email Reportes     : ${YELLOW}$ADMIN_EMAIL${NC}"
    echo -e "Actualiz. Autos    : ${YELLOW}$AUTO_UPGRADES${NC}"
    
    echo -e "\n--- Interfaces de Red Detectadas ---"
    ip -brief addr show | awk '{print "Interfaz: " $1 " -> " $3}'
    
    read -p "Presiona Enter para volver..."
    main_menu
}

# Función auxiliar para puntuar
add_score() {
    local points=$1
    local cond=$2
    if eval "$cond" >/dev/null 2>&1; then
        ((SCORE_TOTAL+=points))
        return 0
    fi
    return 1
}

# Verificación específica de Nginx (Reverse Proxy / Port Forwarding)
check_nginx_security() {
    log_info "Analizando configuración de Nginx..."
    local nscore=0
    
    # Check 1: ¿Oculta la versión de Nginx?
    if grep -q "server_tokens off" "$NGINX_CONF" 2>/dev/null; then
        log_success "[Nginx] Versión oculta (server_tokens off)"
        ((nscore+=3))
    else
        log_warn "[Nginx] La versión es visible. Vulnerable a escaneos de versión."
    fi

    # Check 2: ¿Tiene headers de seguridad básicos?
    if grep -Ei "add_header (X-Frame-Options|X-Content-Type-Options|Content-Security-Policy)" /etc/nginx/conf.d/*.conf 2>/dev/null; then
        log_success "[Nginx] Headers de seguridad detectados"
        ((nscore+=4))
    else
        log_warn "[Nginx] Faltan headers de seguridad (CSP, XFO)."
    fi

    # Check 3: SSL/HTTPS
    if grep -q "ssl_certificate" /etc/nginx/sites-enabled/* 2>/dev/null; then
        log_success "[Nginx] SSL/TLS configurado"
        ((nscore+=3))
    else
        log_warn "[Nginx] No se detecta SSL. El tráfico viaja en texto plano."
    fi
    return $nscore
}

# Modo auditoría con recomendaciones y puntuación
run_audit() {
    SCORE_TOTAL=0
    clear
    log_banner "AUDITORÍA DE SEGURIDAD DIAGNÓSTICA (SCORING)"
    echo -e "Analizando el nivel de blindaje de tu servidor...\n"

    # 1. Sistema Base (10 pts)
    echo -n "1. Sistema actualizado: "
    if add_score 10 "apt-get --simulate upgrade | grep -q '0 upgraded, 0 newly installed'"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] El sistema tiene parches pendientes. Riesgo: Exploits conocidos."
    fi

    # 2. Usuarios (10 pts)
    echo -n "2. Usuario admin no-root: "
    if add_score 10 "id $SUDO_USER"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] No hay usuario admin personalizado. Riesgo: Brute force a root."
    fi

    # 3. SSH Hardening (20 pts total)
    echo -n "3. Puerto SSH no estándar ($SSH_PORT): "
    if add_score 10 "grep -E '^Port $SSH_PORT' /etc/ssh/sshd_config"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] Usas el puerto 22. Riesgo: 99% de los ataques bots van aquí."
    fi

    echo -n "4. Login Root deshabilitado: "
    if add_score 10 "grep -E '^PermitRootLogin no' /etc/ssh/sshd_config"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] Root puede loguearse. Riesgo: Comprometer el sistema completo."
    fi

    # 4. Red (25 pts total)
    echo -n "5. Firewall UFW activo: "
    if add_score 15 "ufw status | grep -q 'active'"; then
        log_success "[OK] (+15)"
    else
        log_warn "[FALLO] Firewall apagado. Riesgo: Puertos abiertos innecesarios."
    fi

    echo -n "6. Fail2Ban / PSAD activos: "
    if add_score 10 "systemctl is-active --quiet fail2ban && systemctl is-active --quiet psad"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] Sin defensas activas. Riesgo: Fuerza bruta sin bloqueo."
    fi

    # 5. Sistema y Polítcas (20 pts)
    echo -n "7. Hardening Sysctl (Kernal): "
    if add_score 10 "ls /etc/sysctl.d/99-security-harden.conf"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] Núcleo sin blindar. Riesgo: IP Spoofing, SYN floods."
    fi

    echo -n "8. PAM Password Quality: "
    if add_score 10 "ls /etc/security/pwquality.conf"; then
        log_success "[OK] (+10)"
    else
        log_warn "[FALLO] Sin política de contraseñas. Riesgo: Claves débiles '123456'."
    fi

    # 6. Nginx (Opcional 15 pts)
    if is_installed "nginx"; then
        echo -e "\n--- Analizando Nginx (Web Server) ---"
        check_nginx_security
        SCORE_TOTAL=$((SCORE_TOTAL + $?))
    fi

    echo -e "\n============================================="
    echo -e " RESULTADO FINAL: ${YELLOW}${SCORE_TOTAL}/100${NC}"
    echo -e "============================================="
    
    if [ $SCORE_TOTAL -lt 50 ]; then
        log_error "NIVEL DE RIESGO: CRÍTICO. Tu servidor es un blanco fácil."
    elif [ $SCORE_TOTAL -lt 80 ]; then
        log_warn "NIVEL DE RIESGO: MEDIO. Tienes defensas básicas pero incompletas."
    else
        log_success "NIVEL DE RIESGO: BAJO. Servidor bien protegido."
    fi

    echo -e "\n${BLUE}Recomendaciones:${NC}"
    [ $SCORE_TOTAL -lt 90 ] && echo "- Ejecuta la opción 2 para aplicar todas las mejoras faltantes."
    
    read -p "Presiona Enter para volver al menú..."
    main_menu
}

# Permite al usuario elegir qué secciones aplicar
run_selective() {
    echo -e "\nFortalecimiento por Módulos (Paso a paso):"
    echo "1) Conceptos Básicos (Actualización y Herramientas)"
    echo "2) Aseguramiento de Usuarios"
    echo "3) Aseguramiento de SSH"
    echo "4) Seguridad de Red (UFW/Fail2Ban/PSAD)"
    echo "5) Refuerzos Extra (PAM/Auditd)"
    echo "6) Antivirus (ClamAV)"
    echo "7) Fortalecimiento del Sistema (Sysctl/Updates)"
    echo "8) Monitoreo y Auditoría"
    echo "r) Regresar al menú principal"
    read -p "Selecciona el módulo a ejecutar: " sel
    
    case $sel in
        1) module_system_basics ;;
        2) module_user_hardening ;;
        3) module_ssh_hardening ;;
        4) module_network_security ;;
        5) module_extra_hardening ;;
        6) module_antivirus_clamav ;;
        7) module_system_hardening ;;
        8) module_monitoring_auditing ;;
        r) main_menu ;;
        *) run_selective ;;
    esac
    run_selective
}

# Ejecuta todo el proceso secuencialmente
run_full_hardening() {
    echo -e "\n${RED}!!! ADVERTENCIA CRÍTICA !!!${NC}"
    echo "Este proceso aplicará cambios profundos de seguridad en el sistema."
    
    # Manejo de múltiples interfaces si no están definidas
    if [[ -z "$SSH_INTERFACE" || "$SSH_INTERFACE" == "all" ]]; then
        read -p "¿Deseas seleccionar una interfaz de red específica (recomendado para multi-NIC)? (s/n): " pick_nic
        [[ $pick_nic == "s" ]] && select_network_interface
    fi

    echo -e "\nConfiguración final a aplicar:"
    echo " - Usuario Admin: $SUDO_USER"
    echo " - Interfaz SSH : ${SSH_INTERFACE:-all}"
    echo " - IP de Escucha: $SSH_LISTEN_IP"
    echo " - Puerto SSH   : $SSH_PORT"
    
    read -p "¿Es correcto? Procede bajo tu responsabilidad (s/n): " confirm
    [[ $confirm != "s" ]] && main_menu
    
    module_system_basics
    module_user_hardening
    module_ssh_hardening
    module_network_security
    module_extra_hardening
    module_antivirus_clamav
    module_system_hardening
    module_monitoring_auditing
    
    log_success "\n¡Proceso de fortalecimiento completo finalizado!"
    log_warn "POR FAVOR, VERIFICA EL ACCESO SSH EN EL PUERTO $SSH_PORT EN UNA NUEVA VENTANA."
    read -p "Presiona Enter para volver al menú..."
    main_menu
}

# Inicio del script
check_root
main_menu
