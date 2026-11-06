#!/bin/sh
# ==============================================================================
# Script de auditoría local para CVE-2026-123158 (SSHole)
# Comprueba si el entorno cumple con los requisitos de la falla de OpenSSH en musl
# ==============================================================================

echo "[*] Iniciando verificación de la vulnerabilidad SSHole (CVE-2026-123158)..."
echo ""

VULN_CONDITIONS=0

# 1. Comprobar si el sistema utiliza musl libc
if ldd /bin/ls 2>/dev/null | grep -q "musl" || [ -e /lib/ld-musl-*.so.* ]; then
    echo "[+] [CONDICIÓN CUMPLIDA] Entorno basado en musl libc detectado."
    MUSL_CHECK=1
else
    echo "[-] [SEGURO] No se detectó musl libc (utiliza glibc u otro entorno)."
    MUSL_CHECK=0
fi

# 2. Comprobar versión de OpenSSH instalada
if command -v sshd >/dev/null 2>&1; then
    SSH_VERSION_RAW=$(sshd -V 2>&1 | head -n 1)
    echo "[*] Versión detectada: $SSH_VERSION_RAW"
    # Nota: La versión parcheada es OpenSSH 10.6p2 o superior.
    # Aquí puedes validar manualmente si es inferior a 10.6p2.
else
    echo "[-] [INFO] El servidor OpenSSH (sshd) no parece estar instalado en este host."
    exit 0
fi

# 3. Comprobar la configuración activa de OpenSSH (PasswordAuth y UsePAM)
if command -v sshd >/dev/null 2>&1; then
    # sshd -T muestra la configuración efectiva evaluada
    PASS_AUTH=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
    USE_PAM=$(sshd -T 2>/dev/null | grep -i "^usepam" | awk '{print $2}')
    
    echo "[*] Configuración efectiva -> PasswordAuthentication: ${PASS_AUTH:-desconocido} | UsePAM: ${USE_PAM:-desconocido}"
    
    if [ "$PASS_AUTH" = "yes" ] && [ "$USE_PAM" = "no" ]; then
        echo "[+] [CONDICIÓN CUMPLIDA] PasswordAuthentication activo y UsePAM desactivado."
        CONFIG_CHECK=1
    else
        echo "[-] [SEGURO] La configuración de autenticación bloquea este vector (PAM activo o PassAuth deshabilitado)."
        CONFIG_CHECK=0
    fi
else
    CONFIG_CHECK=0
fi

# 4. Comprobar estado de cuentas en /etc/shadow (* y hashes SHA-crypt $5$ / $6$)
if [ -f /etc/shadow ]; then
    HAS_ASTERISK=0
    HAS_SHA_HASH=0
    
    while IFS=: read -r user pass rest; do
        if [ "$pass" = "*" ]; then
            HAS_ASTERISK=1
        elif echo "$pass" | grep -qE '^\$(5|6)\$'; then
            HAS_SHA_HASH=1
        fi
    done < /etc/shadow
    
    if [ "$HAS_ASTERISK" -eq 1 ] && [ "$HAS_SHA_HASH" -eq 1 ]; then
        echo "[+] [CONDICIÓN CUMPLIDA] Se detectaron cuentas con '*' combinadas con cuentas con hashes de contraseña SHA-256/512."
        SHADOW_CHECK=1
    else
        echo "[-] [SEGURO] Las cuentas en /etc/shadow no coinciden con el patrón requerido."
        SHADOW_CHECK=0
    fi
else
    echo "[-] [AVISO] No se pudo leer /etc/shadow (¿Estás ejecutando el script como root?)."
    SHADOW_CHECK=0
fi

echo ""
echo "=================================================="
echo "                 RESUMEN DE RIESGO                "
echo "=================================================="

if [ "${MUSL_CHECK:-0}" -eq 1 ] && [ "${CONFIG_CHECK:-0}" -eq 1 ] && [ "${SHADOW_CHECK:-0}" -eq 1 ]; then
    echo "[!] ¡ATENCIÓN! El sistema CUMPLE con todas las condiciones del entorno para la vulnerabilidad SSHole."
    echo "[!] Recomendación urgente:"
    echo "    1. Actualiza OpenSSH a la versión 10.6p2 o posterior (ej: 'apk upgrade -U -a' en Alpine)."
    echo "    2. Reinicia el servicio SSH ('rc-service sshd restart' o systemctl)."
    echo "    3. Si no puedes actualizar de inmediato, deshabilita las contraseñas configurando 'PasswordAuthentication no' en sshd_config."
else
    echo "[✓] El sistema NO reúne simultáneamente todas las condiciones de exposición al fallo."
fi
