# Auditoría de Vulnerabilidad SSHole (CVE-2026-123158)

Este repositorio contiene una herramienta de auditoría en **Bash** para detectar si un sistema es vulnerable al fallo de seguridad **SSHole** (**CVE-2026-123158**), el cual afecta a servidores que ejecutan **OpenSSH** en entornos basados en la biblioteca C **musl libc**.

---

## 📌 Descripción de la Vulnerabilidad

La vulnerabilidad **SSHole** permite una omisión o degradación en la lógica de autenticación cuando coinciden condiciones específicas en la compilación del binario y la configuración de usuarios locales.

### Condiciones para la vulnerabilidad:
1. **Sistema operativo y C library:** Basado en `musl libc` (ej. Alpine Linux, OpenWrt, Yocto, Buildroot).
2. **Versión de OpenSSH:** Versiones anteriores a `10.6p2`.
3. **Configuración de OpenSSH:**
   - `PasswordAuthentication yes` (habilitado por defecto en la mayoría de distribuciones).
   - `UsePAM no` (o compilado sin soporte PAM).
4. **Configuración de cuentas (`/etc/shadow`):**
   - Presencia de al menos una cuenta desactivada expresada con un asterisco (`*`).
   - Presencia de al menos una cuenta con hash de contraseña válido en formato SHA-crypt (`$5$` para SHA-256 o `$6$` para SHA-512).

---

## 🚀 Uso del Script Auditor

El script `sshole.sh` realiza una verificación local **no destructiva** ni invasiva. Simplemente evalúa si el host activo cumple las 4 condiciones del entorno vulnerable.

### Requisitos

- Sistema operativo tipo Unix / Linux.
- Permisos de superusuario (`root` o `sudo`) para poder auditar el archivo `/etc/shadow`.


