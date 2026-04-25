#!/bin/bash
# =============================================================================
# install-ubxcert.sh
# UbxCert global installer — installs the package to /opt/ubxcert and makes
# 'ubxcert' available system-wide as a CLI command.
#
# Usage:
#   bash install-ubxcert.sh [--staging] [--source /path/to/local/package]
#
# After install:
#   ubxcert request --domains "*.example.com,example.com" --email you@example.com
# =============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

INSTALL_DIR="/opt/ubxcert"
BIN_LINK="/usr/local/bin/ubxcert"
STATE_DIR="/etc/ubxcert"
CRON_FILE="/etc/cron.d/ubxcert-renew"
LOG_DIR="/var/log/ubxcert"
REPO_URL="https://github.com/ubxty/ubxcert.git"

# Optional: override install source with a local path (for dev/CI)
LOCAL_SOURCE=""

# -------------------------------------------------------------------------
# Parse args
# -------------------------------------------------------------------------
STAGING=0
for arg in "$@"; do
    case "$arg" in
        --staging)   STAGING=1 ;;
        --source=*)  LOCAL_SOURCE="${arg#*=}" ;;
        --source)    shift; LOCAL_SOURCE="$1" ;;
    esac
done

# -------------------------------------------------------------------------
# Colour helpers
# -------------------------------------------------------------------------
green()  { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
red()    { echo -e "\033[31m$*\033[0m"; }
info()   { echo "[ubxcert-install] $*"; }

# -------------------------------------------------------------------------
# Root check
# -------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    red "This installer must be run as root."
    exit 1
fi

info "Starting ubxcert installation..."

# -------------------------------------------------------------------------
# Detect OS
# -------------------------------------------------------------------------
OS_ID=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
fi

# -------------------------------------------------------------------------
# Install PHP if missing
# -------------------------------------------------------------------------
if ! command -v php &>/dev/null; then
    info "PHP not found — installing..."
    if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        apt-get update -qq
        apt-get install -y -qq php-cli php-curl php-json php-openssl 2>/dev/null || \
        apt-get install -y -qq php8.3-cli php8.3-curl 2>/dev/null || \
        apt-get install -y -qq php8.2-cli php8.2-curl 2>/dev/null || \
        apt-get install -y -qq php8.1-cli php8.1-curl
    elif [ "$OS_ID" = "centos" ] || [ "$OS_ID" = "rhel" ] || [ "$OS_ID" = "almalinux" ] || [ "$OS_ID" = "rocky" ]; then
        yum install -y php-cli php-curl php-json
    else
        red "Unsupported OS: $OS_ID. Install PHP 8.1+ manually."
        exit 1
    fi
fi

PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')
info "PHP version: ${PHP_VERSION}"

# Check required extensions
for EXT in openssl json curl; do
    if ! php -m | grep -qi "^${EXT}$"; then
        red "PHP extension '${EXT}' is missing. Install php-${EXT} and retry."
        exit 1
    fi
done

# -------------------------------------------------------------------------
# Install Composer if missing
# -------------------------------------------------------------------------
if ! command -v composer &>/dev/null; then
    info "Composer not found — installing..."
    EXPECTED_CHECKSUM="$(php -r 'copy("https://composer.github.io/installer.sig", "php://stdout");')"
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    ACTUAL_CHECKSUM="$(php -r "echo hash_file('sha384', 'composer-setup.php');")"

    if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
        rm -f composer-setup.php
        red "Composer installer checksum mismatch!"
        exit 1
    fi

    php composer-setup.php --quiet --install-dir=/usr/local/bin --filename=composer
    rm -f composer-setup.php
fi

info "Composer version: $(composer --version --no-ansi 2>/dev/null | head -1)"

# -------------------------------------------------------------------------
# Install git if needed
# -------------------------------------------------------------------------
if [ -z "$LOCAL_SOURCE" ] && ! command -v git &>/dev/null; then
    info "Installing git..."
    if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        apt-get install -y -qq git
    else
        yum install -y git
    fi
fi

# -------------------------------------------------------------------------
# Place the package
# -------------------------------------------------------------------------
if [ -n "$LOCAL_SOURCE" ]; then
    info "Copying from local source: ${LOCAL_SOURCE}"
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "${INSTALL_DIR}"
    fi
    cp -r "$LOCAL_SOURCE" "$INSTALL_DIR"
else
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Updating existing ubxcert installation..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        info "Cloning ubxcert repository..."
        if [ -d "$INSTALL_DIR" ]; then
            rm -rf "${INSTALL_DIR}"
        fi
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi
fi

# -------------------------------------------------------------------------
# Install PHP dependencies
# -------------------------------------------------------------------------
info "Installing Composer dependencies..."
cd "$INSTALL_DIR"
composer install --no-dev --no-interaction --optimize-autoloader --quiet

# -------------------------------------------------------------------------
# Make bin executable
# -------------------------------------------------------------------------
chmod +x "${INSTALL_DIR}/bin/ubxcert"

# -------------------------------------------------------------------------
# Create symlink in /usr/local/bin
# -------------------------------------------------------------------------
if [ -L "$BIN_LINK" ] || [ -f "$BIN_LINK" ]; then
    rm -f "$BIN_LINK"
fi
ln -s "${INSTALL_DIR}/bin/ubxcert" "$BIN_LINK"
info "Symlink created: ${BIN_LINK} -> ${INSTALL_DIR}/bin/ubxcert"

# -------------------------------------------------------------------------
# Create state directories
# -------------------------------------------------------------------------
for DIR in "${STATE_DIR}" "${STATE_DIR}/accounts" "${STATE_DIR}/orders" "${STATE_DIR}/certs" "${LOG_DIR}"; do
    mkdir -p "$DIR"
    chmod 700 "$DIR"
done

info "State directory: ${STATE_DIR}"

# -------------------------------------------------------------------------
# Update /etc/letsencrypt/live directory (for backward compat symlinks)
# -------------------------------------------------------------------------
mkdir -p /etc/letsencrypt/live
mkdir -p /etc/letsencrypt/archive

# -------------------------------------------------------------------------
# Add /usr/local/bin to PATH in /etc/profile.d/ (in case it's not there)
# -------------------------------------------------------------------------
if ! grep -q '/usr/local/bin' /etc/environment 2>/dev/null; then
    echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/environment
fi

# Ensure it's in root's .bashrc / .bash_profile
for PROFILE in /root/.bashrc /root/.bash_profile; do
    if [ -f "$PROFILE" ] && ! grep -q 'ubxcert' "$PROFILE"; then
        echo '' >> "$PROFILE"
        echo '# ubxcert ACME certificate manager' >> "$PROFILE"
        echo 'export PATH="/usr/local/bin:$PATH"' >> "$PROFILE"
    fi
done

# -------------------------------------------------------------------------
# Install auto-renewal cron job (daily at 03:15 UTC)
# -------------------------------------------------------------------------
cat > "$CRON_FILE" << 'CRON_EOF'
# ubxcert — daily auto-renewal check (runs at 03:15 UTC)
15 3 * * * root /usr/local/bin/ubxcert renew --all --days-before 30 >> /var/log/ubxcert/renew.log 2>&1
CRON_EOF
chmod 644 "$CRON_FILE"
info "Auto-renewal cron installed: ${CRON_FILE}"

# -------------------------------------------------------------------------
# Verify installation
# -------------------------------------------------------------------------
if ubxcert version &>/dev/null; then
    green "✓ ubxcert installed successfully!"
    ubxcert version
else
    red "Installation appears to have failed. Check ${INSTALL_DIR} and PHP configuration."
    exit 1
fi

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
echo ""
green "=== ubxcert installation complete ==="
echo ""
echo "  Binary     : ${BIN_LINK}"
echo "  Install dir: ${INSTALL_DIR}"
echo "  State dir  : ${STATE_DIR}"
echo "  Cron       : ${CRON_FILE}"
echo "  Logs       : ${LOG_DIR}"
echo ""
echo "Quick start:"
echo "  ubxcert request --domains \"*.example.com,example.com\" --email admin@example.com"
echo "  ubxcert complete --domain example.com --wait-dns 600"
echo "  ubxcert install  --domain example.com --webserver openresty"
echo "  ubxcert list"
echo ""
[ "$STAGING" -eq 1 ] && yellow "  NOTE: Use --staging flag to test against Let's Encrypt staging."
