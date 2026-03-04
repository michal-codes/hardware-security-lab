#!/bin/bash
# ATECC608A SSH Agent — instalacja i konfiguracja
#
# Uruchom: bash setup_ssh_agent.sh

set -e

INSTALL_DIR="/opt/atecc-ssh-agent"
SERVICE_NAME="atecc-ssh-agent"

echo "=== ATECC608A SSH Agent Setup ==="

# 1. Instalacja plików
echo "[1/4] Kopiowanie plików..."
sudo mkdir -p "$INSTALL_DIR"
sudo cp atecc_ssh_agent.py "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/atecc_ssh_agent.py"

# 2. Systemd user service
echo "[2/4] Instalacja systemd service..."
mkdir -p ~/.config/systemd/user/
cp atecc-ssh-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload

# 3. Uprawnienia I2C
echo "[3/4] Sprawdzanie uprawnień I2C..."
if groups | grep -q i2c; then
    echo "  Użytkownik jest w grupie i2c — OK"
else
    echo "  Dodaję do grupy i2c..."
    sudo usermod -aG i2c "$USER"
    echo "  ⚠️  Wyloguj się i zaloguj ponownie żeby grupa zadziałała"
fi

# 4. Konfiguracja powłoki
echo "[4/4] Konfiguracja SSH_AUTH_SOCK..."
SHELL_RC="$HOME/.bashrc"
SOCK_LINE='export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/tmp}/atecc-ssh-agent.sock"'

if ! grep -q "atecc-ssh-agent" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# ATECC608A SSH Agent" >> "$SHELL_RC"
    echo "$SOCK_LINE" >> "$SHELL_RC"
    echo "  Dodano SSH_AUTH_SOCK do $SHELL_RC"
else
    echo "  SSH_AUTH_SOCK już skonfigurowany"
fi

echo ""
echo "=== GOTOWE ==="
echo ""
echo "Użycie ręczne:"
echo "  ./atecc_ssh_agent.py --debug"
echo "  export SSH_AUTH_SOCK=/run/user/\$(id -u)/atecc-ssh-agent.sock"
echo ""
echo "Użycie z systemd:"
echo "  systemctl --user enable $SERVICE_NAME"
echo "  systemctl --user start $SERVICE_NAME"
echo "  systemctl --user status $SERVICE_NAME"
echo ""
echo "Test:"
echo "  ssh-add -l"
echo "  ssh -T git@github.com"
