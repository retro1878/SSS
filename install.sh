#!/usr/bin/env bash
set -e

# SNI Spoofing Scanner — installer

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SCRIPT_NAME="sni_scanner"

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "  [MISSING] $1"
        return 1
    fi
    echo "  [OK]      $1"
}

echo ""
echo "SNI Spoofing Scanner — installer"
echo "================================="

echo ""
echo "Checking dependencies..."
all_ok=true
check_dep curl  || all_ok=false
check_dep python3 || all_ok=false

if [ "$all_ok" = false ]; then
    echo ""
    echo "Install missing dependencies, then re-run this script."
    echo "  Debian/Ubuntu:  sudo apt install curl python3"
    echo "  RHEL/Fedora:    sudo dnf install curl python3"
    echo "  macOS:          brew install curl python3"
    exit 1
fi

# Check Python version >= 3.9 (uses list[str] type hints)
py_ver=$(python3 -c "import sys; print(sys.version_info.minor)")
py_maj=$(python3 -c "import sys; print(sys.version_info.major)")
if [ "$py_maj" -lt 3 ] || { [ "$py_maj" -eq 3 ] && [ "$py_ver" -lt 9 ]; }; then
    echo ""
    echo "Python 3.9 or newer is required (found $(python3 --version))."
    exit 1
fi
echo "  [OK]      $(python3 --version)"

echo ""
echo "Installing to $INSTALL_DIR/$SCRIPT_NAME ..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/sni_scanner.py" ]; then
    echo "sni_scanner.py not found next to install.sh — aborting."
    exit 1
fi

# Install without sudo if INSTALL_DIR is user-writable, otherwise use sudo
install_file() {
    if [ -w "$INSTALL_DIR" ]; then
        cp "$SCRIPT_DIR/sni_scanner.py" "$INSTALL_DIR/$SCRIPT_NAME"
        chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    else
        sudo cp "$SCRIPT_DIR/sni_scanner.py" "$INSTALL_DIR/$SCRIPT_NAME"
        sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    fi
}

mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
install_file

echo ""
echo "Done!  Run:  sni_scanner --help"
echo ""
