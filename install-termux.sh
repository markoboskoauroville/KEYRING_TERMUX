#!/data/data/com.termux/files/usr/bin/bash
# Install the Keyring in Termux. One command:
#   curl -fsSL https://raw.githubusercontent.com/markoboskoauroville/KEYRING_TERMUX/main/install-termux.sh | bash
# No venv (Termux's pip installs straight into site-packages, modules/termux-app.md §3).
set -euo pipefail
REPO_URL="https://github.com/markoboskoauroville/KEYRING_TERMUX.git"
INSTALL_DIR="$HOME/KEYRING_TERMUX"
if [ -t 1 ]; then AM="\033[38;5;214m"; OK="\033[1;32m"; BAD="\033[1;31m"; OFF="\033[0m"; else AM=""; OK=""; BAD=""; OFF=""; fi

printf "\n  ${AM}Keyring${OFF}  the key repository on this phone\n\n"
printf "  %-12s " "python"; command -v python3 >/dev/null && printf "${OK}ok${OFF} $(python3 --version 2>&1)\n" || { printf "${BAD}MISSING${OFF}  pkg install python\n"; MISSING=1; }
printf "  %-12s " "git";    command -v git >/dev/null && printf "${OK}ok${OFF}\n" || { printf "${BAD}MISSING${OFF}  pkg install git\n"; MISSING=1; }
printf "  %-12s " "flask";  python3 -c "import flask" 2>/dev/null && printf "${OK}ok${OFF}\n" || printf "will install\n"
printf "  %-12s " "waitress"; python3 -c "import waitress" 2>/dev/null && printf "${OK}ok${OFF}\n" || printf "will install\n"
if [ "${MISSING:-}" = 1 ]; then pkg install -y python git; fi
python3 -c "import flask, waitress" 2>/dev/null || pip install --quiet flask waitress

if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull -q --ff-only
else
  git clone -q "$REPO_URL" "$INSTALL_DIR"
fi
chmod +x "$INSTALL_DIR/keyring"
bash "$INSTALL_DIR/keyring" install
mkdir -p "$HOME/.keyring" && chmod 700 "$HOME/.keyring"
printf "\n  done. ${AM}keyring${OFF} starts it; the vault is ~/.keyring (0700), outside every repository.\n"
printf "  to bring your notes in:  keyring import ~/storage/downloads/Api\n\n"
