#!/bin/sh
# Installs kzsigner for the current user: the program into ~/.local/bin, and a menu entry with
# its icon, so it shows in the applications menu and in "Open with" for .cms and .p12 files.
# It only uses the freedesktop.org (XDG) locations, so it works the same on any distribution and
# desktop (GNOME, KDE Plasma, Xfce, ...). Nothing is installed system-wide and no root is needed.
# Remove with: sh install.sh --uninstall
set -e
cd "$(dirname "$0")"
BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
if [ "$1" = "--uninstall" ]; then
    rm -f "$BIN/kzsigner" "$DATA/applications/kzsigner.desktop" "$DATA/icons/hicolor/256x256/apps/kzsigner.png"
    echo "kzsigner removed."
    exit 0
fi
install -Dm755 kzsigner "$BIN/kzsigner"
install -Dm644 kzsigner.png "$DATA/icons/hicolor/256x256/apps/kzsigner.png"
sed "s|^Exec=kzsigner|Exec=$BIN/kzsigner|" kzsigner.desktop > kzsigner.desktop.tmp
install -Dm644 kzsigner.desktop.tmp "$DATA/applications/kzsigner.desktop"
rm -f kzsigner.desktop.tmp
command -v update-desktop-database >/dev/null && update-desktop-database "$DATA/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "$DATA/icons/hicolor" 2>/dev/null || true
# KDE Plasma picks up new menu entries by itself, but rebuilding its cache makes it immediate
for k in kbuildsycoca6 kbuildsycoca5; do
    command -v "$k" >/dev/null && { "$k" >/dev/null 2>&1 || true; break; }
done
echo "kzsigner installed to $BIN/kzsigner, with a menu entry."
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Note: $BIN is not in your PATH, so 'kzsigner' won't run from a terminal by name."
       echo "The menu entry works anyway. To fix the terminal, add this to your shell's profile:"
       echo "    export PATH=\"$BIN:\$PATH\"" ;;
esac
