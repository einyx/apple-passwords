#!/bin/sh
# Install the app: the binaries, the icon and the desktop entry.
set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
BIN="${BIN:-$PREFIX/bin}"
DATA="${DATA:-$PREFIX/share}"

echo "Installing the app into $PREFIX"

cargo build --release --manifest-path "$ROOT/Cargo.toml"

install -Dm755 "$ROOT/target/release/icp-gui" "$BIN/icp-gui"
install -Dm755 "$ROOT/target/release/icp-cli" "$BIN/icp-cli"
install -Dm755 "$ROOT/target/release/icp-host" "$BIN/icp-host"
install -Dm644 "$ROOT/crates/icp-gui/icons/org.icp.passwords.svg" \
    "$DATA/icons/hicolor/scalable/apps/org.icp.passwords.svg"
install -Dm644 "$ROOT/crates/icp-gui/data/org.icp.passwords.desktop" \
    "$DATA/applications/org.icp.passwords.desktop"

command -v update-desktop-database >/dev/null && \
    update-desktop-database "$DATA/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && \
    gtk-update-icon-cache -f -t "$DATA/icons/hicolor" 2>/dev/null || true

echo "Done. Start it with: icp-gui"
