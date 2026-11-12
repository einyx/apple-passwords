#!/bin/sh
# Build a .deb package.
#
# Usage: build-deb.sh <version> <arch> <output.deb>
#
# The package holds the two binaries, the icon and the desktop entry.
set -e

VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
OUT="${3:-apple-passwords_${VERSION}_${ARCH}.deb}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

PKG="apple-passwords"
DEBIAN="$BUILD/DEBIAN"
mkdir -p "$DEBIAN" \
         "$BUILD/usr/bin" \
         "$BUILD/usr/share/icons/hicolor/scalable/apps" \
         "$BUILD/usr/share/applications" \
         "$BUILD/usr/share/doc/$PKG"

install -m755 "$ROOT/target/release/icp-gui" "$BUILD/usr/bin/icp-gui"
install -m755 "$ROOT/target/release/icp-cli" "$BUILD/usr/bin/icp-cli"
install -m644 "$ROOT/crates/icp-gui/icons/org.icp.passwords.svg" \
    "$BUILD/usr/share/icons/hicolor/scalable/apps/org.icp.passwords.svg"
install -m644 "$ROOT/crates/icp-gui/data/org.icp.passwords.desktop" \
    "$BUILD/usr/share/applications/org.icp.passwords.desktop"
install -m644 "$ROOT/README.md" "$BUILD/usr/share/doc/$PKG/README.md"
install -m644 "$ROOT/LICENSE" "$BUILD/usr/share/doc/$PKG/LICENSE" 2>/dev/null || true

# The installed size, in KiB.
SIZE=$(du -ks "$BUILD" | cut -f1)

cat > "$DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: libc6, libgtk-4-1, libadwaita-1-0, libsodium23
Installed-Size: $SIZE
Homepage: https://github.com/einyx/apple-passwords
Maintainer: einyx <einyx@users.noreply.github.com>
Description: Your iCloud Keychain on Linux
 Apple Passwords reads your iCloud Keychain on Linux: browse and search every
 login, copy the passwords, and add new ones to the real keychain so they reach
 your Apple devices.
EOF

mkdir -p "$BUILD/DEBIAN"
cat > "$DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null; then
    update-desktop-database /usr/share/applications || true
fi
exit 0
EOF
chmod 755 "$DEBIAN/postinst"

chmod 755 "$BUILD"
dpkg-deb --build --root-owner-group "$BUILD" "$OUT"
echo "built $OUT"
