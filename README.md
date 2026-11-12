# apple-passwords

A native Linux app for **Apple Passwords** - the iCloud Keychain, on your own machine.

It reads your iCloud Keychain, shows every login in a searchable window, fills them
into the browser, and can add new ones *to the real keychain*, so they reach your
Apple devices.

The protocol was reverse-engineered from the wire; the findings are written up in
[RUST-NOTES.md](RUST-NOTES.md).

## Status

| | |
| --- | --- |
| Read the keychain | working - every credential decrypts |
| Write a login | working - the write is read back and decrypted before it is reported |
| Sign in | working - the SRP exchange, the two factors and the escrow-based join |
| The desktop app | working (GTK4 + libadwaita) |
| The browser extension | working - fill, save, update, and the one-time codes |
| The shared groups | working - the groups you are a member of open and decrypt |
| Hide My Email | working - the aliases are fetched and cached |

## Installing

The releases carry a `.deb`, an `.rpm`, a Flatpak and the plain binaries, for
x86-64 and aarch64:

```sh
# Debian, Ubuntu
sudo apt install ./apple-passwords_0.1.0_amd64.deb

# Fedora, RHEL
sudo dnf install ./apple-passwords-0.1.0-1.x86_64.rpm

# Flatpak
flatpak install --user ./build.flatpak

# The binaries
tar xf apple-passwords_0.1.0_x86_64.tar.gz
```

The app needs an anisette server (the local one on `http://127.0.0.1:6969`) and a
signed-in session.

## Building from source

```sh
cargo build --release
```

The GTK4 development files (`libgtk-4-dev`, `libadwaita-1-dev`) are needed.

## Using it

```sh
icp-cli login               # sign in, join the keychain trust, and sync
icp-cli sync                # fetch the keychain (and the shared groups) into the vault
icp-cli show                # list the vault
icp-cli groups              # the shared password groups
icp-cli aliases             # the Hide My Email aliases
icp-cli add <domain> <user> <password>
icp-cli status              # what the session holds
```

The desktop app is `icp-gui`.

## The browser extension

The extension is a native-messaging host: `icp-host` answers the browser's
requests from the local vault. It fills the logins, records the new ones - with a
strong-password suggestion - and writes a changed password back to the keychain.

## The session

The session lives in `~/.config/icp/`, encrypted with a libsodium secret box whose
key is in the GNOME keyring. The Python implementation
(`iCloud-Keychain-for-Linux`) reads and writes the same file, the same keyring
item and the same vault, so the two can share one sign-in.

## The vault

The decrypted credentials live in `~/.config/icp/vault.enc`, encrypted with a
libsodium secret box whose key is in the GNOME keyring. A master key that does not
match the vault is never a reason to delete it: that almost always means the
keyring was unreachable, and deleting it would throw the credentials away.

## Licence

MIT.
