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
| The desktop app | working (GTK4 + libadwaita) |
| Sign in | not yet - the app reads an existing session (see below) |

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
icp-cli check      # what the client can see (no secrets)
icp-cli sync       # fetch the keychain into the local vault
icp-cli show       # list the vault
icp-cli add <domain> <user> <password>
```

The desktop app is `icp-gui`.

## The session

The app reads the session the Python implementation (`iCloud-Keychain-for-Linux`)
wrote - the same file, the same keyring item, the same vault - so there is one
sign-in, not two. Signing in from scratch (the SRP exchange and the escrow-based
join) is not ported yet.

## The vault

The decrypted credentials live in `~/.config/icp/vault.enc`, encrypted with a
libsodium secret box whose key is in the GNOME keyring. A master key that does not
match the vault is never a reason to delete it: that almost always means the
keyring was unreachable, and deleting it would throw the credentials away.

## Licence

MIT.
