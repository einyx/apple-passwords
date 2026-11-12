# Apple Passwords

Your iCloud Keychain on Linux - a native app that reads the keychain, shows every
login, and can add new ones to the real keychain so they reach your Apple devices.

## What is in this release

| | |
| --- | --- |
| The keychain client | the CloudKit record protocol, the keychain's unwrap chain, and the write path - a Rust rewrite, checked byte-for-byte against the Python implementation |
| The desktop app | GTK4 + libadwaita: a category sidebar, the list of logins, the detail of the selected one, and a button that adds a login |
| The command line | `icp-cli` - sync, show, add, and a `check` that reports what the client can see |

## Install

**The app (Debian/Ubuntu):**

```sh
sudo apt install ./apple-passwords_<version>_amd64.deb
```

**Fedora/RHEL:**

```sh
sudo dnf install ./apple-passwords-<version>-1.<arch>.rpm
```

**Flatpak:**

```sh
flatpak install --user ./build.flatpak
```

**The binaries:**

```sh
tar xf apple-passwords_<version>_x86_64.tar.gz
```

The app needs an anisette server (the local one on `http://127.0.0.1:6969`) and a
signed-in session.

## Signing in

The app reads the session the Python implementation wrote - the same file, the same
keyring item, the same vault - so there is one sign-in, not two. Signing in from
scratch is not ported yet.

## Checksums

`SHA256SUMS` lists the hash of every artifact in this release.
