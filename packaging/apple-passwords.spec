Name:           apple-passwords
Version:        0.1.0
Release:        1%{?dist}
Summary:        Apple Passwords - your iCloud Keychain on Linux

License:        MIT
URL:            https://github.com/einyx/apple-passwords
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.80
BuildRequires:  pkgconfig
BuildRequires:  gtk4-devel
BuildRequires:  libadwaita-devel
BuildRequires:  openssl-devel

Requires:       gtk4
Requires:       libadwaita
Requires:       libsodium

%description
Apple Passwords reads your iCloud Keychain on Linux: browse and search every
login, copy the passwords, and add new ones to the real keychain so they reach
your Apple devices.

%prep
%autosetup

%build
cargo build --release --locked

%install
mkdir -p %{buildroot}%{_bindir}
install -m755 target/release/icp-gui %{buildroot}%{_bindir}/icp-gui
install -m755 target/release/icp-cli %{buildroot}%{_bindir}/icp-cli
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -m644 crates/icp-gui/icons/org.icp.passwords.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.icp.passwords.svg
mkdir -p %{buildroot}%{_datadir}/applications
install -m644 crates/icp-gui/data/org.icp.passwords.desktop \
    %{buildroot}%{_datadir}/applications/org.icp.passwords.desktop
mkdir -p %{buildroot}%{_datadir}/doc/%{name}
install -m644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md
install -m644 LICENSE %{buildroot}%{_datadir}/doc/%{name}/LICENSE

%check
cargo test --release --locked

%files
%license LICENSE
%{_bindir}/icp-gui
%{_bindir}/icp-cli
%{_datadir}/icons/hicolor/scalable/apps/org.icp.passwords.svg
%{_datadir}/applications/org.icp.passwords.desktop
%doc %{name}/README.md

%changelog
* Thu Nov 12 2026 einyx <einyx@users.noreply.github.com> - 0.1.0-1
- First release: read the iCloud Keychain, and write to it.
