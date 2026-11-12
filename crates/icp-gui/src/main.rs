//! The desktop app for Apple Passwords.
//!
//! A GTK4 + libadwaita window over the keychain client: a searchable list of
//! logins, the details of the selected one, and a button that adds a new login to
//! the real iCloud Keychain.
//!
//! The list is served from the local encrypted vault, so browsing works offline; the
//! network is only touched when the user asks for a sync or adds a login.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::prelude::*;
use icp_core::keychain::Credential;

mod add;
mod ticker;
mod window;

/// How long a copied secret stays on the clipboard.
const CLIPBOARD_TTL: u32 = 20;

fn main() -> gtk::glib::ExitCode {
    // libadwaita has to be initialised before any of its widgets exist.
    adw::init();

    let app = adw::Application::builder()
        .application_id("org.icp.passwords")
        .build();
    app.connect_activate(window::on_activate);
    app.connect_startup(|_| {
        // The app's icon: the bundled SVG, plus whatever the icon theme has.
        if let Some(display) = gtk::gdk::Display::default() {
            let theme = gtk::IconTheme::for_display(&display);
            for dir in icon_dirs() {
                theme.add_search_path(&dir);
            }
        }
        gtk::Window::set_default_icon_name("org.icp.passwords");
    });
    app.run()
}

/// Where the app's icon may live.
fn icon_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    // The icon that ships with the source tree.
    if let Some(manifest) = option_env!("CARGO_MANIFEST_DIR") {
        dirs.push(std::path::PathBuf::from(manifest).join("icons"));
    }
    // The icon next to the executable (an installed copy).
    if let Ok(exe) = std::env::current_exe() {
        for up in exe.ancestors().skip(1).take(4) {
            let candidate = up.join("icons");
            if candidate.is_dir() {
                dirs.push(candidate);
            }
            let candidate = up.join("share/icons/hicolor/scalable/apps");
            if candidate.is_dir() {
                dirs.push(candidate);
            }
        }
    }
    // The installed icon.
    if let Ok(data) = std::env::var("XDG_DATA_HOME") {
        dirs.push(std::path::PathBuf::from(data).join("icons/hicolor/scalable/apps"));
    } else if let Ok(home) = std::env::var("HOME") {
        dirs.push(
            std::path::PathBuf::from(home).join(".local/share/icons/hicolor/scalable/apps"),
        );
    }
    dirs
}

/// The application state, shared by the window and the dialogs.
pub struct AppState {
    pub credentials: RefCell<Vec<Credential>>,
    pub selected: RefCell<Option<Credential>>,
    category: RefCell<Category>,
}

impl AppState {
    pub fn new() -> Rc<AppState> {
        Rc::new(AppState {
            credentials: RefCell::new(Vec::new()),
            selected: RefCell::new(None),
            category: RefCell::new(Category::All),
        })
    }

    /// The category the list is showing.
    pub fn category(&self) -> Category {
        self.category.borrow().clone()
    }

    /// Show a different category.
    pub fn set_category(&self, category: Category) {
        *self.category.borrow_mut() = category;
    }

    /// How many credentials are in a category.
    pub fn count(&self, category: &Category) -> usize {
        self.credentials
            .borrow()
            .iter()
            .filter(|c| category.matches(c))
            .count()
    }

    /// Load the vault into the state.
    pub fn load(&self) {
        match icp_core::vault::load() {
            Ok(creds) => {
                let mut creds = creds;
                creds.sort_by(|a, b| {
                    (a.title.to_lowercase(), a.username.to_lowercase())
                        .cmp(&(b.title.to_lowercase(), b.username.to_lowercase()))
                });
                *self.credentials.borrow_mut() = creds;
            }
            Err(e) => eprintln!("could not open the vault: {e}"),
        }
        eprintln!("vault: {} credentials", self.credentials.borrow().len());
    }
}

/// The categories the sidebar offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    All,
    Passwords,
    Codes,
    Security,
}

impl Category {
    /// Every category, in the order the sidebar shows them.
    pub fn all() -> Vec<Category> {
        vec![
            Category::All,
            Category::Passwords,
            Category::Codes,
            Category::Security,
        ]
    }

    /// The category's name.
    pub fn title(&self) -> &'static str {
        match self {
            Category::All => "All",
            Category::Passwords => "Passwords",
            Category::Codes => "Codes",
            Category::Security => "Security",
        }
    }

    /// The category's icon.
    pub fn icon(&self) -> &'static str {
        match self {
            Category::All => "view-list-symbolic",
            Category::Passwords => "dialog-password-symbolic",
            Category::Codes => "view-pin-entry-symbolic",
            Category::Security => "dialog-warning-symbolic",
        }
    }

    /// Does a credential belong in this category?
    pub fn matches(&self, c: &Credential) -> bool {
        match self {
            Category::All => true,
            Category::Passwords => !c.password.is_empty(),
            Category::Codes => !c.totp.is_empty(),
            // The security category is the logins with a password worth worrying about:
            // a weak one, or one used on more than one site.
            Category::Security => !c.password.is_empty() && is_weak(&c.password),
        }
    }
}

/// A crude strength test, used for the security category and the detail pane.
pub fn is_weak(password: &str) -> bool {
    let mut classes = 0;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes += 1;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        classes += 1;
    }
    let pool: f64 = match classes {
        0 => 1.0,
        1 => 26.0,
        2 => 62.0,
        3 => 94.0,
        _ => 125.0,
    };
    let bits = (password.chars().count() as f64) * pool.log2();
    bits < 60.0
}

/// A coarse 'last used' label.
pub fn relative(when: f64) -> String {
    if when <= 0.0 {
        return String::new();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let days = ((now - when) / 86400.0).floor() as i64;
    if days < 0 {
        "today".to_string()
    } else if days == 0 {
        "today".to_string()
    } else if days == 1 {
        "yesterday".to_string()
    } else if days < 30 {
        format!("{days} days ago")
    } else if days < 365 {
        format!("{} months ago", days / 30)
    } else {
        format!("{} years ago", days / 365)
    }
}

/// Copy a secret to the clipboard, and clear it again after a while.
pub fn copy_secret(widget: &impl IsA<gtk::Widget>, text: &str, what: &str) {
    if text.is_empty() {
        return;
    }
    let widget = widget.clone().upcast::<gtk::Widget>();
    let clipboard = widget.clipboard();
    clipboard.set_text(text);
    let toast = adw::Toast::new(&format!("{what} copied"));
    toast.set_timeout(2);
    if let Some(overlay) = widget
        .clone()
        .ancestor(adw::ToastOverlay::static_type())
        .and_downcast::<adw::ToastOverlay>()
    {
        overlay.add_toast(toast);
    }
    // Clear the clipboard again, so the secret does not sit there.
    glib::timeout_add_local_once(
        std::time::Duration::from_secs(CLIPBOARD_TTL as u64),
        move || {
            let clipboard = widget.clipboard();
            clipboard.set_text("");
        },
    );
}
