//! The tray icon: the app in the top bar.
//!
//! GTK4 has no tray of its own, so this is a StatusNotifierItem - the
//! freedesktop.org way, which GNOME speaks through its app-indicator support.
//!
//! The tray's own thread is not the app's thread, so the tray never touches a
//! widget: it sends a command, and the app reads it.

use std::sync::mpsc::{Receiver, Sender};

use ksni::blocking::TrayMethods;
use ksni::menu::StandardItem;
use ksni::{Category, Status, ToolTip, Tray};

/// What the tray asks the app to do.
#[derive(Clone, Copy, Debug)]
pub enum Command {
    /// Bring the window up.
    Show,
    /// Fetch the keychain again.
    Sync,
    /// Leave.
    Quit,
}

/// The tray icon.
struct TrayIcon {
    commands: Sender<Command>,
    icon_dir: String,
}

impl Tray for TrayIcon {
    fn id(&self) -> String {
        "org.icp.passwords".into()
    }

    fn title(&self) -> String {
        "Apple Passwords".into()
    }

    fn category(&self) -> Category {
        Category::ApplicationStatus
    }

    fn status(&self) -> Status {
        Status::Active
    }

    fn icon_name(&self) -> String {
        "org.icp.passwords".into()
    }

    /// Where the icon is, when the app runs from a checkout.
    fn icon_theme_path(&self) -> String {
        self.icon_dir.clone()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: "org.icp.passwords".into(),
            icon_pixmap: Vec::new(),
            title: "Apple Passwords".into(),
            description: "Your iCloud Keychain".into(),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.commands.send(Command::Show);
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        let _ = self.commands.send(Command::Show);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Open".into(),
                icon_name: "window-new-symbolic".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.commands.send(Command::Show);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Sync now".into(),
                icon_name: "view-refresh-symbolic".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.commands.send(Command::Sync);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit-symbolic".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.commands.send(Command::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Start the tray icon.
///
/// The commands the user picks arrive on the returned channel. `None` means
/// the desktop has no tray at all, and the app runs without one.
pub fn start() -> Option<Receiver<Command>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let icon = TrayIcon {
        commands: tx,
        icon_dir: icon_dir(),
    };
    // The handle keeps the service alive; the tray lives as long as the app.
    match icon.spawn() {
        Ok(handle) => {
            Box::leak(Box::new(handle));
            Some(rx)
        }
        Err(e) => {
            eprintln!("the tray icon could not be started: {e}");
            None
        }
    }
}

/// Where the app's icon is, for a run that is not installed.
fn icon_dir() -> String {
    if let Some(manifest) = option_env!("CARGO_MANIFEST_DIR") {
        let icons = std::path::Path::new(manifest).join("icons");
        if icons.is_dir() {
            return icons.to_string_lossy().to_string();
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for up in exe.ancestors().skip(1).take(4) {
            let candidate = up.join("share/icons/hicolor/scalable/apps");
            if candidate.is_dir() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }
    String::new()
}
