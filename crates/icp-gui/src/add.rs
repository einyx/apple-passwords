//! The "add a login" dialog (which doubles as the edit dialog): writes into the
//! real iCloud Keychain.

use std::rc::Rc;

use adw::prelude::*;
use gtk::prelude::*;
use icp_core::keychain::Credential;

use crate::AppState;

/// Open the dialog. With a credential, it edits that one; without, it adds a new one.
pub fn open(parent: &adw::ApplicationWindow, state: Rc<AppState>, existing: Option<Credential>) {
    let editing = existing.is_some();
    let dialog = adw::Window::builder()
        .modal(true)
        .transient_for(parent)
        .title(if editing { "Edit login" } else { "Add a login" })
        .default_width(440)
        .default_height(if editing { 300 } else { 380 })
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();

    let cancel = gtk::Button::with_label("Cancel");
    cancel.connect_clicked({
        let dialog = dialog.clone();
        move |_| dialog.close()
    });
    header.pack_start(&cancel);

    let save = gtk::Button::with_label(if editing { "Save" } else { "Add" });
    save.add_css_class("suggested-action");
    save.set_sensitive(false);
    let save_for_click = save.clone();
    save.connect_clicked({
        let dialog = dialog.clone();
        let parent = parent.clone();
        let state = state.clone();
        let existing = existing.clone();
        move |_| {
            save_clicked(
                &dialog,
                &parent,
                state.clone(),
                save_for_click.clone(),
                existing.clone(),
            );
        }
    });
    header.pack_end(&save);
    toolbar.add_top_bar(&header);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.set_margin_top(18);
    content.set_margin_bottom(18);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let group = adw::PreferencesGroup::builder().title("Login").build();
    let site = adw::EntryRow::builder().title("Site").build();
    let account = adw::EntryRow::builder().title("Account").build();
    let password = adw::EntryRow::builder().title("Password").build();
    let notes = adw::EntryRow::builder().title("Notes").build();
    group.add(&site);
    group.add(&account);
    group.add(&password);
    group.add(&notes);
    content.append(&group);

    // The strong password suggestions.
    let suggestions_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let suggestions_title = gtk::Label::new(Some("Strong password"));
    suggestions_title.set_xalign(0.0);
    suggestions_title.add_css_class("section-title");
    suggestions_box.append(&suggestions_title);
    for suggestion in icp_core::write::suggest_passwords(3) {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let label = gtk::Label::new(Some(&suggestion));
        label.set_xalign(0.0);
        label.set_hexpand(true);
        label.add_css_class("monospace");
        label.set_selectable(true);
        row.append(&label);
        let use_button = gtk::Button::with_label("Use");
        use_button.set_valign(gtk::Align::Center);
        let password_row = password.clone();
        let suggestion = suggestion.clone();
        use_button.connect_clicked(move |_| {
            set_entry_text(&password_row, &suggestion);
        });
        row.append(&use_button);
        suggestions_box.append(&row);
    }
    let hint = gtk::Label::new(Some(
        "A suggestion fills the password field; you can change it before saving.",
    ));
    hint.set_xalign(0.0);
    hint.add_css_class("detail-sub");
    suggestions_box.append(&hint);
    content.append(&suggestions_box);

    toolbar.set_content(Some(&content));
    dialog.set_content(Some(&toolbar));

    // Prefill, when editing.
    if let Some(credential) = &existing {
        set_entry_text(&site, &credential.domain);
        set_entry_text(&account, &credential.username);
        set_entry_text(&password, &credential.password);
        set_entry_text(&notes, &credential.notes);
    } else {
        site.set_text("https://");
    }

    // The save button is only live once there is something to save.
    {
        let save_c = save.clone();
        let site_c = site.clone();
        let account_c = account.clone();
        let password_c = password.clone();
        let make_check = move |_: &adw::EntryRow| {
            let save = save_c.clone();
            let site = site_c.clone();
            let account = account_c.clone();
            let password = password_c.clone();
            move |_: &adw::EntryRow| {
                save.set_sensitive(
                    !domain_of(&site.text()).is_empty()
                        && !account.text().trim().is_empty()
                        && !password.text().is_empty(),
                );
            }
        };
        let c1 = make_check(&site);
        let c2 = make_check(&account);
        let c3 = make_check(&password);
        site.connect_changed(c1);
        account.connect_changed(c2);
        password.connect_changed(c3);
    }

    dialog.present();
}

/// Set an entry row's text.
fn set_entry_text(row: &adw::EntryRow, text: &str) {
    let mut found = None;
    let mut child = row.first_child();
    while let Some(c) = child {
        if let Some(entry) = c.downcast_ref::<gtk::Entry>() {
            found = Some(entry.clone());
            break;
        }
        child = c.next_sibling();
    }
    if let Some(entry) = found {
        entry.set_text(text);
    }
}

/// The site name from whatever was typed: a URL, or a bare host.
fn domain_of(text: &str) -> String {
    let mut text = text.trim().to_string();
    if text.is_empty() {
        return String::new();
    }
    for prefix in ["https://", "http://"] {
        if text.to_lowercase().starts_with(prefix) {
            text = text[prefix.len()..].to_string();
            break;
        }
    }
    let text = text.split('/').next().unwrap_or("").to_string();
    let text = text.strip_prefix("www.").unwrap_or(&text).to_string();
    text.trim().to_string()
}

/// Write the login into the keychain.
fn save_clicked(
    dialog: &adw::Window,
    parent: &adw::ApplicationWindow,
    state: Rc<AppState>,
    save: gtk::Button,
    existing: Option<Credential>,
) {
    // The entries live in the dialog's content; find them by their title.
    let Some((domain, account, password, notes)) = entries(dialog) else {
        return;
    };
    let domain = domain_of(&domain);
    if domain.is_empty() || account.trim().is_empty() || password.is_empty() {
        return;
    }
    save.set_sensitive(false);
    save.set_label("Saving...");

    let parent = parent.clone();
    let dialog = dialog.clone();
    let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
        let result: Result<String, String> = match rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(_) => return glib::ControlFlow::Break,
        };
        match result {
            Ok(message) => {
                state.load();
                crate::window::show_toast(&parent, &message, "ok");
                dialog.close();
            }
            Err(e) => {
                crate::window::show_toast(&parent, &format!("Could not save: {e}"), "error");
                save.set_sensitive(true);
                save.set_label("Save");
            }
        }
        glib::ControlFlow::Break
    });
    std::thread::spawn(move || {
        let result = (|| -> Result<String, String> {
            let mut engine = icp_core::engine::Engine::open(None).map_err(|e| e.to_string())?;
            let notes = if notes.trim().is_empty() {
                None
            } else {
                Some(notes.trim())
            };
            match &existing {
                Some(credential) if !credential.record_name.is_empty() => {
                    engine
                        .update_password(
                            &credential.record_name,
                            &password,
                            &domain,
                            account.trim(),
                            None,
                            notes,
                            "Passwords",
                        )
                        .map_err(|e| e.to_string())?;
                    Ok(format!("{domain} updated in your iCloud Keychain"))
                }
                _ => {
                    engine
                        .add_password(
                            &domain,
                            account.trim(),
                            &password,
                            None,
                            notes,
                            "Passwords",
                        )
                        .map_err(|e| e.to_string())?;
                    Ok(format!("{domain} saved to your iCloud Keychain"))
                }
            }
        })();
        let _ = tx.send(result);
    });
}

/// The dialog's four entries, found by walking its widget tree.
fn entries(window: &adw::Window) -> Option<(String, String, String, String)> {
    let root = window.content()?;
    let mut found: Vec<(String, gtk::Entry)> = Vec::new();
    collect_entries(&root, &mut found);
    let get = |title: &str| -> String {
        found
            .iter()
            .find(|(t, _)| t == title)
            .map(|(_, e)| e.text().to_string())
            .unwrap_or_default()
    };
    Some((
        get("Site"),
        get("Account"),
        get("Password"),
        get("Notes"),
    ))
}

/// Walk the tree for the entry rows.
fn collect_entries(widget: &gtk::Widget, out: &mut Vec<(String, gtk::Entry)>) {
    if let Some(row) = widget.downcast_ref::<adw::EntryRow>() {
        let mut child = row.first_child();
        while let Some(c) = child {
            if let Some(entry) = c.downcast_ref::<gtk::Entry>() {
                out.push((row.title().to_string(), entry.clone()));
                break;
            }
            child = c.next_sibling();
        }
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        collect_entries(&c, out);
        child = c.next_sibling();
    }
}
