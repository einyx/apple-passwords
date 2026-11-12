//! The main window, laid out like Apple's Passwords app: a category sidebar, the
//! list of logins, and the detail of the selected one.

use std::rc::Rc;

use adw::prelude::*;
use icp_core::keychain::Credential;

use crate::ticker::Ticker;
use crate::{copy_secret, AppState, Category};

/// The site colours, picked so they stay readable on both themes.
const SITE_COLOURS: [(&str, &str); 8] = [
    ("#0a84ff", "#0060df"),
    ("#ff9f0a", "#c96a00"),
    ("#30d158", "#1a9e3c"),
    ("#ff375f", "#c21e42"),
    ("#bf5af2", "#8f36c0"),
    ("#64d2ff", "#0091b8"),
    ("#ff6482", "#c23c55"),
    ("#5e5ce6", "#3f3dbb"),
];

/// The app's CSS.
const CSS: &str = "
.sidebar { background-color: alpha(@theme_fg_color, 0.04); }
.card {
  border-radius: 12px;
  padding: 8px 10px;
}
.card .count { font-size: 11px; opacity: 0.55; }
.login-row {
  border-radius: 10px;
  padding: 4px 8px;
  margin-bottom: 2px;
}
.site-logo {
  border-radius: 10px;
  color: #fff;
  font-weight: 700;
}
.list-title { font-weight: 600; }
.list-sub { font-size: 11px; opacity: 0.55; }
.code { font-size: 12px; color: #0071e3; font-variant-numeric: tabular-nums; }
.detail-title { font-size: 20px; font-weight: 700; }
.detail-sub { font-size: 11px; opacity: 0.55; }
.field-label { font-size: 11px; opacity: 0.55; }
.field-value { font-size: 13px; }
.section-title { font-size: 13px; font-weight: 600; }
.menu-item { padding: 6px 12px; }
";

/// The hover and the selection.
///
/// The theme paints a hovered row with a translucent colour, which *replaces*
/// the row's background: on a card that reads as a transparent card, and on a
/// plain list there is no hover at all. These rules keep the background opaque
/// and blend the tint into it instead. The application's priority is above the
/// theme's, so they win.
const HOVER_CSS: &str = "
.card:hover {
  background-color: color-mix(in srgb, currentColor 6%, var(--card-bg-color));
}
.card.selected {
  background-color: color-mix(in srgb, var(--accent-color) 16%, var(--card-bg-color));
}
.login-row:hover {
  background-color: alpha(@theme_fg_color, 0.05);
}
.login-row.selected {
  background-color: alpha(@accent_bg_color, 0.16);
}
";

pub fn on_activate(app: &adw::Application) {
    // The app's styles.
    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS);
    let hover_provider = gtk::CssProvider::new();
    hover_provider.load_from_data(HOVER_CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        // The hover and selection rules.
        gtk::style_context_add_provider_for_display(
            &display,
            &hover_provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    let state = AppState::new();
    // The vault is the local encrypted store; reading it needs the keyring.
    state.load();
    let ticker = Ticker::new();

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Apple Passwords")
        .default_width(840)
        .default_height(540)
        .build();

    // --- the header ------------------------------------------------------
    let header = adw::HeaderBar::new();
    let title = gtk::Label::new(Some("All"));
    title.add_css_class("title");
    header.set_title_widget(Some(&title));
    let add_button = gtk::Button::from_icon_name("list-add-symbolic");
    add_button.set_tooltip_text(Some("Add a login"));
    add_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        move |_| {
            let _ = crate::add::open(&window, state.clone(), None);
        }
    });
    header.pack_start(&add_button);
    let sync_button = gtk::Button::from_icon_name("view-refresh-symbolic");
    sync_button.set_tooltip_text(Some("Sync now"));
    sync_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        move |_| sync(&window, state.clone())
    });
    header.pack_end(&sync_button);

    // --- the three panes --------------------------------------------------
    let body = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    body.add_css_class("background");
    body.set_vexpand(true);

    // The category sidebar.
    let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 6);
    sidebar.add_css_class("sidebar");
    sidebar.set_size_request(210, -1);
    sidebar.set_margin_top(8);
    sidebar.set_margin_bottom(8);
    sidebar.set_margin_start(6);
    sidebar.set_margin_end(0);
    let categories = gtk::ListBox::new();
    categories.add_css_class("boxed-list");
    categories.set_margin_start(6);
    categories.set_margin_end(6);
    sidebar.append(&categories);

    // The list of logins.
    let middle = gtk::Box::new(gtk::Orientation::Vertical, 0);
    middle.set_size_request(258, -1);
    let search = gtk::SearchEntry::new();
    search.set_hexpand(true);
    search.set_placeholder_text(Some("Search"));
    search.set_margin_top(6);
    search.set_margin_bottom(4);
    search.set_margin_start(8);
    search.set_margin_end(8);
    middle.append(&search);
    let list_box = gtk::ListBox::new();
    list_box.set_margin_top(2);
    list_box.set_margin_bottom(8);
    list_box.set_margin_start(4);
    list_box.set_margin_end(4);
    let scroller = gtk::ScrolledWindow::new();
    scroller.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    scroller.set_vexpand(true);
    // Without this the list asks for the width of its longest row, and the
    // detail pane is squeezed into a sliver.
    scroller.set_propagate_natural_width(false);
    scroller.set_child(Some(&list_box));
    middle.append(&scroller);

    // The detail.
    let detail = gtk::Box::new(gtk::Orientation::Vertical, 14);
    detail.set_size_request(320, -1);
    detail.set_margin_top(16);
    detail.set_margin_bottom(16);
    detail.set_margin_start(16);
    detail.set_margin_end(16);
    let detail_scroller = gtk::ScrolledWindow::new();
    detail_scroller.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    detail_scroller.set_vexpand(true);
    detail_scroller.set_propagate_natural_width(false);
    detail_scroller.set_child(Some(&detail));

    body.append(&sidebar);
    body.append(&middle);
    body.append(&detail_scroller);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&body));
    window.set_content(Some(&toolbar));

    // --- wiring -----------------------------------------------------------
    let list_box = Rc::new(list_box);
    let detail = Rc::new(detail);
    let categories = Rc::new(categories);
    let title = Rc::new(title);

    // Rebuild the list for the current category and query.
    let rebuild: Rc<dyn Fn()> = {
        let list_box = list_box.clone();
        let state = state.clone();
        let search = search.clone();
        let ticker = ticker.clone();
        let window = window.clone();
        let detail = detail.clone();
        Rc::new(move || {
            let query = search.text().to_lowercase();
            while let Some(child) = list_box.first_child() {
                list_box.remove(&child);
            }
            ticker.clear();
            let category = state.category();
            let mut shown = 0;
            for c in state.credentials.borrow().iter() {
                if !category.matches(c) {
                    continue;
                }
                let hay = format!("{} {} {}", c.domain, c.title, c.username).to_lowercase();
                if !query.is_empty() && !hay.contains(&query) {
                    continue;
                }
                let row = list_row(c, &ticker);
                let cred = c.clone();
                // The login that is selected stays highlighted.
                if state.selected.borrow().as_ref() == Some(&cred) {
                    row.add_css_class("selected");
                }
                let clicked = row.clone();
                row.connect_activated({
                    let detail = detail.clone();
                    let state = state.clone();
                    let ticker = ticker.clone();
                    let list_box = list_box.clone();
                    let cred = cred.clone();
                    move |_| {
                        *state.selected.borrow_mut() = Some(cred.clone());
                        show_detail(&detail, &cred, &ticker);
                        // Only one row is highlighted at a time.
                        let mut child = list_box.first_child();
                        while let Some(row) = child {
                            if let Some(row) = row.downcast_ref::<gtk::ListBoxRow>() {
                                row.remove_css_class("selected");
                            }
                            child = row.next_sibling();
                        }
                        clicked.add_css_class("selected");
                    }
                });
                // The right-click menu.
                add_context_menu(&row, &cred, &window, &state, &ticker, &detail);
                list_box.append(&row);
                shown += 1;
            }
            if shown == 0 {
                let page = adw::StatusPage::builder()
                    .icon_name("dialog-password-symbolic")
                    .title("Nothing here")
                    .description("Sync to fill the vault, or add a login with the + button.")
                    .build();
                page.set_vexpand(true);
                list_box.append(&page);
            }
        })
    };

    // Rebuild the category cards.
    rebuild_categories(&categories, &state, &title, &rebuild);
    rebuild();
    show_empty_detail(&detail);

    search.connect_search_changed({
        let rebuild = rebuild.clone();
        move |_| rebuild()
    });

    // The codes tick.
    glib::timeout_add_local(std::time::Duration::from_secs(1), move || {
        ticker.tick();
        glib::ControlFlow::Continue
    });

    let state2 = state.clone();
    window.connect_close_request(move |_| {
        state2.load();
        glib::Propagation::Proceed
    });

    window.present();

    // A debug hook: render the window - and the add dialog - to PNGs, and quit.
    if let Ok(path) = std::env::var("ICP_SCREENSHOT") {
        let state = state.clone();
        let list_box = list_box.clone();
        let window = window.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(900), move || {
            // The first login, so the detail pane is in the picture too.
            if let Some(row) = list_box.first_child() {
                if let Some(row) = row.downcast_ref::<gtk::ListBoxRow>() {
                    row.activate();
                }
            }
            glib::timeout_add_local_once(std::time::Duration::from_millis(700), move || {
                let surface = window
                    .clone()
                    .native()
                    .and_then(|n| n.surface())
                    .expect("the window has a surface");
                let renderer = gtk::gsk::Renderer::for_surface(&surface).expect("a renderer");
                if let Err(e) = save_png(&window, &path, &renderer) {
                    eprintln!("the screenshot failed: {e}");
                }
                let dialog = crate::add::open(&window, state, None);
                let dialog_path = path.replace(".png", "-add.png");
                glib::timeout_add_local_once(std::time::Duration::from_millis(800), move || {
                    if let Err(e) = save_png(&dialog, &dialog_path, &renderer) {
                        eprintln!("the dialog screenshot failed: {e}");
                    }
                    std::process::exit(0);
                });
            });
        });
    }
}

/// Render a widget to a PNG.
fn save_png(
    widget: &impl IsA<gtk::Widget>,
    path: &str,
    renderer: &gtk::gsk::Renderer,
) -> Result<(), String> {
    let paintable = gtk::WidgetPaintable::new(Some(widget));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, 1240.0, 760.0);
    let node = snapshot.to_node().ok_or("no render node")?;
    let texture = renderer.render_texture(&node, None);
    gtk::gdk::Texture::save_to_png(&texture, path).map_err(|e| e.to_string())
}

/// Draw the category cards.
fn rebuild_categories(
    grid: &gtk::ListBox,
    state: &Rc<AppState>,
    title: &gtk::Label,
    rebuild_list: &Rc<dyn Fn()>,
) {
    while let Some(child) = grid.first_child() {
        grid.remove(&child);
    }
    let current = state.category();
    for (index, category) in Category::all().iter().enumerate() {
        let count = state.count(category);
        let card = category_card(category, count, category == &current);
        card.connect_activated({
            let state = state.clone();
            let category = category.clone();
            let grid = grid.clone();
            let title = title.clone();
            let rebuild_list = rebuild_list.clone();
            move |_| {
                state.set_category(category.clone());
                rebuild_categories(&grid, &state, &title, &rebuild_list);
                rebuild_list();
            }
        });
        let _ = index;
        grid.append(&card);
    }
    title.set_text(current.title());
}

/// One row of the list: the site's logo, its name, the account and its code.
fn list_row(c: &Credential, ticker: &Rc<Ticker>) -> adw::ActionRow {
    let title = if c.title.is_empty() {
        c.domain.clone()
    } else {
        c.title.clone()
    };
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(c.username.clone())
        .activatable(true)
        .build();
    row.set_title_lines(1);
    row.set_subtitle_lines(1);
    row.add_css_class("login-row");

    let (fg, bg) = site_colour(&c.domain);
    let logo = gtk::Label::new(Some(&initial(&c.title, &c.domain)));
    logo.add_css_class("site-logo");
    logo.set_size_request(34, 34);
    logo.set_halign(gtk::Align::Center);
    logo.set_valign(gtk::Align::Center);
    paint(&logo, fg, bg);
    row.add_prefix(&logo);

    // The verification code, if the login has one.
    if !c.totp.is_empty() {
        let code = gtk::Label::new(Some(""));
        code.add_css_class("code");
        code.set_xalign(0.0);
        row.add_suffix(&code);
        ticker.watch(&code, c);
    }
    row
}

/// The right-click menu of a login.
fn add_context_menu(
    row: &adw::ActionRow,
    credential: &Credential,
    window: &adw::ApplicationWindow,
    state: &Rc<AppState>,
    ticker: &Rc<Ticker>,
    detail: &Rc<gtk::Box>,
) {
    let row = row.clone();
    let popover = gtk::Popover::new();
    popover.set_parent(&row);
    let menu = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let add_item = |label: &str, action: Box<dyn Fn() + 'static>| {
        let button = gtk::Button::with_label(label);
        button.add_css_class("flat");
        button.add_css_class("menu-item");
        let popover = popover.clone();
        button.connect_clicked(move |_| {
            popover.popdown();
            action();
        });
        menu.append(&button);
    };

    add_item("Copy password", {
        let row = row.clone();
        let secret = credential.password.clone();
        Box::new(move || copy_secret(&row, &secret, "password"))
    });
    add_item("Copy account name", {
        let row = row.clone();
        let secret = credential.username.clone();
        Box::new(move || copy_secret(&row, &secret, "account name"))
    });
    add_item("Edit", {
        let window = window.clone();
        let state = state.clone();
        let credential = credential.clone();
        Box::new(move || {
            let _ = crate::add::open(&window, state.clone(), Some(credential.clone()));
        })
    });
    add_item("Delete", {
        let window = window.clone();
        let state = state.clone();
        let credential = credential.clone();
        let ticker = ticker.clone();
        let detail = detail.clone();
        Box::new(move || {
            // The clones are moved into the closure, so clone them again here.
            let window = window.clone();
            let state = state.clone();
            let credential = credential.clone();
            let ticker = ticker.clone();
            let detail = detail.clone();
            confirm_delete(&window, state, credential, ticker, detail);
        })
    });

    popover.set_child(Some(&menu));

    let click = gtk::GestureClick::new();
    click.set_button(3);
    click.connect_released({
        let popover = popover.clone();
        move |_gesture, _clicks, x, y| {
            let rect = gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1);
            popover.set_pointing_to(Some(&rect));
            popover.popup();
        }
    });
    row.add_controller(click);
}

/// Ask before deleting a login.
fn confirm_delete(
    window: &adw::ApplicationWindow,
    state: Rc<AppState>,
    credential: Credential,
    ticker: Rc<Ticker>,
    detail: Rc<gtk::Box>,
) {
    let window = window.clone();
    let dialog = adw::MessageDialog::builder()
        .heading("Delete this login?")
        .body(format!(
            "{} will be removed from your iCloud Keychain, and from your other Apple devices.",
            if credential.title.is_empty() {
                credential.domain.clone()
            } else {
                credential.title.clone()
            }
        ))
        .modal(true)
        .transient_for(&window)
        .build();
    dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.connect_response(None, move |dialog, response| {
        if response == "delete" {
            let window = window.clone();
            let state = state.clone();
            let credential = credential.clone();
            let ticker = ticker.clone();
            let detail = detail.clone();
            let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
            glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
                let result: Result<String, String> = match rx.try_recv() {
                    Ok(r) => r,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        return glib::ControlFlow::Continue
                    }
                    Err(_) => return glib::ControlFlow::Break,
                };
                match result {
                    Ok(message) => {
                        state.load();
                        show_toast(&window, &message, "ok");
                    }
                    Err(e) => show_toast(&window, &format!("Could not delete: {e}"), "error"),
                }
                let _ = &ticker;
                let _ = &detail;
                glib::ControlFlow::Break
            });
            std::thread::spawn(move || {
                let result = (|| -> Result<String, String> {
                    let mut engine =
                        icp_core::engine::Engine::open(None).map_err(|e| e.to_string())?;
                    if credential.record_name.is_empty() {
                        return Err("that login has no keychain record".into());
                    }
                    engine
                        .delete_password(&credential.record_name, "Passwords")
                        .map_err(|e| e.to_string())?;
                    Ok("the login was deleted".to_string())
                })();
                let _ = tx.send(result);
            });
        }
        dialog.close();
    });
    dialog.present();
}

/// Give a widget its own colours.
fn paint(widget: &impl IsA<gtk::Widget>, fg: &str, bg: &str) {
    let provider = gtk::CssProvider::new();
    // A rule, not a bare declaration: GTK's parser reads a stylesheet, so
    // "background-color: #fff" on its own would be read as a selector.
    provider.load_from_data(&format!("* {{ background-color: {bg}; color: {fg}; }}"));
    widget
        .style_context()
        .add_provider(&provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
}

/// A category card: an icon, a name and a count.
fn category_card(category: &Category, count: usize, selected: bool) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(category.title())
        .activatable(true)
        .build();
    row.add_css_class("card");
    // One line: the name ellipsizes rather than wrapping.
    row.set_title_lines(1);
    let icon = gtk::Image::from_icon_name(category.icon());
    row.add_prefix(&icon);
    let count_label = gtk::Label::new(Some(&count.to_string()));
    count_label.add_css_class("count");
    row.add_suffix(&count_label);
    if selected {
        row.add_css_class("selected");
    }
    row
}

/// The first letter of a site's name.
fn initial(title: &str, domain: &str) -> String {
    let source = if title.is_empty() { domain } else { title };
    source
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// A stable colour for a site, from its name.
fn site_colour(domain: &str) -> (&'static str, &'static str) {
    let mut hash: u32 = 0;
    for b in domain.to_lowercase().bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    SITE_COLOURS[(hash % SITE_COLOURS.len() as u32) as usize]
}

/// The detail pane, empty.
fn show_empty_detail(detail: &gtk::Box) {
    clear(detail);
    let page = adw::StatusPage::builder()
        .icon_name("system-search-symbolic")
        .title("No login selected")
        .description("Pick a login to see its details.")
        .build();
    detail.append(&page);
}

/// The detail pane, for one credential.
fn show_detail(detail: &gtk::Box, c: &Credential, ticker: &Rc<Ticker>) {
    clear(detail);

    // The header: logo, name, when it changed.
    let head = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    let (fg, bg) = site_colour(&c.domain);
    let logo = gtk::Label::new(Some(&initial(&c.title, &c.domain)));
    logo.add_css_class("site-logo");
    logo.set_size_request(56, 56);
    logo.set_halign(gtk::Align::Center);
    logo.set_valign(gtk::Align::Center);
    paint(&logo, fg, bg);
    head.append(&logo);

    let names = gtk::Box::new(gtk::Orientation::Vertical, 2);
    names.set_valign(gtk::Align::Center);
    let title = gtk::Label::new(Some(if c.title.is_empty() {
        &c.domain
    } else {
        &c.title
    }));
    title.set_xalign(0.0);
    title.add_css_class("detail-title");
    names.append(&title);
    let when = modified(c.mdat);
    if !when.is_empty() {
        let sub = gtk::Label::new(Some(&when));
        sub.set_xalign(0.0);
        sub.add_css_class("detail-sub");
        names.append(&sub);
    }
    head.append(&names);

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    actions.set_halign(gtk::Align::End);
    actions.set_valign(gtk::Align::Center);
    let share = gtk::Button::from_icon_name("send-to-symbolic");
    share.set_tooltip_text(Some("Copy the password"));
    share.set_valign(gtk::Align::Center);
    share.connect_clicked({
        let secret = c.password.clone();
        move |b| copy_secret(b, &secret, "password")
    });
    actions.append(&share);
    head.append(&actions);
    detail.append(&head);

    // The fields.
    let group = gtk::Box::new(gtk::Orientation::Vertical, 10);
    group.append(&field(
        "User Name",
        &c.username,
        Some("edit-copy-symbolic"),
        c.username.clone(),
        "user name",
    ));
    group.append(&password_field(c));
    if !c.domain.is_empty() {
        group.append(&field("Website", &c.domain, None, String::new(), ""));
    }
    if !c.notes.is_empty() {
        group.append(&field("Note", &c.notes, None, String::new(), ""));
    }
    detail.append(&group);

    // The verification code.
    if !c.totp.is_empty() {
        let code = gtk::Label::new(Some(""));
        code.add_css_class("code");
        code.set_xalign(0.0);
        ticker.watch(&code, c);
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let caption = gtk::Label::new(Some("Verification code"));
        caption.set_xalign(0.0);
        caption.set_size_request(110, -1);
        caption.add_css_class("field-label");
        caption.set_valign(gtk::Align::Center);
        row.append(&caption);
        row.append(&code);
        let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
        copy.set_tooltip_text(Some("Copy the code"));
        copy.set_valign(gtk::Align::Center);
        copy.connect_clicked({
            let credential = c.clone();
            move |b| {
                if let Some(code) = icp_core::totp::code_for(&credential, None) {
                    copy_secret(b, &code.code, "code");
                }
            }
        });
        row.append(&copy);
        detail.append(&row);
    }

    // The security section.
    let security = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let section = gtk::Label::new(Some("Security"));
    section.set_xalign(0.0);
    section.add_css_class("section-title");
    security.append(&section);
    if c.password.is_empty() {
        let none = gtk::Label::new(Some("This item has no password."));
        none.add_css_class("detail-sub");
        none.set_xalign(0.0);
        security.append(&none);
    } else {
        let (label, fraction, colour) = strength(&c.password);
        let bar = gtk::ProgressBar::new();
        bar.set_fraction(fraction);
        bar.set_valign(gtk::Align::Center);
        {
            let provider = gtk::CssProvider::new();
            provider.load_from_data(&format!(
                "progressbar trough {{ background-color: {colour}; min-height: 6px; }}"
            ));
            bar.style_context()
                .add_provider(&provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
        security.append(&bar);
        let text = gtk::Label::new(Some(&label));
        text.set_xalign(0.0);
        text.add_css_class("detail-sub");
        security.append(&text);
    }
    detail.append(&security);
}

/// A labelled value, with an optional copy button.
fn field(label: &str, value: &str, icon: Option<&str>, secret: String, what: &str) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let caption = gtk::Label::new(Some(label));
    caption.set_xalign(0.0);
    caption.set_size_request(110, -1);
    caption.add_css_class("field-label");
    caption.set_valign(gtk::Align::Center);
    row.append(&caption);

    let value_label = gtk::Label::new(Some(value));
    value_label.set_xalign(0.0);
    value_label.set_hexpand(true);
    value_label.set_selectable(true);
    value_label.add_css_class("field-value");
    value_label.set_valign(gtk::Align::Center);
    row.append(&value_label);

    if let Some(icon) = icon {
        let b = gtk::Button::from_icon_name(icon);
        b.set_tooltip_text(Some(&format!("Copy the {what}")));
        b.set_valign(gtk::Align::Center);
        let what = what.to_string();
        b.connect_clicked(move |b| copy_secret(b, &secret, &what));
        row.append(&b);
    }
    row
}

/// The password row: masked, and clicking the dots reveals it (as in Apple's app).
fn password_field(c: &Credential) -> gtk::Box {
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 4);
    let caption = gtk::Label::new(Some("Password"));
    caption.set_xalign(0.0);
    caption.add_css_class("field-label");
    caption.add_css_class("caption-heading");
    box_.append(&caption);

    let row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let value = gtk::Label::new(Some(&masked(&c.password)));
    value.set_xalign(0.0);
    value.set_hexpand(true);
    value.add_css_class("monospace");
    value.set_selectable(true);
    let secret = c.password.clone();
    let revealed = std::rc::Rc::new(std::cell::Cell::new(false));
    {
        let label = value.clone();
        let secret = secret.clone();
        let revealed = revealed.clone();
        let click = gtk::GestureClick::new();
        click.connect_released(move |_, _clicks, _x, _y| {
            let now = !revealed.get();
            revealed.set(now);
            label.set_text(&if now { secret.clone() } else { masked(&secret) });
        });
        value.add_controller(click);
    }
    row.append(&value);
    let copy = gtk::Button::from_icon_name("edit-copy-symbolic");
    copy.set_tooltip_text(Some("Copy the password"));
    copy.set_valign(gtk::Align::Center);
    copy.connect_clicked({
        let secret = secret.clone();
        move |b| copy_secret(b, &secret, "password")
    });
    row.append(&copy);
    box_.append(&row);
    box_
}

/// The password, masked.
fn masked(password: &str) -> String {
    if password.is_empty() {
        String::new()
    } else {
        // One dot per character: the length is not a secret worth hiding from
        // the person who owns the keychain.
        "\u{2022}".repeat(password.chars().count())
    }
}

/// "Last modified today at 9:41 AM", or "Last modified on 4 May 2026".
fn modified(when: f64) -> String {
    if when <= 0.0 {
        return String::new();
    }
    let secs = when as i64;
    let day: i64 = secs.div_euclid(86400);
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);
    let time_of_day = secs.rem_euclid(86400);
    let (h, m) = (time_of_day / 3600, (time_of_day % 3600) / 60);
    let (pm, hour12) = (h >= 12, h % 12);
    let hour12 = if hour12 == 0 { 12 } else { hour12 };
    let clock = format!("{hour12}:{m:02} {}", if pm { "PM" } else { "AM" });
    let when_text = match day - today {
        0 => format!("today at {clock}"),
        -1 => format!("yesterday at {clock}"),
        _ => {
            let (year, month, day) = icp_core::civil_from_days(day);
            format!("on {} {} {}", day, MONTHS[(month - 1) as usize], year)
        }
    };
    format!("Last modified {when_text}")
}

/// The month names, for the dates.
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A crude password strength: length, character classes, and how many of them.
fn strength(password: &str) -> (String, f64, &'static str) {
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
    let len = password.chars().count();
    // A rough entropy estimate, in bits.
    let pool: f64 = match classes {
        0 => 1.0,
        1 => 26.0,
        2 => 62.0,
        3 => 94.0,
        _ => 125.0,
    };
    let bits = (len as f64) * pool.log2();
    let (label, colour) = if bits >= 100.0 {
        ("Strong Password", "#30d158")
    } else if bits >= 70.0 {
        ("Good Password", "#a3d911")
    } else if bits >= 45.0 {
        ("Fair Password", "#ffd60a")
    } else {
        ("Weak Password", "#ff453a")
    };
    let fraction = (bits / 120.0).clamp(0.05, 1.0);
    (
        format!("{label} - {bits:.0} bits of entropy"),
        fraction,
        colour,
    )
}

/// Empty a box.
fn clear(box_: &gtk::Box) {
    while let Some(child) = box_.first_child() {
        box_.remove(&child);
    }
}

/// Refresh the keychain in the background.
fn sync(window: &adw::ApplicationWindow, state: Rc<AppState>) {
    let window = window.clone();
    let toast = adw::Toast::new("Syncing...");
    toast.set_timeout(2);
    if let Some(overlay) = overlay_of(&window) {
        overlay.add_toast(toast);
    }
    let (tx, rx) = std::sync::mpsc::channel::<Result<usize, String>>();
    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
        let result: Result<usize, String> = match rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(_) => return glib::ControlFlow::Break,
        };
        state.load();
        let message = match &result {
            Ok(n) => format!("{n} logins"),
            Err(e) => format!("sync failed: {e}"),
        };
        show_toast(
            &window,
            &message,
            if result.is_ok() { "ok" } else { "error" },
        );
        glib::ControlFlow::Break
    });
    std::thread::spawn(move || {
        let result = (|| -> Result<usize, String> {
            let mut engine = icp_core::engine::Engine::open(None).map_err(|e| e.to_string())?;
            let creds = engine
                .sync_with_groups(icp_core::ckks::KEYCHAIN_ZONES)
                .map_err(|e| e.to_string())?;
            icp_core::vault::save(&creds).map_err(|e| e.to_string())?;
            Ok(creds.len())
        })();
        let _ = tx.send(result);
    });
}

/// The window's toast overlay, if it has one.
pub fn overlay_of(window: &adw::ApplicationWindow) -> Option<adw::ToastOverlay> {
    window
        .content()
        .and_then(|c| c.ancestor(adw::ToastOverlay::static_type()))
        .and_downcast::<adw::ToastOverlay>()
}

/// Show a message.
pub fn show_toast(window: &adw::ApplicationWindow, message: &str, kind: &str) {
    let toast = adw::Toast::new(message);
    if kind == "error" {
        toast.set_timeout(6);
    }
    if let Some(overlay) = overlay_of(window) {
        overlay.add_toast(toast);
    }
}
