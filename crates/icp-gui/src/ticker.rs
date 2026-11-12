//! The codes that tick: a one-time password under a login, refreshed every second.

use std::cell::RefCell;
use std::rc::Rc;

use icp_core::keychain::Credential;

/// The labels that show a code, and the credential each belongs to.
#[derive(Default)]
pub struct Ticker {
    entries: RefCell<Vec<(gtk::Label, Credential)>>,
}

impl Ticker {
    pub fn new() -> Rc<Ticker> {
        Rc::new(Ticker::default())
    }

    /// Show a credential's code in a label, and keep it up to date.
    pub fn watch(self: &Rc<Self>, label: &gtk::Label, credential: &Credential) {
        if credential.totp.is_empty() {
            return;
        }
        self.entries
            .borrow_mut()
            .push((label.clone(), credential.clone()));
        self.paint_one(label, credential);
    }

    /// Forget the labels of the list that is about to be rebuilt.
    pub fn clear(&self) {
        self.entries.borrow_mut().clear();
    }

    /// Refresh every code.
    pub fn tick(&self) {
        for (label, credential) in self.entries.borrow().iter() {
            self.paint_one(label, credential);
        }
    }

    fn paint_one(&self, label: &gtk::Label, credential: &Credential) {
        let code = icp_core::totp::code_for(credential, None);
        match code {
            Some(code) => {
                let left = (code.expires - now()) as i64;
                label.set_text(&format!("{}  {}s", code.code, left.max(0)));
            }
            None => label.set_text(""),
        }
    }
}

/// The current time, in unix seconds.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
