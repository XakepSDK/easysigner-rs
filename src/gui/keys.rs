//! Keys kept on the phone (src/vault.rs): the list on the Sign screen, saving a key after it
//! is first opened, removing one, and signing with one after the fingerprint or PIN prompt.
//!
//! The store's lock can be held by a background thread for as long as a prompt is open, so
//! the window never takes it: it draws from a copy of the list ([`StoredKey`]) that each
//! background job hands back.

use std::sync::Mutex;

use super::*;
use crate::vault::{Guard, Level, Prompt, Security, Store, VaultError};

/// The key store the window uses.
pub type KeyStore = Arc<Mutex<Store<Box<dyn Guard>>>>;

/// What the window shows of a stored key.
#[derive(Clone, Debug)]
pub struct StoredKey {
    pub id: String,
    pub name: String,
    /// The IIN with all but its last four digits hidden.
    pub iin: Option<String>,
    pub not_after: Option<i64>,
    pub level: Level,
    pub security: Security,
    /// The key's algorithm OID.
    pub key_alg: String,
    /// SHA-256 of the certificate, to tell whether an opened key is already stored.
    cert_hash: Vec<u8>,
}

/// Where saving the opened key file into the store stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum Saving {
    #[default]
    None,
    Running,
    Saved(Level),
    /// The prompt was closed: offer to save again.
    NotSaved,
    Failed(String),
}

/// `900101300123` -> `••••••••0123`.
pub(super) fn mask_iin(iin: &str) -> String {
    let n = iin.chars().count();
    iin.chars()
        .enumerate()
        .map(|(i, c)| if i + 4 < n { '•' } else { c })
        .collect()
}

/// The window's copy of the store's list.
pub(super) fn snapshot(engine: &Engine, store: &Store<Box<dyn Guard>>) -> Vec<StoredKey> {
    store
        .keys()
        .iter()
        .map(|e| {
            let d = engine.describe(e.cert());
            StoredKey {
                id: e.id.clone(),
                name: d.name(),
                iin: d.get("IIN").map(mask_iin),
                not_after: d.not_after,
                level: e.level,
                security: e.security,
                key_alg: e.cert().key_alg(),
                cert_hash: crate::gost::sha256(&e.cert().der),
            }
        })
        .collect()
}

/// Whether a password contains letters that are not Latin: NCA key passwords use Latin letters
/// only, so the keyboard is probably set to Russian or Kazakh.
pub(super) fn non_latin(password: &str) -> bool {
    password.chars().any(|c| c.is_alphabetic() && !c.is_ascii())
}

impl App {
    /// Uses `store` for keys kept on this device (the phone app).
    pub fn with_key_store(mut self, store: Store<Box<dyn Guard>>) -> App {
        self.stored = snapshot(&self.engine, &store);
        self.key.stored = self.stored.first().map(|k| k.id.clone());
        self.keys = Some(Arc::new(Mutex::new(store)));
        self
    }

    /// The keys kept on this device.
    pub fn stored_keys(&self) -> &[StoredKey] {
        &self.stored
    }

    /// Whether the Sign screen shows the stored keys rather than the key file field.
    pub(super) fn stored_mode(&self) -> bool {
        self.keys.is_some() && !self.stored.is_empty() && !self.key.use_file
    }

    /// The selected stored key, in stored mode.
    pub(super) fn selected_stored(&self) -> Option<&StoredKey> {
        if !self.stored_mode() {
            return None;
        }
        let id = self.key.stored.as_ref()?;
        self.stored.iter().find(|k| &k.id == id)
    }

    /// The Sign screen's key card in stored mode: one row per key, the password for a
    /// password-only key, and the way to another key file.
    pub(super) fn stored_key_card(&mut self, ui: &mut egui::Ui) {
        let keys = self.stored.clone();
        if self
            .key
            .stored
            .as_ref()
            .is_none_or(|s| !keys.iter().any(|k| &k.id == s))
        {
            self.key.stored = keys.first().map(|k| k.id.clone());
        }
        for k in &keys {
            let selected = self.key.stored.as_deref() == Some(k.id.as_str());
            if stored_row(ui, k, selected).clicked() {
                self.key.stored = Some(k.id.clone());
                self.key.password.clear();
            }
            ui.add_space(4.0);
        }
        if let Some(k) = self.selected_stored().cloned()
            && k.level.needs_password()
        {
            self.password_field(ui, None);
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if ui.link(tr("Use another key file…")).clicked() {
                self.key.use_file = true;
                self.key.password.clear();
            }
            ui.add_space(12.0);
            if let Some(k) = self.selected_stored()
                && ui.link(tr("Remove this key from the phone…")).clicked()
            {
                self.key.confirm_remove = Some(k.id.clone());
            }
        });
    }

    /// The password field with its eye button, and the keyboard hint. `on_done` runs when the
    /// field loses focus.
    pub(super) fn password_field(&mut self, ui: &mut egui::Ui, on_done: Option<&egui::Context>) {
        ui.horizontal(|ui| {
            let l = ui.label(tr("Password"));
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut self.key.password)
                        .password(!self.key.show_password)
                        .desired_width(if self.narrow {
                            // room for the eye button beside it
                            let eye = ui.spacing().interact_size.y.max(22.0) + 8.0;
                            (ui.available_width() - eye - ui.spacing().item_spacing.x).max(80.0)
                        } else {
                            240.0
                        }),
                )
                .labelled_by(l.id);
            if r.lost_focus()
                && let Some(ctx) = on_done
            {
                self.open_key(ctx);
            }
            let hint = if self.key.show_password {
                tr("Hide password")
            } else {
                tr("Show password")
            };
            if eye_button(ui, self.key.show_password, hint).clicked() {
                self.key.show_password = !self.key.show_password;
            }
        });
        if non_latin(&self.key.password) {
            warning(
                ui,
                tr(
                    "The keyboard is not typing Latin letters. NCA key passwords use only Latin letters.",
                ),
            );
        }
    }

    /// The question before a stored key is removed.
    pub(super) fn remove_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.key.confirm_remove.clone() else {
            return;
        };
        let name = self
            .stored
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.name.clone())
            .unwrap_or_default();
        egui::Modal::new(egui::Id::unique("remove_key")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.label(
                RichText::new(trf("Remove the key of {} from this phone?", &[&name]))
                    .strong()
                    .size(16.0),
            );
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(tr(
                    "You can add it again later from its .p12 file and password.",
                ))
                .wrap(),
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.add(primary_button(tr("Remove"))).clicked() {
                    self.key.confirm_remove = None;
                    self.remove_stored(ctx, id.clone());
                }
                if ui.button(tr("Cancel")).clicked() {
                    self.key.confirm_remove = None;
                }
            });
        });
    }

    fn remove_stored(&mut self, ctx: &egui::Context, id: String) {
        let Some(store) = self.keys.clone() else {
            return;
        };
        self.background(ctx, move |e| {
            let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
            let r = s.remove(&id).map(|_| snapshot(e, &s));
            Msg::KeysChanged(r.map_err(|x| x.to_string()))
        });
    }

    /// After a key file opened: keeps it on the phone, unless it is there already or cannot
    /// sign. The prompt says what is happening; a password-only store asks nothing.
    pub(super) fn save_opened_key(&mut self, ctx: &egui::Context) {
        let (Some(store), Some(file), Some(k)) = (
            self.keys.clone(),
            self.key.file.clone(),
            self.key.opened.clone(),
        ) else {
            return;
        };
        // the password was just typed: this signing goes on with the file, with no prompt
        // on top; the kept key is offered from the next start
        self.key.use_file = true;
        let hash = crate::gost::sha256(&k.cert.der);
        if let Some(s) = self.stored.iter().find(|s| s.cert_hash == hash) {
            self.key.saving = Saving::Saved(s.level);
            return;
        }
        let d = self.engine.describe(&k.cert);
        if d.usage_error.is_some() || !k.cert.valid_on(crate::time::now_ms()) {
            return;
        }
        self.key.saving = Saving::Running;
        let password = self.key.password.clone();
        let alias = k.alias.clone();
        let prompt = Prompt {
            title: tr("Keep your key on this phone").into(),
            subtitle: d.name(),
            detail: tr("Next time, a fingerprint or the screen lock is enough to sign.").into(),
        };
        self.background(ctx, move |e| {
            let r = (|| {
                let data = std::fs::read(&file)
                    .map_err(|err| VaultError::Failed(format!("{}: {err}", file.display())))?;
                let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
                let id = s.add(&data, &password, Some(&alias), &prompt)?;
                Ok((id, snapshot(e, &s), s.chip_problem()))
            })();
            Msg::KeySaved(r)
        });
    }

    /// A key was saved into the store (or not).
    pub(super) fn key_saved(
        &mut self,
        r: Result<(String, Vec<StoredKey>, Option<String>), VaultError>,
    ) {
        match r {
            Ok((id, keys, problem)) => {
                self.key.chip_problem = problem;
                let level = keys
                    .iter()
                    .find(|k| k.id == id)
                    .map(|k| k.level)
                    .unwrap_or(Level::Standard);
                self.stored = keys;
                self.key.stored = Some(id);
                self.key.saving = Saving::Saved(level);
            }
            Err(VaultError::Cancelled) => self.key.saving = Saving::NotSaved,
            Err(VaultError::AlreadyAdded) => self.key.saving = Saving::Saved(Level::Standard),
            Err(e) => self.key.saving = Saving::Failed(e.to_string()),
        }
    }

    pub(super) fn keys_changed(&mut self, r: Result<Vec<StoredKey>, String>) {
        match r {
            Ok(keys) => {
                self.stored = keys;
                if self.stored.is_empty() {
                    self.key.use_file = false;
                }
            }
            Err(e) => self.message = Some((e, true)),
        }
    }

    /// Under an opened key file: whether it was kept on the phone.
    pub(super) fn saving_note(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.keys.is_none() {
            return;
        }
        match self.key.saving.clone() {
            Saving::None => {}
            Saving::Running => {
                ui.label(Tone::Muted.text(ui, tr("Keeping the key on this phone…")));
            }
            Saving::Saved(level) => {
                let t = if level.needs_password() {
                    tr(
                        "✔ Kept on this phone. Next time only the password is needed. Set a screen lock on the phone to sign with your fingerprint instead.",
                    )
                } else {
                    tr(
                        "✔ Kept on this phone. Next time, sign with your fingerprint or screen lock.",
                    )
                };
                ui.add(egui::Label::new(Tone::Good.text(ui, t)).wrap());
                if level.needs_password()
                    && let Some(p) = &self.key.chip_problem
                {
                    let t = trf("The phone's security chip could not be used: {}", &[p]);
                    ui.add(egui::Label::new(Tone::Muted.text(ui, t).size(12.5)).wrap());
                }
            }
            Saving::NotSaved | Saving::Failed(_) => {
                if let Saving::Failed(e) = &self.key.saving {
                    ui.add(egui::Label::new(Tone::Warn.text(ui, e.as_str())).wrap());
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(Tone::Muted.text(ui, tr("Not kept on this phone.")));
                    if ui.link(tr("Keep it on this phone")).clicked() {
                        self.save_opened_key(ctx);
                    }
                });
            }
        }
    }

    /// What signing with the selected stored key needs: the store, the key's id, the
    /// password for a password level, and the prompt (its detail is filled in with the
    /// document's code once the document is read).
    pub(super) fn stored_signing(&self) -> Option<StoredSigning> {
        let k = self.selected_stored()?;
        let doc = self
            .sign
            .doc
            .as_ref()?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let who = match &k.iin {
            Some(iin) => format!("{} · {}", k.name, trf("IIN {}", &[iin])),
            None => k.name.clone(),
        };
        Some(StoredSigning {
            store: self.keys.clone()?,
            id: k.id.clone(),
            password: k.level.needs_password().then(|| self.key.password.clone()),
            retry_password: k.level == Level::PasswordOnly,
            prompt: Prompt {
                title: trf("Sign {}", &[&doc]),
                subtitle: who,
                detail: String::new(),
            },
        })
    }
}

/// See [`App::stored_signing`].
pub(super) struct StoredSigning {
    store: KeyStore,
    id: String,
    password: Option<String>,
    /// Try the password as typed on a Latin keyboard too (no prompt is shown for it).
    retry_password: bool,
    prompt: Prompt,
}

impl StoredSigning {
    /// The key, after the prompt; Err("") when the prompt was closed.
    pub(super) fn unlock(mut self, document: &[u8]) -> Result<Key, String> {
        let h = crate::hex(&crate::gost::sha256(document)).to_uppercase();
        self.prompt.detail = trf("Document code {} {}", &[&&h[..4], &&h[4..8]]);
        let mut s = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let mut r = s.key(&self.id, self.password.as_deref(), &self.prompt);
        if matches!(r, Err(VaultError::WrongPassword))
            && self.retry_password
            && let Some(alt) = self.password.as_deref().and_then(i18n::latin_keyboard)
        {
            r = s.key(&self.id, Some(&alt), &self.prompt);
        }
        r.map_err(|e| match e {
            VaultError::Cancelled => String::new(),
            e => e.to_string(),
        })
    }
}

/// One stored key, as a selectable row.
fn stored_row(ui: &mut egui::Ui, k: &StoredKey, selected: bool) -> egui::Response {
    let v = ui.visuals().clone();
    let id = ui.make_persistent_id(("stored_key", &k.id));
    let stroke = if selected {
        egui::Stroke::new(2.0, v.selection.bg_fill)
    } else {
        v.widgets.noninteractive.bg_stroke
    };
    let inner = egui::Frame::new()
        .stroke(stroke)
        .corner_radius(10.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                // a radio mark, drawn: the app's fonts have no ◉
                let (r, p) = ui.allocate_painter(egui::vec2(20.0, 22.0), egui::Sense::hover());
                let c = r.rect.center();
                let color = if selected {
                    v.selection.bg_fill
                } else {
                    v.widgets.inactive.fg_stroke.color
                };
                p.circle_stroke(c, 8.0, egui::Stroke::new(1.5, color));
                if selected {
                    p.circle_filled(c, 4.5, color);
                }
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&k.name).strong().size(16.0))
                            .wrap()
                            .selectable(false),
                    );
                    let mut line = Vec::new();
                    if let Some(iin) = &k.iin {
                        line.push(trf("IIN {}", &[iin]));
                    }
                    line.push(trf("valid until {}", &[&time::fmt(k.not_after)]));
                    ui.add(
                        egui::Label::new(Tone::Muted.text(ui, line.join(" · ")))
                            .wrap()
                            .selectable(false),
                    );
                    let expired = k.not_after.is_some_and(|t| t < crate::time::now_ms());
                    if expired {
                        ui.label(Tone::Bad.text(ui, tr("Expired: get a new key on egov.kz.")));
                    }
                    let how = match (k.level, k.security) {
                        (Level::PasswordOnly, _) => tr("Signs with the password"),
                        (_, Security::Chip) => tr("Protected by the phone's security chip"),
                        (_, Security::Protected) => {
                            tr("Protected by the phone's secure processor area")
                        }
                        (_, Security::Software) => tr("Protected by the phone's screen lock"),
                    };
                    ui.add(
                        egui::Label::new(Tone::Muted.text(ui, how).size(12.5)).selectable(false),
                    );
                });
            });
        });
    let r = ui.interact(inner.response.rect, id, egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::selected(egui::Role::RadioButton, true, selected, &k.name));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iin_is_masked() {
        assert_eq!(mask_iin("900101300123"), "••••••••0123");
        assert_eq!(mask_iin("123"), "123");
        assert!(non_latin("Qwerty1й") && !non_latin("Qwerty12!") && !non_latin(""));
    }
}
