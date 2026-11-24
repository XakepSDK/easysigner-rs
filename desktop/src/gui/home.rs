//! Home, Add key, Your keys and About.

use std::path::PathBuf;

use eframe::egui::{self, RichText};
use kzsigner::i18n::Lang;
use kzsigner_ffi::{AddKeyError, CantSign, ChipPrompt, KeyInfo, Unlock};

use super::text::{self, t, tf};
use super::ui::{self, Tone};
use super::*;

pub const EGOV: &str = "https://egov.kz/cms/ru/services/pass_onlineecp";

/// Why a key wasn't added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddProblem {
    WrongPassword {
        cyrillic: bool,
    },
    NotAKey,
    AlreadyAdded,
    CantSign {
        reason: CantSign,
        from: i64,
        to: i64,
    },
    Failed(String),
}

/// A key's lines under its name: IIN, company and BIN.
pub fn who(k: &KeyInfo) -> String {
    let mut parts = vec![];
    if let Some(iin) = &k.iin {
        parts.push(tf("IIN {}", &[iin]));
    }
    match (&k.company, &k.bin) {
        (Some(c), Some(b)) => parts.push(tf("For {} · BIN {}", &[c, b])),
        (Some(c), None) => parts.push(tf("For {}", &[c])),
        _ => {}
    }
    parts.join(" · ")
}

/// The title and text for a key that can't sign.
pub fn cant_sign(reason: CantSign, from: i64, to: i64) -> (String, String) {
    match reason {
        CantSign::Expired => (
            t("Your key has expired").into(),
            tf("It stopped working on {}.", &[&text::date(to)]),
        ),
        CantSign::NotYetValid => (
            t("Your key isn't valid yet").into(),
            tf(
                "It starts working on {}. Check that the computer's date is right.",
                &[&text::date(from)],
            ),
        ),
        CantSign::Gost2004 => (
            t("This key is too old to sign").into(),
            t("It's a GOST 2004 key. NCA no longer confirms the time of its signatures, so documents signed with it aren't accepted.").into(),
        ),
        CantSign::Revoked => (
            t("Your key was revoked").into(),
            t("NCA says this key no longer works. A key is revoked when a new one is issued or the old one is reported lost.").into(),
        ),
        CantSign::NotRecognized => (
            t("This key isn't recognized").into(),
            t("It isn't a key from NCA, Kazakhstan's certification authority, or NCA doesn't know it. Documents signed with it aren't accepted.").into(),
        ),
    }
}

/// "Get a new key": where, and the link.
pub fn get_new_key(ui: &mut egui::Ui) {
    ui::notice(
        ui,
        Tone::Grey,
        t("Get a new key"),
        t(
            "On egov.kz or in the eGov Mobile app, under “Get a digital signature”. It's free. Then add the new key here.",
        ),
    );
    ui.hyperlink_to(RichText::new(t("Open egov.kz")).strong(), EGOV);
}

impl App {
    pub(super) fn home(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(24.0);
        if let Err(e) = &self.vault {
            ui::notice(ui, Tone::Bad, t("Can't read your keys."), e);
        }
        let sign_body = if self.keys.is_empty() {
            t("PDF, Word or any file. First add your key: only once.")
        } else {
            t("PDF, Word or any file. Confirm with your key's password.")
        };
        if big_choice(ui, Icon::Pen, t("Sign a document"), sign_body, true).clicked() {
            if self.keys.is_empty() {
                self.start_add_key(true);
            } else if let Some(f) = self.dialogs.open(Pick::Document) {
                self.open_to_sign(&ctx, f);
            }
        }
        ui.add_space(4.0);
        if big_choice(
            ui,
            Icon::ShieldCheck,
            t("Check a signature"),
            t("Who signed it, and was it changed?"),
            false,
        )
        .clicked()
            && let Some(f) = self.dialogs.open(Pick::Signed)
        {
            self.start_check(&ctx, f);
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            icons::show(ui, Icon::Download, 20.0, ui::MUTED);
            ui.label(ui::muted(t("Or drop a file anywhere in this window. kzsigner sees whether it's signed and opens the right screen.")));
        });
    }

    /// A document chosen with "Sign a document": a detached .cms or key goes where it belongs.
    fn open_to_sign(&mut self, ctx: &egui::Context, f: PathBuf) {
        self.screen = Screen::Home;
        self.open_file(ctx, f);
    }

    /// Opens Add key. `then_pick`: from "Sign a document" (a document is chosen right after).
    pub(super) fn start_add_key(&mut self, then_pick: bool) {
        let back = if self.screen == Screen::AddKey {
            self.add.back
        } else {
            Some(self.screen)
        };
        self.add = AddForm {
            back,
            then_pick,
            ..Default::default()
        };
        self.screen = Screen::AddKey;
    }

    pub(super) fn set_key_file(&mut self, path: PathBuf, bytes: Vec<u8>) {
        self.add.file = Some(path);
        self.add.p12 = Some(bytes);
        self.add.problem = None;
        // the password belongs to the file
        self.add.password.clear();
    }

    pub(super) fn add_key(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(16.0);
        ui::title(ui, t("Add your signature key"));
        let waiting = self.sign.as_ref().map(|s| s.name.clone());
        let intro = match (&waiting, self.add.then_pick) {
            (Some(n), _) => tf(
                "To sign {}, first add your key. You'll come straight back to it.",
                &[n],
            ),
            (None, true) => {
                t("To sign, first add your key. You do this once, then choose the document.").into()
            }
            (None, false) => t("Only once. After this, you sign with the key's password.").into(),
        };
        ui.label(ui::muted(intro).size(16.0));
        ui.add_space(6.0);

        // the key file
        let chosen = self.add.file.as_ref().map(|f| {
            f.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        let label = if chosen.is_some() {
            t("Choose another key file")
        } else {
            t("Choose the key file")
        };
        let r = ui::card_button(ui, label, |ui| {
            ui.horizontal(|ui| {
                icons::show(ui, Icon::Key, 28.0, ui::ACCENT);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    match &chosen {
                        Some(n) => {
                            ui.label(RichText::new(n).size(16.0).strong());
                            ui.label(
                                RichText::new(t("Choose another key file"))
                                    .size(13.0)
                                    .color(ui::ACCENT),
                            );
                        }
                        None => {
                            ui.label(
                                RichText::new(t("Choose the key file"))
                                    .size(16.0)
                                    .strong()
                                    .color(ui::ACCENT),
                            );
                            ui.label(
                                ui::muted(t(
                                    "or drop it here. From NCA or egov.kz, usually GOSTKNCA_….p12",
                                ))
                                .size(13.0),
                            );
                        }
                    }
                });
            });
        });
        if r.clicked()
            && let Some(f) = self.dialogs.open(Pick::Key)
            && let Some((_, bytes)) = self.read(&f)
        {
            self.set_key_file(f, bytes);
        }

        // the password
        ui.add_space(6.0);
        let before = self.add.password.clone();
        let r = ui::password(
            ui,
            &mut self.add.password,
            &mut self.add.shown,
            t("Key password"),
            t("The one from NCA's center or egov.kz"),
        );
        if self.add.password != before
            && matches!(self.add.problem, Some(AddProblem::WrongPassword { .. }))
        {
            self.add.problem = None;
        }
        let ready = self.add.p12.is_some() && !self.add.password.is_empty() && !self.busy();
        let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        match self.add.problem.clone() {
            Some(AddProblem::WrongPassword { cyrillic }) => {
                ui::notice(ui, Tone::Bad, t("That password doesn't open this key."), "");
                if cyrillic {
                    ui::notice(
                        ui,
                        Tone::Warn,
                        t("Is the keyboard in Russian or Kazakh?"),
                        t("Switch it to English and try again."),
                    );
                }
                ui.label(ui::muted(t(
                    "Forgot it? NCA can't recover it. Get a new key on egov.kz.",
                )));
            }
            Some(AddProblem::NotAKey) => ui::notice(
                ui,
                Tone::Bad,
                t("This file isn't a signature key."),
                t("Choose the .p12 file from NCA or egov.kz."),
            ),
            Some(AddProblem::AlreadyAdded) => ui::notice(
                ui,
                Tone::Info,
                t("This key is already on this computer."),
                "",
            ),
            Some(AddProblem::CantSign { reason, from, to }) => {
                let (title, body) = cant_sign(reason, from, to);
                ui::notice(ui, Tone::Bad, &title, &body);
                get_new_key(ui);
            }
            Some(AddProblem::Failed(e)) => {
                ui::notice(ui, Tone::Bad, &tf("Couldn't save the key: {}", &[&e]), "")
            }
            None => ui::notice(
                ui,
                Tone::Info,
                "",
                t(
                    "The key stays on this computer, locked with this password. You type it each time you sign; it is never saved.",
                ),
            ),
        }
        ui.add_space(6.0);
        let label = if self.busy() {
            t("Adding…")
        } else {
            t("Add key")
        };
        let w = ui.available_width();
        let clicked = ui
            .add_enabled_ui(ready, |ui| ui::main_button(ui, label, w))
            .inner
            .clicked();
        if ready && (clicked || enter) {
            self.add_now(&ctx);
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(ui::muted(t("Don't have a key?")));
            ui.hyperlink_to(t("Get one free on egov.kz"), EGOV);
        });
    }

    fn add_now(&mut self, ctx: &egui::Context) {
        let (Ok(v), Some(p12)) = (&self.vault, self.add.p12.clone()) else {
            return;
        };
        let (v, nca, pw) = (v.clone(), self.nca.clone(), self.add.password.clone());
        self.add.problem = None;
        self.job(ctx, move || {
            Msg::KeyAdded(v.add_key(nca, p12, pw, ChipPrompt::default()))
        });
    }

    pub(super) fn key_added(&mut self, ctx: &egui::Context, r: Result<String, AddKeyError>) {
        let cyrillic = self
            .add
            .password
            .chars()
            .any(|c| ('\u{400}'..='\u{4ff}').contains(&c));
        self.add.problem = match r {
            Ok(id) => {
                self.reload_keys();
                self.key_id = Some(id);
                let then_pick = self.add.then_pick;
                self.add = AddForm::default();
                if let Some(s) = &mut self.sign {
                    s.problem = None;
                    self.screen = Screen::Sign;
                } else if then_pick {
                    self.screen = Screen::Home;
                    if let Some(f) = self.dialogs.open(Pick::Document) {
                        self.open_to_sign(ctx, f);
                    }
                } else {
                    self.screen = Screen::Keys;
                }
                return;
            }
            Err(AddKeyError::WrongPassword) => Some(AddProblem::WrongPassword { cyrillic }),
            Err(AddKeyError::NotAKey) => Some(AddProblem::NotAKey),
            Err(AddKeyError::AlreadyAdded) => Some(AddProblem::AlreadyAdded),
            Err(AddKeyError::KeyCantSign {
                reason,
                valid_from_ms,
                expires_ms,
            }) => Some(AddProblem::CantSign {
                reason,
                from: valid_from_ms,
                to: expires_ms,
            }),
            Err(AddKeyError::Cancelled) => None,
            Err(AddKeyError::Failed { detail }) => Some(AddProblem::Failed(detail)),
        };
    }

    pub(super) fn keys_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(16.0);
        ui::title(ui, t("Your keys"));
        if let Err(e) = &self.vault {
            ui::notice(ui, Tone::Bad, t("Can't read your keys."), e);
        }
        for k in self.keys.clone() {
            ui::card(ui, |ui| {
                ui.horizontal(|ui| {
                    icons::show(ui, Icon::Key, 28.0, ui::ACCENT);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.label(RichText::new(&k.name).size(18.0).strong());
                        let w = who(&k);
                        if !w.is_empty() {
                            ui.label(ui::muted(w));
                        }
                        let (state, tone) = validity(&k);
                        let opens = match k.unlock {
                            Unlock::Password => t("Opens with its password"),
                            Unlock::Fingerprint => t("Opens with your fingerprint"),
                            Unlock::FingerprintOrScreenLock => t("Opens with Windows Hello"),
                            Unlock::FingerprintAndPassword => {
                                t("Opens with your fingerprint and its password")
                            }
                        };
                        let color = if tone == Tone::Bad {
                            Tone::Bad.colors().1
                        } else {
                            ui::MUTED
                        };
                        ui.label(RichText::new(format!("{state} · {opens}")).color(color));
                        if let Some(r) = k.cant_sign {
                            let (title, _) = cant_sign(r, 0, k.expires_ms);
                            ui.label(RichText::new(title).color(Tone::Bad.colors().1).strong());
                        }
                    });
                });
                if self.confirm_remove.as_ref() == Some(&k.id) {
                    ui::notice(
                        ui,
                        Tone::Warn,
                        &tf("Remove {}'s key from this computer?", &[&k.name]),
                        t(
                            "To sign again, you'll need the key file and its password. The key itself stays valid: this only removes it from this computer.",
                        ),
                    );
                    ui.horizontal(|ui| {
                        if ui::second_button(ui, t("Remove")).clicked() {
                            self.remove_key(&k.id);
                        }
                        if ui::text_button(ui, t("Keep it")).clicked() {
                            self.confirm_remove = None;
                        }
                    });
                } else if ui::text_button(ui, t("Remove from this computer")).clicked() {
                    self.confirm_remove = Some(k.id.clone());
                }
            });
        }
        if self.keys.is_empty() {
            ui.label(ui::muted(t("No keys on this computer yet.")));
        }
        let label = if self.keys.is_empty() {
            t("Add key")
        } else {
            t("Add another key")
        };
        if ui::second_button(ui, label).clicked() {
            self.start_add_key(false);
        }

        ui.add_space(14.0);
        ui.label(RichText::new(t("Language")).size(17.0).strong());
        let mut choice = self.chosen_lang;
        ui.horizontal_wrapped(|ui| {
            ui.radio_value(&mut choice, None, t("Same as the computer"));
            for l in Lang::ALL {
                ui.radio_value(&mut choice, Some(l), l.name());
            }
        });
        if choice != self.chosen_lang {
            self.set_language(&ctx, choice);
        }
        ui.add_space(14.0);
        if ui::text_button(ui, t("About kzsigner · version, license, privacy")).clicked() {
            self.screen = Screen::About;
        }
    }

    fn remove_key(&mut self, id: &str) {
        if let Ok(v) = &self.vault
            && let Err(e) = v.remove_key(id.to_string())
        {
            self.message = Some((tf("Couldn't remove the key: {}", &[&e]), Tone::Bad));
        }
        self.confirm_remove = None;
        self.reload_keys();
    }

    pub(super) fn about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        ui::title(ui, t("About kzsigner"));
        ui::notice(
            ui,
            Tone::Good,
            t("Your documents stay on your computer"),
            t(
                "When you sign or check, only a short fingerprint of the document goes to NCA, never the document itself. Your key never leaves the computer. No accounts, no tracking.",
            ),
        );
        ui::card(ui, |ui| {
            ui::field(ui, t("Version"), kzsigner::version(), None);
            ui.separator();
            ui::field(
                ui,
                t("Talks only to"),
                t("NCA: key check and signing time (pki.gov.kz)"),
                None,
            );
            ui.separator();
            ui::field(ui, t("License"), t("See the source code"), None);
            ui.hyperlink_to(
                "github.com/XakepSDK/easysigner-rs",
                "https://github.com/XakepSDK/easysigner-rs",
            );
        });
    }
}

/// "Valid until …", "Expires in N days …" or "Expired on …", and how worrying it is.
pub fn validity(k: &KeyInfo) -> (String, Tone) {
    let now = kzsigner::time::now_ms();
    let day = 86_400_000;
    if k.expires_ms < now {
        return (tf("Expired on {}", &[&text::date(k.expires_ms)]), Tone::Bad);
    }
    let days = (k.expires_ms - now) / day;
    if days == 0 {
        (t("Expires today").into(), Tone::Warn)
    } else if days <= 30 {
        (
            text::expires_in(days, &text::date(k.expires_ms)),
            Tone::Warn,
        )
    } else {
        (
            tf("Valid until {}", &[&text::date(k.expires_ms)]),
            Tone::Grey,
        )
    }
}

/// One of Home's two big choices.
fn big_choice(
    ui: &mut egui::Ui,
    icon: Icon,
    title: &str,
    body: &str,
    main: bool,
) -> egui::Response {
    let (fill, fg, sub) = if main {
        (
            ui::ACCENT,
            egui::Color32::WHITE,
            egui::Color32::from_rgb(0xDC, 0xE7, 0xFB),
        )
    } else {
        (egui::Color32::WHITE, ui::TEXT, ui::MUTED)
    };
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 108.0), egui::Sense::click());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, title));
    let hovered = resp.hovered() || resp.has_focus();
    let p = ui.painter();
    let fill = if hovered && main {
        ui::ACCENT.gamma_multiply(0.9)
    } else if hovered {
        ui::SURFACE
    } else {
        fill
    };
    p.rect(
        rect,
        20.0,
        fill,
        egui::Stroke::new(if main { 0.0 } else { 1.0 }, ui::BORDER),
        egui::StrokeKind::Inside,
    );
    if resp.has_focus() {
        p.rect_stroke(
            rect.expand(3.0),
            22.0,
            egui::Stroke::new(2.0, ui::ACCENT),
            egui::StrokeKind::Outside,
        );
    }
    let icon_rect = egui::Rect::from_center_size(
        rect.left_center() + egui::vec2(52.0, 0.0),
        egui::Vec2::splat(34.0),
    );
    icons::paint(p, icon_rect, icon, fg, 2.2);
    let x = rect.left() + 100.0;
    let tw = rect.right() - x - 20.0;
    let g = p.layout(title.into(), egui::FontId::proportional(21.0), fg, tw);
    let b = p.layout(body.into(), egui::FontId::proportional(15.0), sub, tw);
    let h = g.size().y + 6.0 + b.size().y;
    let top = rect.center().y - h / 2.0;
    p.galley(egui::pos2(x, top), g.clone(), fg);
    p.galley(egui::pos2(x, top + g.size().y + 6.0), b, sub);
    resp
}
