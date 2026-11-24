//! Sign and Signed.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText};
use kzsigner_ffi::{CantSign, ChipPrompt, Doc, DocKind, Output, SignError, Signed, Unlock};

use super::home::{self, get_new_key};
use super::text::{self, t, tf};
use super::ui::{self, Tone};
use super::*;

/// Why the last Sign didn't sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignProblem {
    NoAnswer,
    CantSign {
        reason: CantSign,
        from: i64,
        to: i64,
    },
    WrongPassword {
        cyrillic: bool,
    },
    Wait(u64),
    KeyReset,
    Cannot,
    Failed(String),
}

/// What the document is, for its card: "PDF document", "Signed file (.cms)", ...
fn kind_label(doc: &Doc) -> &'static str {
    match doc.kind {
        DocKind::Pdf => t("PDF document"),
        DocKind::Xml => t("XML document"),
        DocKind::Cms if doc.output == Output::Cannot => t("Signatures only (.cms)"),
        DocKind::Cms => t("Signed file (.cms)"),
        DocKind::Key => t("Signature key"),
        DocKind::Other => t("Document"),
    }
}

/// Names joined for a sentence: "A", "A and B", "A, B and C".
fn names(doc: &Doc) -> String {
    let n: Vec<&str> = doc.signers.iter().map(|s| s.name.as_str()).collect();
    match n.as_slice() {
        [] => String::new(),
        [a] => a.to_string(),
        [rest @ .., last] => tf("{} and {}", &[&rest.join(", "), last]),
    }
}

/// What signing makes, and where it goes.
fn output_text(doc: &Doc) -> String {
    let saved = tf("Saved next to the original as {}.", &[&doc.output_name]);
    let what = match doc.output {
        Output::InsidePdf if doc.signers.is_empty() => {
            t("Your signature goes inside this PDF, and a “Who signed” page is added at the end with your name and the signing time.").to_string()
        }
        Output::InsidePdf if doc.who_signed_page => {
            tf("Your name is added next to {}'s on the “Who signed” page.", &[&names(doc)])
        }
        Output::InsidePdf => tf("Your signature is added inside this PDF, next to {}'s.", &[&names(doc)]),
        Output::InsideXml => t("Your signature goes inside this XML file.").to_string(),
        Output::NewCms => t("You get one .cms file with the document and your signature inside.").to_string(),
        Output::JoinCms => tf("Your signature joins {}'s in the same file.", &[&names(doc)]),
        Output::Cannot if doc.kind == DocKind::Xml => {
            return t("This XML file is signed in a way that another signature would break. Ask the sender for a copy without signatures.").into();
        }
        Output::Cannot => {
            return t("This .cms holds only signatures, not the document itself. Ask the sender for the .cms with the document inside.").into();
        }
    };
    format!("{what} {saved}")
}

impl App {
    /// Opens `path` on Sign (Add key first when there is no key yet).
    pub(super) fn start_sign_with(
        &mut self,
        path: PathBuf,
        name: String,
        bytes: Vec<u8>,
        doc: Doc,
    ) {
        self.sign = Some(SignState {
            path,
            name,
            bytes: Arc::new(bytes),
            doc,
            password: String::new(),
            shown: false,
            problem: None,
            choosing_key: false,
            request: 0,
            focus: true,
        });
        self.signed = None;
        if self.keys.is_empty() {
            self.start_add_key(false);
            self.add.back = Some(Screen::Home);
        } else {
            self.screen = Screen::Sign;
        }
    }

    pub(super) fn sign_screen(&mut self, ui: &mut egui::Ui, wide: bool) {
        let ctx = ui.ctx().clone();
        let Some(s) = &self.sign else {
            self.screen = Screen::Home;
            return;
        };
        ui.add_space(16.0);
        let title = if s.doc.signers.is_empty() {
            t("Sign this document?")
        } else {
            t("Add your signature?")
        };
        ui::title(ui, title);
        ui.add_space(4.0);
        if wide {
            ui.columns(2, |c| {
                c[0].spacing_mut().item_spacing.y = 10.0;
                ui::plain(&mut c[0], |ui| self.document_card(&ctx, ui));
                c[1].spacing_mut().item_spacing.y = 10.0;
                ui::plain(&mut c[1], |ui| self.sign_side(&ctx, ui));
            });
        } else {
            self.document_card(&ctx, ui);
            self.sign_side(&ctx, ui);
        }
    }

    /// The document: its name, kind, who signed it already, and Read it.
    fn document_card(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let Some(s) = &self.sign else { return };
        let mut read = false;
        ui::card(ui, |ui| {
            ui.horizontal(|ui| {
                icons::show(ui, Icon::File, 40.0, ui::ACCENT);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(egui::Label::new(RichText::new(&s.name).size(18.0).strong()).wrap());
                    let mut kind = kind_label(&s.doc).to_string();
                    if let Some(inner) = &s.doc.inner_name
                        && s.doc.output == Output::JoinCms
                    {
                        kind = format!("{kind} · {}", tf("Inside {}", &[inner]));
                    }
                    ui.label(ui::muted(kind));
                });
            });
            for b in &s.doc.signers {
                let when = b.signed_ms.map(text::date_time).unwrap_or_default();
                let line = if when.is_empty() {
                    tf("Already signed by {}", &[&b.name])
                } else {
                    format!("{} · {}", tf("Already signed by {}", &[&b.name]), when)
                };
                ui.horizontal(|ui| {
                    icons::show(ui, Icon::Check, 18.0, ui::GREEN);
                    ui.add(egui::Label::new(line).wrap());
                });
            }
            ui.add_space(4.0);
            read = ui::second_button(ui, t("Read it")).clicked();
            ui.label(
                ui::muted(t(
                    "Opens in the computer's viewer, to check what you're signing.",
                ))
                .size(13.0),
            );
        });
        if read {
            let s = self.sign.as_ref().unwrap();
            if s.doc.kind == DocKind::Cms {
                let content = kzsigner_ffi::cms_content(s.bytes.to_vec()).unwrap_or_default();
                let name = s.doc.inner_name.clone().unwrap_or_else(|| s.name.clone());
                self.view(ctx, None, name, Arc::new(content));
            } else {
                let (p, n, b) = (s.path.clone(), s.name.clone(), s.bytes.clone());
                self.view(ctx, Some(p), n, b);
            }
        }
    }

    /// Who signs, what signing makes, the password and Sign.
    fn sign_side(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let key = self.key().cloned();
        let busy = self.busy();
        let keys = self.keys.clone();
        let Some(s) = &mut self.sign else { return };

        // the last attempt's problem, before anything else
        let mut retry = false;
        let problem = s.problem.clone().or_else(|| {
            key.as_ref()
                .and_then(|k| k.cant_sign)
                .map(|r| SignProblem::CantSign {
                    reason: r,
                    from: 0,
                    to: key.as_ref().unwrap().expires_ms,
                })
        });
        match &problem {
            Some(SignProblem::NoAnswer) => {
                ui::notice(
                    ui,
                    Tone::Warn,
                    t("Can't reach NCA right now"),
                    t(
                        "Nothing was signed. NCA confirms your key and records the official signing time, and it didn't answer. Check the internet connection and try again in a few minutes.",
                    ),
                );
                retry = true;
            }
            Some(SignProblem::CantSign { reason, from, to }) => {
                let (title, body) = home::cant_sign(*reason, *from, *to);
                ui::notice(ui, Tone::Bad, &title, &body);
                get_new_key(ui);
            }
            Some(SignProblem::KeyReset) => ui::notice(
                ui,
                Tone::Bad,
                t("This key can't be opened on this computer anymore."),
                t("Remove it in Your keys and add the key file again."),
            ),
            Some(SignProblem::Cannot) => ui::notice(ui, Tone::Bad, "", &output_text(&s.doc)),
            Some(SignProblem::Failed(e)) => {
                ui::notice(ui, Tone::Bad, &tf("Couldn't sign: {}", &[e]), "")
            }
            _ => {}
        }
        let can_sign = s.doc.output != Output::Cannot
            && !matches!(
                problem,
                Some(SignProblem::CantSign { .. } | SignProblem::KeyReset | SignProblem::Cannot)
            );

        // who signs
        ui.label(ui::muted(t("You sign as")).size(14.0));
        if let Some(k) = &key {
            ui::card(ui, |ui| {
                ui.label(RichText::new(&k.name).size(18.0).strong());
                let w = home::who(k);
                if !w.is_empty() {
                    ui.label(ui::muted(w));
                }
                if keys.len() > 1 {
                    if s.choosing_key {
                        for o in &keys {
                            let mut line = o.name.clone();
                            if let Some(c) = &o.company {
                                line = format!("{line} · {c}");
                            }
                            if ui.radio(o.id == k.id, line).clicked() {
                                self.key_id = Some(o.id.clone());
                                s.choosing_key = false;
                                s.problem = None;
                                s.password.clear();
                            }
                        }
                    } else if ui::text_button(ui, t("Sign with another key")).clicked() {
                        s.choosing_key = true;
                    }
                }
            });
        }

        // what signing makes
        if s.doc.output != Output::Cannot {
            ui.label(output_text(&s.doc));
        } else if problem != Some(SignProblem::Cannot) {
            ui::notice(
                ui,
                Tone::Bad,
                t("This file can't be signed"),
                &output_text(&s.doc),
            );
        }

        // the password, for a key kept under it
        let needs_password = key
            .as_ref()
            .is_some_and(|k| matches!(k.unlock, Unlock::Password | Unlock::FingerprintAndPassword));
        let mut enter = false;
        if can_sign && needs_password {
            let before = s.password.clone();
            let r = ui::password(ui, &mut s.password, &mut s.shown, t("Key password"), "");
            if s.focus {
                r.request_focus();
                s.focus = false;
            }
            if s.password != before
                && matches!(
                    s.problem,
                    Some(SignProblem::WrongPassword { .. } | SignProblem::Wait(_))
                )
            {
                s.problem = None;
            }
            enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            match &s.problem {
                Some(SignProblem::WrongPassword { cyrillic }) => {
                    ui::notice(ui, Tone::Bad, t("That password doesn't open this key."), "");
                    if *cyrillic {
                        ui::notice(
                            ui,
                            Tone::Warn,
                            t("Is the keyboard in Russian or Kazakh?"),
                            t("Switch it to English and try again."),
                        );
                    }
                }
                Some(SignProblem::Wait(n)) => {
                    ui::notice(ui, Tone::Warn, &text::wait_seconds(*n), "")
                }
                _ => {}
            }
        }
        if can_sign {
            let ready = !busy && (!needs_password || !s.password.is_empty());
            let label = if busy {
                t("Signing…")
            } else if retry {
                t("Try again")
            } else if s.doc.signers.is_empty() {
                t("Sign")
            } else {
                t("Add my signature")
            };
            let w = ui.available_width();
            let clicked = ui
                .add_enabled_ui(ready, |ui| ui::main_button(ui, label, w))
                .inner
                .clicked();
            if busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(ui::muted(t("Asking NCA…")));
                });
            }
            if ready && (clicked || enter) {
                self.sign_now(ctx);
            }
        }
    }

    fn sign_now(&mut self, ctx: &egui::Context) {
        let Ok(v) = self.vault.clone() else { return };
        let Some(key) = self.key().cloned() else {
            return;
        };
        let id = self.next_request();
        let nca = self.nca.clone();
        let lang = kzsigner::i18n::lang().code().to_string();
        let Some(s) = &mut self.sign else { return };
        s.request = id;
        s.problem = None;
        let password = matches!(
            key.unlock,
            Unlock::Password | Unlock::FingerprintAndPassword
        )
        .then(|| s.password.clone());
        let (name, bytes) = (s.name.clone(), s.bytes.clone());
        let prompt = ChipPrompt {
            title: tf("Sign {}", &[&name]),
            subtitle: t("Confirm it's you to sign").into(),
            detail: String::new(),
        };
        self.job(ctx, move || {
            Msg::Signed(
                id,
                v.sign(nca, key.id, name, bytes.to_vec(), password, prompt, lang),
            )
        });
    }

    pub(super) fn signed_answer(&mut self, id: u64, r: Result<Signed, SignError>) {
        let Some(s) = &mut self.sign else { return };
        if s.request != id || self.screen != Screen::Sign {
            return;
        }
        let cyrillic = s
            .password
            .chars()
            .any(|c| ('\u{400}'..='\u{4ff}').contains(&c));
        s.problem = Some(match r {
            Ok(signed) => {
                s.password.clear();
                let dir = s.path.parent().map(Path::to_path_buf).unwrap_or_default();
                let pdf = signed.name.to_lowercase().ends_with(".pdf");
                let (path, next_to_original) = match save_new(&dir, &signed.name, &signed.bytes) {
                    Ok(p) => (Some(p), true),
                    // the folder can't be written (a read-only share, a phone): ask where
                    Err(_) => (
                        self.dialogs
                            .save(&dir.join(&signed.name))
                            .and_then(|p| std::fs::write(&p, &signed.bytes).ok().map(|_| p)),
                        false,
                    ),
                };
                self.signed = Some(SignedState {
                    path,
                    name: signed.name,
                    bytes: signed.bytes,
                    nca_time_ms: signed.nca_time_ms,
                    pdf,
                    next_to_original,
                    copy_saved: None,
                });
                self.sign = None;
                self.screen = Screen::Signed;
                return;
            }
            Err(SignError::NoAnswer) => SignProblem::NoAnswer,
            Err(SignError::KeyCantSign {
                reason,
                valid_from_ms,
                expires_ms,
            }) => SignProblem::CantSign {
                reason,
                from: valid_from_ms,
                to: expires_ms,
            },
            Err(SignError::WrongPassword) => SignProblem::WrongPassword { cyrillic },
            Err(SignError::Wait { seconds }) => SignProblem::Wait(seconds),
            Err(SignError::Cancelled) => {
                s.problem = None;
                return;
            }
            Err(SignError::KeyReset | SignError::NoSuchKey) => SignProblem::KeyReset,
            Err(SignError::Cannot) => SignProblem::Cannot,
            Err(SignError::Failed { detail }) => SignProblem::Failed(detail),
        });
    }

    pub(super) fn signed_screen(&mut self, ui: &mut egui::Ui) {
        let Some(s) = &mut self.signed else {
            self.screen = Screen::Home;
            return;
        };
        ui.add_space(24.0);
        let body = s
            .nca_time_ms
            .map(|ms| tf("Signing time confirmed by NCA, {}", &[&text::date_time(ms)]))
            .unwrap_or_default();
        ui::verdict(ui, Tone::Good, Icon::Check, t("Signed"), &body);
        let mut reveal = None;
        let mut save_copy = false;
        ui::card(ui, |ui| {
            ui.horizontal(|ui| {
                icons::show(ui, Icon::FileCheck, 36.0, ui::GREEN);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    match &s.path {
                        Some(p) => {
                            let n = p
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            ui.add(egui::Label::new(RichText::new(n).size(18.0).strong()).wrap());
                            let folder = p
                                .parent()
                                .map(|d| d.display().to_string())
                                .unwrap_or_default();
                            let where_ = if s.next_to_original {
                                tf("Saved in {}, next to the original", &[&folder])
                            } else {
                                tf("Saved in {}", &[&folder])
                            };
                            ui.add(egui::Label::new(ui::muted(where_)).wrap());
                        }
                        None => {
                            ui.label(RichText::new(&s.name).size(18.0).strong());
                            ui.label(
                                RichText::new(t("Not saved yet.")).color(Tone::Bad.colors().1),
                            );
                        }
                    }
                });
            });
        });
        let body = if s.pdf {
            t(
                "The signature is inside the file. The boxes on the last page only show who signed; a printed copy is just paper.",
            )
        } else {
            t("The signature is inside the file. A printed copy is just paper.")
        };
        ui::notice(ui, Tone::Info, t("Send the file, not a printout"), body);
        if let Some(c) = &s.copy_saved {
            ui::notice(ui, Tone::Good, &tf("Copy saved: {}", &[&c.display()]), "");
        }
        ui.add_space(6.0);
        ui::actions(ui, |ui| {
            match &s.path {
                Some(p) => {
                    if ui::main_button(ui, t("Show in folder"), 220.0).clicked() {
                        reveal = Some(p.clone());
                    }
                    if ui::second_button(ui, t("Save a copy elsewhere")).clicked() {
                        save_copy = true;
                    }
                }
                None => {
                    if ui::main_button(ui, t("Save"), 220.0).clicked() {
                        save_copy = true;
                    }
                }
            }
            if ui::text_button(ui, t("Done")).clicked() {
                self.screen = Screen::Home;
            }
        });
        if let Some(p) = reveal {
            self.dialogs.reveal(&p);
        }
        if save_copy {
            let s = self.signed.as_mut().unwrap();
            let suggested = s.path.clone().unwrap_or_else(|| PathBuf::from(&s.name));
            if let Some(p) = self.dialogs.save(&suggested) {
                match std::fs::write(&p, &s.bytes) {
                    Ok(()) if s.path.is_none() => s.path = Some(p),
                    Ok(()) => s.copy_saved = Some(p),
                    Err(e) => {
                        self.message = Some((tf("Couldn't save the file: {}", &[&e]), Tone::Bad))
                    }
                }
            }
        }
        if self.screen == Screen::Home {
            self.signed = None;
        }
    }
}

/// Writes `bytes` as `name` in `dir`, or "name (2).ext", "name (3).ext"... when taken: an
/// existing file is never replaced.
pub fn save_new(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let p = Path::new(name);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for n in 1..1000 {
        let candidate = if n == 1 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
                    drop(f);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(e);
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("too many files with this name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_file_never_replaces_another() {
        let dir = std::env::temp_dir().join(format!("kzsigner-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = save_new(&dir, "X-signed.pdf", b"1").unwrap();
        let b = save_new(&dir, "X-signed.pdf", b"2").unwrap();
        let c = save_new(&dir, "doc.txt.cms", b"3").unwrap();
        let d = save_new(&dir, "doc.txt.cms", b"4").unwrap();
        assert_eq!(a, dir.join("X-signed.pdf"));
        assert_eq!(b, dir.join("X-signed (2).pdf"));
        assert_eq!(c, dir.join("doc.txt.cms"));
        assert_eq!(d, dir.join("doc.txt (2).cms"));
        assert_eq!(std::fs::read(&a).unwrap(), b"1");
        assert_eq!(std::fs::read(&b).unwrap(), b"2");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
