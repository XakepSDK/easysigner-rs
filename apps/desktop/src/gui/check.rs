//! Check: the verdict, who signed, and the details.

use eframe::egui::{self, RichText};
use kzsigner_ffi::{Checked, Format, Reason, SignerCheck, Verdict};

use super::text::{self, t, tf};
use super::ui::{self, Tone};
use super::*;

/// A reason's title and what to do.
fn reason(r: Reason) -> (&'static str, &'static str) {
    match r {
        Reason::Changed => (
            t("Changed after it was signed"),
            t("Ask the sender to sign it again and send the new file."),
        ),
        Reason::Revoked => (
            t("The signer's key was revoked"),
            t(
                "It was cancelled before this signature was made. Ask the sender to sign again with their new key.",
            ),
        ),
        Reason::Expired => (
            t("The signer's key had expired"),
            t(
                "It was no longer valid when this was signed. Ask the sender to sign again with a current key.",
            ),
        ),
        Reason::ExpiredSince => (
            t("The signer's key has expired since"),
            t(
                "It was signed without NCA's time, so it can only be checked while the key is valid. Ask for a newly signed file.",
            ),
        ),
        Reason::NotRecognized => (
            t("This key isn't recognized in Kazakhstan"),
            t(
                "It wasn't issued by NCA or another accredited center, or by a foreign one registered here, so the signature has no legal force. Ask the sender to sign with a Kazakhstan key.",
            ),
        ),
        Reason::Damaged => (
            t("The signature is damaged"),
            t("The file may have been cut or broken in sending. Ask for it again."),
        ),
        Reason::NotConfirmed => (
            t("NCA didn't confirm the key"),
            t(
                "Try again in a few minutes. If it keeps happening, check that the computer is online.",
            ),
        ),
    }
}

/// The short word in the signers table.
fn status(s: &SignerCheck) -> (&'static str, Tone) {
    match s.reason {
        None if s.valid => (t("valid"), Tone::Good),
        None => (t("not confirmed"), Tone::Warn),
        Some(Reason::Changed) => (t("changed"), Tone::Bad),
        Some(Reason::Revoked) => (t("revoked"), Tone::Bad),
        Some(Reason::Expired | Reason::ExpiredSince) => (t("expired"), Tone::Bad),
        Some(Reason::NotRecognized) => (t("not recognized"), Tone::Bad),
        Some(Reason::Damaged) => (t("damaged"), Tone::Bad),
        Some(Reason::NotConfirmed) => (t("not confirmed"), Tone::Warn),
    }
}

fn format_name(f: Option<Format>) -> &'static str {
    match f {
        Some(Format::Pdf) => t("PAdES, signature inside the PDF"),
        Some(Format::Xml) => t("XAdES, signature inside the XML document"),
        Some(Format::Cms) => t("CAdES, document and signatures inside the .cms"),
        Some(Format::DetachedCms) => t("CAdES, signatures in a .cms beside the document"),
        Some(Format::Card) => t("Document card (PDF with the original and its signatures)"),
        None => t("No signature"),
    }
}

fn revocation(s: &SignerCheck) -> String {
    use kzsigner_ffi::RevocationAnswer as A;
    let words = match s.revocation_answer {
        None => return String::new(),
        Some(A::Good) => t("Not revoked: NCA confirmed the key"),
        Some(A::Revoked) => t("Revoked: NCA cancelled this key"),
        Some(A::Unknown) => t("NCA doesn't know this key"),
        Some(A::NoAnswer) => t("NCA didn't answer"),
    };
    if s.revocation_kept {
        format!("{words} ({})", t("NCA's answer kept in the signature"))
    } else {
        words.into()
    }
}

/// Everything the details show, as text for "Copy details".
fn details_text(c: &Checked) -> String {
    let mut out = vec![
        format!("{}: {}", t("Document"), c.document_name),
        format!("{}: {}", t("Format"), format_name(c.format)),
    ];
    for s in &c.signers {
        out.push(String::new());
        out.push(format!("{}: {}", t("Signed by"), s.name));
        if let Some(iin) = &s.iin {
            out.push(tf("IIN {}", &[iin]));
        }
        if let Some(co) = &s.company {
            out.push(format!(
                "{}: {co}{}",
                t("On behalf of"),
                s.bin
                    .as_ref()
                    .map(|b| format!(" · {}", tf("BIN {}", &[b])))
                    .unwrap_or_default()
            ));
        }
        for (k, v) in signer_details(s) {
            out.push(format!("{k}: {v}"));
        }
    }
    if let Some(f) = &c.fingerprint {
        out.push(String::new());
        out.push(format!("{} (SHA-256): {f}", t("Document fingerprint")));
    }
    out.join("\n")
}

/// The details rows for one signer: (label, value).
fn signer_details(s: &SignerCheck) -> Vec<(&'static str, String)> {
    let mut rows = vec![];
    let time = match (s.signed_ms, s.nca_time) {
        (Some(ms), true) => format!("{} ({})", text::date_time(ms), t("timestamp by NCA (TSA)")),
        (Some(ms), false) => format!(
            "{} ({})",
            text::date_time(ms),
            t("from the signer's own clock, not confirmed by NCA")
        ),
        (None, _) => "—".into(),
    };
    rows.push((t("Signing time"), time));
    let rev = revocation(s);
    if !rev.is_empty() {
        rows.push((t("Revocation"), rev));
    }
    let mut cert = vec![];
    if let Some(a) = &s.algorithm {
        cert.push(a.clone());
    }
    if let Some(n) = &s.serial {
        cert.push(tf("serial {}", &[n]));
    }
    if let (Some(a), Some(b)) = (s.valid_from_ms, s.expires_ms) {
        cert.push(tf("valid {} to {}", &[&text::date(a), &text::date(b)]));
    }
    if !cert.is_empty() {
        rows.push((t("Certificate"), cert.join(", ")));
    }
    if let Some(i) = &s.issuer {
        rows.push((t("Issued by"), i.clone()));
    }
    if let Some(l) = &s.level {
        rows.push((t("Level"), l.clone()));
    }
    if !s.problems.is_empty() {
        rows.push((t("Found"), s.problems.join("; ")));
    }
    rows
}

impl App {
    /// Checks `path`.
    pub(super) fn start_check(&mut self, ctx: &egui::Context, path: PathBuf) {
        if let Some((name, bytes)) = self.read(&path) {
            self.start_check_with(ctx, path, name, bytes);
        }
    }

    pub(super) fn start_check_with(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        name: String,
        bytes: Vec<u8>,
    ) {
        self.check = Some(CheckState {
            path,
            name,
            bytes: Arc::new(bytes),
            original: None,
            original_bytes: None,
            result: None,
            details: false,
            request: 0,
        });
        self.screen = Screen::Check;
        self.recheck(ctx);
    }

    /// The document a detached .cms signs.
    pub(super) fn set_original(&mut self, ctx: &egui::Context, path: PathBuf, bytes: Vec<u8>) {
        if let Some(c) = &mut self.check {
            c.original = Some(path);
            c.original_bytes = Some(Arc::new(bytes));
            self.recheck(ctx);
        }
    }

    /// Asks NCA again (Check again, a new language, the document chosen).
    pub(super) fn recheck(&mut self, ctx: &egui::Context) {
        let id = self.next_request();
        let nca = self.nca.clone();
        let lang = kzsigner::i18n::lang().code().to_string();
        let Some(c) = &mut self.check else { return };
        c.request = id;
        c.result = None;
        let (name, bytes, original) = (c.name.clone(), c.bytes.clone(), c.original_bytes.clone());
        self.job(ctx, move || {
            let r = kzsigner_ffi::check_file(
                nca,
                name,
                bytes.to_vec(),
                original.map(|o| o.to_vec()),
                lang,
            );
            Msg::Checked(id, Box::new(r))
        });
    }

    pub(super) fn check_screen(&mut self, ui: &mut egui::Ui, wide: bool) {
        let ctx = ui.ctx().clone();
        let Some(c) = &self.check else {
            self.screen = Screen::Home;
            return;
        };
        ui.add_space(16.0);
        ui::title(ui, t("Check a signature"));
        ui.horizontal(|ui| {
            icons::show(ui, Icon::File, 22.0, ui::MUTED);
            ui.add(egui::Label::new(ui::muted(&c.name).size(15.0)).wrap());
        });
        let Some(r) = c.result.clone() else {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(t("Asking NCA…")).size(17.0));
            });
            return;
        };

        // the verdict
        let mut next = Next::default();
        match r.verdict {
            Verdict::NotSigned => {
                ui::verdict(
                    ui,
                    Tone::Grey,
                    Icon::File,
                    t("This file isn't signed"),
                    &tf(
                        "{} has no electronic signature in it, so there is nothing to check.",
                        &[&c.name],
                    ),
                );
                ui.label(ui::muted(t("If someone sent it as signed, ask them for the signed file: a .cms, or the PDF they signed.")));
                next.sign = true;
            }
            Verdict::NeedsDocument => {
                ui::verdict(
                    ui,
                    Tone::Info,
                    Icon::File,
                    t("Choose the signed document"),
                    &tf(
                        "This .cms holds only the signatures. To check them, choose the document they sign: {}.",
                        &[&r.document_name],
                    ),
                );
                if ui::main_button(ui, t("Choose the document"), 260.0).clicked()
                    && let Some(f) = self.dialogs.open(Pick::Original)
                    && let Some((_, b)) = self.read(&f)
                {
                    self.set_original(&ctx, f, b);
                    return;
                }
                ui.label(ui::muted(t("Or drop it here.")));
            }
            Verdict::Valid => {
                let n = r.signers.len();
                let title = match n {
                    1 => t("The signature is valid").to_string(),
                    2 => t("Both signatures are valid").to_string(),
                    _ => tf("All {} signatures are valid", &[&n]),
                };
                let body = if r.signers.iter().all(|s| s.nca_time) {
                    t("Not changed since it was signed, and the key was valid then.")
                } else {
                    t("Not changed since it was signed, and the key is valid today.")
                };
                ui::verdict(ui, Tone::Good, Icon::ShieldCheck, &title, body);
                next.join = true;
                next.open = r.document.is_some();
            }
            Verdict::Invalid => {
                let bad = r
                    .signers
                    .iter()
                    .find_map(|s| s.reason)
                    .unwrap_or(Reason::Damaged);
                let (what, todo) = reason(bad);
                ui::verdict(
                    ui,
                    Tone::Bad,
                    Icon::XCircle,
                    t("Do not trust this document"),
                    &format!("{what}. {todo}"),
                );
            }
            Verdict::Unknown => {
                ui::verdict(
                    ui,
                    Tone::Warn,
                    Icon::Warning,
                    t("Couldn't confirm the signature"),
                    t(
                        "NCA didn't confirm the key was valid when it signed. Until it does, don't rely on this document.",
                    ),
                );
                ui.label(ui::muted(t("Try again in a few minutes. If it keeps happening, check that the computer is online.")));
                next.again = true;
            }
        }

        // who signed
        if !r.signers.is_empty() {
            signers_table(ui, &r.signers, wide);
            for s in &r.signers {
                if s.valid
                    && !s.nca_time
                    && let Some(exp) = s.expires_ms
                {
                    ui::notice(
                        ui,
                        Tone::Warn,
                        t("Not confirmed by NCA"),
                        &tf(
                            "This signature can only be checked until {}'s key expires on {}, or sooner if it is cancelled. After that, ask for a newly signed file.",
                            &[&s.name, &text::date(exp)],
                        ),
                    );
                }
            }
        }

        // what next
        ui.add_space(6.0);
        let mut act = None;
        ui::actions(ui, |ui| {
            if next.again && ui::main_button(ui, t("Check again"), 200.0).clicked() {
                act = Some(Act::Again);
            }
            if next.join
                && self.can_join()
                && ui::main_button(ui, t("Add my signature"), 220.0).clicked()
            {
                act = Some(Act::Sign);
            }
            if next.sign && ui::main_button(ui, t("Sign it myself"), 200.0).clicked() {
                act = Some(Act::Sign);
            }
            if next.open && ui::second_button(ui, t("Open the document")).clicked() {
                act = Some(Act::Open);
            }
            if !r.signers.is_empty() {
                let label = if c_details(self) {
                    t("Hide details")
                } else {
                    t("Details")
                };
                if ui::second_button(ui, label).clicked() {
                    act = Some(Act::Details);
                }
            }
            if ui::text_button(ui, t("Check another file")).clicked() {
                act = Some(Act::Another);
            }
        });
        match act {
            Some(Act::Again) => self.recheck(&ctx),
            Some(Act::Sign) => {
                let c = self.check.take().unwrap();
                let doc = kzsigner_ffi::inspect(c.name.clone(), c.bytes.to_vec());
                self.start_sign_with(c.path, c.name, Arc::unwrap_or_clone(c.bytes), doc);
                return;
            }
            Some(Act::Open) => {
                let c = self.check.as_ref().unwrap();
                let content = Arc::new(r.document.clone().unwrap_or_default());
                // the file itself when the document is the file (a signed PDF or XML)
                let path = (content.as_slice() == c.bytes.as_slice()).then(|| c.path.clone());
                let path = path.or_else(|| {
                    c.original_bytes
                        .as_ref()
                        .filter(|o| o.as_slice() == content.as_slice())
                        .and(c.original.clone())
                });
                self.view(&ctx, path, r.document_name.clone(), content);
            }
            Some(Act::Details) => {
                let c = self.check.as_mut().unwrap();
                c.details = !c.details;
            }
            Some(Act::Another) => {
                if let Some(f) = self.dialogs.open(Pick::Signed) {
                    self.start_check(&ctx, f);
                }
                return;
            }
            None => {}
        }

        if self.check.as_ref().is_some_and(|c| c.details) {
            details(ui, &r);
        }
    }

    /// "Add my signature" makes sense: there is a key, and the file takes another signature.
    fn can_join(&self) -> bool {
        let Some(c) = &self.check else { return false };
        c.original.is_none() && {
            let d = kzsigner_ffi::inspect(c.name.clone(), c.bytes.to_vec());
            d.output != kzsigner_ffi::Output::Cannot
        }
    }
}

fn c_details(app: &App) -> bool {
    app.check.as_ref().is_some_and(|c| c.details)
}

#[derive(Default)]
struct Next {
    again: bool,
    join: bool,
    sign: bool,
    open: bool,
}

enum Act {
    Again,
    Sign,
    Open,
    Details,
    Another,
}

/// Signed by, on behalf of, when, and the word.
fn signers_table(ui: &mut egui::Ui, signers: &[SignerCheck], wide: bool) {
    ui::card(ui, |ui| {
        if wide {
            egui::Grid::new("signers")
                .num_columns(4)
                .spacing([24.0, 12.0])
                .min_col_width(190.0)
                .show(ui, |ui| {
                    for h in [t("Signed by"), t("On behalf of"), t("Signed on"), ""] {
                        ui.label(ui::muted(h).size(13.0));
                    }
                    ui.end_row();
                    for s in signers {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(&s.name).strong());
                            if let Some(iin) = &s.iin {
                                ui.label(ui::muted(tf("IIN {}", &[iin])).size(13.0));
                            }
                        });
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            match &s.company {
                                Some(c) => {
                                    ui.label(c);
                                    if let Some(b) = &s.bin {
                                        ui.label(ui::muted(tf("BIN {}", &[b])).size(13.0));
                                    }
                                }
                                None => {
                                    ui.label(ui::muted("—"));
                                }
                            }
                        });
                        when(ui, s);
                        ui.vertical(|ui| word(ui, s));
                        ui.end_row();
                    }
                });
        } else {
            for (i, s) in signers.iter().enumerate() {
                if i > 0 {
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&s.name).strong());
                    word(ui, s);
                });
                if let Some(iin) = &s.iin {
                    ui.label(ui::muted(tf("IIN {}", &[iin])).size(13.0));
                }
                if let Some(c) = &s.company {
                    let line = match &s.bin {
                        Some(b) => tf("For {} · BIN {}", &[c, b]),
                        None => tf("For {}", &[c]),
                    };
                    ui.label(line);
                }
                when(ui, s);
            }
        }
    });
}

fn when(ui: &mut egui::Ui, s: &SignerCheck) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        match (s.signed_ms, s.nca_time) {
            (Some(ms), true) => {
                ui.label(text::date_time(ms));
                ui.label(ui::muted(t("NCA time")).size(13.0));
            }
            (Some(ms), false) => {
                ui.label(RichText::new(t("Not confirmed by NCA")).color(Tone::Warn.colors().1));
                ui.label(
                    ui::muted(tf(
                        "The file says {}, but that comes from the signer's own clock.",
                        &[&text::date_time(ms)],
                    ))
                    .size(13.0),
                );
            }
            (None, _) => {
                ui.label(ui::muted("—"));
            }
        }
    });
}

fn word(ui: &mut egui::Ui, s: &SignerCheck) {
    let (w, tone) = status(s);
    let (bg, fg, _) = tone.colors();
    egui::Frame::new()
        .fill(bg)
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(w).color(fg).strong().size(13.0));
        });
}

fn details(ui: &mut egui::Ui, r: &Checked) {
    ui.add_space(8.0);
    ui.label(RichText::new(t("Signature details")).size(20.0).strong());
    ui.label(ui::muted(t(
        "For checking by hand or by a specialist. Nothing here needs action.",
    )));
    ui::card(ui, |ui| {
        ui::field(ui, t("Format"), format_name(r.format), None);
        for s in &r.signers {
            ui.separator();
            ui.label(RichText::new(&s.name).size(16.0).strong());
            for (k, v) in signer_details(s) {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(ui::muted(k).size(13.0));
                    ui.add(egui::Label::new(v).wrap());
                });
            }
        }
        if let Some(f) = &r.fingerprint {
            ui.separator();
            ui.label(ui::muted(format!("{} (SHA-256)", t("Document fingerprint"))).size(13.0));
            ui.add(egui::Label::new(RichText::new(f).monospace()).wrap());
        }
    });
    if ui::second_button(ui, t("Copy details")).clicked() {
        ui.ctx().copy_text(details_text(r));
    }
}
