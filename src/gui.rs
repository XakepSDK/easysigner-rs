//! The desktop window: Sign and Verify / Extract tabs. All crypto runs off the UI thread.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, Color32, RichText};

use crate::i18n::{self, Lang, tr, trf};
use crate::p12::Key;
use crate::pdf::card::CardLang;
use crate::report::{SignResult, SignerReport, VerifyReport};
use crate::{DEFAULT_OCSP_URL, DEFAULT_TSA_URL, Engine, time};

/// Text colours that read well on the light and the dark theme.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Plain,
    Strong,
    Good,
    Bad,
    Warn,
    Muted,
}

impl Tone {
    fn text(self, ui: &egui::Ui, t: impl Into<String>) -> RichText {
        let dark = ui.visuals().dark_mode;
        let rgb = |l: (u8, u8, u8), d: (u8, u8, u8)| {
            let (r, g, b) = if dark { d } else { l };
            Color32::from_rgb(r, g, b)
        };
        let r = RichText::new(t);
        match self {
            Tone::Plain => r,
            Tone::Strong => r.strong(),
            Tone::Good => r.color(rgb((0x1a, 0x7f, 0x37), (0x4a, 0xc2, 0x6b))),
            Tone::Bad => r.color(rgb((0xc6, 0x28, 0x28), (0xff, 0x7b, 0x72))),
            Tone::Warn => r.color(rgb((0x8a, 0x5a, 0x00), (0xe3, 0xb3, 0x41))),
            Tone::Muted => r.color(rgb((0x5d, 0x66, 0x73), (0x9a, 0xa4, 0xb0))),
        }
    }
}

/// File choosers: the system's own, or scripted ones in tests.
pub trait Dialogs {
    fn open(&mut self, start: Option<&Path>) -> Option<PathBuf>;
    /// The save location; the system dialog asks before replacing a file.
    fn save(&mut self, suggested: &Path) -> Option<PathBuf>;
}

/// The operating system's file dialogs.
pub struct SystemDialogs;

impl Dialogs for SystemDialogs {
    fn open(&mut self, start: Option<&Path>) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new();
        if let Some(dir) = start.and_then(Path::parent) {
            d = d.set_directory(dir);
        }
        d.pick_file()
    }

    fn save(&mut self, suggested: &Path) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new();
        if let Some(dir) = suggested.parent().filter(|p| !p.as_os_str().is_empty()) {
            d = d.set_directory(dir);
        }
        if let Some(name) = suggested.file_name() {
            d = d.set_file_name(name.to_string_lossy());
        }
        d.save_file()
    }
}

/// Opens the window and runs until it is closed. `file`: a document, .cms or key to start with.
pub fn run(engine: Engine, file: Option<PathBuf>) -> Result<(), String> {
    i18n::set(i18n::detect());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("kzsigner")
            .with_app_id("kzsigner")
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/kzsigner-64.rgba").to_vec(),
                width: 64,
                height: 64,
            })
            .with_inner_size([760.0, 640.0])
            .with_drag_and_drop(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "kzsigner",
        options,
        Box::new(|cc| {
            let mut app = App::new(engine, Box::new(SystemDialogs));
            install_fonts(&cc.egui_ctx);
            app.fonts_installed = true;
            app.pending_open = file;
            Ok(Box::new(Window::new(app)))
        }),
    )
    .map_err(|e| trf("Could not open the window: {}", &[&e]))
}

struct Window(App);

impl Window {
    fn new(app: App) -> Window {
        Window(app)
    }
}

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| self.0.ui(ui));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Sign,
    Verify,
}

/// A note under a field: lines of text with a tone each.
#[derive(Clone, Default)]
struct Note(Vec<(String, Tone)>);

impl Note {
    fn error(m: &str) -> Note {
        Note(vec![(m.to_string(), Tone::Bad)])
    }
    fn show(&self, ui: &mut egui::Ui) {
        for (t, tone) in &self.0 {
            ui.label(tone.text(ui, t));
        }
    }
}

enum Msg {
    DocChecked(u64, Result<(DocKind, Option<VerifyReport>), String>),
    KeyOpened(u64, PathBuf, String, Result<Box<Key>, String>),
    Signed(PathBuf, SignAs, Result<SignResult, String>),
    Verified(u64, Result<VerifyReport, String>),
    /// (file, suggested name for the saved document, bytes)
    Extracted(PathBuf, Option<String>, Result<Vec<u8>, String>),
}

/// What the chosen document is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DocKind {
    Other,
    Cms,
    Pdf,
    SignedPdf,
    Card,
}

/// What signing makes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignAs {
    /// A .cms file.
    Cms,
    /// The signature inside the PDF (PAdES).
    Pdf,
    /// A document card (ddcard).
    Card,
}

/// The window's state and behaviour, without the native window around it (tests drive it).
pub struct App {
    engine: Arc<Engine>,
    dialogs: Box<dyn Dialogs>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: usize,
    fonts_installed: bool,
    /// The text in each file field, by field id, while it is being typed.
    path_fields: std::collections::HashMap<&'static str, PathField>,
    /// A file given on the command line, opened on the first frame.
    pub pending_open: Option<PathBuf>,
    pub tab: Tab,
    /// A message box: (text, is error).
    pub message: Option<(String, bool)>,

    // Sign tab
    pub doc: Option<PathBuf>,
    pub sign_original: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub password: String,
    show_password: bool,
    aliases: Vec<String>,
    alias: Option<String>,
    doc_note: Note,
    key_note: Note,
    pub detached: bool,
    pub timestamp: bool,
    pub sign_as: SignAs,
    pub card_qr: bool,
    pub card_lang: CardLang,
    doc_kind: DocKind,
    key: Option<Arc<Key>>,
    doc_is_detached_cms: bool,
    doc_is_cms: bool,
    signing: bool,
    doc_request: u64,
    key_request: u64,
    opened_for: Option<String>,

    // Verify tab
    pub cms: Option<PathBuf>,
    pub verify_original: Option<PathBuf>,
    show_verify_original: bool,
    pub ocsp: bool,
    verify_request: u64,
    pub result: Option<Result<VerifyReport, String>>,
    checking: bool,
}

impl App {
    pub fn new(engine: Engine, dialogs: Box<dyn Dialogs>) -> App {
        let (tx, rx) = channel();
        App {
            engine: Arc::new(engine),
            dialogs,
            tx,
            rx,
            busy: 0,
            fonts_installed: false,
            path_fields: Default::default(),
            pending_open: None,
            tab: Tab::Sign,
            message: None,
            doc: None,
            sign_original: None,
            key_file: None,
            password: String::new(),
            show_password: false,
            aliases: vec![],
            alias: None,
            doc_note: Note::default(),
            key_note: Note::default(),
            detached: false,
            timestamp: false,
            sign_as: SignAs::Cms,
            card_qr: false,
            card_lang: CardLang::Ru,
            doc_kind: DocKind::Other,
            key: None,
            doc_is_detached_cms: false,
            doc_is_cms: false,
            signing: false,
            doc_request: 0,
            key_request: 0,
            opened_for: None,
            cms: None,
            verify_original: None,
            show_verify_original: false,
            ocsp: false,
            verify_request: 0,
            result: None,
            checking: false,
        }
    }

    /// Whether background work is running.
    pub fn busy(&self) -> bool {
        self.busy > 0
    }

    /// Runs `work` off the UI thread; its message comes back through the channel.
    fn background(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce(&Engine) -> Msg + Send + 'static,
    ) {
        self.busy += 1;
        let (tx, engine, ctx) = (self.tx.clone(), self.engine.clone(), ctx.clone());
        std::thread::spawn(move || {
            let m = work(&engine);
            let _ = tx.send(m);
            ctx.request_repaint();
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if !self.fonts_installed {
            install_fonts(&ctx);
            self.fonts_installed = true;
        }
        while let Ok(m) = self.rx.try_recv() {
            self.busy -= 1;
            self.handle(m);
        }
        if self.busy > 0 {
            ctx.set_cursor_icon(egui::CursorIcon::Progress);
        }
        if let Some(f) = self.pending_open.take() {
            self.open_file(&ctx, f);
        }
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if let Some(f) = dropped.into_iter().find(|p| !p.as_os_str().is_empty()) {
            self.open_file(&ctx, f);
        }
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.tab,
                Tab::Sign,
                RichText::new(tr("Sign")).size(16.0),
            );
            ui.selectable_value(
                &mut self.tab,
                Tab::Verify,
                RichText::new(tr("Verify / Extract")).size(16.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut lang = i18n::lang();
                egui::ComboBox::from_id_salt("language")
                    .selected_text(lang.name())
                    .show_ui(ui, |ui| {
                        for l in Lang::ALL {
                            ui.selectable_value(&mut lang, l, l.name());
                        }
                    })
                    .response
                    .on_hover_text(tr("Language"));
                if lang != i18n::lang() {
                    i18n::save(lang);
                    self.set_language(&ctx, lang);
                }
            });
        });
        ui.separator();
        match self.tab {
            Tab::Sign => {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| self.sign_tab(ui));
            }
            Tab::Verify => self.verify_tab(ui),
        }
        if let Some((text, error)) = self.message.clone() {
            egui::Modal::new(egui::Id::unique("message")).show(&ctx, |ui| {
                ui.set_max_width(460.0);
                let title = if error {
                    Tone::Bad.text(ui, tr("Error"))
                } else {
                    Tone::Strong.text(ui, "kzsigner")
                };
                ui.label(title.strong());
                ui.add_space(6.0);
                ui.label(text);
                ui.add_space(8.0);
                if ui.button("OK").clicked() {
                    self.message = None;
                }
            });
        }
    }

    // ------------------------------------------------------------------ fields

    /// A file field: label, path, Browse button. The path can also be typed or pasted; it is
    /// taken when the field loses focus or Enter is pressed. Returns a newly chosen file.
    fn file_field(
        &mut self,
        ui: &mut egui::Ui,
        id: &'static str,
        label: &str,
        current: &Option<PathBuf>,
    ) -> Option<PathBuf> {
        let mut chosen = None;
        let l = ui.label(label);
        let field = self.path_fields.entry(id).or_default();
        if field.shown != *current {
            // chosen another way (Browse, drop, command line): show it
            field.text = current
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            field.shown = current.clone();
        }
        let dialogs = &mut self.dialogs;
        ui.horizontal(|ui| {
            let w = ui.available_width() - 90.0;
            let r = ui
                .add_sized(
                    [w.max(100.0), 22.0],
                    egui::TextEdit::singleline(&mut field.text),
                )
                .labelled_by(l.id);
            if r.lost_focus() {
                // "Copy as path" in Windows Explorer adds quotes
                let typed = field.text.trim().trim_matches('"').trim();
                let typed = (!typed.is_empty()).then(|| PathBuf::from(typed));
                if typed.is_some() && typed != *current {
                    chosen = typed;
                } else if typed.is_none() {
                    // emptied: put back the current file
                    field.shown = current.clone();
                    field.text = current
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                }
            }
            if ui.button(tr("Browse…")).on_hover_text(label).clicked() {
                chosen = dialogs.open(current.as_deref());
            }
        });
        chosen
    }

    /// A dropped or command-line file: a key goes to the key field, a signed .cms to the
    /// Verify tab (unless the Sign tab is open, where it is co-signed), anything else is signed.
    /// (A PDF goes to the Sign tab: it may be a document to sign, a signed PDF or a card.)
    pub fn open_file(&mut self, ctx: &egui::Context, f: PathBuf) {
        let ext = f
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext == "p12" || ext == "pfx" {
            self.tab = Tab::Sign;
            self.set_key_file(ctx, f);
        } else if self.tab == Tab::Verify
            || (self.doc.is_none() && self.cms.is_none() && ext == "cms")
        {
            self.tab = Tab::Verify;
            self.set_cms(ctx, f);
        } else {
            self.set_doc(ctx, f);
        }
    }

    // ------------------------------------------------------------------ Sign tab

    fn sign_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        section(ui, tr("1. Document"));
        let doc = self.doc.clone();
        if let Some(f) = self.file_field(
            ui,
            "doc",
            tr("Document to sign (or a .cms to add your signature to)"),
            &doc,
        ) {
            self.set_doc(&ctx, f);
        }
        self.doc_note.show(ui);
        if self.doc_is_detached_cms {
            let o = self.sign_original.clone();
            if let Some(f) = self.file_field(
                ui,
                "sign_original",
                tr("Original document (only for a detached .cms)"),
                &o,
            ) {
                self.sign_original = Some(f);
            }
        }

        section(ui, tr("2. Your key"));
        let kf = self.key_file.clone();
        if let Some(f) = self.file_field(
            ui,
            "key",
            tr("Key file (.p12), e.g. RSA_… or GOSTKNCA_…"),
            &kf,
        ) {
            self.set_key_file(&ctx, f);
        }
        ui.horizontal(|ui| {
            let l = ui.label(tr("Password:"));
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(!self.show_password)
                        .desired_width(220.0),
                )
                .labelled_by(l.id);
            if r.lost_focus() {
                self.open_key(&ctx);
            }
            let hint = if self.show_password {
                tr("Hide password")
            } else {
                tr("Show password")
            };
            if eye_button(ui, self.show_password, hint).clicked() {
                self.show_password = !self.show_password;
            }
        });
        if self.aliases.len() > 1 {
            let before = self.alias.clone();
            ui.horizontal(|ui| {
                ui.label(tr("Key:"));
                egui::ComboBox::from_id_salt("alias")
                    .selected_text(self.alias.clone().unwrap_or_default())
                    .show_ui(ui, |ui| {
                        for a in self.aliases.clone() {
                            ui.selectable_value(&mut self.alias, Some(a.clone()), a);
                        }
                    });
            });
            if self.alias != before {
                self.open_key(&ctx);
            }
        }
        self.key_note.show(ui);

        section(ui, tr("3. Options"));
        let kind = self.doc_kind;
        ui.add_enabled_ui(!matches!(kind, DocKind::Cms | DocKind::Card), |ui| {
            ui.radio_value(&mut self.sign_as, SignAs::Cms, tr("Signature file (.cms)"));
            ui.add_enabled_ui(matches!(kind, DocKind::Pdf | DocKind::SignedPdf), |ui| {
                ui.radio_value(
                    &mut self.sign_as,
                    SignAs::Pdf,
                    tr("Inside the PDF (opens in any PDF viewer; PDF documents only)"),
                );
            });
            ui.radio_value(
                &mut self.sign_as,
                SignAs::Card,
                tr("Document card (a PDF with the document, its signatures and their details)"),
            );
        });
        ui.indent("sign_as_options", |ui| match self.sign_as {
            SignAs::Cms => {
                ui.add_enabled(
                    !self.doc_is_cms,
                    egui::Checkbox::new(
                        &mut self.detached,
                        tr("Detached signature (the .cms will not contain the document)"),
                    ),
                );
            }
            SignAs::Pdf => {}
            SignAs::Card => {
                ui.checkbox(
                    &mut self.card_qr,
                    tr("Print the signatures as QR codes too"),
                );
                ui.horizontal(|ui| {
                    ui.label(tr("Card language:"));
                    egui::ComboBox::from_id_salt("card_lang")
                        .selected_text(card_lang_name(self.card_lang))
                        .show_ui(ui, |ui| {
                            for l in [CardLang::Ru, CardLang::Kk, CardLang::KkRu] {
                                ui.selectable_value(&mut self.card_lang, l, card_lang_name(l));
                            }
                        });
                });
            }
        });
        if self.sign_as == SignAs::Card {
            ui.add_enabled(
                false,
                egui::Checkbox::new(
                    &mut true,
                    tr("Add NCA timestamp and revocation answer (a card always has them; needs internet)"),
                ),
            );
        } else {
            ui.checkbox(
                &mut self.timestamp,
                tr("Add NCA timestamp (needs internet, sends only a hash)"),
            );
        }
        ui.add_space(8.0);
        let can_sign = !self.signing
            && self.doc.is_some()
            && self.key.is_some()
            && (!self.doc_is_detached_cms || self.sign_original.is_some());
        if ui
            .add_enabled(can_sign, egui::Button::new(tr("Sign…")))
            .clicked()
        {
            self.sign(&ctx);
        }
    }

    pub fn set_doc(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.doc = Some(file.clone());
        self.doc_request += 1;
        let request = self.doc_request;
        self.doc_is_detached_cms = false;
        self.doc_is_cms = false;
        self.doc_kind = DocKind::Other;
        self.sign_original = None;
        self.doc_note = Note::default();
        self.background(ctx, move |e| {
            let r = std::fs::read(&file)
                .map_err(|err| format!("{}: {err}", file.display()))
                .and_then(|data| {
                    if e.is_signed_cms(&data) {
                        let rep = e.verify(&data, None, None).map_err(|x| x.0)?;
                        Ok((DocKind::Cms, Some(rep)))
                    } else if e.card_original(&data).is_some() {
                        let rep = e.verify(&data, None, None).map_err(|x| x.0)?;
                        Ok((DocKind::Card, Some(rep)))
                    } else if e.is_pdf(&data) {
                        match e.verify(&data, None, None) {
                            Ok(rep) if !rep.signers.is_empty() => {
                                Ok((DocKind::SignedPdf, Some(rep)))
                            }
                            _ => Ok((DocKind::Pdf, None)),
                        }
                    } else {
                        Ok((DocKind::Other, None))
                    }
                });
            Msg::DocChecked(request, r)
        });
    }

    pub fn set_key_file(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.key_file = Some(file);
        self.aliases.clear();
        self.alias = None;
        self.open_key(ctx);
    }

    /// Opens the key with the current file, password and alias, unless that is already done.
    pub fn open_key(&mut self, ctx: &egui::Context) {
        let Some(f) = self.key_file.clone() else {
            return;
        };
        let wanted = self.alias.clone();
        let pw_hash = crate::hex(&crate::gost::sha256(self.password.as_bytes()));
        let request = key_request(&f, wanted.as_deref(), &pw_hash);
        if self.opened_for.as_deref() == Some(request.as_str()) && self.key.is_some() {
            return; // nothing changed (e.g. focus lost)
        }
        self.key = None;
        self.opened_for = None;
        // any key still being opened is for an older file, password or alias: ignore it
        self.key_request += 1;
        let id = self.key_request;
        if self.password.is_empty() {
            self.key_note = Note::default();
            return;
        }
        self.key_note = Note(vec![(tr("Opening key…").into(), Tone::Muted)]);
        let pw = self.password.clone();
        self.background(ctx, move |e| {
            let r = std::fs::read(&f)
                .map_err(|err| format!("{}: {err}", f.display()))
                .and_then(|d| {
                    e.open_key(&d, &pw, wanted.as_deref())
                        .map(Box::new)
                        .map_err(|x| x.0)
                });
            Msg::KeyOpened(id, f, pw_hash, r)
        });
    }

    fn describe_key(&self, k: &Key) -> Note {
        let s = self.engine.describe(&k.cert);
        let text = |t: String| (t, Tone::Plain);
        let mut n = vec![(s.name(), Tone::Strong)];
        if let Some(iin) = s.get("IIN") {
            n.push(text(trf("IIN {}", &[&iin])));
        }
        if let Some(o) = s.get("O") {
            let bin = s
                .get("BIN")
                .map(|b| trf(" (BIN {})", &[&b]))
                .unwrap_or_default();
            n.push(text(format!("{o}{bin}")));
        }
        n.push(text(trf(
            "Valid until {} · {}",
            &[
                &time::fmt(s.not_after),
                &s.algorithm.clone().unwrap_or_default(),
            ],
        )));
        let issuer = s.issuer_cn.clone().unwrap_or_default();
        if s.chain_ok {
            n.push((trf("Issuer: {} ✔", &[&issuer]), Tone::Plain));
        } else {
            n.push((
                trf("Issuer: {} (not a trusted NCA RK issuer)", &[&issuer]),
                Tone::Bad,
            ));
        }
        for w in self.engine.key_warnings(&k.cert) {
            n.push((format!("⚠ {w}"), Tone::Warn));
        }
        Note(n)
    }

    pub fn sign(&mut self, ctx: &egui::Context) {
        let (Some(doc), Some(key)) = (self.doc.clone(), self.key.clone()) else {
            return;
        };
        let det = self.detached && !self.doc_is_cms;
        let tsa = self.timestamp.then(|| DEFAULT_TSA_URL.to_string());
        let sign_as = self.sign_as;
        let (qr, lang) = (self.card_qr, self.card_lang);
        let card_cosign = self.doc_kind == DocKind::Card;
        let orig = if self.doc_is_detached_cms {
            self.sign_original.clone()
        } else {
            None
        };
        self.signing = true;
        self.background(ctx, move |e| {
            let r = (|| -> Result<SignResult, String> {
                let input =
                    std::fs::read(&doc).map_err(|err| format!("{}: {err}", doc.display()))?;
                let o = orig
                    .map(|p| std::fs::read(&p).map_err(|err| format!("{}: {err}", p.display())))
                    .transpose()?;
                match sign_as {
                    SignAs::Cms => e.sign(&input, &key, det, tsa.as_deref(), true, o.as_deref()),
                    SignAs::Pdf => e.sign_pdf(&input, &key, tsa.as_deref()),
                    SignAs::Card => {
                        let name = doc
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        // adding to a card keeps how it was made
                        let (lang, qr) = if card_cosign {
                            (None, None)
                        } else {
                            (Some(lang), Some(qr))
                        };
                        e.sign_card(
                            &input,
                            &name,
                            &key,
                            DEFAULT_TSA_URL,
                            DEFAULT_OCSP_URL,
                            lang,
                            qr,
                        )
                    }
                }
                .map_err(|x| x.0)
            })();
            Msg::Signed(doc, sign_as, r)
        });
    }

    fn save_signed(&mut self, doc: &Path, sign_as: SignAs, r: SignResult) {
        let suggested = if r.cosigned {
            doc.to_path_buf()
        } else {
            match sign_as {
                SignAs::Cms => PathBuf::from(format!("{}.cms", doc.display())),
                SignAs::Pdf => {
                    let stem = doc
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    doc.with_file_name(format!("{stem}-signed.pdf"))
                }
                SignAs::Card => PathBuf::from(format!("{}.card.pdf", doc.display())),
            }
        };
        let Some(out) = self.dialogs.save(&suggested) else {
            return;
        };
        if let Err(e) = std::fs::write(&out, &r.cms) {
            self.message = Some((trf("Could not save: {}", &[&e]), true));
            return;
        }
        let mut m = format!(
            "{}.\n{}\n{}{}.",
            if r.cosigned {
                tr("Signature added")
            } else {
                tr("Signed")
            },
            trf("Saved to {}", &[&out.display()]),
            trf("Signatures in the file: {}", &[&r.signer_count]),
            if r.timestamped {
                tr(", with timestamp")
            } else {
                ""
            }
        );
        for w in &r.warnings {
            m.push_str("\n\n");
            m.push_str(&trf("Warning: {}", &[w]));
        }
        self.message = Some((m, false));
    }

    /// Switches the window's language and redoes what holds translated text: the key details,
    /// the document check and the verification report.
    pub fn set_language(&mut self, ctx: &egui::Context, lang: Lang) {
        i18n::set(lang);
        if let Some(k) = self.key.clone() {
            self.key_note = self.describe_key(&k);
        } else if self.key_file.is_some() && !self.password.is_empty() {
            self.opened_for = None;
            self.open_key(ctx);
        }
        if let Some(d) = self.doc.clone() {
            let original = self.sign_original.clone();
            self.set_doc(ctx, d);
            self.sign_original = original;
        }
        if self.result.is_some() {
            self.verify(ctx);
        }
    }

    // ------------------------------------------------------------------ Verify tab

    fn verify_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let c = self.cms.clone();
        if let Some(f) = self.file_field(
            ui,
            "cms",
            tr("Signed file (.cms, signed PDF or document card)"),
            &c,
        ) {
            self.set_cms(&ctx, f);
        }
        if self.show_verify_original {
            let o = self.verify_original.clone();
            if let Some(f) = self.file_field(
                ui,
                "verify_original",
                tr("Original document (only for a detached .cms)"),
                &o,
            ) {
                self.verify_original = Some(f);
                self.verify(&ctx);
            }
        }
        ui.checkbox(
            &mut self.ocsp,
            tr("Check revocation online (OCSP, ocsp.pki.gov.kz)"),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.cms.is_some(), egui::Button::new(tr("Verify")))
                .clicked()
            {
                self.verify(&ctx);
            }
            let can_extract =
                !self.checking && matches!(&self.result, Some(Ok(r)) if r.has_content && !r.is_pdf);
            if ui
                .add_enabled(
                    can_extract,
                    egui::Button::new(tr("Save original document…")),
                )
                .clicked()
            {
                self.extract(&ctx);
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                if self.checking {
                    ui.label(tr("Checking…"));
                } else {
                    match &self.result {
                        Some(Ok(r)) => report(ui, r),
                        Some(Err(e)) => {
                            ui.label(Tone::Bad.text(ui, e));
                        }
                        None => {}
                    }
                }
            });
    }

    pub fn set_cms(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.cms = Some(file);
        self.verify_original = None;
        self.verify(ctx);
    }

    pub fn verify(&mut self, ctx: &egui::Context) {
        let Some(file) = self.cms.clone() else { return };
        let orig = self.verify_original.clone();
        let ocsp = self.ocsp.then(|| DEFAULT_OCSP_URL.to_string());
        self.verify_request += 1;
        let id = self.verify_request;
        self.checking = true;
        self.background(ctx, move |e| {
            let r = (|| -> Result<VerifyReport, String> {
                let data =
                    std::fs::read(&file).map_err(|err| format!("{}: {err}", file.display()))?;
                let o = orig
                    .map(|p| std::fs::read(&p).map_err(|err| format!("{}: {err}", p.display())))
                    .transpose()?;
                e.verify(&data, o.as_deref(), ocsp.as_deref())
                    .map_err(|x| x.0)
            })();
            Msg::Verified(id, r)
        });
    }

    pub fn extract(&mut self, ctx: &egui::Context) {
        let Some(file) = self.cms.clone() else { return };
        self.background(ctx, move |e| {
            let (name, r) = match std::fs::read(&file) {
                Err(err) => (None, Err(format!("{}: {err}", file.display()))),
                Ok(d) => match e.card_original(&d) {
                    Some((name, data)) => (Some(name), Ok(data)),
                    None => (None, e.extract(&d).map_err(|x| x.0)),
                },
            };
            Msg::Extracted(file, name, r)
        });
    }

    fn save_extracted(&mut self, file: &Path, name: Option<String>, data: Vec<u8>) {
        let n = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // a card's document keeps its own name (only the name, never a path inside the card)
        let card_name = name
            .as_deref()
            .and_then(|n| n.rsplit(['/', '\\']).next())
            .filter(|n| !n.is_empty() && *n != "." && *n != "..");
        let base = if let Some(c) = card_name {
            c.to_string()
        } else if n.to_lowercase().ends_with(".cms") {
            n[..n.len() - 4].to_string()
        } else {
            format!("{n}.original")
        };
        let Some(out) = self.dialogs.save(&file.with_file_name(base)) else {
            return;
        };
        self.message = Some(match std::fs::write(&out, &data) {
            Ok(()) => (
                trf("Saved {} bytes to\n{}", &[&data.len(), &out.display()]),
                false,
            ),
            Err(e) => (trf("Could not save: {}", &[&e]), true),
        });
    }

    // ------------------------------------------------------------------ results

    fn handle(&mut self, m: Msg) {
        match m {
            Msg::DocChecked(id, r) => {
                if id != self.doc_request {
                    return;
                }
                match r {
                    Ok((kind, rep)) => {
                        self.doc_kind = kind;
                        if let Some(rep) = rep {
                            let names: Vec<String> =
                                rep.signers.iter().map(SignerReport::name).collect();
                            self.doc_note = Note(vec![
                                (
                                    trf(
                                        "Already signed ({}): {}.",
                                        &[&rep.signers.len(), &names.join(", ")],
                                    ),
                                    Tone::Plain,
                                ),
                                (
                                    match kind {
                                        DocKind::Card => tr(
                                            "Your signature will be added to this document card.",
                                        ),
                                        DocKind::SignedPdf => {
                                            tr("Your signature can be added inside this PDF.")
                                        }
                                        _ => tr("Your signature will be added to this file."),
                                    }
                                    .into(),
                                    Tone::Strong,
                                ),
                            ]);
                            if kind == DocKind::Cms {
                                self.doc_is_cms = true;
                                self.detached = false;
                                self.doc_is_detached_cms = !rep.has_content;
                            }
                        }
                        self.sign_as = match kind {
                            DocKind::Cms => SignAs::Cms,
                            DocKind::Card => SignAs::Card,
                            DocKind::SignedPdf => SignAs::Pdf,
                            DocKind::Other if self.sign_as == SignAs::Pdf => SignAs::Cms,
                            _ => self.sign_as,
                        };
                    }
                    Err(e) => self.doc_note = Note::error(&e),
                }
            }
            Msg::KeyOpened(id, f, pw_hash, r) => {
                if id != self.key_request {
                    return;
                }
                match r {
                    Ok(k) => {
                        if !k.other_aliases.is_empty() && self.aliases.is_empty() {
                            self.aliases = std::iter::once(k.alias.clone())
                                .chain(k.other_aliases.iter().cloned())
                                .collect();
                            self.alias = Some(k.alias.clone());
                        }
                        self.key_note = self.describe_key(&k);
                        self.alias = Some(k.alias.clone());
                        self.opened_for = Some(key_request(&f, Some(&k.alias), &pw_hash));
                        self.key = Some(Arc::new(*k));
                    }
                    Err(e) => self.key_note = Note::error(&e),
                }
            }
            Msg::Signed(doc, sign_as, r) => {
                self.signing = false;
                match r {
                    Ok(r) => self.save_signed(&doc, sign_as, r),
                    Err(e) => self.message = Some((e, true)),
                }
            }
            Msg::Verified(id, r) => {
                if id != self.verify_request {
                    return;
                }
                self.checking = false;
                if let Ok(rep) = &r {
                    self.show_verify_original = !rep.has_content;
                }
                self.result = Some(r);
            }
            Msg::Extracted(file, name, r) => match r {
                Ok(d) => self.save_extracted(&file, name, d),
                Err(e) => self.message = Some((e, true)),
            },
        }
    }
}

/// What a key was opened with: file, alias and a hash of the password.
fn key_request(file: &Path, alias: Option<&str>, pw_hash: &str) -> String {
    format!("{}|{}|{pw_hash}", file.display(), alias.unwrap_or(""))
}

/// Noto Sans cut down to Latin and Cyrillic (with Kazakh), and ✔ ✖ ⚠ from Noto Emoji: 51 KB
/// instead of egui's bundled 650 KB of fonts. See assets/README.md.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::empty();
    for (name, data) in [
        ("text", &include_bytes!("../assets/NotoSans-subset.ttf")[..]),
        ("symbols", &include_bytes!("../assets/symbols.ttf")[..]),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(egui::FontData::from_static(data)));
    }
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .insert(family, vec!["text".into(), "symbols".into()]);
    }
    ctx.set_fonts(fonts);
}

#[derive(Default)]
struct PathField {
    text: String,
    /// The path the text was last set from.
    shown: Option<PathBuf>,
}

/// A small button with an eye (crossed out while the password is hidden).
fn eye_button(ui: &mut egui::Ui, open: bool, hint: &str) -> egui::Response {
    let r = ui
        .add_sized([30.0, 22.0], egui::Button::new(""))
        .on_hover_text(hint);
    r.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, open, hint));
    let c = r.rect.center();
    let color = ui.style().interact(&r).fg_stroke.color;
    let stroke = egui::Stroke::new(1.5, color);
    let p = ui.painter();
    // the eye: two arcs meeting at the corners, and the iris
    let (w, h) = (9.0, 5.5);
    let arc = |sign: f32| -> Vec<egui::Pos2> {
        (0..=16)
            .map(|i| {
                let t = i as f32 / 16.0 * std::f32::consts::PI;
                egui::pos2(c.x - w * t.cos(), c.y + sign * h * t.sin())
            })
            .collect()
    };
    p.add(egui::Shape::line(arc(-1.0), stroke));
    p.add(egui::Shape::line(arc(1.0), stroke));
    p.circle_filled(c, 2.6, color);
    if !open {
        p.line_segment(
            [c + egui::vec2(-8.0, 6.5), c + egui::vec2(8.0, -6.5)],
            stroke,
        );
    }
    r
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add_space(2.0);
}

/// The verification report, as shown in the Verify tab.
pub fn report(ui: &mut egui::Ui, r: &VerifyReport) {
    let n = r.signers.len();
    if r.valid {
        let t = trf("✔ Valid. Signatures: {}, all check out.", &[&n]);
        ui.heading(Tone::Good.text(ui, t));
    } else {
        ui.heading(Tone::Bad.text(ui, tr("✖ Not valid (see details)")));
    }
    if let Some(name) = &r.card_document {
        ui.label(trf(
            "Document card. Document inside: {}, {} bytes, SHA-256 {}",
            &[
                name,
                &r.content_size,
                &r.content_sha256.clone().unwrap_or_default(),
            ],
        ));
    } else if r.is_pdf {
        ui.label(trf(
            "Signed PDF: {} bytes, SHA-256 {}",
            &[
                &r.content_size,
                &r.content_sha256.clone().unwrap_or_default(),
            ],
        ));
    } else if r.has_content {
        ui.label(trf(
            "Document inside: {} bytes, SHA-256 {}",
            &[
                &r.content_size,
                &r.content_sha256.clone().unwrap_or_default(),
            ],
        ));
    } else if r.detached_provided {
        ui.label(tr(
            "Detached signature, checked against the original you chose.",
        ));
    }
    for w in &r.warnings {
        ui.label(Tone::Warn.text(ui, format!("⚠ {w}")));
    }
    for s in &r.signers {
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{}. {}", s.index, s.name()))
                    .strong()
                    .size(15.0),
            );
            if s.valid {
                ui.label(Tone::Good.text(ui, tr("VALID")).strong());
            } else {
                ui.label(Tone::Bad.text(ui, tr("NOT VALID")).strong());
            }
        });
        egui::Grid::new(("signer", s.index))
            .num_columns(2)
            .spacing([12.0, 3.0])
            .show(ui, |ui| {
                let mut row = |k: &str, v: String| {
                    ui.label(Tone::Muted.text(ui, k));
                    ui.add(egui::Label::new(v).wrap());
                    ui.end_row();
                };
                if let Some(k) = &s.kind {
                    row(tr("Type"), k.clone());
                }
                for n in &s.notes {
                    row(tr("Covers"), n.clone());
                }
                if let Some(v) = s.get("IIN") {
                    row(tr("IIN"), v.into());
                }
                if let Some(o) = s.get("O") {
                    row(
                        tr("Organization"),
                        format!(
                            "{o}{}",
                            s.get("BIN")
                                .map(|b| trf(" (BIN {})", &[&b]))
                                .unwrap_or_default()
                        ),
                    );
                }
                if let Some(v) = s.get("E") {
                    row(tr("Email"), v.into());
                }
                row(tr("Signed at"), signed_at(s));
                row(
                    tr("Signature"),
                    if s.signature_ok {
                        tr("Matches the document ✔").into()
                    } else {
                        s.signature_error.clone().unwrap_or_default()
                    },
                );
                row(
                    tr("Trust"),
                    format!(
                        "{}{}",
                        if s.chain_ok { "✔ " } else { "✖ " },
                        s.chain_status.clone().unwrap_or("-".into())
                    ),
                );
                row(
                    tr("Revocation"),
                    s.ocsp_status
                        .clone()
                        .unwrap_or_else(|| tr("Not checked").into()),
                );
                row(tr("Algorithm"), s.algorithm.clone().unwrap_or_default());
                row(
                    tr("Certificate"),
                    trf(
                        "serial {}, valid {} – {}",
                        &[
                            &s.serial_hex.clone().unwrap_or_default(),
                            &time::fmt(s.not_before),
                            &time::fmt(s.not_after),
                        ],
                    ),
                );
                row(tr("Issuer"), s.issuer_cn.clone().unwrap_or_default());
            });
        for w in &s.warnings {
            ui.label(Tone::Warn.text(ui, format!("⚠ {w}")));
        }
    }
}

fn card_lang_name(l: CardLang) -> &'static str {
    match l {
        CardLang::Ru => "Русский",
        CardLang::Kk => "Қазақша",
        CardLang::KkRu => "Қазақша / Русский",
    }
}

fn signed_at(s: &SignerReport) -> String {
    let Some(ts) = s.timestamp_time else {
        return trf("{} · signer's own clock", &[&time::fmt(s.signing_time)]);
    };
    let state = if s.timestamp_ok != Some(true) {
        tr(" (INVALID)")
    } else if s.timestamp_trusted == Some(true) {
        " ✔"
    } else {
        tr(" (TSA not trusted)")
    };
    trf(
        "{} · timestamp by {}{}",
        &[
            &time::fmt(Some(ts)),
            &s.timestamp_info.clone().unwrap_or_default(),
            &state,
        ],
    )
}
