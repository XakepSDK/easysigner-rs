//! The desktop window: a start screen with two choices (sign, check), each on its own screen.
//! All crypto runs off the UI thread.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, Color32, RichText};

use crate::i18n::{self, Lang, tr, trf};
use crate::icons::{self, Icon};
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
        let r = RichText::new(t);
        match self {
            Tone::Plain => r,
            Tone::Strong => r.strong(),
            _ => r.color(self.color(ui)),
        }
    }

    /// The tone's colour, for text and icons.
    fn color(self, ui: &egui::Ui) -> Color32 {
        let dark = ui.visuals().dark_mode;
        let rgb = |l: (u8, u8, u8), d: (u8, u8, u8)| {
            let (r, g, b) = if dark { d } else { l };
            Color32::from_rgb(r, g, b)
        };
        match self {
            Tone::Plain => ui.visuals().text_color(),
            Tone::Strong => ui.visuals().strong_text_color(),
            Tone::Good => rgb((0x1a, 0x7f, 0x37), (0x4a, 0xc2, 0x6b)),
            Tone::Bad => rgb((0xc6, 0x28, 0x28), (0xff, 0x7b, 0x72)),
            Tone::Warn => rgb((0x8a, 0x5a, 0x00), (0xe3, 0xb3, 0x41)),
            Tone::Muted => rgb((0x5d, 0x66, 0x73), (0x9a, 0xa4, 0xb0)),
        }
    }
}

/// The accent colour for icons and lines (the theme's link colour, which reads well on its
/// background; filled buttons use the selection colour).
fn accent(ui: &egui::Ui) -> Color32 {
    ui.visuals().hyperlink_color
}

/// File choosers: the system's own, or scripted ones in tests.
pub trait Dialogs {
    /// A file for the file field `field`. A chooser that can't answer at once (Android's)
    /// returns None and hands the file over later through [`Dialogs::poll`].
    fn open(&mut self, field: &'static str, start: Option<&Path>) -> Option<PathBuf>;
    /// The save location; the system dialog asks before replacing a file.
    fn save(&mut self, suggested: &Path) -> Option<PathBuf>;
    /// Called after `path` (from [`Dialogs::save`]) was written.
    fn saved(&mut self, _path: &Path) {}
    /// Shows a saved file: its folder on the desktop, the share sheet on a phone.
    fn reveal(&mut self, path: &Path) {
        show_in_folder(path);
    }
    /// Opens `path` in the system's viewer for its type, to read before signing (Digital Code
    /// Art. 50: the signer sees what they sign). A failure to start the viewer is an error.
    fn view(&mut self, path: &Path) -> Result<(), String> {
        open_with_system(path).map_err(|e| e.to_string())
    }
    /// A folder for files made only to be viewed (a document taken out of a .cms).
    fn view_dir(&self) -> PathBuf {
        std::env::temp_dir().join("kzsigner-view")
    }
    /// Shows or hides the on-screen keyboard.
    fn keyboard(&mut self, _show: bool) {}
    /// What happened since the last frame: chosen files, files opened from other apps.
    fn poll(&mut self) -> Option<DialogEvent> {
        None
    }
}

/// See [`Dialogs::poll`].
pub enum DialogEvent {
    /// A file chosen for the file field with this id.
    Picked(&'static str, PathBuf),
    /// A file opened in kzsigner from another app.
    Open(PathBuf),
    /// A message for the user: (text, is error).
    Message(String, bool),
}

/// The operating system's file dialogs.
#[cfg(not(target_os = "android"))]
pub struct SystemDialogs;

#[cfg(not(target_os = "android"))]
impl Dialogs for SystemDialogs {
    fn open(&mut self, _field: &'static str, start: Option<&Path>) -> Option<PathBuf> {
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
#[cfg(not(target_os = "android"))]
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
            .with_inner_size([780.0, 720.0])
            .with_min_inner_size([620.0, 480.0])
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

#[cfg(not(target_os = "android"))]
struct Window(App);

#[cfg(not(target_os = "android"))]
impl Window {
    fn new(app: App) -> Window {
        Window(app)
    }
}

#[cfg(not(target_os = "android"))]
impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| self.0.ui(ui));
    }
}

/// The screen the window shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// Two big choices: sign or check.
    Start,
    Sign,
    /// What signing made, and where it was saved.
    Signed,
    Check,
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
            ui.add(egui::Label::new(tone.text(ui, t)).wrap());
        }
    }
}

enum Msg {
    DocChecked(u64, Result<(DocKind, Option<VerifyReport>), String>),
    KeyOpened(u64, PathBuf, String, Result<Box<Key>, String>),
    Signed(PathBuf, SignAs, Result<SignResult, String>),
    Verified(u64, Result<VerifyReport, String>),
    /// (file, (suggested name for the saved document, bytes))
    Extracted(PathBuf, Result<(String, Vec<u8>), String>),
    /// A document to read, for the request it answers.
    ToView(ViewFor, Result<PathBuf, String>),
}

/// Which choice a document to read was asked for: the document to sign or the signed file
/// to check, by request number. An answer for an older choice is dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ViewFor {
    Sign(u64),
    Check(u64),
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

/// A finished signing, for the Signed screen.
#[derive(Clone, Debug)]
pub struct Done {
    /// Where the signed file was saved.
    pub saved: PathBuf,
    /// The document's file name.
    pub doc_name: String,
    pub signer: String,
    pub cosigned: bool,
    pub timestamped: bool,
    pub sign_as: SignAs,
    pub detached: bool,
    pub signer_count: usize,
    pub warnings: Vec<String>,
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
    /// A file chosen for a file field (by its id) that the field has not taken yet.
    picked: Option<(&'static str, PathBuf)>,
    keyboard_shown: bool,
    /// A phone-sized window: one column, full-width buttons.
    narrow: bool,
    pub screen: Screen,
    /// A message box: (text, is error).
    pub message: Option<(String, bool)>,
    /// The last signing, shown on the Signed screen.
    pub done: Option<Done>,
    /// The document was opened from the start screen: if it turns out to be signed already,
    /// show the check instead.
    route_signed_to_check: bool,

    // signing
    pub doc: Option<PathBuf>,
    pub sign_original: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub password: String,
    show_password: bool,
    aliases: Vec<String>,
    alias: Option<String>,
    doc_note: Note,
    key_note: Note,
    /// The opened key's holder, for the line under the key.
    key_holder: Option<String>,
    /// The opened key is from a trusted NCA RK issuer and has no warnings.
    key_ok: bool,
    pub detached: bool,
    pub timestamp: bool,
    /// With the timestamp: a long-term signature (B-LTA), checkable after the certificate
    /// expires.
    pub long_term: bool,
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

    // checking
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
            picked: None,
            keyboard_shown: false,
            narrow: false,
            screen: Screen::Start,
            message: None,
            done: None,
            route_signed_to_check: false,
            doc: None,
            sign_original: None,
            key_file: None,
            password: String::new(),
            show_password: false,
            aliases: vec![],
            alias: None,
            doc_note: Note::default(),
            key_note: Note::default(),
            key_holder: None,
            key_ok: false,
            detached: false,
            timestamp: true,
            long_term: true,
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
            ocsp: true,
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
            self.handle(&ctx, m);
        }
        if self.busy > 0 {
            ctx.set_cursor_icon(egui::CursorIcon::Progress);
        }
        if let Some(f) = self.pending_open.take() {
            self.open_file(&ctx, f);
        }
        while let Some(e) = self.dialogs.poll() {
            match e {
                DialogEvent::Picked(field, f) => self.picked = Some((field, f)),
                DialogEvent::Open(f) => self.open_file(&ctx, f),
                DialogEvent::Message(m, error) => self.message = Some((m, error)),
            }
        }
        let typing = ctx.egui_wants_keyboard_input();
        if typing != self.keyboard_shown {
            self.keyboard_shown = typing;
            self.dialogs.keyboard(typing);
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
        self.narrow = ui.available_width() < 600.0;
        self.header(ui);
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.add_space(6.0);
                match self.screen {
                    Screen::Start => self.start_screen(ui),
                    Screen::Sign => self.sign_screen(ui),
                    Screen::Signed => self.signed_screen(ui),
                    Screen::Check => self.check_screen(ui),
                }
            });
        if let Some((text, error)) = self.message.clone() {
            egui::Modal::new(egui::Id::unique("message")).show(&ctx, |ui| {
                ui.set_max_width(460.0);
                let title = if error {
                    Tone::Bad.text(ui, tr("Something went wrong"))
                } else {
                    Tone::Strong.text(ui, "kzsigner")
                };
                ui.label(title.strong().size(16.0));
                ui.add_space(6.0);
                ui.label(text);
                ui.add_space(10.0);
                if ui.add(primary_button(tr("OK"))).clicked() {
                    self.message = None;
                }
            });
        }
    }

    /// Back, the screen's title and the language menu.
    fn header(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.set_min_height(32.0);
            if self.screen == Screen::Start {
                icons::show(ui, Icon::Logo, 26.0, accent(ui));
                ui.label(RichText::new("kzsigner").strong().size(18.0));
            } else {
                let back = if self.narrow {
                    // an icon only, as phones show it
                    let r = ui.add_sized([40.0, 40.0], egui::Button::new("").frame(false));
                    r.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::Role::Button, true, tr("Back"))
                    });
                    let color = ui.style().interact(&r).fg_stroke.color;
                    let rect =
                        egui::Rect::from_center_size(r.rect.center(), egui::vec2(24.0, 24.0));
                    icons::paint(ui.painter(), rect, Icon::Back, color, 2.0);
                    r.on_hover_text(tr("Back"))
                } else {
                    icons::button(
                        ui,
                        Icon::Back,
                        tr("Back"),
                        15.0,
                        egui::vec2(0.0, 30.0),
                        false,
                    )
                };
                if back.clicked() {
                    self.screen = Screen::Start;
                }
                let title = match self.screen {
                    Screen::Check => tr("Check a signed file"),
                    _ => tr("Sign a document"),
                };
                ui.add_space(8.0);
                ui.label(RichText::new(title).strong().size(18.0));
            }
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
    }

    // ------------------------------------------------------------------ Start

    fn start_screen(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.label(
            RichText::new(tr("What do you want to do?"))
                .size(22.0)
                .strong(),
        );
        ui.add_space(14.0);
        let sign = |ui: &mut egui::Ui| {
            let c = accent(ui);
            choice_card(
                ui,
                "start_sign",
                tr("Sign a document"),
                tr(
                    "Put your electronic signature (ЭЦП) on a contract, a letter or any other file.",
                ),
                true,
                (Icon::Pen, c),
            )
        };
        let check = |ui: &mut egui::Ui| {
            let c = Tone::Good.color(ui);
            choice_card(
                ui,
                "start_check",
                tr("Check a signed file"),
                tr(
                    "See who signed it and when, and whether it was changed. Get the document out of a .cms file.",
                ),
                false,
                (Icon::ShieldCheck, c),
            )
        };
        if self.narrow {
            if sign(ui).clicked() {
                self.screen = Screen::Sign;
            }
            ui.add_space(12.0);
            if check(ui).clicked() {
                self.screen = Screen::Check;
            }
        } else {
            ui.columns(2, |cols| {
                let left = egui::Layout::top_down(egui::Align::Min);
                if cols[0].with_layout(left, sign).inner.clicked() {
                    self.screen = Screen::Sign;
                }
                if cols[1].with_layout(left, check).inner.clicked() {
                    self.screen = Screen::Check;
                }
            });
        }
        ui.add_space(18.0);
        card(ui, |ui| {
            if cfg!(target_os = "android") {
                ui.horizontal_top(|ui| {
                    icons::show(ui, Icon::Share, 24.0, Tone::Muted.color(ui));
                    ui.vertical(|ui| {
                        ui.label(RichText::new(tr("Got a file in Telegram, WhatsApp or e-mail?")).strong());
                        ui.add(egui::Label::new(Tone::Muted.text(
                            ui,
                            tr("Tap Share or Open with on the file, then choose kzsigner. It opens in the right place."),
                        )).wrap());
                    });
                });
                return;
            }
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                icons::show(ui, Icon::Download, 28.0, Tone::Muted.color(ui));
                ui.add_space(4.0);
                ui.label(RichText::new(tr("Or drop a file onto this window")).size(16.0));
                ui.add_space(4.0);
                ui.label(Tone::Muted.text(
                    ui,
                    tr("A document opens for signing, a signed file is checked, and a key file (.p12) is remembered for signing."),
                ));
                ui.add_space(12.0);
            });
        });
    }

    // ------------------------------------------------------------------ Sign

    fn sign_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card(ui, |ui| {
            step(ui, tr("1 · Document"));
            if let Some(d) = self.doc.clone() {
                file_title(ui, &d);
                if icons::button(
                    ui,
                    Icon::Open,
                    tr("Open the document"),
                    14.0,
                    egui::vec2(0.0, 32.0),
                    false,
                )
                .on_hover_text(tr(
                    "Read it before you sign: it opens in the program your computer uses for it.",
                ))
                .clicked()
                {
                    self.view_doc(&ctx, d);
                }
            }
            let doc = self.doc.clone();
            if let Some(f) = self.file_field(ui, "doc", tr("Document to sign"), &doc) {
                self.set_doc(&ctx, f);
            }
            self.doc_note.show(ui);
            if self.doc_is_detached_cms {
                ui.add_space(4.0);
                let o = self.sign_original.clone();
                if let Some(f) = self.file_field(
                    ui,
                    "sign_original",
                    tr("This signature file does not contain the document. Choose the signed document:"),
                    &o,
                ) {
                    self.sign_original = Some(f);
                }
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            step(ui, tr("2 · Your signature key"));
            let kf = self.key_file.clone();
            if let Some(f) = self.file_field(
                ui,
                "key",
                tr("Key file (.p12), for example GOSTKNCA_… or RSA_…"),
                &kf,
            ) {
                self.set_key_file(&ctx, f);
            }
            ui.horizontal(|ui| {
                let l = ui.label(tr("Password"));
                let r = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.show_password)
                            .desired_width(if self.narrow {
                                // room for the eye button beside it
                                let eye = ui.spacing().interact_size.y.max(22.0) + 8.0;
                                (ui.available_width() - eye - ui.spacing().item_spacing.x).max(80.0)
                            } else {
                                240.0
                            }),
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
                    ui.label(tr("Key in the file:"));
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
            if self.key.is_some() {
                let tone = if self.key_ok { Tone::Good } else { Tone::Warn };
                banner(ui, tone, |ui| self.key_note.show(ui));
            } else {
                self.key_note.show(ui);
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            step(ui, tr("3 · How to save the signed document"));
            self.how_to_save(ui);
        });
        ui.add_space(12.0);
        let can_sign = !self.signing
            && self.doc.is_some()
            && self.key.is_some()
            && (!self.doc_is_detached_cms || self.sign_original.is_some());
        let label = if self.signing {
            tr("Signing…")
        } else {
            tr("Sign")
        };
        let hint = if self.doc.is_none() {
            tr("Choose the document first.")
        } else if self.key.is_none() {
            tr("Choose your key file and type its password.")
        } else if self.doc_is_detached_cms && self.sign_original.is_none() {
            tr("Choose the signed document.")
        } else {
            ""
        };
        if self.narrow {
            let w = ui.available_width();
            let clicked = ui
                .add_enabled_ui(can_sign, |ui| {
                    icons::button(ui, Icon::Pen, label, 17.0, egui::vec2(w, 52.0), true)
                })
                .inner
                .clicked();
            if clicked {
                self.sign(&ctx);
            }
            if !hint.is_empty() {
                ui.vertical_centered(|ui| ui.label(Tone::Muted.text(ui, hint)));
            }
            ui.add_space(8.0);
        } else {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let clicked = ui
                        .add_enabled_ui(can_sign, |ui| {
                            icons::button(ui, Icon::Pen, label, 16.0, egui::vec2(120.0, 38.0), true)
                        })
                        .inner
                        .clicked();
                    if clicked {
                        self.sign(&ctx);
                    }
                    ui.label(Tone::Muted.text(ui, hint));
                });
            });
        }
    }

    /// The three ways to sign, and their options.
    fn how_to_save(&mut self, ui: &mut egui::Ui) {
        let kind = self.doc_kind;
        // a signed file keeps its own kind: a .cms gets another .cms signature, and so on
        let locked = matches!(kind, DocKind::Cms | DocKind::Card | DocKind::SignedPdf);
        let pdf_ok = matches!(kind, DocKind::Pdf | DocKind::SignedPdf);
        let options = [
            (
                SignAs::Cms,
                tr("Signature file"),
                tr("Saves a .cms file, like NCALayer and eGov. Recommended."),
                !locked || kind == DocKind::Cms,
            ),
            (
                SignAs::Pdf,
                tr("Inside the PDF"),
                tr("Still opens as a normal PDF. Only for PDF files."),
                pdf_ok && (!locked || kind == DocKind::SignedPdf),
            ),
            (
                SignAs::Card,
                tr("Printable card"),
                tr("A PDF that shows the document and who signed it, to print or send."),
                !locked || kind == DocKind::Card,
            ),
        ];
        // the three boxes as tall as the tallest one was on the last frame
        let height_id = egui::Id::unique("how_to_save_height");
        let height = ui
            .ctx()
            .data(|d| d.get_temp::<f32>(height_id))
            .unwrap_or(60.0);
        let mut tallest: f32 = 0.0;
        let narrow = self.narrow;
        let sign_as = &mut self.sign_as;
        let mut option =
            |ui: &mut egui::Ui,
             i: usize,
             (value, title, desc, enabled): (SignAs, &str, &str, bool)| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    let id = ui.scope_id().with(("how", i));
                    let hovered =
                        enabled && ui.ctx().read_response(id).is_some_and(|r| r.hovered());
                    let v = ui.visuals();
                    let stroke = if *sign_as == value {
                        egui::Stroke::new(2.0, v.selection.bg_fill)
                    } else if hovered {
                        egui::Stroke::new(1.0, v.widgets.hovered.fg_stroke.color)
                    } else {
                        v.widgets.noninteractive.bg_stroke
                    };
                    let frame = egui::Frame::new()
                        .stroke(stroke)
                        .corner_radius(10.0)
                        .inner_margin(if narrow { 12.0 } else { 10.0 })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if !narrow {
                                ui.set_min_height(height);
                            }
                            ui.add_enabled_ui(enabled, |ui| {
                                ui.vertical(|ui| {
                                    ui.radio_value(sign_as, value, RichText::new(title).strong());
                                    ui.add(
                                        egui::Label::new(Tone::Muted.text(ui, desc).size(12.5))
                                            .wrap()
                                            .selectable(false),
                                    );
                                })
                                .response
                                .rect
                                .height()
                            })
                            .inner
                        });
                    tallest = tallest.max(frame.inner);
                    // the whole box picks the option, not only its radio button
                    let r = ui.interact(frame.response.rect, id, egui::Sense::click());
                    if enabled {
                        if r.clicked() {
                            *sign_as = value;
                        }
                        if r.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                    }
                });
            };
        if narrow {
            for (i, o) in options.into_iter().enumerate() {
                option(ui, i, o);
                ui.add_space(4.0);
            }
        } else {
            ui.columns(3, |cols| {
                for (i, o) in options.into_iter().enumerate() {
                    option(&mut cols[i], i, o);
                }
            });
        }
        if (tallest - height).abs() > 0.5 {
            ui.ctx().data_mut(|d| d.insert_temp(height_id, tallest));
            ui.ctx().request_repaint();
        }
        ui.add_space(6.0);
        if self.sign_as == SignAs::Card && kind != DocKind::Card {
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
        egui::CollapsingHeader::new(tr("More options"))
            .id_salt("more_options")
            .show(ui, |ui| {
                if self.sign_as == SignAs::Card {
                    ui.add_enabled(
                        false,
                        egui::Checkbox::new(
                            &mut true,
                            tr("Official signing time and key check from NCA (always on a card; needs internet)"),
                        ),
                    );
                    if kind != DocKind::Card {
                        ui.checkbox(
                            &mut self.card_qr,
                            tr("Also print the signatures as QR codes"),
                        );
                    }
                } else {
                    ui.checkbox(
                        &mut self.timestamp,
                        tr("Add the official signing time from NCA (needs internet; only a fingerprint of the document is sent)"),
                    );
                    ui.add_enabled(
                        self.timestamp,
                        egui::Checkbox::new(
                            &mut self.long_term,
                            tr("Keep it checkable for years: store NCA's revocation answers in the signature and add an archive timestamp (long-term signature)"),
                        ),
                    );
                }
                if self.sign_as == SignAs::Cms {
                    ui.add_enabled(
                        !self.doc_is_cms,
                        egui::Checkbox::new(
                            &mut self.detached,
                            tr("Keep the document out of the signature file (then send both files together)"),
                        ),
                    );
                }
            });
    }

    // ------------------------------------------------------------------ Signed

    fn signed_screen(&mut self, ui: &mut egui::Ui) {
        let Some(d) = self.done.clone() else {
            self.screen = Screen::Start;
            return;
        };
        ui.vertical_centered(|ui| {
            ui.add_space(24.0);
            let good = Tone::Good.color(ui);
            icons::badge(ui, Icon::Check, 80.0, good, good.gamma_multiply(0.14));
            ui.add_space(6.0);
            ui.label(
                RichText::new(if d.cosigned {
                    tr("Signature added")
                } else {
                    tr("Signed")
                })
                .size(24.0)
                .strong(),
            );
            ui.add_space(6.0);
            let when = if d.timestamped {
                tr("The signing time is confirmed by NCA.")
            } else {
                tr("The signing time comes from this computer's clock.")
            };
            ui.add(
                egui::Label::new(format!(
                    "{} {}",
                    trf("{} is signed by {}.", &[&d.doc_name, &d.signer]),
                    when
                ))
                .wrap(),
            );
            if d.signer_count > 1 {
                ui.label(trf("Signatures in the file now: {}", &[&d.signer_count]));
            }
            ui.add_space(12.0);
        });
        card(ui, |ui| {
            file_title_with(ui, &d.saved, Icon::FileCheck);
            // on Android the file is in the app's own folder until Android's Save as or Share
            // takes it somewhere the user can see
            if !cfg!(target_os = "android") {
                ui.label(
                    Tone::Muted.text(
                        ui,
                        trf(
                            "Saved in {}",
                            &[&d.saved
                                .parent()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default()],
                        ),
                    ),
                );
            }
            let what = match d.sign_as {
                SignAs::Cms if d.detached => tr(
                    "Send this .cms file together with the document: it holds only your signature.",
                ),
                SignAs::Cms => {
                    tr("Send this .cms file: it holds both the document and your signature.")
                }
                SignAs::Pdf => {
                    tr("This PDF opens in any PDF viewer and carries your signature inside it.")
                }
                SignAs::Card => tr(
                    "This PDF shows the document and its signatures; the original file and the signatures are attached inside it.",
                ),
            };
            ui.add(egui::Label::new(what).wrap());
        });
        for w in &d.warnings {
            warning(ui, w);
        }
        ui.add_space(14.0);
        let android = cfg!(target_os = "android");
        action_row(ui, self.narrow, |ui, size, min| {
            let (icon, reveal) = if android {
                (Icon::Share, tr("Share"))
            } else {
                (Icon::Folder, tr("Show in folder"))
            };
            if icons::button(ui, icon, reveal, size, min, true).clicked() {
                self.dialogs.reveal(&d.saved);
            }
            if android
                && icons::button(
                    ui,
                    Icon::Download,
                    tr("Save to the phone…"),
                    size,
                    min,
                    false,
                )
                .clicked()
            {
                self.dialogs.saved(&d.saved);
            }
            if icons::button(ui, Icon::Pen, tr("Sign another document"), size, min, false).clicked()
            {
                self.doc = None;
                self.doc_note = Note::default();
                self.doc_kind = DocKind::Other;
                self.doc_is_cms = false;
                self.doc_is_detached_cms = false;
                self.sign_original = None;
                self.screen = Screen::Sign;
            }
        });
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
        let mut chosen = match self.picked.take() {
            Some((f, p)) if f == id => Some(p),
            other => {
                self.picked = other;
                None
            }
        };
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
        if cfg!(target_os = "android") {
            // a phone has no paths to type: one big button opens Android's file chooser
            let w = ui.available_width();
            let text = if current.is_some() {
                tr("Choose another…")
            } else {
                tr("Choose a file…")
            };
            // the document fields show their file in a title above; the others show it here
            if let Some(c) = current
                && !matches!(id, "doc" | "cms")
            {
                file_title(ui, c);
            }
            if icons::button(ui, Icon::File, text, 15.0, egui::vec2(w, 44.0), false)
                .labelled_by(l.id)
                .clicked()
            {
                chosen = dialogs.open(id, current.as_deref());
            }
            return chosen;
        }
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
                chosen = dialogs.open(id, current.as_deref());
            }
        });
        chosen
    }

    /// A dropped or command-line file: a key goes to the key field, a signed file is checked
    /// (unless a document is being signed, where it is co-signed), anything else is signed.
    /// (A PDF is signed: it may be a document to sign, a signed PDF or a card.)
    pub fn open_file(&mut self, ctx: &egui::Context, f: PathBuf) {
        let ext = f
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext == "p12" || ext == "pfx" {
            if self.screen != Screen::Sign {
                self.screen = Screen::Sign;
            }
            self.set_key_file(ctx, f);
        } else if self.screen == Screen::Check || (self.screen != Screen::Sign && ext == "cms") {
            self.screen = Screen::Check;
            self.set_cms(ctx, f);
        } else {
            self.route_signed_to_check = self.screen == Screen::Start;
            self.screen = Screen::Sign;
            self.set_doc(ctx, f);
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

    /// Opens the document to sign for reading: the file itself, or the document inside a
    /// signed file (a .cms or a card), taken out into a private temporary folder. For a
    /// detached .cms, the original chosen beside it.
    pub fn view_doc(&mut self, ctx: &egui::Context, doc: PathBuf) {
        let original = self.sign_original.clone();
        self.view_file(ctx, doc, original, ViewFor::Sign(self.doc_request));
    }

    /// Opens `doc` for reading, or the document inside it when it is signed (`original` for a
    /// detached .cms). `id`: the choice it is for.
    fn view_file(
        &mut self,
        ctx: &egui::Context,
        doc: PathBuf,
        original: Option<PathBuf>,
        id: ViewFor,
    ) {
        let dir = self.dialogs.view_dir();
        self.background(ctx, move |e| {
            let r = (|| -> Result<PathBuf, String> {
                let data =
                    std::fs::read(&doc).map_err(|err| format!("{}: {err}", doc.display()))?;
                // what the file is, from its content (the background check may still be running)
                let signed = e.is_signed_cms(&data) || e.card_original(&data).is_some();
                if !signed {
                    return Ok(doc);
                }
                let (name, content) = match taken_out(e, &doc, &data) {
                    Ok(x) => x,
                    // detached: the document is the original chosen beside it
                    Err(_) if e.is_signed_cms(&data) => {
                        return original.ok_or_else(|| tr("Choose the signed document.").into());
                    }
                    Err(err) => return Err(err),
                };
                write_for_viewing(&dir, &viewable_name(&name, &content), &content)
            })();
            Msg::ToView(id, r)
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
        if let Some(e) = &s.usage_error {
            n.push((trf("This key may not sign documents: {}", &[e]), Tone::Bad));
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
        let long_term = self.timestamp && self.long_term && self.sign_as != SignAs::Card;
        // online anyway for the timestamp: check that the key is not revoked too (p.4),
        // unless online checks are turned off
        let ocsp = (self.timestamp && self.ocsp).then(|| DEFAULT_OCSP_URL.to_string());
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
                let r = match sign_as {
                    SignAs::Cms => e.sign(
                        &input,
                        &key,
                        det,
                        tsa.as_deref(),
                        ocsp.as_deref(),
                        true,
                        o.as_deref(),
                    ),
                    SignAs::Pdf => e.sign_pdf(&input, &key, tsa.as_deref(), ocsp.as_deref()),
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
                .map_err(|x| x.0)?;
                if !long_term {
                    return Ok(r);
                }
                // the document a detached .cms signs
                let doc = if det { Some(&input) } else { o.as_ref() };
                e.extend_new(
                    r,
                    doc.map(Vec::as_slice),
                    crate::ltv::Level::Lta,
                    DEFAULT_TSA_URL,
                    DEFAULT_OCSP_URL,
                )
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
        self.dialogs.saved(&out);
        let doc_name = doc
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.done = Some(Done {
            saved: out,
            doc_name,
            signer: self.key_holder.clone().unwrap_or_default(),
            cosigned: r.cosigned,
            timestamped: r.timestamped || sign_as == SignAs::Card,
            sign_as,
            detached: sign_as == SignAs::Cms && self.detached && !self.doc_is_cms,
            signer_count: r.signer_count,
            warnings: r.warnings,
        });
        self.screen = Screen::Signed;
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

    // ------------------------------------------------------------------ Check

    fn check_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card(ui, |ui| {
            if let Some(c) = &self.cms {
                file_title(ui, c);
            }
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
                    tr("This signature file does not contain the document. Choose the signed document:"),
                    &o,
                ) {
                    self.verify_original = Some(f);
                    self.verify(&ctx);
                }
            }
            egui::CollapsingHeader::new(tr("More options"))
                .id_salt("check_options")
                .show(ui, |ui| {
                    if ui
                        .checkbox(
                            &mut self.ocsp,
                            tr("Check online that the signers' keys were not revoked (needs internet)"),
                        )
                        .changed()
                        && self.cms.is_some()
                    {
                        self.verify(&ctx);
                    }
                });
        });
        ui.add_space(10.0);
        if self.checking {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr("Checking…"));
            });
            return;
        }
        match &self.result {
            Some(Ok(r)) => {
                let r = r.clone();
                report(ui, &r);
                let can_extract = r.has_content && !r.is_pdf;
                // a detached signature has nothing to show until its original is chosen
                let can_view = r.has_content || r.is_pdf || self.verify_original.is_some();
                ui.add_space(10.0);
                action_row(ui, self.narrow, |ui, size, min| {
                    // the main action only when the document can be trusted
                    if can_view
                        && icons::button(
                            ui,
                            Icon::Open,
                            tr("Open the document"),
                            size,
                            min,
                            r.valid,
                        )
                        .clicked()
                        && let Some(c) = self.cms.clone()
                    {
                        let o = self.verify_original.clone();
                        self.view_file(&ctx, c, o, ViewFor::Check(self.verify_request));
                    }
                    if can_extract
                        && icons::button(
                            ui,
                            Icon::Download,
                            tr("Save the document…"),
                            size,
                            min,
                            false,
                        )
                        .clicked()
                    {
                        self.extract(&ctx);
                    }
                });
            }
            Some(Err(e)) => {
                let e = e.clone();
                banner(ui, Tone::Bad, |ui| {
                    ui.label(
                        RichText::new(tr("This file could not be checked"))
                            .strong()
                            .size(18.0),
                    );
                    ui.add(egui::Label::new(e).wrap());
                });
            }
            None => {
                ui.label(Tone::Muted.text(
                    ui,
                    tr("Choose a signed file above, or drop it onto this window."),
                ));
            }
        }
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
            let r = std::fs::read(&file)
                .map_err(|err| format!("{}: {err}", file.display()))
                .and_then(|d| taken_out(e, &file, &d));
            Msg::Extracted(file, r)
        });
    }

    fn save_extracted(&mut self, file: &Path, base: String, data: Vec<u8>) {
        let Some(out) = self.dialogs.save(&file.with_file_name(base)) else {
            return;
        };
        self.message = Some(match std::fs::write(&out, &data) {
            // Android's own "Save as" comes next and says where it went
            Ok(()) if cfg!(target_os = "android") => {
                self.dialogs.saved(&out);
                return;
            }
            Ok(()) => (
                trf("Saved {} bytes to\n{}", &[&data.len(), &out.display()]),
                false,
            ),
            Err(e) => (trf("Could not save: {}", &[&e]), true),
        });
    }

    // ------------------------------------------------------------------ results

    fn handle(&mut self, ctx: &egui::Context, m: Msg) {
        match m {
            Msg::DocChecked(id, r) => {
                if id != self.doc_request {
                    return;
                }
                let route = std::mem::take(&mut self.route_signed_to_check);
                if route
                    && matches!(
                        &r,
                        Ok((DocKind::Cms | DocKind::SignedPdf | DocKind::Card, _))
                    )
                    && let Some(f) = self.doc.take()
                {
                    // a signed file opened from the start: the person most likely wants to see
                    // who signed it (adding a signature is one click away, from Sign)
                    self.screen = Screen::Check;
                    self.doc_note = Note::default();
                    self.set_cms(ctx, f);
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
                        let d = self.engine.describe(&k.cert);
                        self.key_holder = Some(d.name());
                        self.key_ok = d.chain_ok
                            && d.usage_error.is_none()
                            && self.engine.key_warnings(&k.cert).is_empty();
                        self.alias = Some(k.alias.clone());
                        self.opened_for = Some(key_request(&f, Some(&k.alias), &pw_hash));
                        self.key = Some(Arc::new(*k));
                    }
                    Err(e) => {
                        self.key_holder = None;
                        self.key_note = Note::error(&e);
                    }
                }
            }
            Msg::Signed(doc, sign_as, r) => {
                self.signing = false;
                match r {
                    Ok(r) => self.save_signed(&doc, sign_as, r),
                    Err(e) => {
                        // NCA's time (on by default) and a card's key check need the internet
                        let offline_hint =
                            e.contains(DEFAULT_TSA_URL) || e.contains(DEFAULT_OCSP_URL);
                        let e = if offline_hint && sign_as == SignAs::Card {
                            format!(
                                "{e}\n\n{}",
                                tr(
                                    "A printable card needs the internet: it gets the official time and the key check from NCA. Check the connection and try again, or save a signature file instead."
                                )
                            )
                        } else if offline_hint {
                            format!(
                                "{e}\n\n{}",
                                tr(
                                    "Getting the official time from NCA needs the internet. Check the connection and try again, or turn off the NCA time under More options."
                                )
                            )
                        } else {
                            e
                        };
                        self.message = Some((e, true));
                    }
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
            Msg::Extracted(file, r) => match r {
                Ok((name, d)) => self.save_extracted(&file, name, d),
                Err(e) => self.message = Some((e, true)),
            },
            // another document has been chosen since: don't show the old one
            Msg::ToView(ViewFor::Sign(id), _) if id != self.doc_request => {}
            Msg::ToView(ViewFor::Check(id), _) if id != self.verify_request => {}
            Msg::ToView(_, r) => {
                if let Err(e) = r.and_then(|f| self.dialogs.view(&f)) {
                    self.message = Some((trf("Could not open the document: {}", &[&e]), true));
                }
            }
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
    let h = ui.spacing().interact_size.y.max(22.0);
    let r = ui
        .add_sized([h + 8.0, h], egui::Button::new(""))
        .on_hover_text(hint);
    r.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, open, hint));
    let color = ui.style().interact(&r).fg_stroke.color;
    let rect = egui::Rect::from_center_size(r.rect.center(), egui::Vec2::splat(h * 0.8));
    let icon = if open { Icon::Eye } else { Icon::EyeOff };
    icons::paint(ui.painter(), rect, icon, color, 2.0);
    r
}

/// A rounded panel around a group of fields.
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let v = ui.visuals();
    egui::Frame::new()
        .fill(v.faint_bg_color)
        .stroke(v.widgets.noninteractive.bg_stroke)
        .corner_radius(10.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 6.0;
            add(ui)
        })
        .inner
}

/// A coloured box for a verdict or an opened key.
fn banner<R>(ui: &mut egui::Ui, tone: Tone, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let dark = ui.visuals().dark_mode;
    let (fill, stroke) = match (tone, dark) {
        (Tone::Good, false) => ((0xea, 0xf5, 0xee), (0xb9, 0xdc, 0xc6)),
        (Tone::Good, true) => ((0x16, 0x2e, 0x20), (0x2c, 0x5a, 0x3e)),
        (Tone::Bad, false) => ((0xfc, 0xec, 0xea), (0xef, 0xc3, 0xbc)),
        (Tone::Bad, true) => ((0x3a, 0x1d, 0x1a), (0x6e, 0x33, 0x2b)),
        (_, false) => ((0xfd, 0xf5, 0xe1), (0xe8, 0xd3, 0x9a)),
        (_, true) => ((0x36, 0x2c, 0x12), (0x66, 0x55, 0x22)),
    };
    let c = |(r, g, b): (u8, u8, u8)| Color32::from_rgb(r, g, b);
    egui::Frame::new()
        .fill(c(fill))
        .stroke(egui::Stroke::new(1.0, c(stroke)))
        .corner_radius(10.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A row of a screen's actions: side by side, or on a phone one under another at full width.
/// `add` gets the text size and the least size for each button.
fn action_row(ui: &mut egui::Ui, narrow: bool, add: impl FnOnce(&mut egui::Ui, f32, egui::Vec2)) {
    if narrow {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 10.0;
            let w = ui.available_width();
            add(ui, 17.0, egui::vec2(w, 52.0))
        });
    } else {
        ui.horizontal(|ui| add(ui, 15.0, egui::vec2(0.0, 38.0)));
    }
}

/// A warning line, with the warning sign.
fn warning(ui: &mut egui::Ui, text: &str) {
    ui.horizontal_top(|ui| {
        icons::show(ui, Icon::Warning, 18.0, Tone::Warn.color(ui));
        ui.add(egui::Label::new(Tone::Warn.text(ui, text)).wrap());
    });
}

/// A step's heading inside a card.
fn step(ui: &mut egui::Ui, title: &str) {
    ui.label(Tone::Muted.text(ui, title).strong().size(13.5));
}

/// The main action of a screen.
fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).size(16.0).strong())
        .min_size(egui::vec2(120.0, 38.0))
}

/// A big clickable choice with an icon, a title and a line of explanation.
fn choice_card(
    ui: &mut egui::Ui,
    id: &str,
    title: &str,
    text: &str,
    first: bool,
    (icon, color): (Icon, Color32),
) -> egui::Response {
    let v = ui.visuals().clone();
    let id = ui.scope_id().with(id);
    let hovered = ui.ctx().read_response(id).is_some_and(|r| r.hovered());
    let stroke = if hovered || first {
        egui::Stroke::new(2.0, v.selection.bg_fill)
    } else {
        v.widgets.noninteractive.bg_stroke
    };
    let inner = egui::Frame::new()
        .fill(v.faint_bg_color)
        .stroke(stroke)
        .corner_radius(14.0)
        .inner_margin(18.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(96.0);
            ui.horizontal_top(|ui| {
                icons::badge(ui, icon, 52.0, color, color.gamma_multiply(0.14));
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(title).size(19.0).strong())
                            .selectable(false),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(Tone::Muted.text(ui, text).size(14.0))
                            .wrap()
                            .selectable(false),
                    );
                });
            });
        });
    let r = ui.interact(inner.response.rect, id, egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, title));
    if r.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    r
}

/// A chosen file: its name large, its folder small.
fn file_title(ui: &mut egui::Ui, f: &Path) {
    file_title_with(ui, f, Icon::File);
}

fn file_title_with(ui: &mut egui::Ui, f: &Path, icon: Icon) {
    let name = f
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| f.display().to_string());
    ui.horizontal(|ui| {
        icons::show(ui, icon, 24.0, Tone::Muted.color(ui));
        ui.add(egui::Label::new(RichText::new(name).size(16.0).strong()).truncate());
    });
}

/// The name for the document taken out of signed `file`: a card's document keeps its own name
/// (only the name, never a path inside the card), "x.pdf.cms" gives "x.pdf", anything else
/// "<name>.original".
fn original_name(file: &Path, card_name: Option<&str>) -> String {
    let n = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let card_name = card_name
        .and_then(|n| n.rsplit(['/', '\\']).next())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..");
    if let Some(c) = card_name {
        c.to_string()
    } else if n.to_lowercase().ends_with(".cms") {
        n[..n.len() - 4].to_string()
    } else {
        format!("{n}.original")
    }
}

/// The document inside a signed file (a card's original, or a .cms's content), with its name.
fn taken_out(e: &Engine, file: &Path, data: &[u8]) -> Result<(String, Vec<u8>), String> {
    match e.card_original(data) {
        Some((name, d)) => Ok((original_name(file, Some(&name)), d)),
        None => Ok((original_name(file, None), e.extract(data).map_err(|x| x.0)?)),
    }
}

/// `name` with an extension a viewer understands, guessed from the content when it has none
/// that helps ("contract" from contract.cms holding a PDF gives "contract.pdf").
fn viewable_name(name: &str, data: &[u8]) -> String {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase());
    if ext.is_some_and(|e| e != "original") {
        return name.to_string();
    }
    let guess = if data.starts_with(b"%PDF") {
        "pdf"
    } else if data.starts_with(b"\x89PNG") {
        "png"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "jpg"
    } else if data.starts_with(b"PK\x03\x04") {
        "zip"
    } else if std::str::from_utf8(data).is_ok() {
        "txt"
    } else {
        return name.to_string();
    };
    format!("{name}.{guess}")
}

/// Writes `data` as `name` in a fresh folder under `dir`, readable only by this user; copies
/// made for earlier viewing are removed first.
fn write_for_viewing(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf, String> {
    let fail = |p: &Path, err: std::io::Error| format!("{}: {err}", p.display());
    // a viewer may still hold an old copy open (Windows): then it stays until next time
    let _ = std::fs::remove_dir_all(dir);
    let sub = dir.join(time::now_ms().to_string());
    std::fs::create_dir_all(&sub).map_err(|err| fail(&sub, err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [dir, sub.as_path()] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| fail(d, err))?;
        }
    }
    let out = sub.join(name);
    std::fs::write(&out, data).map_err(|err| fail(&out, err))?;
    Ok(out)
}

/// Opens `f` with the program the system uses for its type.
fn open_with_system(f: &Path) -> std::io::Result<()> {
    // the shell's own file handler: no command line parsing of the path (explorer splits
    // at commas)
    #[cfg(windows)]
    let child = std::process::Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(f)
        .spawn()?;
    #[cfg(target_os = "macos")]
    let child = std::process::Command::new("open").arg(f).spawn()?;
    #[cfg(not(any(windows, target_os = "macos")))]
    let child = std::process::Command::new("xdg-open").arg(f).spawn()?;
    // reap it when it ends
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Ok(())
}

/// Opens the folder with `f` in the system's file manager.
fn show_in_folder(f: &Path) {
    // explorer wants /select,"C:\a b\c.cms" as one argument, quoted only around the path
    #[cfg(windows)]
    let r = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer")
            .raw_arg(format!("/select,\"{}\"", f.display()))
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg("-R").arg(f).spawn();
    #[cfg(not(any(windows, target_os = "macos")))]
    let r = std::process::Command::new("xdg-open")
        .arg(f.parent().unwrap_or(Path::new(".")))
        .spawn();
    let _ = r;
}

/// The main reason a check failed, in a sentence.
fn failure_reason(r: &VerifyReport) -> String {
    let Some(s) = r.signers.iter().find(|s| !s.valid) else {
        return r
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| tr("This file has no signatures.").into());
    };
    if !s.signature_ok {
        return s
            .signature_error
            .clone()
            .unwrap_or_else(|| tr("The document was changed after it was signed.").into());
    }
    if s.cert_valid_at_signing == Some(false) {
        if s.trusted_time().is_some() {
            return tr("The signer's key was not valid when the document was signed (expired, or not yet valid).").into();
        }
        return tr("The signer's key is not valid now, and the signature has no trusted timestamp that would show it was valid when the document was signed.").into();
    }
    if !s.chain_ok {
        return trf(
            "The signer's key was not issued by NCA RK: {}",
            &[&s.chain_status.clone().unwrap_or_default()],
        );
    }
    if let Some(e) = &s.usage_error {
        return trf("The signer's key may not sign documents: {}", &[e]);
    }
    if let Some(o) = &s.ocsp_status {
        return trf("The signer's key check failed: {}", &[o]);
    }
    tr("A signature failed the checks; see the details below.").into()
}

/// Every failing signature is otherwise fine and only lacks a revocation answer (no network,
/// or the OCSP server could not be used): a warning, not a verdict against the document.
fn revocation_unchecked(r: &VerifyReport) -> bool {
    let failing: Vec<&SignerReport> = r.signers.iter().filter(|s| !s.valid).collect();
    !failing.is_empty()
        && failing.iter().all(|s| {
            s.signature_ok
                && s.chain_ok
                && s.usage_error.is_none()
                && s.timestamp_ok != Some(false)
                && s.cert_valid_at_signing != Some(false)
                && s.ocsp_answer == Some("")
        })
}

/// The result of a check: a verdict, then each signer.
pub fn report(ui: &mut egui::Ui, r: &VerifyReport) {
    let n = r.signers.len();
    if r.valid {
        banner(ui, Tone::Good, |ui| {
            let title = if n == 1 {
                tr("The signature is valid").to_string()
            } else {
                trf("All {} signatures are valid", &[&n])
            };
            verdict(ui, Icon::ShieldCheck, Tone::Good, &title);
            let text = if r.card_document.is_some() {
                tr(
                    "The document inside the card has not been changed since it was signed, and the keys were issued by NCA RK.",
                )
            } else {
                tr(
                    "The document has not been changed since it was signed, and the keys were issued by NCA RK.",
                )
            };
            ui.add(egui::Label::new(text).wrap());
        });
    } else if revocation_unchecked(r) {
        banner(ui, Tone::Warn, |ui| {
            verdict(
                ui,
                Icon::Warning,
                Tone::Warn,
                tr("Valid, but not checked for revocation"),
            );
            ui.add(
                egui::Label::new(tr(
                    "The document has not been changed and the keys were issued by NCA RK, but NCA's revocation service could not be reached, so it is not known whether a key was revoked. Check the internet connection and open the file again.",
                ))
                .wrap(),
            );
        });
    } else {
        banner(ui, Tone::Bad, |ui| {
            verdict(
                ui,
                Icon::XCircle,
                Tone::Bad,
                tr("Do not trust this document"),
            );
            ui.add(egui::Label::new(failure_reason(r)).wrap());
        });
    }
    for w in &r.warnings {
        warning(ui, w);
    }
    for s in &r.signers {
        ui.add_space(8.0);
        card(ui, |ui| signer(ui, r, s));
    }
}

/// A verdict's title with its icon.
fn verdict(ui: &mut egui::Ui, icon: Icon, tone: Tone, title: &str) {
    ui.horizontal(|ui| {
        icons::show(ui, icon, 30.0, tone.color(ui));
        ui.add(egui::Label::new(tone.text(ui, title).size(20.0).strong()).wrap());
    });
}

fn signer(ui: &mut egui::Ui, r: &VerifyReport, s: &SignerReport) {
    ui.horizontal(|ui| {
        let (icon, tone) = if s.valid {
            (Icon::Check, Tone::Good)
        } else {
            (Icon::Close, Tone::Bad)
        };
        icons::show(ui, icon, 18.0, tone.color(ui));
        ui.label(RichText::new(s.name()).strong().size(16.0));
    });
    egui::Grid::new(("signer", s.index))
        .num_columns(2)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            let mut row = |k: &str, v: String, tone: Tone| {
                ui.label(Tone::Muted.text(ui, k));
                ui.add(egui::Label::new(tone.text(ui, v)).wrap());
                ui.end_row();
            };
            if let Some(v) = s.get("IIN") {
                row(tr("IIN"), v.into(), Tone::Plain);
            }
            if let Some(o) = s.get("O") {
                let bin = s
                    .get("BIN")
                    .map(|b| trf(" · BIN {}", &[&b]))
                    .unwrap_or_default();
                row(tr("Organization"), format!("{o}{bin}"), Tone::Plain);
            }
            row(tr("Signed on"), signed_on(s), Tone::Plain);
            let (doc, tone) = if s.signature_ok {
                (tr("Not changed since signing ✔").to_string(), Tone::Good)
            } else {
                (s.signature_error.clone().unwrap_or_default(), Tone::Bad)
            };
            row(tr("Document"), doc, tone);
            let (key, tone) = if !s.chain_ok {
                (s.chain_status.clone().unwrap_or_default(), Tone::Bad)
            } else if let Some(e) = &s.usage_error {
                (e.clone(), Tone::Bad)
            } else {
                (tr("Issued by NCA RK ✔").to_string(), Tone::Good)
            };
            row(tr("Key"), key, tone);
            let (rev, tone) = match (&s.ocsp_status, s.ocsp_answer) {
                (Some(o), Some("good")) => (o.clone(), Tone::Good),
                (Some(o), Some("")) => (o.clone(), Tone::Warn),
                (Some(o), _) if s.valid => (o.clone(), Tone::Plain),
                (Some(o), _) => (o.clone(), Tone::Bad),
                (None, _) => (
                    tr("Not checked (the online check is off in More options)").into(),
                    Tone::Muted,
                ),
            };
            row(tr("Revoked?"), rev, tone);
        });
    for w in &s.warnings {
        warning(ui, w);
    }
    egui::CollapsingHeader::new(tr("Technical details"))
        .id_salt(("details", s.index))
        .show(ui, |ui| {
            egui::Grid::new(("tech", s.index))
                .num_columns(2)
                .spacing([14.0, 3.0])
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
                    if let Some(name) = &r.card_document {
                        row(tr("Document in the card"), name.clone());
                    }
                    if let Some(h) = &r.content_sha256 {
                        row(
                            tr("Document fingerprint"),
                            trf("{} bytes, SHA-256 {}", &[&r.content_size, h]),
                        );
                    }
                    if let Some(v) = s.get("E") {
                        row(tr("Email"), v.into());
                    }
                    row(tr("Time"), signed_at(s));
                    if let Some(l) = s.level {
                        row(tr("Long-term"), level_text(l).into());
                    }
                    for a in &s.archive_timestamps {
                        row(tr("Archive timestamp"), archive_text(a));
                    }
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
        });
}

fn card_lang_name(l: CardLang) -> &'static str {
    match l {
        CardLang::Ru => tr("Russian"),
        CardLang::Kk => tr("Kazakh"),
        CardLang::KkRu => tr("Kazakh and Russian"),
    }
}

/// When it was signed, in plain words.
fn signed_on(s: &SignerReport) -> String {
    match s.timestamp_time {
        Some(ts) if s.trusted_time().is_some() => {
            trf("{} · time confirmed by NCA", &[&time::fmt(Some(ts))])
        }
        Some(ts) => trf(
            "{} · time stamp not confirmed (see details)",
            &[&time::fmt(Some(ts))],
        ),
        None => trf(
            "{} · time from the signer's computer",
            &[&time::fmt(s.signing_time)],
        ),
    }
}

/// What a signature's ETSI level means, in plain words.
fn level_text(l: &str) -> &'static str {
    match l {
        "B-B" => tr("B-B: no timestamp, checkable only while the key is valid"),
        "B-T" => tr("B-T: with a timestamp"),
        "B-LT" => tr("B-LT: NCA's revocation answers are kept in it"),
        "B-LTA" => tr("B-LTA: revocation answers kept, and an archive timestamp"),
        _ => "",
    }
}

fn archive_text(a: &crate::report::ArchiveStamp) -> String {
    let state = if !a.checked || !a.valid {
        format!(" ({})", a.error.clone().unwrap_or_default())
    } else if a.trusted {
        " ✔".into()
    } else {
        tr(" (TSA not trusted)").into()
    };
    trf(
        "{} · timestamp by {}{}",
        &[
            &time::fmt(a.time),
            &a.tsa.clone().unwrap_or_default(),
            &state,
        ],
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_for_taken_out_documents() {
        let f = Path::new("/x/contract.pdf.cms");
        assert_eq!(original_name(f, None), "contract.pdf");
        assert_eq!(original_name(Path::new("/x/a.p7s"), None), "a.p7s.original");
        assert_eq!(original_name(f, Some("../../etc/passwd")), "passwd");
        assert_eq!(original_name(f, Some("dir\\note.txt")), "note.txt");
        assert_eq!(viewable_name("contract.pdf", b"%PDF-1.7"), "contract.pdf");
        assert_eq!(viewable_name("contract", b"%PDF-1.7"), "contract.pdf");
        assert_eq!(
            viewable_name("a.p7s.original", "текст".as_bytes()),
            "a.p7s.original.txt"
        );
        assert_eq!(viewable_name("blob", &[0xff, 0x00, 0xfe]), "blob");
    }

    #[test]
    fn viewing_copies_are_private_and_replaced() {
        let dir = std::env::temp_dir().join(format!("kzsigner-view-test-{}", std::process::id()));
        let a = write_for_viewing(&dir, "a.txt", b"one").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = write_for_viewing(&dir, "b.txt", b"two").unwrap();
        assert!(!a.exists() && std::fs::read(&b).unwrap() == b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
