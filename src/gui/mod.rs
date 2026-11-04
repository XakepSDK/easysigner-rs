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

mod check;
mod files;
mod report;
mod sign;
mod widgets;

use files::*;
pub use report::report;
use widgets::*;

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
                rgba: include_bytes!("../../assets/kzsigner-64.rgba").to_vec(),
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
    Xml,
    /// An XML document with a signature inside it; true when another one can go in too.
    SignedXml(bool),
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
    /// The signature inside the XML document (XAdES).
    Xml,
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
    /// Online checks (OCSP, and the NCA time when signing); off for working offline.
    pub ocsp: bool,
    /// The Sign screen: the document and how to sign it.
    pub sign: SignForm,
    /// The key to sign with.
    pub key: KeyForm,
    /// The Check screen.
    pub check: CheckForm,
}

/// The Sign screen's state: the document, the options, and the last signing.
pub struct SignForm {
    pub doc: Option<PathBuf>,
    /// For a detached .cms to add a signature to: its document.
    pub sign_original: Option<PathBuf>,
    doc_note: Note,
    doc_kind: DocKind,
    doc_is_detached_cms: bool,
    doc_is_cms: bool,
    /// The number of the latest document check; older answers are dropped.
    doc_request: u64,
    /// The document was opened from the start screen: if it turns out to be signed already,
    /// show the check instead.
    route_signed_to_check: bool,
    pub detached: bool,
    pub timestamp: bool,
    /// With the timestamp: a long-term signature (B-LTA), checkable after the certificate
    /// expires.
    pub long_term: bool,
    /// Signing inside a PDF: a visible stamp on its last page.
    pub stamp: bool,
    pub sign_as: SignAs,
    pub card_qr: bool,
    pub card_lang: CardLang,
    signing: bool,
    /// The last signing, shown on the Signed screen.
    pub done: Option<Done>,
}

impl Default for SignForm {
    fn default() -> SignForm {
        SignForm {
            doc: None,
            sign_original: None,
            doc_note: Note::default(),
            doc_kind: DocKind::Other,
            doc_is_detached_cms: false,
            doc_is_cms: false,
            doc_request: 0,
            route_signed_to_check: false,
            detached: false,
            timestamp: true,
            long_term: true,
            stamp: false,
            sign_as: SignAs::Cms,
            card_qr: false,
            card_lang: CardLang::Ru,
            signing: false,
            done: None,
        }
    }
}

/// The key file, its password, and the key once opened.
#[derive(Default)]
pub struct KeyForm {
    pub file: Option<PathBuf>,
    pub password: String,
    show_password: bool,
    aliases: Vec<String>,
    alias: Option<String>,
    note: Note,
    /// The opened key's holder, for the line under the key.
    holder: Option<String>,
    /// The opened key is from a trusted NCA RK issuer and has no warnings.
    ok: bool,
    opened: Option<Arc<Key>>,
    /// The number of the latest opening; older answers are dropped.
    request: u64,
    /// What the opened key was opened with (see [`key_request`]).
    opened_for: Option<String>,
}

/// The Check screen's state.
#[derive(Default)]
pub struct CheckForm {
    pub cms: Option<PathBuf>,
    pub verify_original: Option<PathBuf>,
    show_verify_original: bool,
    /// The number of the latest check; older answers are dropped.
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
            ocsp: true,
            sign: SignForm::default(),
            key: KeyForm::default(),
            check: CheckForm::default(),
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
            self.sign.route_signed_to_check = self.screen == Screen::Start;
            self.screen = Screen::Sign;
            self.set_doc(ctx, f);
        }
    }

    /// Switches the window's language and redoes what holds translated text: the key details,
    /// the document check and the verification report.
    pub fn set_language(&mut self, ctx: &egui::Context, lang: Lang) {
        i18n::set(lang);
        if let Some(k) = self.key.opened.clone() {
            self.key.note = self.describe_key(&k);
        } else if self.key.file.is_some() && !self.key.password.is_empty() {
            self.key.opened_for = None;
            self.open_key(ctx);
        }
        if let Some(d) = self.sign.doc.clone() {
            let original = self.sign.sign_original.clone();
            self.set_doc(ctx, d);
            self.sign.sign_original = original;
        }
        if self.check.result.is_some() {
            self.verify(ctx);
        }
    }

    // ------------------------------------------------------------------ Check

    fn handle(&mut self, ctx: &egui::Context, m: Msg) {
        match m {
            Msg::DocChecked(id, r) => self.doc_checked(ctx, id, r),
            Msg::KeyOpened(id, f, pw_hash, r) => self.key_opened(id, &f, &pw_hash, r),
            Msg::Signed(doc, sign_as, r) => self.signed(&doc, sign_as, r),
            Msg::Verified(id, r) => self.verified(id, r),
            Msg::Extracted(file, r) => match r {
                Ok((name, d)) => self.save_extracted(&file, name, d),
                Err(e) => self.message = Some((e, true)),
            },
            // another document has been chosen since: don't show the old one
            Msg::ToView(ViewFor::Sign(id), _) if id != self.sign.doc_request => {}
            Msg::ToView(ViewFor::Check(id), _) if id != self.check.verify_request => {}
            Msg::ToView(_, r) => {
                if let Err(e) = r.and_then(|f| {
                    check_viewable(&f)?;
                    self.dialogs.view(&f)
                }) {
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
        (
            "text",
            &include_bytes!("../../assets/NotoSans-subset.ttf")[..],
        ),
        ("symbols", &include_bytes!("../../assets/symbols.ttf")[..]),
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
        // a card can't name a Windows stream or hide the real extension
        assert_eq!(original_name(f, Some("a.exe:b.pdf")), "a.exe_b.pdf");
        assert_eq!(
            original_name(f, Some("invoice\u{202e}fdp.exe")),
            "invoice_fdp.exe"
        );
    }

    #[test]
    fn only_documents_are_opened() {
        for ok in [
            "a.pdf", "a.PDF", "b.docx", "c.xlsx", "d.txt", "e.jpg", "f.zip", "g.xml",
        ] {
            assert!(check_viewable(Path::new(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "a.exe",
            "a.pdf.exe",
            "a.lnk",
            "a.hta",
            "a.js",
            "a.vbs",
            "a.bat",
            "a.cmd",
            "a.ps1",
            "a.scr",
            "a.msi",
            "a.jar",
            "a.html",
            "a.svg",
            "a.docm",
            "a.xlsm",
            "a.desktop",
            "a.sh",
            "a.apk",
            "a.url",
            "a.pdf.",
            "noext",
            "a.exe_b",
        ] {
            assert!(check_viewable(Path::new(bad)).is_err(), "{bad}");
        }
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
